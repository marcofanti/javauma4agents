package io.uma4agents.shim;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.uma4agents.agent.AgentKeys;
import io.uma4agents.agent.GrantClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Minimal MCP streamable-http client with the grant dance built in — the
 * shim's connection to the gateway (port of the Python Upstream class).
 */
final class Upstream {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient client;
    private final AgentKeys keys;
    private final String gateway;
    private final String authority;
    private final String mcpPath;
    private final Consumer<String> log;
    private final Consumer<String> onReceipt;
    private String sessionId;
    private long id;
    private boolean initialized;
    private Map<String, Object> prm;
    private boolean prmFetched;

    Upstream(HttpClient client, AgentKeys keys, String gateway,
             Consumer<String> log, Consumer<String> onReceipt) {
        this.client = client;
        this.keys = keys;
        this.gateway = gateway;
        URI uri = URI.create(gateway);
        this.authority = uri.getAuthority();
        this.mcpPath = uri.getRawPath() == null || uri.getRawPath().isEmpty()
                ? "/" : uri.getRawPath();
        this.log = log;
        this.onReceipt = onReceipt;
    }

    private record Reply(int status, Map<String, Object> payload, String wwwAuthenticate,
                         String raw) {}

    private synchronized Reply request(String method, Map<String, Object> params,
                                       Map<String, String> headers, boolean notification) {
        Map<String, Object> msg = new LinkedHashMap<>();
        msg.put("jsonrpc", "2.0");
        msg.put("method", method);
        if (params != null) {
            msg.put("params", params);
        }
        if (!notification) {
            msg.put("id", ++id);
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(gateway))
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json");
        if (sessionId != null) {
            builder.header("mcp-session-id", sessionId);
        }
        if (headers != null) {
            headers.forEach(builder::header);
        }
        try {
            HttpRequest request = builder.POST(HttpRequest.BodyPublishers.ofString(
                    MAPPER.writeValueAsString(msg))).build();
            HttpResponse<String> response =
                    client.send(request, HttpResponse.BodyHandlers.ofString());
            response.headers().firstValue("mcp-session-id").ifPresent(sid -> sessionId = sid);
            String contentType = response.headers().firstValue("content-type").orElse("");
            Map<String, Object> payload = null;
            if (contentType.contains("text/event-stream")) {
                for (String line : response.body().split("\n")) {
                    if (line.startsWith("data:")) {
                        payload = MAPPER.readValue(line.substring(5).trim(),
                                new TypeReference<>() {});
                        break;
                    }
                }
            } else if (!response.body().isEmpty()) {
                payload = MAPPER.readValue(response.body(), new TypeReference<>() {});
            }
            return new Reply(response.statusCode(), payload,
                    response.headers().firstValue("www-authenticate").orElse(""),
                    response.body());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("gateway request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Beat 0 — the resource's RFC 9728 metadata, fetched once. Names the
     * owner's AS and the protected tool surfaces before any call. Discovery is
     * declarative; the challenge remains authoritative when it is unavailable.
     */
    private synchronized Map<String, Object> resourceMetadata() {
        if (prmFetched) {
            return prm;
        }
        prmFetched = true;
        String url = GrantClient.wellKnownPrmUrl(gateway);
        try {
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
            HttpResponse<String> response =
                    client.send(request, HttpResponse.BodyHandlers.ofString());
            Map<String, Object> doc = MAPPER.readValue(response.body(),
                    new TypeReference<>() {});
            prm = GrantClient.validateResourceMetadata(doc, gateway, null);
            Object servers = doc.get("authorization_servers");
            int surfaces = doc.get("tool_surfaces") instanceof List<?> list ? list.size() : 0;
            log.accept("beat 0: resource metadata at " + url + " — AS " + servers
                    + ", " + surfaces + " tool surfaces");
        } catch (GrantClient.DiscoveryMismatchException e) {
            throw e;
        } catch (IOException | InterruptedException | RuntimeException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.accept("beat 0: resource metadata unavailable (" + e.getMessage()
                    + "); continuing challenge-driven");
        }
        return prm;
    }

    private synchronized void ensureInitialized() {
        if (initialized) {
            return;
        }
        Reply reply = request("initialize", Map.of(
                "protocolVersion", "2025-03-26",
                "capabilities", Map.of(),
                "clientInfo", Map.of("name", "uma4agents-agent-shim", "version", "0.1")),
                null, false);
        if (reply.status() != 200) {
            throw new IllegalStateException("gateway initialize failed: " + reply.status());
        }
        request("notifications/initialized", Map.of(), null, true);
        initialized = true;
    }

    /** tools/call through the gateway, negotiating a grant on 401. */
    String callTool(String tool, Map<String, Object> args, Map<String, Object> operation,
                    Predicate<Map<String, Object>> approveTerms) {
        ensureInitialized();
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", tool);
        params.put("arguments", args);
        Reply reply = request("tools/call", params, null, false);

        if (reply.status() == 401) {
            GrantClient.Challenge challenge = GrantClient.Challenge.parse(reply.wwwAuthenticate());
            if (challenge == null) {
                throw new IllegalStateException("401 without a UMA challenge: "
                        + truncate(reply.raw(), 200));
            }
            log.accept("challenged by " + challenge.asUri() + "; negotiating");
            Map<String, Object> metadata = resourceMetadata();
            if (metadata != null) {
                try {
                    GrantClient.validateResourceMetadata(metadata, gateway, challenge.asUri());
                    log.accept("challenge corroborated against the resource's "
                            + "published metadata");
                } catch (GrantClient.DiscoveryMismatchException e) {
                    throw new IllegalStateException("refusing to negotiate: " + e.getMessage());
                }
            }
            String rpt = GrantClient.runGrant(client, challenge.asUri(), challenge.ticket(),
                    keys, approveTerms, operation, log, onReceipt, 120);
            Map<String, String> headers = GrantClient.signedHeaders(
                    "POST", authority, mcpPath, rpt, keys);
            reply = request("tools/call", params, headers, false);
        }

        if (reply.status() != 200) {
            throw new IllegalStateException("call failed: " + reply.status() + " "
                    + truncate(reply.raw(), 300));
        }
        try {
            Object result = reply.payload().get("result");
            Object content = ((Map<?, ?>) result).get("content");
            return String.valueOf(((Map<?, ?>) ((List<?>) content).get(0)).get("text"));
        } catch (RuntimeException e) {
            try {
                return MAPPER.writeValueAsString(reply.payload());
            } catch (tools.jackson.core.JacksonException je) {
                return String.valueOf(reply.payload());
            }
        }
    }

    private static String truncate(String value, int max) {
        return value == null ? "" : value.substring(0, Math.min(max, value.length()));
    }
}
