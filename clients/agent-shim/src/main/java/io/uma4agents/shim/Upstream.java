package io.uma4agents.shim;

import io.uma4agents.agent.AgentKeys;
import io.uma4agents.agent.GrantClient;
import io.uma4agents.agent.GrantClient.Challenge;
import io.uma4agents.agent.GrantClient.Contribution;
import io.uma4agents.agent.GrantClient.Negotiator;
import io.uma4agents.agent.GrantClient.PendingHandbackException;
import io.uma4agents.common.PyJson;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * The shim's client of the protected resource: MCP 2026-07-28 over streamable HTTP
 * (stateless, {@code server/discover}, per-request {@code _meta}, routing headers), with the
 * grant built in. Ported from the pinned {@code Upstream} in {@code clients/agent-shim}.
 */
final class Upstream {

    static final String PENDING_TEXT = "PENDING — the resource owner has not decided this yet.\n"
            + "This is normal and is not an error. She has been asked, the request is holding "
            + "at her authorization server, and she may take minutes or hours.\n"
            + "Call this same tool again, with the same arguments, to check whether she has "
            + "answered. Do not change the request and do not give up after one attempt.";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A pend this shim holds: where it is waiting and the ticket to present. */
    private record Held(String asUri, String ticket) {}

    /** One MCP reply: the HTTP status, headers of interest and parsed JSON-RPC payload. */
    record Reply(int status, String wwwAuthenticate, String text, Map<String, Object> payload) {}

    private final HttpClient http;
    private final AgentKeys keys;
    private final String gateway;
    private final long handbackSeconds;
    private final String authority;
    private final String path;
    private final Consumer<String> log;
    private final Consumer<String> onReceipt;
    private final Map<String, Object> clientMeta;
    private final Map<String, Held> outstanding = new ConcurrentHashMap<>();
    private final AtomicLong ids = new AtomicLong();
    private volatile boolean discovered;
    private volatile Map<String, Object> prm;

    /** Where the resource is, and how long to poll a pend before asking about it. */
    record Settings(String gateway, long handbackSeconds) {}

    Upstream(HttpClient http, AgentKeys keys, Settings settings, Consumer<String> log,
             Consumer<String> onReceipt) {
        this.http = http;
        this.keys = keys;
        this.gateway = settings.gateway();
        this.handbackSeconds = settings.handbackSeconds();
        String gateway = settings.gateway();
        URI u = URI.create(gateway);
        this.authority = u.getRawAuthority();
        this.path = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
        this.log = log;
        this.onReceipt = onReceipt;
        this.clientMeta = GrantClient.mcpMeta("uma4agents-agent-shim", "0.1");
    }

    /** What one tool call needs from the shim's own client: terms and waiting. */
    interface Asker {
        boolean approveTerms(Map<String, Object> template);

        boolean keepWaiting(GrantClient.Pend pend);
    }

    /** The tool call, with a pend rendered as an answer rather than a wait. */
    String callTool(String tool, Map<String, Object> args, Contribution contribution,
                    Asker asker) {
        try {
            return callOnce(tool, args, contribution, asker);
        } catch (PendingHandbackException pend) {
            return PENDING_TEXT;
        }
    }

    private String callOnce(String tool, Map<String, Object> args, Contribution contribution,
                            Asker asker) {
        ensureDiscovered();
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", tool);
        params.put("arguments", args);
        Reply reply = request("tools/call", params, null);
        Challenge challenge = challengeOf(reply);
        String key = tool + ":" + PyJson.dumpsSorted(args);
        Held held = outstanding.get(key);
        if (held != null) {
            String resumed = resume(key, held, params);
            if (resumed != null) {
                return resumed;
            }
        }
        if (challenge != null) {
            String rpt = negotiate(tool, challenge, key, contribution, asker);
            reply = request("tools/call", params, rpt);
        }
        return resultText(reply);
    }

    private Challenge challengeOf(Reply reply) {
        if (reply.status() == 401) {
            Challenge c = Challenge.parse(reply.wwwAuthenticate());
            if (c == null) {
                throw new IllegalStateException("401 without a UMA challenge: "
                        + truncate(reply.text()));
            }
            return c;
        }
        return GrantClient.jsonRpcChallenge(reply.payload());
    }

    /** Resume a held pend: the result text, or null to negotiate afresh. */
    private String resume(String key, Held held, Map<String, Object> params) {
        Map<String, Object> body = GrantClient.poll(http, held.asUri(), held.ticket());
        if (body == null) {
            log.accept("could not poll the held ticket; still waiting");
            throw new PendingHandbackException(held.asUri(), held.ticket());
        }
        if ("request_submitted".equals(body.get("error"))) {
            String ticket = body.get("ticket") instanceof String t ? t : held.ticket();
            outstanding.put(key, new Held(held.asUri(), ticket));
            log.accept("still waiting on her — the same request, not a new one");
            throw new PendingHandbackException(held.asUri(), ticket);
        }
        outstanding.remove(key);
        if (body.get("access_token") instanceof String rpt) {
            log.accept("she answered the request that was already waiting");
            if (body.get("receipt") instanceof String receipt) {
                onReceipt.accept(receipt);
            }
            Reply reply = request("tools/call", params, rpt);
            if (reply.status() == 200 && !hasError(reply.payload())) {
                return firstText(reply.payload());
            }
            throw new IllegalStateException("the owner approved this, and the call made under "
                    + "her approval failed (" + reply.status() + "); not asking her again");
        }
        if ("request_denied".equals(body.get("error"))) {
            log.accept("she declined the request that was waiting");
            Object description = body.get("error_description");
            throw new GrantClient.GrantDeniedException(description != null
                    ? String.valueOf(description) : "the owner declined");
        }
        log.accept("the held ticket is no longer valid; negotiating afresh");
        return null;
    }

    private String negotiate(String tool, Challenge challenge, String key,
                             Contribution contribution, Asker asker) {
        log.accept("challenged by " + challenge.asUri() + "; negotiating");
        Map<String, Object> doc = resourceMetadata();
        if (doc == null) {
            throw new IllegalStateException("refusing to negotiate: the resource's metadata "
                    + "could not be read, so the authorization server " + challenge.asUri()
                    + " is uncorroborated");
        }
        try {
            GrantClient.validateResourceMetadata(doc, gateway, challenge.asUri(),
                    challenge.resourceMetadata());
            log.accept("challenge corroborated against the resource's published metadata");
        } catch (GrantClient.DiscoveryMismatchException e) {
            throw new IllegalStateException("refusing to negotiate: " + e.getMessage(), e);
        }
        log.accept("Alice's AS requires terms before " + tool + " — negotiating");
        try {
            String rpt = GrantClient.runGrant(http, challenge, keys, contribution,
                    negotiator(asker));
            outstanding.remove(key);
            return rpt;
        } catch (PendingHandbackException pend) {
            outstanding.put(key, new Held(pend.asUri(), pend.ticket()));
            throw pend;
        }
    }

    private Negotiator negotiator(Asker asker) {
        return new Negotiator() {
            @Override
            public long maxWaitSeconds() {
                return handbackSeconds;
            }

            @Override
            public boolean approveTerms(Map<String, Object> template) {
                return asker.approveTerms(template);
            }

            @Override
            public boolean keepWaiting(GrantClient.Pend pend) {
                return asker.keepWaiting(pend);
            }

            @Override
            public void status(String message) {
                log.accept(message);
            }

            @Override
            public void receipt(String jws) {
                onReceipt.accept(jws);
            }
        };
    }

    private String resultText(Reply reply) {
        if (reply.status() != 200 || hasError(reply.payload())) {
            GrantClient.Refusal refusal = GrantClient.refusal(reply.status(), reply.payload());
            if (!refusal.terminal()) {
                throw new IllegalStateException(refusal.value() + ": the authorization server "
                        + "could not be reached; the same call may be sent again");
            }
            throw new IllegalStateException("call refused (" + refusal.value() + "): "
                    + truncate(reply.text()));
        }
        return firstText(reply.payload());
    }

    /** The 2026-07-28 handshake: stateless, and the only door to the modern protocol. */
    private void ensureDiscovered() {
        if (discovered) {
            return;
        }
        Reply reply = request("server/discover", new LinkedHashMap<>(), null);
        Map<String, Object> payload = reply.payload();
        if (reply.status() != 200 || payload == null) {
            throw new IllegalStateException("server/discover failed: " + reply.status() + " "
                    + truncate(reply.text()));
        }
        if (!(payload.get("result") instanceof Map<?, ?> result)) {
            throw new IllegalStateException("server/discover failed: "
                    + payload.getOrDefault("error", payload));
        }
        Object versions = result.get("supportedVersions");
        if (!(versions instanceof List<?> list)
                || !list.contains(GrantClient.MCP_PROTOCOL_VERSION)) {
            throw new IllegalStateException("resource does not speak "
                    + GrantClient.MCP_PROTOCOL_VERSION + " (offers " + versions + ")");
        }
        if (result.get("capabilities") instanceof Map<?, ?> caps
                && caps.get("extensions") instanceof Map<?, ?> exts
                && exts.get("dev.uma4agents/uma-enforcement") instanceof Map<?, ?> uma) {
            log.accept("resource enforces UMA in-process; AS "
                    + uma.get("authorization_servers"));
        }
        discovered = true;
    }

    /** Beat 0: the resource's RFC 9728 metadata, fetched once from where §3 puts it. */
    private Map<String, Object> resourceMetadata() {
        if (prm != null) {
            return prm;
        }
        String url = GrantClient.wellKnownPrmUrl(gateway);
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder().uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            Map<String, Object> doc = MAPPER.readValue(r.body(), new TypeReference<>() {});
            prm = GrantClient.validateResourceMetadata(doc, gateway, null, null);
            log.accept("beat 0: resource metadata at " + url + " — AS "
                    + doc.get("authorization_servers"));
        } catch (GrantClient.DiscoveryMismatchException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            log.accept("beat 0: resource metadata unavailable (" + e.getMessage()
                    + "); continuing challenge-driven");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return prm;
    }

    /** One JSON-RPC request; signed over its exact bytes when an RPT is given. */
    Reply request(String method, Map<String, Object> params, String rpt) {
        Map<String, Object> p = new LinkedHashMap<>(params);
        p.put("_meta", clientMeta);
        Map<String, Object> msg = new LinkedHashMap<>();
        msg.put("jsonrpc", "2.0");
        msg.put("method", method);
        msg.put("params", p);
        msg.put("id", ids.incrementAndGet());
        byte[] content;
        try {
            content = MAPPER.writeValueAsBytes(msg);
        } catch (JacksonException e) {
            throw new IllegalStateException("unserializable request", e);
        }
        HttpRequest.Builder b = HttpRequest.newBuilder().uri(URI.create(gateway))
                .timeout(Duration.ofSeconds(30))
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .header("MCP-Protocol-Version", GrantClient.MCP_PROTOCOL_VERSION)
                .header("Mcp-Method", method)
                .POST(HttpRequest.BodyPublishers.ofByteArray(content));
        if (params.get("name") instanceof String name) {
            b.header("Mcp-Name", name);
        }
        if (rpt != null) {
            GrantClient.signedHeaders(new GrantClient.Target("POST", authority, path), rpt, keys,
                    content).forEach(b::header);
        }
        return send(b.build());
    }

    private Reply send(HttpRequest request) {
        try {
            HttpResponse<String> r = http.send(request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            String type = r.headers().firstValue("content-type").orElse("");
            Map<String, Object> payload = r.body().isEmpty() ? null : parsePayload(r, type);
            return new Reply(r.statusCode(),
                    r.headers().firstValue("www-authenticate").orElse(null), r.body(), payload);
        } catch (IOException e) {
            throw new IllegalStateException("gateway unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted calling the gateway", e);
        }
    }

    private static Map<String, Object> parsePayload(HttpResponse<String> r, String type) {
        try {
            return GrantClient.mcpJson(r.body(), type);
        } catch (IllegalStateException e) {
            throw new IllegalStateException("non-JSON response (" + r.statusCode()
                    + ") from the gateway: " + truncate(r.body()), e);
        }
    }

    private static boolean hasError(Map<String, Object> payload) {
        return payload != null && payload.get("error") != null;
    }

    private static String firstText(Map<String, Object> payload) {
        if (payload != null && payload.get("result") instanceof Map<?, ?> result
                && result.get("content") instanceof List<?> content && !content.isEmpty()
                && content.get(0) instanceof Map<?, ?> first && first.get("text") instanceof String t) {
            return t;
        }
        try {
            return MAPPER.writeValueAsString(payload);
        } catch (JacksonException e) {
            return String.valueOf(payload);
        }
    }

    private static String truncate(String text) {
        return text == null ? "" : text.substring(0, Math.min(300, text.length()));
    }
}
