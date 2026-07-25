package io.uma4agents.portal;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * Minimal MCP streamable-http client for the portal backend — a direct port of
 * the Python {@code mcp_client.py}. Alice's portal reads her own vault directly
 * (she owns it); the gateway and grant loop exist for other people's agents.
 */
@Component
public class VaultClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String url;
    private final HttpClient http;
    private final AtomicLong id = new AtomicLong();

    public VaultClient(PortalConfig config, HttpClient http) {
        this.url = config.vaultMcpUrl;
        this.http = http;
    }

    public Map<String, Object> callTool(String tool, Map<String, Object> args) {
        Result init = call(null, "initialize", Map.of(
                "protocolVersion", "2025-03-26",
                "capabilities", Map.of(),
                "clientInfo", Map.of("name", "alice-portal", "version", "1.0")), false);
        call(init.sessionId(), "notifications/initialized", Map.of(), true);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", tool);
        params.put("arguments", args == null ? Map.of() : args);
        Result result = call(init.sessionId(), "tools/call", params, false);

        Object resultObj = result.payload().get("result");
        if (!(resultObj instanceof Map<?, ?> resultMap)) {
            throw new IllegalStateException("vault returned no result for " + tool
                    + ": " + result.payload());
        }
        Object content = resultMap.get("content");
        if (!(content instanceof java.util.List<?> list) || list.isEmpty()
                || !(list.get(0) instanceof Map<?, ?> first)
                || !(first.get("text") instanceof String text)) {
            throw new IllegalStateException("vault result has no text content for " + tool);
        }
        try {
            return MAPPER.readValue(text, new TypeReference<>() {});
        } catch (tools.jackson.core.JacksonException e) {
            throw new IllegalStateException(
                    "vault tool " + tool + " returned non-JSON text: " + text, e);
        }
    }

    private record Result(String sessionId, Map<String, Object> payload) {}

    private Result call(String sessionId, String method, Map<String, Object> params,
                        boolean notification) {
        Map<String, Object> msg = new LinkedHashMap<>();
        msg.put("jsonrpc", "2.0");
        msg.put("method", method);
        if (params != null) {
            msg.put("params", params);
        }
        if (!notification) {
            msg.put("id", id.incrementAndGet());
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(10))
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json");
        if (sessionId != null) {
            builder.header("mcp-session-id", sessionId);
        }
        try {
            HttpRequest request = builder.POST(HttpRequest.BodyPublishers.ofString(
                    MAPPER.writeValueAsString(msg))).build();
            HttpResponse<String> response =
                    http.send(request, HttpResponse.BodyHandlers.ofString());
            String sid = response.headers().firstValue("mcp-session-id").orElse(sessionId);
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
            return new Result(sid, payload == null ? Map.of() : payload);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("vault MCP call " + method + " failed: "
                    + e.getMessage(), e);
        }
    }
}
