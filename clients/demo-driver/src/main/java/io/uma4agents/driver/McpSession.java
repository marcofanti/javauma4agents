package io.uma4agents.driver;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;

/** Minimal streamable-http MCP session — port of the Python McpSession. */
final class McpSession {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    record Reply(int status, Map<String, Object> payload, String wwwAuthenticate, String raw) {}

    private final HttpClient client;
    private final String url;
    private String sessionId;
    private long id;

    McpSession(HttpClient client, String url) {
        this.client = client;
        this.url = url;
    }

    Reply request(String method, Map<String, Object> params, Map<String, String> headers,
                  boolean notification) {
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
                .uri(URI.create(url))
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
                try {
                    payload = MAPPER.readValue(response.body(), new TypeReference<>() {});
                } catch (tools.jackson.core.JacksonException e) {
                    throw new IllegalStateException("non-JSON response ("
                            + response.statusCode() + "): "
                            + response.body().substring(0, Math.min(200, response.body().length())));
                }
            }
            return new Reply(response.statusCode(), payload,
                    response.headers().firstValue("www-authenticate").orElse(""),
                    response.body());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("MCP request failed: " + e.getMessage(), e);
        }
    }

    void initialize() {
        Reply reply = request("initialize", Map.of(
                "protocolVersion", "2025-03-26",
                "capabilities", Map.of(),
                "clientInfo", Map.of("name", "uma4agents-demo-driver", "version", "0.2")),
                null, false);
        if (reply.status() != 200) {
            throw new IllegalStateException("initialize failed: " + reply.status()
                    + " " + reply.raw().substring(0, Math.min(200, reply.raw().length())));
        }
        request("notifications/initialized", Map.of(), null, true);
    }
}
