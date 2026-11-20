package io.uma4agents.shim;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.uma4agents.agent.GrantClient;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * The shim over stateless streamable HTTP at {@code /mcp}, for MCP clients that are services
 * rather than a person's desktop agent. Stateless means no session to elicit on: terms are
 * decided by Bob's standing config, and a pend is handed back as a PENDING result for the
 * caller to poll by calling again. A thin JSON-RPC adapter on the JDK HTTP server, sharing the
 * tool code with the stdio transport.
 */
final class ShimHttp {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final List<String> VERSIONS = List.of("2025-11-25", "2025-06-18",
            "2025-03-26");
    private static final int MAX_BODY_BYTES = 1024 * 1024;

    private final ShimTools tools;
    private final long standingMaxExpires;
    private final Consumer<String> log;

    ShimHttp(ShimTools tools, long standingMaxExpires, Consumer<String> log) {
        this.tools = tools;
        this.standingMaxExpires = standingMaxExpires;
        this.log = log;
    }

    static boolean standingAccepts(Map<String, Object> template, long maxExpires) {
        long expiresIn = template.get("expires_in") instanceof Number n ? n.longValue()
                : Long.MAX_VALUE;
        return expiresIn <= maxExpires;
    }

    void serve(String host, int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.createContext("/mcp", this::handle);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            if (!"POST".equals(ex.getRequestMethod())) {
                reply(ex, 405, Map.of("error", "method not allowed: this server is stateless"));
                return;
            }
            Map<String, Object> msg;
            try (InputStream in = ex.getRequestBody()) {
                byte[] body = in.readNBytes(MAX_BODY_BYTES + 1);
                if (body.length > MAX_BODY_BYTES) {
                    reply(ex, 413, Map.of("error", "request body too large"));
                    return;
                }
                msg = MAPPER.readValue(body, new TypeReference<>() {});
            } catch (JacksonException e) {
                reply(ex, 400, error(null, -32700, "Parse error"));
                return;
            }
            Object id = msg.get("id");
            String method = String.valueOf(msg.get("method"));
            if (id == null) {
                ex.sendResponseHeaders(202, -1);
                return;
            }
            reply(ex, 200, dispatch(id, method, msg.get("params") instanceof Map<?, ?> p
                    ? p : Map.of()));
        }
    }

    private Map<String, Object> dispatch(Object id, String method, Map<?, ?> params) {
        return switch (method) {
            case "initialize" -> ok(id, initialize(params));
            case "ping" -> ok(id, Map.of());
            case "tools/list" -> ok(id, Map.of("tools", toolList()));
            case "tools/call" -> ok(id, callTool(params));
            default -> error(id, -32601, "Method not found: " + method);
        };
    }

    private static Map<String, Object> initialize(Map<?, ?> params) {
        String requested = params.get("protocolVersion") instanceof String v ? v : "";
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("protocolVersion", VERSIONS.contains(requested) ? requested : VERSIONS.get(0));
        result.put("capabilities", Map.of("tools", Map.of("listChanged", false)));
        result.put("serverInfo", Map.of("name", "alice-vault-via-uma", "version", "0.1.0"));
        return result;
    }

    private static List<Map<String, Object>> toolList() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ShimTools.Definition d : ShimTools.DEFINITIONS) {
            Map<String, Object> tool = new LinkedHashMap<>();
            tool.put("name", d.name());
            tool.put("description", d.description());
            tool.put("inputSchema", parse(d.inputSchema()));
            out.add(tool);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> callTool(Map<?, ?> params) {
        String name = String.valueOf(params.get("name"));
        Map<String, Object> args = params.get("arguments") instanceof Map<?, ?> a
                ? (Map<String, Object>) a : Map.of();
        Set<String> known = Set.of("get_positions", "get_transactions", "execute_trade");
        String text;
        boolean failed = false;
        try {
            if (!known.contains(name)) {
                throw new IllegalArgumentException("Unknown tool: " + name);
            }
            text = tools.call(name, args, new StandingAsker());
        } catch (RuntimeException e) {
            text = "Error executing tool " + name + ": " + e.getMessage();
            failed = true;
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", List.of(Map.of("type", "text", "text", text)));
        result.put("isError", failed);
        return result;
    }

    /** No person on this connection: standing config for terms, hand back for pends. */
    private final class StandingAsker implements Upstream.Asker {
        @Override
        public boolean approveTerms(Map<String, Object> template) {
            boolean ok = standingAccepts(template, standingMaxExpires);
            log.accept("elicitation unavailable over stateless HTTP; standing config "
                    + (ok ? "accepts" : "refuses") + " (max_expires=" + standingMaxExpires + ")");
            return ok;
        }

        @Override
        public boolean keepWaiting(GrantClient.Pend pend) {
            log.accept("client cannot render the pend; handing it back to be polled");
            throw new GrantClient.PendingHandbackException(pend.asUri(), pend.ticket());
        }
    }

    private static Map<String, Object> ok(Object id, Object result) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jsonrpc", "2.0");
        out.put("id", id);
        out.put("result", result);
        return out;
    }

    private static Map<String, Object> error(Object id, int code, String message) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jsonrpc", "2.0");
        out.put("id", id);
        out.put("error", Map.of("code", code, "message", message));
        return out;
    }

    private static Map<String, Object> parse(String json) {
        return MAPPER.readValue(json, new TypeReference<>() {});
    }

    private static void reply(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = MAPPER.writeValueAsBytes(body);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }
}
