package io.uma4agents.shim;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ElicitRequest;
import io.modelcontextprotocol.spec.McpSchema.ElicitResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.uma4agents.agent.AgentKeys;
import io.uma4agents.agent.EnrollClient;
import io.uma4agents.agent.GrantClient;
import io.uma4agents.common.SslContexts;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * agent-shim — lets an unmodified agent (Claude Code, Claude Desktop, any MCP
 * client) act as Bob's requesting agent: a local stdio MCP server that proxies
 * Alice's vault tools through the gateway, holds Bob's agent signing key, and
 * runs the four-beat grant dance whenever the gateway challenges. Alice's
 * dictated terms are surfaced to Bob inside his agent via MCP elicitation when
 * the client supports it; otherwise Bob's standing config decides.
 */
public final class ShimMain {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final String gateway = env("UMA4A_GATEWAY", "https://gateway.uma.lab/mcp");
    private final String cacert = env("UMA4A_CACERT", "certs/rootCA.pem");
    private final String keystore = env("UMA4A_KEYSTORE",
            System.getProperty("user.home") + "/.uma4agents/agent-key.pem");
    private final String receiptsDir;
    private final long standingMaxExpires =
            Long.parseLong(env("UMA4A_STANDING_MAX_EXPIRES", String.valueOf(7 * 24 * 3600)));
    private final String agentIssuer = env("UMA4A_AGENT_ISSUER", null);
    private final String personToken = env("UMA4A_PERSON_TOKEN", null);

    private final HttpClient http;
    private final AgentKeys keys;
    private final Upstream upstream;

    private ShimMain() {
        Path keystorePath = Path.of(keystore);
        Path parent = keystorePath.getParent();
        this.receiptsDir = env("UMA4A_RECEIPTS",
                (parent == null ? Path.of(".") : parent).resolve("receipts").toString());
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30));
        if (cacert != null && Files.exists(Path.of(cacert))) {
            builder.sslContext(SslContexts.fromPem(Path.of(cacert)));
        }
        this.http = builder.build();
        this.keys = bootstrapIdentity();
        this.upstream = new Upstream(http, keys, gateway, ShimMain::log, this::storeReceipt);
    }

    public static void main(String[] args) throws InterruptedException {
        ShimMain shim = new ShimMain();
        log("proxying " + shim.gateway + "; keystore " + shim.keystore);
        shim.serve();
        Thread.currentThread().join();
    }

    private static void log(String msg) {
        System.err.println("[agent-shim] " + msg);
        System.err.flush();
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Pseudonymous by default; identified (enrolled) when an issuer is set. */
    private AgentKeys bootstrapIdentity() {
        if (agentIssuer == null) {
            return AgentKeys.loadOrCreate(Path.of(keystore));
        }
        AgentKeys identified = AgentKeys.loadOrCreateIdentified(Path.of(keystore));
        identified.agentToken = EnrollClient.enroll(http, agentIssuer, identified.stable,
                identified.key, "Bob's agent via uma4agents shim", personToken,
                ShimMain::log, 300, 3);
        log("enrolled with " + agentIssuer + "; running identified");
        return identified;
    }

    /** Persist the counter-signed receipt — the agent's half of the dual record. */
    private void storeReceipt(String receiptJws) {
        String family = "unknown";
        try {
            String payload = receiptJws.split("\\.")[1];
            int pad = (4 - payload.length() % 4) % 4;
            Map<String, Object> claims = MAPPER.readValue(
                    Base64.getUrlDecoder().decode(payload + "=".repeat(pad)),
                    new TypeReference<>() {});
            if (claims.get("family") instanceof String f) {
                family = f;
            }
        } catch (Exception e) {
            // Keep the receipt anyway under "unknown".
        }
        try {
            Path dir = Path.of(receiptsDir);
            Files.createDirectories(dir);
            Path path = dir.resolve(family + ".receipt.jws");
            Files.writeString(path, receiptJws);
            log("receipt held: " + path);
        } catch (java.io.IOException e) {
            log("could not persist receipt: " + e.getMessage());
        }
    }

    /** Elicit Bob inside his agent; fall back to his standing config. */
    private boolean approveTerms(McpSyncServerExchange exchange, String tool,
                                 Map<String, Object> template) {
        String message = "Alice's authorization server dictates these terms for `" + tool + "`:\n"
                + "• purpose: " + template.get("purpose") + "\n"
                + "• access expires in: " + template.get("expires_in") + "s\n"
                + "• prohibited: " + joined(template.get("prohibited")) + "\n\n"
                + "Sign this intent contract on your behalf?";
        try {
            ElicitResult result = exchange.createElicitation(
                    ElicitRequest.builder(message, Map.of(
                            "type", "object",
                            "properties", Map.of("approve", Map.of("type", "boolean")),
                            "required", List.of("approve"))).build());
            if (result.action() == ElicitResult.Action.ACCEPT && result.content() != null) {
                boolean approve = Boolean.TRUE.equals(result.content().get("approve"));
                log("terms " + (approve ? "approved" : "refused") + " via elicitation");
                return approve;
            }
            log("elicitation declined/cancelled — refusing terms");
            return false;
        } catch (Exception e) {  // client without elicitation support
            long expiresIn = template.get("expires_in") instanceof Number n ? n.longValue() : 0;
            boolean ok = expiresIn <= standingMaxExpires;
            log("elicitation unavailable (" + e.getClass().getSimpleName() + "); standing config "
                    + (ok ? "accepts" : "refuses") + " (max_expires=" + standingMaxExpires + ")");
            return ok;
        }
    }

    private static String joined(Object list) {
        if (list instanceof List<?> items) {
            return items.stream().map(String::valueOf).collect(Collectors.joining(", "));
        }
        return "";
    }

    private void serve() {
        JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(MAPPER);
        StdioServerTransportProvider transport = new StdioServerTransportProvider(jsonMapper);
        McpServer.sync(transport)
                .serverInfo("alice-vault-via-uma", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(
                        tool(jsonMapper, "get_positions",
                                "Alice's current holdings summary (tier 1: auto-grant under her"
                                        + " standard terms).",
                                "{\"type\":\"object\",\"properties\":{},\"required\":[]}",
                                (exchange, args) -> upstream.callTool("get_positions", Map.of(),
                                        null, t -> approveTerms(exchange, "get_positions", t))),
                        tool(jsonMapper, "get_transactions",
                                "Alice's transaction history (tier 2: stricter dictated terms).",
                                "{\"type\":\"object\",\"properties\":{\"account\":{"
                                        + "\"type\":\"string\",\"default\":\"brokerage-main\"}},"
                                        + "\"required\":[]}",
                                (exchange, args) -> {
                                    String account = args.get("account") instanceof String s
                                            ? s : "brokerage-main";
                                    return upstream.callTool("get_transactions",
                                            Map.of("account", account), null,
                                            t -> approveTerms(exchange, "get_transactions", t));
                                }),
                        tool(jsonMapper, "execute_trade",
                                "Propose a trade in Alice's account (tier 3: pends until Alice"
                                        + " approves; the grant is single-use and bound to exactly"
                                        + " this order).",
                                "{\"type\":\"object\",\"properties\":{"
                                        + "\"symbol\":{\"type\":\"string\"},"
                                        + "\"side\":{\"type\":\"string\"},"
                                        + "\"quantity\":{\"type\":\"integer\"}},"
                                        + "\"required\":[\"symbol\",\"side\",\"quantity\"]}",
                                (exchange, args) -> {
                                    Map<String, Object> order = new LinkedHashMap<>();
                                    order.put("symbol", args.get("symbol"));
                                    order.put("side", args.get("side"));
                                    order.put("quantity",
                                            ((Number) args.get("quantity")).intValue());
                                    Map<String, Object> operation = new LinkedHashMap<>();
                                    operation.put("tool", "execute_trade");
                                    operation.put("params", order);
                                    try {
                                        return upstream.callTool("execute_trade", order, operation,
                                                t -> approveTerms(exchange, "execute_trade", t));
                                    } catch (GrantClient.GrantDeniedException e) {
                                        return "Alice did not authorize this trade: "
                                                + e.getMessage();
                                    } catch (GrantClient.TermsRejectedException e) {
                                        return "You declined Alice's terms; the trade was not"
                                                + " submitted.";
                                    }
                                }))
                .build();
    }

    private interface ToolHandler {
        String handle(McpSyncServerExchange exchange, Map<String, Object> args);
    }

    private static SyncToolSpecification tool(JacksonMcpJsonMapper jsonMapper, String name,
                                              String description, String schema,
                                              ToolHandler handler) {
        return SyncToolSpecification.builder()
                .tool(Tool.builder().name(name).description(description)
                        .inputSchema(jsonMapper, schema).build())
                .callHandler((exchange, request) -> {
                    try {
                        String text = handler.handle(exchange,
                                request.arguments() == null ? Map.of() : request.arguments());
                        return CallToolResult.builder()
                                .content(List.of(new McpSchema.TextContent(text)))
                                .build();
                    } catch (RuntimeException e) {
                        return CallToolResult.builder()
                                .isError(true)
                                .content(List.of(new McpSchema.TextContent(
                                        "Error executing tool " + name + ": " + e.getMessage())))
                                .build();
                    }
                })
                .build();
    }
}
