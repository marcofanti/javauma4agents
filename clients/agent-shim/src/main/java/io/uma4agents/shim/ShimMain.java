package io.uma4agents.shim;

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
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import tools.jackson.databind.json.JsonMapper;

/**
 * agent-shim: lets an unmodified MCP client act as Bob's requesting agent. A local MCP server
 * (stdio, or stateless streamable HTTP with {@code UMA4A_SHIM_TRANSPORT}) that proxies Alice's
 * vault tools, holds Bob's signing key, and runs the grant whenever the resource challenges.
 * Terms and pends are surfaced through MCP elicitation when the client supports it;
 * otherwise Bob's standing config decides terms and a pend is handed back as a result.
 */
public final class ShimMain {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    final ShimEnv env = new ShimEnv();
    private final HttpClient http;
    private final ShimTools tools;

    private ShimMain() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30));
        if (Files.exists(Path.of(env.cacert))) {
            builder.sslContext(SslContexts.fromPem(Path.of(env.cacert)));
        }
        this.http = builder.build();
        AgentKeys keys = bootstrapIdentity();
        Upstream upstream = new Upstream(http, keys,
                new Upstream.Settings(env.gateway, env.pendHandbackSeconds), ShimMain::log,
                this::storeReceipt);
        this.tools = new ShimTools(upstream, env.mission);
    }

    public static void main(String[] args) throws InterruptedException, IOException {
        ShimMain shim = new ShimMain();
        log("proxying " + shim.env.gateway + "; keystore " + shim.env.keystore);
        if ("stdio".equals(shim.env.transport)) {
            shim.serveStdio();
        } else {
            new ShimHttp(shim.tools, shim.env.standingMaxExpires, ShimMain::log)
                    .serve(shim.env.host, shim.env.port);
            log("listening on " + shim.env.host + ":" + shim.env.port + " ("
                    + shim.env.transport + ")");
        }
        Thread.currentThread().join();
    }

    static void log(String msg) {
        System.err.println("[agent-shim] " + msg);
        System.err.flush();
    }

    /** Pseudonymous by default; identified when an issuer is set; published when asked. */
    private AgentKeys bootstrapIdentity() {
        AgentKeys keys;
        if (env.agentIssuer == null) {
            keys = AgentKeys.loadOrCreate(Path.of(env.keystore));
        } else {
            keys = AgentKeys.loadOrCreateIdentified(Path.of(env.keystore));
            keys.agentToken = EnrollClient.enroll(http, env.agentIssuer, keys.stable, keys.key,
                    env.agentName, env.personToken, ShimMain::log, 300, 3);
            log("enrolled with " + env.agentIssuer + "; running identified");
        }
        if (env.publishTo != null) {
            keys.clientId = env.publishTo + "/agent.json";
            keys.signatureAgent = keys.publish(http, env.publishTo, env.registerToken);
            log(keys.signatureAgent != null ? "key published at " + keys.signatureAgent
                    : "operator directory unreachable; continuing without Signature-Agent");
        }
        if (env.clientId != null) {
            keys.clientId = env.clientId;
        }
        return keys;
    }

    /** Persists the counter-signed receipt under a name the receipt cannot steer. */
    private void storeReceipt(String receiptJws) {
        try {
            Path dir = Path.of(env.receiptsDir);
            Files.createDirectories(dir);
            Path path = dir.resolve(GrantClient.receiptFilename(receiptJws));
            Files.writeString(path, receiptJws);
            log("receipt held: " + path);
        } catch (IOException e) {
            log("could not persist receipt: " + e.getMessage());
        }
    }

    private void serveStdio() {
        JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(MAPPER);
        List<SyncToolSpecification> specs = new ArrayList<>();
        for (ShimTools.Definition d : ShimTools.DEFINITIONS) {
            specs.add(SyncToolSpecification.builder()
                    .tool(Tool.builder().name(d.name()).description(d.description())
                            .inputSchema(jsonMapper, d.inputSchema()).build())
                    .callHandler((exchange, request) -> result(d.name(),
                            () -> tools.call(d.name(), request.arguments(),
                                    new ElicitingAsker(exchange, d.name()))))
                    .build());
        }
        McpServer.sync(new StdioServerTransportProvider(jsonMapper))
                .serverInfo("alice-vault-via-uma", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(specs).build();
    }

    private static CallToolResult result(String tool, java.util.function.Supplier<String> call) {
        try {
            return CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent(call.get()))).build();
        } catch (RuntimeException e) {
            return CallToolResult.builder().isError(true).content(List.of(
                    new McpSchema.TextContent("Error executing tool " + tool + ": "
                            + e.getMessage()))).build();
        }
    }

    static String joined(Object list) {
        return list instanceof List<?> items
                ? items.stream().map(String::valueOf).collect(Collectors.joining(", ")) : "";
    }

    /** Terms and waits put to Bob inside his agent, through MCP elicitation. */
    private final class ElicitingAsker implements Upstream.Asker {
        private final McpSyncServerExchange exchange;
        private final String tool;

        ElicitingAsker(McpSyncServerExchange exchange, String tool) {
            this.exchange = exchange;
            this.tool = tool;
        }

        private boolean canElicit() {
            McpSchema.ClientCapabilities caps = exchange.getClientCapabilities();
            return caps != null && caps.elicitation() != null;
        }

        @Override
        public boolean approveTerms(Map<String, Object> template) {
            if (!canElicit()) {
                boolean ok = ShimHttp.standingAccepts(template, env.standingMaxExpires);
                log("elicitation unavailable (MCPError); standing config "
                        + (ok ? "accepts" : "refuses") + " (max_expires="
                        + env.standingMaxExpires + ")");
                return ok;
            }
            String message = "Alice's authorization server dictates these terms for `" + tool
                    + "`:\n• purpose: " + template.get("purpose") + "\n• access expires in: "
                    + template.get("expires_in") + "s\n• prohibited: "
                    + joined(template.get("prohibited"))
                    + "\n\nSign this intent contract on your behalf?";
            ElicitResult r = exchange.createElicitation(ElicitRequest.builder(message,
                    booleanSchema("approve")).build());
            boolean approve = r.action() == ElicitResult.Action.ACCEPT && r.content() != null
                    && Boolean.TRUE.equals(r.content().get("approve"));
            log(r.action() == ElicitResult.Action.ACCEPT
                    ? "terms " + (approve ? "approved" : "refused") + " via elicitation"
                    : "elicitation declined/cancelled — refusing terms");
            return approve;
        }

        @Override
        public boolean keepWaiting(GrantClient.Pend pend) {
            if (!canElicit()) {
                log("client cannot render the pend; handing it back to be polled");
                throw new GrantClient.PendingHandbackException(pend.asUri(), pend.ticket());
            }
            String message = "`" + tool + "` is waiting on the resource owner's decision.\n\n"
                    + "• who must decide: the resource owner — not you, and not reachable from "
                    + "this connection\n• where: " + pend.asUri() + "\n• they have been "
                    + "notified and the request is holding\n\nKeep waiting?";
            ElicitResult r = exchange.createElicitation(ElicitRequest.builder(message,
                    booleanSchema("keep_waiting")).build());
            if (r.action() == ElicitResult.Action.ACCEPT && r.content() != null) {
                return Boolean.TRUE.equals(r.content().get("keep_waiting"));
            }
            log("requesting side stopped waiting");
            return false;
        }
    }

    private static Map<String, Object> booleanSchema(String field) {
        return Map.of("type", "object",
                "properties", Map.of(field, Map.of("type", "boolean")),
                "required", List.of(field));
    }
}
