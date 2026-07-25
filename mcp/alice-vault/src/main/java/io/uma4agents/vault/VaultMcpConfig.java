package io.uma4agents.vault;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.util.List;
import java.util.Map;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Registers the MCP streamable-http endpoint at /mcp with the three vault tools. */
@Configuration
public class VaultMcpConfig {

    private static final String POSITIONS_SCHEMA = """
            {"type":"object","properties":{},"required":[]}""";
    private static final String TRANSACTIONS_SCHEMA = """
            {"type":"object","properties":{
              "account":{"type":"string","default":"brokerage-main"}},
             "required":[]}""";
    private static final String TRADE_SCHEMA = """
            {"type":"object","properties":{
              "symbol":{"type":"string"},
              "side":{"type":"string"},
              "quantity":{"type":"integer"}},
             "required":["symbol","side","quantity"]}""";

    @Bean
    public McpJsonMapper mcpJsonMapper(JsonMapper mapper) {
        return new JacksonMcpJsonMapper(mapper);
    }

    @Bean
    public HttpServletStreamableServerTransportProvider transportProvider(McpJsonMapper jsonMapper) {
        return HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(jsonMapper)
                .mcpEndpoint("/mcp")
                .build();
    }

    @Bean
    public ServletRegistrationBean<HttpServletStreamableServerTransportProvider> mcpServlet(
            HttpServletStreamableServerTransportProvider transportProvider) {
        return new ServletRegistrationBean<>(transportProvider, "/mcp/*", "/mcp");
    }

    @Bean
    public McpSyncServer mcpServer(HttpServletStreamableServerTransportProvider transportProvider,
                                   Fixtures fixtures, ObjectMapper mapper) {
        VaultTools tools = new VaultTools(fixtures, mapper);
        return McpServer.sync(transportProvider)
                .serverInfo("alice-vault", "1.0.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(
                        tool("get_positions",
                                "Alice's current holdings summary: positions and allocation (read-only).",
                                POSITIONS_SCHEMA, (exchange, request) ->
                                        tools.getPositions()),
                        tool("get_transactions",
                                "Transaction history and cost basis for one of Alice's accounts.",
                                TRANSACTIONS_SCHEMA, (exchange, request) ->
                                        tools.getTransactions(request.arguments())),
                        tool("execute_trade",
                                "Execute a trade in Alice's account. (Fixture execution — no market.)",
                                TRADE_SCHEMA, (exchange, request) ->
                                        tools.executeTrade(request.arguments())))
                .build();
    }

    private static SyncToolSpecification tool(
            String name, String description, String schema,
            java.util.function.BiFunction<Object, McpSchema.CallToolRequest, CallToolResult> handler) {
        return SyncToolSpecification.builder()
                .tool(Tool.builder().name(name).description(description).inputSchema(
                        new JacksonMcpJsonMapper(JsonMapper.builder().build()), schema).build())
                .callHandler((exchange, request) -> handler.apply(exchange, request))
                .build();
    }

    static CallToolResult jsonResult(ObjectMapper mapper, Map<String, Object> value) {
        try {
            return CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent(mapper.writeValueAsString(value))))
                    .build();
        } catch (tools.jackson.core.JacksonException e) {
            throw new IllegalStateException("unserializable tool result", e);
        }
    }
}
