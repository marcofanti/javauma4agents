package io.uma4agents.vault;

import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.modern.McpSchema.CallToolOutcome;
import io.modelcontextprotocol.modern.McpSchema.Implementation;
import io.modelcontextprotocol.modern.McpSchema.TextContent;
import io.modelcontextprotocol.modern.server.McpFeature;
import io.modelcontextprotocol.modern.server.McpSyncResponse;
import io.modelcontextprotocol.modern.server.feature.McpSyncTool;
import io.modelcontextprotocol.modern.server.feature.McpSyncToolRepository;
import io.modelcontextprotocol.modern.server.feature.ToolsFeature;
import io.modelcontextprotocol.modern.server.feature.ToolsPage;
import io.modelcontextprotocol.modern.server.transport.HttpServletMcpTransport;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * The vault's MCP endpoint at /mcp, serving both protocol generations from one tool
 * implementation: the MCP 2026-07-28 stateless transport ({@code server/discover}, per-
 * request {@code _meta}, routing headers) used by agents and the gateway, and the legacy
 * session-based {@code initialize} transport the portal still uses. {@link McpDispatchServlet}
 * picks one per request.
 */
@Configuration
public class VaultMcpConfig {

    static final String MODERN_VERSION = "2026-07-28";

    @Bean
    public McpJsonMapper mcpJsonMapper(JsonMapper mapper) {
        return new JacksonMcpJsonMapper(mapper);
    }

    @Bean
    public VaultTools vaultTools(Fixtures fixtures) {
        return new VaultTools(fixtures);
    }

    @Bean
    public ServletRegistrationBean<McpDispatchServlet> mcpServlet(McpJsonMapper jsonMapper,
                                                                  VaultTools tools,
                                                                  VaultSettings settings,
                                                                  ObjectMapper mapper) {
        HttpServletStreamableServerTransportProvider legacy =
                HttpServletStreamableServerTransportProvider.builder()
                        .jsonMapper(jsonMapper).mcpEndpoint("/mcp").build();
        legacyServer(legacy, tools, mapper, settings.owner);
        HttpServletMcpTransport modern = HttpServletMcpTransport.builder(
                modernServer(jsonMapper, tools, settings, mapper)).jsonMapper(jsonMapper)
                .endpoint("/mcp").build();
        return new ServletRegistrationBean<>(new McpDispatchServlet(modern, legacy), "/mcp",
                "/mcp/*");
    }

    private static io.modelcontextprotocol.modern.server.McpServer modernServer(
            McpJsonMapper jsonMapper, VaultTools tools, VaultSettings settings,
            ObjectMapper mapper) {
        List<McpFeature> features = new ArrayList<>();
        features.add(ToolsFeature.ofSync(new ModernTools(jsonMapper, tools, mapper)));
        if (settings.embedded) {
            features.add(new EnforcementExtension(settings));
        }
        return io.modelcontextprotocol.modern.server.McpServer.builder()
                .serverInfo(Implementation.builder(settings.owner + "-vault", "1.0.0").build())
                .supportedVersions(List.of(MODERN_VERSION))
                .jsonMapper(jsonMapper).features(features).build();
    }

    private static McpSyncServer legacyServer(HttpServletStreamableServerTransportProvider t,
                                              VaultTools tools, ObjectMapper mapper,
                                              String owner) {
        McpJsonMapper schemaMapper = new JacksonMcpJsonMapper(JsonMapper.builder().build());
        List<SyncToolSpecification> specs = new ArrayList<>();
        for (VaultTools.Definition d : VaultTools.DEFINITIONS) {
            specs.add(SyncToolSpecification.builder()
                    .tool(McpSchema.Tool.builder().name(d.name()).description(d.description())
                            .inputSchema(schemaMapper, d.inputSchema()).build())
                    .callHandler((exchange, request) -> legacyResult(mapper,
                            tools.call(d.name(), request.arguments())))
                    .build());
        }
        return McpServer.sync(t).serverInfo(owner + "-vault", "1.0.0")
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .tools(specs).build();
    }

    private static McpSchema.CallToolResult legacyResult(ObjectMapper mapper,
                                                         VaultTools.Outcome outcome) {
        if (outcome.error() != null) {
            return McpSchema.CallToolResult.builder().isError(true)
                    .content(List.of(new McpSchema.TextContent(outcome.error()))).build();
        }
        return McpSchema.CallToolResult.builder()
                .content(List.of(new McpSchema.TextContent(json(mapper, outcome.value()))))
                .build();
    }

    static String json(ObjectMapper mapper, Map<String, Object> value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JacksonException e) {
            throw new IllegalStateException("unserializable tool result", e);
        }
    }

    /** The tool repository for the 2026-07-28 server: the same tools, the same results. */
    static final class ModernTools implements McpSyncToolRepository {
        private final Map<String, McpSyncTool> byName = new LinkedHashMap<>();

        ModernTools(McpJsonMapper jsonMapper, VaultTools tools, ObjectMapper mapper) {
            for (VaultTools.Definition d : VaultTools.DEFINITIONS) {
                var definition = io.modelcontextprotocol.modern.McpSchema.Tool
                        .builder(d.name(), jsonMapper, d.inputSchema())
                        .description(d.description()).build();
                byName.put(d.name(), McpSyncTool.of(definition, (ctx, request) ->
                        McpSyncResponse.<CallToolOutcome>result(
                                modernResult(mapper, tools.call(d.name(), request.arguments())))));
            }
        }

        @Override
        public ToolsPage list(io.modelcontextprotocol.modern.server.McpRequestContext ctx,
                              String cursor) {
            return ToolsPage.of(byName.values().stream().map(McpSyncTool::definition).toList());
        }

        @Override
        public McpSyncTool find(io.modelcontextprotocol.modern.server.McpRequestContext ctx,
                                String name) {
            return byName.get(name);
        }

        private static CallToolOutcome modernResult(ObjectMapper mapper,
                                                    VaultTools.Outcome outcome) {
            var builder = io.modelcontextprotocol.modern.McpSchema.CallToolResult.builder();
            if (outcome.error() != null) {
                return builder.isError(true)
                        .addContent(TextContent.builder(outcome.error()).build()).build();
            }
            return builder.addContent(TextContent.builder(json(mapper, outcome.value())).build())
                    .structuredContent(outcome.value()).build();
        }
    }
}
