package io.uma4agents.vault;

import tools.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The three vault tools, mirroring the Python FastMCP handlers exactly. */
final class VaultTools {

    private final Fixtures fixtures;
    private final ObjectMapper mapper;

    VaultTools(Fixtures fixtures, ObjectMapper mapper) {
        this.fixtures = fixtures;
        this.mapper = mapper;
    }

    CallToolResult getPositions() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("as_of", fixtures.asOf());
        result.put("positions", fixtures.positions());
        return VaultMcpConfig.jsonResult(mapper, result);
    }

    CallToolResult getTransactions(Map<String, Object> args) {
        String account = args != null && args.get("account") instanceof String s
                ? s : "brokerage-main";
        List<Map<String, Object>> txns = fixtures.transactions().stream()
                .filter(t -> account.equals(t.get("account")))
                .toList();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("account", account);
        result.put("transactions", txns);
        return VaultMcpConfig.jsonResult(mapper, result);
    }

    CallToolResult executeTrade(Map<String, Object> args) {
        Object side = args == null ? null : args.get("side");
        if (!"buy".equals(side) && !"sell".equals(side)) {
            return CallToolResult.builder()
                    .isError(true)
                    .content(List.of(new McpSchema.TextContent(
                            "Error executing tool execute_trade: side must be 'buy' or 'sell'")))
                    .build();
        }
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("symbol", args.get("symbol"));
        order.put("side", side);
        order.put("quantity", ((Number) args.get("quantity")).intValue());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "executed");
        result.put("order", order);
        result.put("note", "fixture execution — no real market behind this endpoint");
        return VaultMcpConfig.jsonResult(mapper, result);
    }
}
