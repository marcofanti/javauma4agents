package io.uma4agents.pep;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Alice's vault tool surface: tool → (resource_id, scopes). This is what the
 * gateway registers at her AS on startup.
 */
public final class ToolCatalog {

    public record Surface(String resourceId, List<String> scopes) {}

    public static final Map<String, Surface> TOOLS = tools();
    public static final Set<String> SINGLE_USE_TOOLS = Set.of("execute_trade");
    public static final Set<String> OPEN_METHODS =
            Set.of("initialize", "notifications/initialized", "tools/list", "ping");

    private ToolCatalog() {}

    private static Map<String, Surface> tools() {
        Map<String, Surface> tools = new LinkedHashMap<>();
        tools.put("get_positions",
                new Surface("alice-vault/get_positions", List.of("positions:read")));
        tools.put("get_transactions",
                new Surface("alice-vault/get_transactions", List.of("transactions:read")));
        tools.put("execute_trade",
                new Surface("alice-vault/execute_trade", List.of("trades:execute")));
        return tools;
    }
}
