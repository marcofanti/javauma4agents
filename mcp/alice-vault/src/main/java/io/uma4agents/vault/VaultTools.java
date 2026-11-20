package io.uma4agents.vault;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The three vault tools, mirroring the pinned Python handlers. Transport-neutral: each MCP
 * transport adapts {@link Outcome} into its own result type, so both protocol generations
 * share one implementation.
 */
final class VaultTools {

    /** One tool's name, description and JSON input schema. */
    record Definition(String name, String description, String inputSchema) {}

    /** A tool result value, or the error message the call failed with. */
    record Outcome(Map<String, Object> value, String error) {
        static Outcome ok(Map<String, Object> value) {
            return new Outcome(value, null);
        }

        static Outcome failed(String message) {
            return new Outcome(null, message);
        }
    }

    static final List<Definition> DEFINITIONS = List.of(
            new Definition("get_positions",
                    "The owner's current holdings summary: positions and allocation.",
                    "{\"type\":\"object\",\"properties\":{},\"required\":[]}"),
            new Definition("get_transactions",
                    "Transaction history and cost basis for one of Alice's accounts.",
                    "{\"type\":\"object\",\"properties\":{\"account\":{\"type\":\"string\","
                            + "\"default\":\"brokerage-main\"}},\"required\":[]}"),
            new Definition("execute_trade",
                    "Execute a trade in Alice's account. (Fixture execution — no market.)",
                    "{\"type\":\"object\",\"properties\":{\"symbol\":{\"type\":\"string\"},"
                            + "\"side\":{\"type\":\"string\"},\"quantity\":{\"type\":"
                            + "\"integer\"}},\"required\":[\"symbol\",\"side\",\"quantity\"]}"));

    private final Fixtures fixtures;

    VaultTools(Fixtures fixtures) {
        this.fixtures = fixtures;
    }

    Outcome call(String tool, Map<String, Object> args) {
        Map<String, Object> safeArgs = args == null ? Map.of() : args;
        return switch (tool) {
            case "get_positions" -> getPositions();
            case "get_transactions" -> getTransactions(safeArgs);
            case "execute_trade" -> executeTrade(safeArgs);
            default -> Outcome.failed("Unknown tool: " + tool);
        };
    }

    private Outcome getPositions() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("as_of", fixtures.asOf());
        result.put("positions", fixtures.positions());
        return Outcome.ok(result);
    }

    private Outcome getTransactions(Map<String, Object> args) {
        String account = args.get("account") instanceof String s ? s : "brokerage-main";
        List<Map<String, Object>> txns = fixtures.transactions().stream()
                .filter(t -> account.equals(t.get("account")))
                .toList();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("account", account);
        result.put("transactions", txns);
        return Outcome.ok(result);
    }

    private Outcome executeTrade(Map<String, Object> args) {
        Object side = args.get("side");
        if (!"buy".equals(side) && !"sell".equals(side)) {
            return Outcome.failed(
                    "Error executing tool execute_trade: side must be 'buy' or 'sell'");
        }
        if (!(args.get("quantity") instanceof Number quantity)) {
            return Outcome.failed("Error executing tool execute_trade: quantity must be an "
                    + "integer");
        }
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("symbol", args.get("symbol"));
        order.put("side", side);
        order.put("quantity", quantity.intValue());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "executed");
        result.put("order", order);
        result.put("note", "fixture execution — no real market behind this endpoint");
        return Outcome.ok(result);
    }
}
