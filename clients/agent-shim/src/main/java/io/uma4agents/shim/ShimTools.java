package io.uma4agents.shim;

import io.uma4agents.agent.GrantClient;
import io.uma4agents.agent.GrantClient.Contribution;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The three tools the shim exposes, transport-neutral: each transport supplies an
 * {@link Upstream.Asker} for its client and renders the returned text.
 */
final class ShimTools {

    /** One tool's name, description and JSON input schema. */
    record Definition(String name, String description, String inputSchema) {}

    static final List<Definition> DEFINITIONS = List.of(
            new Definition("get_positions",
                    "Alice's current holdings summary (tier 1: auto-grant under her standard "
                            + "terms).",
                    "{\"type\":\"object\",\"properties\":{},\"required\":[]}"),
            new Definition("get_transactions",
                    "Alice's transaction history (tier 2: stricter dictated terms).\n"
                            + "`reason`: why you are asking, in one sentence, for Alice to read.",
                    "{\"type\":\"object\",\"properties\":{\"account\":{\"type\":\"string\","
                            + "\"default\":\"brokerage-main\"},\"reason\":{\"type\":\"string\","
                            + "\"default\":\"\"}},\"required\":[]}"),
            new Definition("execute_trade",
                    "Propose a trade in Alice's account (tier 3: pends until Alice approves; "
                            + "the grant is single-use and bound to exactly this order).\n"
                            + "`reason`: why this order, in one sentence.",
                    "{\"type\":\"object\",\"properties\":{\"symbol\":{\"type\":\"string\"},"
                            + "\"side\":{\"type\":\"string\"},\"quantity\":{\"type\":\"integer\"},"
                            + "\"reason\":{\"type\":\"string\",\"default\":\"\"}},"
                            + "\"required\":[\"symbol\",\"side\",\"quantity\"]}"));

    private final Upstream upstream;
    private final Map<String, Object> mission;

    ShimTools(Upstream upstream, Map<String, Object> mission) {
        this.upstream = upstream;
        this.mission = mission;
    }

    /** Runs one tool call and returns its text. */
    String call(String tool, Map<String, Object> args, Upstream.Asker asker) {
        Map<String, Object> safe = args == null ? Map.of() : args;
        String reason = safe.get("reason") instanceof String r ? r : "";
        return switch (tool) {
            case "get_positions" -> upstream.callTool("get_positions", Map.of(),
                    new Contribution(null, null, mission), asker);
            case "get_transactions" -> upstream.callTool("get_transactions",
                    Map.of("account", safe.get("account") instanceof String a
                            ? a : "brokerage-main"),
                    new Contribution(null, reason, mission), asker);
            case "execute_trade" -> executeTrade(safe, reason, asker);
            default -> throw new IllegalArgumentException("Unknown tool: " + tool);
        };
    }

    private String executeTrade(Map<String, Object> args, String reason, Upstream.Asker asker) {
        if (!(args.get("quantity") instanceof Number quantity)) {
            throw new IllegalArgumentException("quantity must be an integer");
        }
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("symbol", args.get("symbol"));
        order.put("side", args.get("side"));
        order.put("quantity", quantity.intValue());
        Map<String, Object> operation = new LinkedHashMap<>();
        operation.put("tool", "execute_trade");
        operation.put("params", order);
        try {
            return upstream.callTool("execute_trade", order,
                    new Contribution(operation, reason, mission), asker);
        } catch (GrantClient.GrantDeniedException e) {
            return "Alice did not authorize this trade: " + e.getMessage();
        } catch (GrantClient.TermsRejectedException e) {
            return "You declined Alice's terms; the trade was not submitted.";
        }
    }
}
