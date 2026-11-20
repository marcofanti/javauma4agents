package io.uma4agents.portal;

import jakarta.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Health, identity, and Alice's first-party brokerage data (direct vault MCP). */
@RestController
@ConditionalOnProperty(name = "uma.portal.mode", havingValue = "owner", matchIfMissing = true)
public class ApiController {

    private final PortalConfig config;
    private final Sessions sessions;
    private final VaultClient vault;

    public ApiController(PortalConfig config, Sessions sessions, VaultClient vault) {
        this.config = config;
        this.sessions = sessions;
        this.vault = vault;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok", "auth", config.authMode);
    }

    @GetMapping("/api/me")
    public ResponseEntity<Map<String, Object>> me(HttpServletRequest request) {
        String user = sessions.currentUser(request);
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("authenticated", false));
        }
        return ResponseEntity.ok(Map.of(
                "authenticated", true, "name", user, "auth", config.authMode));
    }

    @GetMapping("/api/portfolio")
    public ResponseEntity<Map<String, Object>> portfolio(HttpServletRequest request) {
        if (sessions.currentUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("error", "auth"));
        }
        Map<String, Object> data = vault.callTool("get_positions", null);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> positions = (List<Map<String, Object>>) data.get("positions");
        Map<String, Object> enriched = enrich(positions);
        enriched.put("as_of", data.get("as_of"));
        return ResponseEntity.ok(enriched);
    }

    @GetMapping("/api/transactions")
    public ResponseEntity<Map<String, Object>> transactions(
            HttpServletRequest request,
            @RequestParam(defaultValue = "brokerage-main") String account) {
        if (sessions.currentUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("error", "auth"));
        }
        return ResponseEntity.ok(vault.callTool("get_transactions", Map.of("account", account)));
    }

    @PostMapping("/api/trade")
    public ResponseEntity<Map<String, Object>> trade(HttpServletRequest request,
                                                     @RequestBody Map<String, Object> body) {
        if (sessions.currentUser(request) == null) {
            return ResponseEntity.status(401).body(Map.of("error", "auth"));
        }
        Map<String, Object> args = Map.of(
                "symbol", body.get("symbol"),
                "side", body.get("side"),
                "quantity", toInt(body.get("quantity")));
        return ResponseEntity.ok(vault.callTool("execute_trade", args));
    }

    /** Port of Python _enrich(): per-position gain/weight/price plus totals. */
    static Map<String, Object> enrich(List<Map<String, Object>> positions) {
        double totalMv = positions.stream().mapToDouble(p -> num(p.get("market_value"))).sum();
        double totalCb = positions.stream().mapToDouble(p -> num(p.get("cost_basis"))).sum();
        for (Map<String, Object> p : positions) {
            double mv = num(p.get("market_value"));
            double cb = num(p.get("cost_basis"));
            double quantity = num(p.get("quantity"));
            double gain = round2(mv - cb);
            p.put("gain", gain);
            p.put("gain_pct", round2(cb != 0 ? gain / cb * 100 : 0));
            p.put("weight", round2(totalMv != 0 ? mv / totalMv * 100 : 0));
            p.put("price", quantity != 0 ? round2(mv / quantity) : 0);
        }
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        result.put("total_value", round2(totalMv));
        result.put("total_cost", round2(totalCb));
        result.put("total_gain", round2(totalMv - totalCb));
        result.put("total_gain_pct", round2(totalCb != 0 ? (totalMv - totalCb) / totalCb * 100 : 0));
        result.put("positions", positions);
        return result;
    }

    private static double num(Object value) {
        return value instanceof Number n ? n.doubleValue() : 0;
    }

    private static double round2(double value) {
        return BigDecimal.valueOf(value).setScale(2, RoundingMode.HALF_EVEN).doubleValue();
    }

    private static int toInt(Object value) {
        return switch (value) {
            case Number n -> n.intValue();
            case String s -> Integer.parseInt(s);
            case null, default -> throw new IllegalArgumentException("quantity required");
        };
    }
}
