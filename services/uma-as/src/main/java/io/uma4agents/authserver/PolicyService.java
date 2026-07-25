package io.uma4agents.authserver;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Alice's tier policy — a small, legible document, not a policy language. Each
 * tier names the resources it covers, the terms template the AS dictates, and
 * whether granting requires asking her. The portal edits it via the owner API.
 */
@Component
public class PolicyService {

    private final Object lock = new Object();
    private final Map<String, Map<String, Object>> tiers = defaults();

    private static Map<String, Map<String, Object>> defaults() {
        Map<String, Map<String, Object>> tiers = new LinkedHashMap<>();
        tiers.put("tier1", tier(
                "Holdings summary",
                List.of("alice-vault/get_positions"),
                false,
                terms("alice/advisor-tier1/v2",
                        "Suitability review for advisory onboarding",
                        List.of("positions:read"), 172800,
                        List.of("retention-after-review", "marketing", "model-training"),
                        null, false)));
        tiers.put("tier2", tier(
                "Transaction history and cost basis",
                List.of("alice-vault/get_transactions"),
                false,
                terms("alice/advisor-tier2/v2",
                        "Portfolio analysis for the current advisory engagement",
                        List.of("transactions:read"), 86400,
                        List.of("client-benchmarking", "sharing-outside-engagement-team",
                                "retention-after-engagement"),
                        Map.of("accounts", List.of("brokerage-main")), false)));
        tiers.put("tier3", tier(
                "Trade execution",
                List.of("alice-vault/execute_trade"),
                true,
                terms("alice/advisor-tier3/v2",
                        "Execution of one client-approved order",
                        List.of("trades:execute"), 900,
                        List.of("orders-beyond-approved-parameters",
                                "discretionary-reuse-of-authority"),
                        null, true)));
        return tiers;
    }

    private static Map<String, Object> tier(String name, List<String> resources,
                                            boolean askMe, Map<String, Object> terms) {
        Map<String, Object> tier = new LinkedHashMap<>();
        tier.put("name", name);
        tier.put("resources", new ArrayList<>(resources));
        tier.put("ask_me", askMe);
        tier.put("terms", terms);
        return tier;
    }

    private static Map<String, Object> terms(String templateId, String purpose,
                                             List<String> scope, int expiresIn,
                                             List<String> prohibited,
                                             Map<String, Object> constraints,
                                             boolean perOperation) {
        Map<String, Object> terms = new LinkedHashMap<>();
        terms.put("template_id", templateId);
        terms.put("purpose", purpose);
        terms.put("scope", new ArrayList<>(scope));
        terms.put("expires_in", expiresIn);
        terms.put("prohibited", new ArrayList<>(prohibited));
        if (constraints != null) {
            terms.put("constraints", constraints);
        }
        if (perOperation) {
            terms.put("per_operation", true);
        }
        return terms;
    }

    public Map<String, Map<String, Object>> tiers() {
        synchronized (lock) {
            return deepCopyTiers();
        }
    }

    /** Returns {tierId, tier} for the resource, or null when no tier governs it. */
    public Map.Entry<String, Map<String, Object>> tierForResource(String resourceId) {
        synchronized (lock) {
            for (Map.Entry<String, Map<String, Object>> e : tiers.entrySet()) {
                Object resources = e.getValue().get("resources");
                if (resources instanceof List<?> list && list.contains(resourceId)) {
                    return Map.entry(e.getKey(), deepCopy(e.getValue()));
                }
            }
        }
        return null;
    }

    /**
     * Owner edits: terms fields and the ask_me switch; resources are fixed by
     * registration. Every edit bumps the template version so contracts are
     * verifiably tied to the terms in force when they were signed.
     */
    public Map<String, Object> updateTier(String tierId, Map<String, Object> patch) {
        synchronized (lock) {
            Map<String, Object> tier = tiers.get(tierId);
            if (tier == null) {
                throw new java.util.NoSuchElementException(tierId);
            }
            if (patch.containsKey("ask_me")) {
                tier.put("ask_me", Boolean.TRUE.equals(patch.get("ask_me")));
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> terms = (Map<String, Object>) tier.get("terms");
            if (patch.get("terms") instanceof Map<?, ?> termsPatch) {
                for (String field : List.of("purpose", "expires_in", "prohibited")) {
                    if (termsPatch.containsKey(field)) {
                        terms.put(field, termsPatch.get(field));
                    }
                }
            }
            String templateId = (String) terms.get("template_id");
            int split = templateId.lastIndexOf("/v");
            String base = templateId.substring(0, split);
            int version = Integer.parseInt(templateId.substring(split + 2)) + 1;
            terms.put("template_id", base + "/v" + version);
            return deepCopy(tier);
        }
    }

    private Map<String, Map<String, Object>> deepCopyTiers() {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        tiers.forEach((k, v) -> out.put(k, deepCopy(v)));
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> deepCopy(Map<String, Object> value) {
        return (Map<String, Object>) copyValue(value);
    }

    private static Object copyValue(Object value) {
        return switch (value) {
            case Map<?, ?> map -> {
                Map<Object, Object> out = new LinkedHashMap<>();
                map.forEach((k, v) -> out.put(k, copyValue(v)));
                yield out;
            }
            case List<?> list -> {
                List<Object> out = new ArrayList<>();
                list.forEach(item -> out.add(copyValue(item)));
                yield out;
            }
            case null, default -> value;
        };
    }
}
