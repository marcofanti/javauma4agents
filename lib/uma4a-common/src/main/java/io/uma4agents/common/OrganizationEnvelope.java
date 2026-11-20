package io.uma4agents.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** The charter ceiling, applied to owner terms and checked again at enforcement. */
public final class OrganizationEnvelope {
    private OrganizationEnvelope() {}

    public record Clamp(Map<String, Object> patch, List<Map<String, Object>> changes) {}

    public static boolean reaches(String resource, Map<String, Object> envelope) {
        return envelope != null
                && !OrganizationPatterns.matches(resource, list(envelope.get("excluded")))
                && OrganizationPatterns.matches(resource, list(envelope.get("claims")));
    }

    public static Clamp clamp(Map<String, Object> tier, Map<String, Object> envelope) {
        if (list(tier.get("resources")).stream()
                .noneMatch(resource -> reaches((String) resource, envelope))) {
            return new Clamp(Map.of(), List.of());
        }
        Map<String, Object> terms = object(tier.get("terms"));
        Map<String, Object> patch = new LinkedHashMap<>();
        Map<String, Object> editedTerms = new LinkedHashMap<>();
        List<Map<String, Object>> changes = new ArrayList<>();

        long cap = seconds(envelope.get("max_expires_in"));
        long lifetime = seconds(terms.get("expires_in"));
        if (cap > 0 && lifetime > cap) {
            editedTerms.put("expires_in", cap);
            changes.add(change("max_expires_in", lifetime, cap, "Access expires after "
                    + duration(lifetime) + " → " + duration(cap)));
        }
        List<?> scope = list(terms.get("scope"));
        if (envelope.get("allowed_scopes") instanceof List<?> allowed) {
            List<?> dropped = scope.stream().filter(s -> !allowed.contains(s)).toList();
            if (!dropped.isEmpty()) {
                List<?> remaining = scope.stream().filter(allowed::contains).toList();
                editedTerms.put("scope", remaining);
                changes.add(change("allowed_scopes", scope, remaining, "No longer offers "
                        + join(dropped) + " — the organization does not allow it"));
            }
        }
        List<?> prohibited = list(terms.get("prohibited"));
        List<?> missing = list(envelope.get("require_prohibited")).stream()
                .filter(p -> !prohibited.contains(p)).toList();
        if (!missing.isEmpty()) {
            List<Object> extended = new ArrayList<>(prohibited);
            extended.addAll(missing);
            editedTerms.put("prohibited", extended);
            changes.add(change("require_prohibited", prohibited, extended,
                    "Always forbids " + join(missing)));
        }
        if (!Boolean.TRUE.equals(tier.get("ask_me")) && list(tier.get("resources")).stream()
                .anyMatch(r -> OrganizationPatterns.matches((String) r,
                        list(envelope.get("always_ask"))))) {
            patch.put("ask_me", true);
            changes.add(change("always_ask", false, true,
                    "Asks you every time — the organization requires it here"));
        }
        Map<String, Object> before = object(tier.get(Clearance.CLAIM));
        if (!object(envelope.get("require_clearance")).isEmpty()) {
            Map<String, Object> after = Clearance.tighten(before, envelope.get("require_clearance"));
            if (!after.equals(before)) {
                patch.put(Clearance.CLAIM, after);
                changes.add(change("require_clearance", before, after,
                        "Only while the organization can attest: "
                                + String.join(", ", new TreeSet<>(after.keySet()))));
            }
        }
        if (!editedTerms.isEmpty()) {
            patch.put("terms", editedTerms);
        }
        return new Clamp(patch, changes);
    }

    public static List<String> wouldExceed(Map<String, Object> spec, List<String> resources,
                                           Map<String, Object> envelope) {
        if (resources.stream().noneMatch(r -> reaches(r, envelope))) {
            return List.of();
        }
        List<String> problems = new ArrayList<>();
        Map<String, Object> terms = object(spec.get("terms"));
        long cap = seconds(envelope.get("max_expires_in"));
        long lifetime = seconds(terms.get("expires_in"));
        if (cap > 0 && lifetime > cap) {
            problems.add(envelope.get("name") + " caps access to these resources at "
                    + duration(cap) + "; these terms ask for " + duration(lifetime));
        }
        if (envelope.get("allowed_scopes") instanceof List<?> allowed) {
            List<?> extra = list(terms.get("scope")).stream().filter(s -> !allowed.contains(s)).toList();
            if (!extra.isEmpty()) {
                problems.add(envelope.get("name") + " does not allow " + join(extra)
                        + " over these resources");
            }
        }
        return problems;
    }

    public static Map<String, Object> compliance(Map<String, Map<String, Object>> tiers,
                                                 Set<String> resources,
                                                 Map<String, Object> envelope,
                                                 Set<String> changed) {
        Set<String> fields = new TreeSet<>(changed);
        boolean within = true;
        int governedTiers = 0;
        for (Map<String, Object> tier : tiers.values()) {
            if (list(tier.get("resources")).stream()
                    .noneMatch(resource -> reaches((String) resource, envelope))) {
                continue;
            }
            governedTiers++;
            List<Map<String, Object>> differences = clamp(tier, envelope).changes();
            if (!differences.isEmpty()) {
                within = false;
                differences.forEach(c -> fields.add((String) c.get("field")));
            }
        }
        return Map.of("charter_version", envelope.get("charter_version"),
                "resources_governed", resources.stream().filter(r -> reaches(r, envelope)).count(),
                "tiers_governed", governedTiers, "clamped_fields", new ArrayList<>(fields),
                "within", within);
    }

    public static String breach(Map<String, Object> permission, Map<String, Object> envelope,
                                double remaining) {
        long cap = seconds(envelope.get("max_expires_in"));
        if (cap > 0 && remaining > cap + 5) {
            return "the grant has " + (long) remaining + "s left, past the " + cap + "s ceiling "
                    + envelope.get("name") + " sets for this resource";
        }
        if (envelope.get("allowed_scopes") instanceof List<?> allowed) {
            List<?> extra = list(permission.get("resource_scopes")).stream()
                    .filter(s -> !allowed.contains(s)).toList();
            if (!extra.isEmpty()) {
                return "the grant carries " + join(extra) + ", which " + envelope.get("name")
                        + " does not allow for this resource";
            }
        }
        return null;
    }

    private static Map<String, Object> change(String field, Object was, Object now, String text) {
        return Map.of("field", field, "was", was, "now", now, "text", text);
    }

    public static String duration(long seconds) {
        if (seconds > 0 && seconds % 86400 == 0) {
            return seconds / 86400 + "d";
        }
        if (seconds > 0 && seconds % 3600 == 0) {
            return seconds / 3600 + "h";
        }
        if (seconds > 0 && seconds % 60 == 0) {
            return seconds / 60 + "m";
        }
        return seconds + "s";
    }

    private static long seconds(Object value) {
        return value instanceof Number n ? n.longValue() : 0;
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> list ? list : List.of();
    }

    private static String join(List<?> values) {
        return String.join(", ", values.stream().map(String::valueOf).toList());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }
}
