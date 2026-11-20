package io.uma4agents.organization;

import io.uma4agents.common.Clearance;
import io.uma4agents.common.OrganizationPatterns;
import io.uma4agents.common.PyRepr;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Validates the member-facing charter before the custom rules can reach OPA. */
final class OrganizationCharter {
    private static final Set<String> DELEGATION = Set.of("any-agent", "first-party-only", "none");
    private static final Pattern ALLOW = Pattern.compile("(?m)^\\s*(default\\s+)?allow\\b");
    private static final Pattern CUSTOM = Pattern.compile(
            "^package\\s+u4a\\.custom(?:\\s|$)");

    private OrganizationCharter() {}

    static Map<String, Object> validate(Map<String, Object> charter) {
        Map<String, Object> out = new LinkedHashMap<>(charter);
        String name = text(charter.get("name")).strip();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("the charter needs a name — members are shown it");
        }
        out.put("name", name);
        List<String> claims = strings(charter.get("claims"), "claims");
        if (claims.isEmpty()) {
            throw new IllegalArgumentException("claims must be a non-empty list of resource patterns");
        }
        claims = claims.stream().map(String::strip).toList();
        for (String claim : claims) {
            validatePattern(claim);
            String namespace = claim.split("/", 2)[0];
            if (namespace.isEmpty() || namespace.contains("*")) {
                throw new IllegalArgumentException("claims must name the organization's own namespace — "
                        + PyRepr.of(claim) + " has a wildcard where the namespace goes, and would "
                        + "reach resources belonging to members and to people who have never heard "
                        + "of this organization. Claim `"
                        + (namespace.isEmpty() ? "<namespace>" : namespace)
                        + "…` as a concrete namespace instead.");
            }
        }
        out.put("claims", claims);

        Map<String, Object> envelope = section(charter, "envelope");
        if (!envelope.containsKey("max_expires_in") || numeric(envelope.get("max_expires_in")) == 0) {
            throw new IllegalArgumentException("envelope.max_expires_in is required — the ceiling on "
                    + "how long any member's grant may last");
        }
        bounded(envelope, "max_expires_in", "envelope.", 1, 30 * 86400);
        for (String field : List.of("allowed_scopes", "require_prohibited", "always_ask")) {
            if (envelope.containsKey(field)) {
                strings(envelope.get(field), "envelope." + field);
            }
        }
        strings(envelope.get("always_ask"), "envelope.always_ask")
                .forEach(OrganizationCharter::validatePattern);
        envelope.put("require_clearance",
                Clearance.validateRequirement(envelope.get("require_clearance"),
                        "envelope.require_clearance"));
        out.put("envelope", envelope);

        Map<String, Object> roles = section(charter, "roles");
        for (Map.Entry<String, Object> entry : roles.entrySet()) {
            if (!(entry.getValue() instanceof Map<?, ?> raw)) {
                throw new IllegalArgumentException("role " + PyRepr.of(entry.getKey())
                        + " must be an object");
            }
            Map<String, Object> role = new LinkedHashMap<>(object(raw));
            for (String pattern : strings(role.get("grants"), "roles." + entry.getKey() + ".grants")) {
                validatePattern(pattern);
                if (!covered(pattern, claims)) {
                    throw new IllegalArgumentException("role " + PyRepr.of(entry.getKey())
                            + " grants " + PyRepr.of(pattern) + ", which this charter does not claim. "
                            + "A role may only hand out access to the organization's own resources.");
                }
            }
            Object delegation = role.getOrDefault("delegation", "none");
            if (!(delegation instanceof String mode) || !DELEGATION.contains(mode)) {
                throw new IllegalArgumentException("roles." + entry.getKey() + ".delegation must be "
                        + "one of ['any-agent', 'first-party-only', 'none'], got "
                        + PyRepr.of(delegation));
            }
            role.put("delegation", delegation);
            role.putIfAbsent("name", entry.getKey());
            entry.setValue(role);
        }
        String defaultRole = text(charter.get("default_role"));
        if (!defaultRole.isEmpty() && !roles.containsKey(defaultRole)) {
            throw new IllegalArgumentException("default_role " + PyRepr.of(defaultRole)
                    + " is not a role here");
        }
        out.put("roles", roles);

        Map<String, Object> conditions = section(charter, "conditions");
        for (String floor : List.of("min_binding", "min_provenance", "min_accountability")) {
            bounded(conditions, floor, "conditions.", 0, 3);
        }
        for (String flag : List.of("require_reason", "require_mission")) {
            if (conditions.containsKey(flag) && !(conditions.get(flag) instanceof Boolean)) {
                throw new IllegalArgumentException("conditions." + flag + " is true or false");
            }
        }
        out.put("conditions", conditions);
        out.put("break_glass", breakGlass(charter, claims));
        normalizeIdentityProvider(charter, out);

        Object rawRego = charter.get("rego");
        if (rawRego != null && !(rawRego instanceof String)) {
            throw new IllegalArgumentException("rego must be a string — the module text");
        }
        String rego = text(rawRego).strip();
        if (!rego.isEmpty() && !CUSTOM.matcher(rego).find()) {
            throw new IllegalArgumentException("custom rules must begin with `package u4a.custom` — "
                    + "the shipped module reads `deny` and `ask` from that package");
        }
        if (ALLOW.matcher(rego).find()) {
            throw new IllegalArgumentException("custom rules can contribute `deny` and `ask` and "
                    + "nothing else. An `allow` here would load, evaluate, and be ignored: this "
                    + "layer sits above the member's policy and can only ever make a request "
                    + "harder. What she permits is hers to decide.");
        }
        out.put("rego", rego);
        return out;
    }

    private static Map<String, Object> breakGlass(Map<String, Object> charter, List<String> claims) {
        Map<String, Object> glass = section(charter, "break_glass");
        boolean enabled = Boolean.TRUE.equals(glass.get("enabled"));
        glass.put("enabled", enabled);
        List<String> resources = strings(glass.get("resources"), "break_glass.resources");
        strings(glass.get("invokers"), "break_glass.invokers");
        resources.forEach(OrganizationCharter::validatePattern);
        if (!enabled) {
            return glass;
        }
        if (resources.isEmpty()) {
            throw new IllegalArgumentException("break_glass.resources is required when break-glass "
                    + "is enabled — an override with no stated subject is not an exception, it is "
                    + "a second way in");
        }
        bounded(glass, "max_expires_in", "break_glass.", 1, 3600);
        glass.putIfAbsent("max_expires_in", 900);
        for (String resource : resources) {
            if (!covered(resource, claims)) {
                throw new IllegalArgumentException("break_glass.resources names " + PyRepr.of(resource)
                        + ", which the charter does not claim — an override may only reach what "
                        + "members were told the organization governs");
            }
        }
        return glass;
    }

    private static void normalizeIdentityProvider(Map<String, Object> charter, Map<String, Object> out) {
        if (charter.get("identity_provider") == null) {
            return;
        }
        Map<String, Object> source = section(charter, "identity_provider");
        String issuer = text(source.get("issuer")).strip();
        boolean enabled = !Boolean.FALSE.equals(source.get("enabled"));
        if (!enabled && issuer.isEmpty()) {
            out.remove("identity_provider");
            return;
        }
        https(issuer, "identity_provider.issuer");
        String assertion = text(source.getOrDefault("assertion", "id-jag")).strip();
        if (!"id-jag".equals(assertion)) {
            throw new IllegalArgumentException("identity_provider.assertion: this profile understands "
                    + "`id-jag` and nothing else");
        }
        String directory = text(source.get("directory")).strip();
        if (!directory.isEmpty()) {
            https(directory, "identity_provider.directory");
        }
        Map<String, Object> subjectMap = section(source, "subject_map");
        if (subjectMap.values().stream().anyMatch(v -> !(v instanceof String))) {
            throw new IllegalArgumentException("identity_provider.subject_map maps what the provider "
                    + "asserts to the member it means here — strings to strings");
        }
        Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("enabled", enabled);
        provider.put("issuer", issuer);
        provider.put("assertion", assertion);
        provider.put("directory", directory);
        provider.put("subject_map", subjectMap);
        String subjectClaim = text(source.get("subject_claim"));
        if (!subjectClaim.isEmpty()) {
            provider.put("subject_claim", subjectClaim);
        }
        provider.put("enrol", !Boolean.FALSE.equals(source.get("enrol")));
        out.put("identity_provider", provider);
    }

    private static void https(String value, String label) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException(label + " must be an https issuer");
        }
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new IllegalArgumentException(label + " must be an https issuer");
        }
    }

    private static boolean covered(String pattern, List<String> claims) {
        return claims.contains(pattern)
                || !pattern.contains("*") && OrganizationPatterns.matches(pattern, claims);
    }

    private static void validatePattern(String pattern) {
        String problem = OrganizationPatterns.problem(pattern);
        if (problem != null) {
            throw new IllegalArgumentException(problem);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    static String text(Object value) {
        return value instanceof String s ? s : "";
    }

    static long numeric(Object value) {
        return value instanceof Number n ? n.longValue() : Long.MIN_VALUE;
    }

    static List<String> strings(Object value, String label) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list) || list.stream().anyMatch(v -> !(v instanceof String))) {
            throw new IllegalArgumentException(label + " must be a list of strings");
        }
        return list.stream().map(String.class::cast).toList();
    }

    private static Map<String, Object> section(Map<String, Object> source, String name) {
        Object value = source.get(name);
        if (value == null && !source.containsKey(name)) {
            return new LinkedHashMap<>();
        }
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException(name + " must be an object");
        }
        return new LinkedHashMap<>(object(value));
    }

    private static void bounded(Map<String, Object> source, String name, String prefix,
                                long min, long max) {
        if (!source.containsKey(name)) {
            return;
        }
        Object value = source.get(name);
        long number = numeric(value);
        if (!(value instanceof Number n) || !n.toString().matches("^-?[0-9]+$")
                || number < min || number > max) {
            throw new IllegalArgumentException(prefix + name + " must be an integer between "
                    + min + " and " + max);
        }
    }
}
