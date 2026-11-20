package io.uma4agents.authserver;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What her authority can establish about the asking agent, on three independent axes and
 * with no composite: binding (the agreement verified against a key this server can name),
 * provenance (an issuer-verified credential), accountability (a named operator; that
 * operator having published this agent's key). Every level comes from a field a
 * verification step wrote, never from the call path. Assurance may only tighten; standing,
 * what she has seen, is kept apart. Ported from the pinned {@code assurance.py}.
 */
public final class Assurance {

    public static final int ACCOUNTABILITY_ATTESTED = 2;

    private static final List<String> AXES = List.of("binding", "provenance", "accountability");

    private static final Map<String, Map<Integer, String>> DESCRIPTIONS = Map.of(
            "binding", Map.of(
                    0, "not bound to any key this server verified",
                    1, "bound to a key, recognisable next time"),
            "provenance", Map.of(
                    0, "self-minted key — nothing to check it against",
                    1, "credential issued by {issuer}, signature verified"),
            "accountability", Map.of(
                    0, "no operator named",
                    1, "{operator} says it operates this agent (self-asserted)",
                    2, "{operator} published this agent's signing key as its own"));

    private Assurance() {}

    /** The axes, from the identity record {@code verifyContract} built. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> assess(Map<String, Object> identity) {
        Map<String, Object> meta = identity.get("client_metadata") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Map.of();
        int binding = Py.truthy(identity.get("key_bound")) ? 1 : 0;
        int provenance = "identified".equals(identity.get("level")) ? 1 : 0;
        int accountability;
        if (meta.isEmpty()) {
            accountability = 0;
        } else if (Py.truthy(meta.get("verified")) && Py.truthy(identity.get("operator_attested"))) {
            accountability = ACCOUNTABILITY_ATTESTED;
        } else if (Py.truthy(meta.get("verified"))) {
            accountability = 1;
        } else {
            accountability = 0;
        }
        Map<String, Object> axes = new LinkedHashMap<>();
        axes.put("binding", binding);
        axes.put("provenance", provenance);
        axes.put("accountability", accountability);
        return axes;
    }

    /** One sentence per axis, for the dialog she reads before deciding. */
    @SuppressWarnings("unchecked")
    public static List<String> describe(Map<String, Object> axes, Map<String, Object> identity) {
        Map<String, Object> meta = identity.get("client_metadata") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Map.of();
        Object operator = firstTruthy(meta.get("client_name"), meta.get("client_id"),
                "an operator");
        Object issuer = firstTruthy(identity.get("iss"), "an issuer");
        List<String> out = new ArrayList<>();
        for (String axis : AXES) {
            int level = axes.get(axis) instanceof Number n ? n.intValue() : 0;
            String text = DESCRIPTIONS.get(axis).getOrDefault(level, "");
            out.add(format(text, Map.of("operator", String.valueOf(operator),
                    "issuer", String.valueOf(issuer))));
        }
        return out;
    }

    /**
     * {@code str.format} for named fields, in one pass: an inserted value is never read
     * again, so a display name containing {@code {issuer}} stays literal.
     */
    static String format(String template, Map<String, String> fields) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < template.length()) {
            int open = template.indexOf('{', i);
            int close = open < 0 ? -1 : template.indexOf('}', open);
            if (open < 0 || close < 0) {
                out.append(template, i, template.length());
                break;
            }
            String name = template.substring(open + 1, close);
            out.append(template, i, open);
            out.append(fields.containsKey(name) ? fields.get(name)
                    : template.substring(open, close + 1));
            i = close + 1;
        }
        return out.toString();
    }

    private static Object firstTruthy(Object... values) {
        for (Object value : values) {
            if (Py.truthy(value)) {
                return value;
            }
        }
        return values[values.length - 1];
    }
}
