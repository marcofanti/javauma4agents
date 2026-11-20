package io.uma4agents.common;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * What an operation leaves behind, as a declared fact: reversible, compensatable,
 * forward-recoverable or irreversible, ordered by how much remedy remains. The resource
 * declares it; it may only tighten a requirement; absent is unknown, not benign and not
 * severe. Ported from the pinned {@code lib/uma4a_consequence.py}.
 */
public final class Consequence {

    /** The classes, most remedy first. */
    public static final List<String> CLASSES =
            List.of("reversible", "compensatable", "forward_recoverable", "irreversible");

    private Consequence() {}

    /**
     * A declared class, or null for anything unrecognised. Python's {@code str.strip} and
     * {@code str.lower} are applied, so surrounding Unicode whitespace is ignored.
     */
    public static String normalise(Object value) {
        if (!(value instanceof String text)) {
            return null;
        }
        String cleaned = PyStr.strip(text).toLowerCase(Locale.ROOT);
        return CLASSES.contains(cleaned) ? cleaned : null;
    }

    /** Position in the order, or null when nothing was declared. */
    public static Integer rank(Object value) {
        String cls = normalise(value);
        return cls == null ? null : CLASSES.indexOf(cls);
    }

    /** Whether {@code actual} leaves at most as much remedy as {@code floor}; false if either is undeclared. */
    public static boolean atOrAbove(Object actual, Object floor) {
        Integer a = rank(actual);
        Integer f = rank(floor);
        return a != null && f != null && a >= f;
    }

    /** The nearest class MCP's tool annotations express, read only from hints present. */
    public static String fromMcpAnnotations(Object annotations) {
        if (!(annotations instanceof Map<?, ?> hints)) {
            return null;
        }
        if (hints.get("reversibleHint") instanceof Boolean reversible) {
            return reversible ? "reversible" : "irreversible";
        }
        if (Boolean.TRUE.equals(hints.get("readOnlyHint"))) {
            return "reversible";
        }
        if (Boolean.TRUE.equals(hints.get("destructiveHint"))) {
            return "irreversible";
        }
        if (Boolean.FALSE.equals(hints.get("destructiveHint"))) {
            return "compensatable";
        }
        return null;
    }

    /** Whether a tool of this class takes a grant bound to one operation. */
    public static boolean singleUse(Object consequence) {
        return "irreversible".equals(normalise(consequence));
    }
}
