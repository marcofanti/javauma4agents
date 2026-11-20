package io.uma4agents.common;

import tools.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Serializes object graphs exactly as CPython's {@code json.dumps} does, because the
 * protocol hashes canonical JSON on both sides of the wire.
 *
 * <p>Two named forms exist in the Python reference and must never be merged:
 * <ul>
 *   <li>{@link #dumpsSorted} — {@code json.dumps(obj, sort_keys=True)} with the
 *       <em>default</em> separators {@code ", "} and {@code ": "} (spaces included).
 *       Used for {@code params_s256} operation binding by both uma-as and uma-pep.</li>
 *   <li>{@link #compactSorted} — {@code json.dumps(obj, sort_keys=True, separators=(",", ":"))}.
 *       Used for RFC 7638 JWK thumbprints.</li>
 *   <li>{@link #compactSortedUnicode} — the same with {@code ensure_ascii=False}. Used for
 *       {@code params_s256} operation binding, {@code authorization_reference} and the
 *       clearance digest at the pinned upstream.</li>
 *   <li>{@link #compactOrdered} — {@code json.dumps(obj, separators=(",", ":"))}: insertion
 *       order, ASCII-escaped. Used for the base64url {@code authorization_remediation}.</li>
 * </ul>
 *
 * Accepts Map / List / String / Boolean / null / Integer / Long / BigInteger /
 * Double / Float / BigDecimal and Jackson {@link JsonNode} graphs.
 */
public final class PyJson {

    private PyJson() {}

    private record Style(String itemSep, String kvSep, boolean sortKeys, boolean ensureAscii) {}

    private static final Style DEFAULT_SORTED = new Style(", ", ": ", true, true);
    private static final Style COMPACT_SORTED = new Style(",", ":", true, true);
    private static final Style COMPACT_SORTED_UNICODE = new Style(",", ":", true, false);
    private static final Style COMPACT_ORDERED = new Style(",", ":", false, true);

    public static String dumpsSorted(Object value) {
        return dumps(value, DEFAULT_SORTED);
    }

    public static String compactSorted(Object value) {
        return dumps(value, COMPACT_SORTED);
    }

    public static String compactSortedUnicode(Object value) {
        return dumps(value, COMPACT_SORTED_UNICODE);
    }

    public static String compactOrdered(Object value) {
        return dumps(value, COMPACT_ORDERED);
    }

    private static String dumps(Object value, Style style) {
        StringBuilder sb = new StringBuilder();
        write(sb, value, style);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object value, Style style) {
        switch (value) {
            case null -> sb.append("null");
            case JsonNode node -> write(sb, fromNode(node), style);
            case Boolean b -> sb.append(b ? "true" : "false");
            case String s -> writeString(sb, s, style.ensureAscii());
            case Integer i -> sb.append(i.toString());
            case Long l -> sb.append(l.toString());
            case BigInteger bi -> sb.append(bi.toString());
            case Double d -> sb.append(PyFloatRepr.repr(d));
            case Float f -> sb.append(PyFloatRepr.repr(f.doubleValue()));
            case BigDecimal bd -> writeBigDecimal(sb, bd);
            case Map<?, ?> map -> writeMap(sb, map, style);
            case List<?> list -> writeList(sb, list, style);
            default -> throw new IllegalArgumentException(
                    "PyJson cannot serialize " + value.getClass().getName()
                            + "; supply Map/List/String/Number/Boolean/null");
        }
    }

    private static void writeMap(StringBuilder sb, Map<?, ?> map, Style style) {
        Map<String, Object> sorted = style.sortKeys()
                ? new TreeMap<>(PyJson::compareCodePoints) : new java.util.LinkedHashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (!(e.getKey() instanceof String key)) {
                throw new IllegalArgumentException(
                        "PyJson requires String map keys, got: " + e.getKey());
            }
            sorted.put(key, e.getValue());
        }
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> e : sorted.entrySet()) {
            if (!first) {
                sb.append(style.itemSep());
            }
            first = false;
            writeString(sb, e.getKey(), style.ensureAscii());
            sb.append(style.kvSep());
            write(sb, e.getValue(), style);
        }
        sb.append('}');
    }

    private static void writeList(StringBuilder sb, List<?> list, Style style) {
        sb.append('[');
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(style.itemSep());
            }
            first = false;
            write(sb, item, style);
        }
        sb.append(']');
    }

    private static void writeBigDecimal(StringBuilder sb, BigDecimal bd) {
        if (bd.scale() <= 0) {
            sb.append(bd.toBigInteger().toString());
        } else {
            sb.append(PyFloatRepr.repr(bd.doubleValue()));
        }
    }

    /**
     * Python json.dumps string encoding. With ensure_ascii everything above 0x7E escapes;
     * without it only quotes, backslashes and control characters below 0x20 do.
     */
    private static void writeString(StringBuilder sb, String s, boolean ensureAscii) {
        sb.append('"');
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || (ensureAscii && c > 0x7E)) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
            i++;
        }
        sb.append('"');
    }

    /** Python sorts keys by Unicode code point; String.compareTo is UTF-16 order. */
    static int compareCodePoints(String a, String b) {
        int la = a.length();
        int lb = b.length();
        int i = 0;
        int j = 0;
        while (i < la && j < lb) {
            int ca = a.codePointAt(i);
            int cb = b.codePointAt(j);
            if (ca != cb) {
                return Integer.compare(ca, cb);
            }
            i += Character.charCount(ca);
            j += Character.charCount(cb);
        }
        return Integer.compare(la - i, lb - j);
    }

    private static Object fromNode(JsonNode node) {
        return switch (node.getNodeType()) {
            case NULL, MISSING -> null;
            case BOOLEAN -> node.booleanValue();
            case STRING -> node.textValue();
            case NUMBER -> node.isIntegralNumber() ? node.bigIntegerValue() : node.doubleValue();
            case ARRAY -> {
                java.util.ArrayList<Object> items = new java.util.ArrayList<>();
                node.forEach(child -> items.add(fromNode(child)));
                yield items;
            }
            case OBJECT -> {
                java.util.LinkedHashMap<String, Object> map = new java.util.LinkedHashMap<>();
                node.properties().forEach(e -> map.put(e.getKey(), fromNode(e.getValue())));
                yield map;
            }
            default -> throw new IllegalArgumentException("unsupported node: " + node.getNodeType());
        };
    }
}
