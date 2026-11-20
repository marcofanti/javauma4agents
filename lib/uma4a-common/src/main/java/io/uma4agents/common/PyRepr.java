package io.uma4agents.common;

/**
 * Python's {@code repr} for the values refusal messages quote, so a Java refusal reads
 * the same as the pinned reference's: {@code 'ap-1'}, {@code None}, {@code 3}.
 */
public final class PyRepr {

    private PyRepr() {}

    /**
     * Formats a decoded JSON value the way CPython's {@code repr} would.
     *
     * @param value a String, Number, Boolean or null; anything else uses toString
     * @return the repr text
     */
    public static String of(Object value) {
        if (value == null) {
            return "None";
        }
        if (value instanceof Boolean b) {
            return b ? "True" : "False";
        }
        if (value instanceof String s) {
            boolean useDouble = s.contains("'") && !s.contains("\"");
            char quote = useDouble ? '"' : '\'';
            StringBuilder out = new StringBuilder().append(quote);
            for (char c : s.toCharArray()) {
                if (c == '\\') {
                    out.append("\\\\");
                } else if (c == quote) {
                    out.append('\\').append(c);
                } else if (c == '\n') {
                    out.append("\\n");
                } else {
                    out.append(c);
                }
            }
            return out.append(quote).toString();
        }
        return String.valueOf(value);
    }
}
