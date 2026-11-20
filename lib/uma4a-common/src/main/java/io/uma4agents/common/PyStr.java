package io.uma4agents.common;

/**
 * CPython {@code str} whitespace semantics. {@code str.isspace} is true for the separators
 * (Unicode Zs, Zl, Zp), the bidirectional whitespace, segment and paragraph separators
 * (code points 0x09 to 0x0D, 0x1C to 0x1F, and 0x85). Java's {@code isWhitespace} excludes
 * no-break spaces and {@code isBlank} follows it, so a reason made only of NBSP would read
 * as present in Java and absent at the pin.
 */
public final class PyStr {

    private PyStr() {}

    /** CPython {@code str.isspace} for one code point. */
    public static boolean isSpace(int cp) {
        if ((cp >= 0x09 && cp <= 0x0D) || (cp >= 0x1C && cp <= 0x1F) || cp == 0x85) {
            return true;
        }
        int type = Character.getType(cp);
        return type == Character.SPACE_SEPARATOR || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR;
    }

    /** CPython {@code str.strip()} with no argument. */
    public static String strip(String text) {
        int start = 0;
        int end = text.length();
        while (start < end) {
            int cp = text.codePointAt(start);
            if (!isSpace(cp)) {
                break;
            }
            start += Character.charCount(cp);
        }
        while (end > start) {
            int cp = text.codePointBefore(end);
            if (!isSpace(cp)) {
                break;
            }
            end -= Character.charCount(cp);
        }
        return text.substring(start, end);
    }
}
