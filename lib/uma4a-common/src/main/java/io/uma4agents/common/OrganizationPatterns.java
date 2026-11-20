package io.uma4agents.common;

import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

/** Charter patterns match literal text and stars, one path segment at a time. */
public final class OrganizationPatterns {
    private OrganizationPatterns() {}

    public static String problem(Object value) {
        if (!(value instanceof String pattern) || pattern.isEmpty()) {
            return "a pattern must be a non-empty string";
        }
        var invalid = new TreeSet<Character>();
        for (char c : pattern.toCharArray()) {
            if ("?[]{}!\\".indexOf(c) >= 0) {
                invalid.add(c);
            }
        }
        if (!invalid.isEmpty()) {
            var symbols = new StringBuilder();
            invalid.forEach(symbols::append);
            return "'" + pattern + "' uses " + symbols + "; a pattern is literal text and * alone";
        }
        if (pattern.contains("**")) {
            return "'" + pattern + "' uses **; a * matches within one segment only";
        }
        return null;
    }

    public static boolean matches(String resource, Collection<?> patterns) {
        if (patterns == null) {
            return false;
        }
        List<String> segments = List.of(resource.split("/", -1));
        for (Object pattern : patterns) {
            if (problem(pattern) == null && matches(segments, (String) pattern)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matches(List<String> segments, String pattern) {
        String[] parts = pattern.split("/", -1);
        if (parts.length != segments.size()) {
            return false;
        }
        for (int i = 0; i < parts.length; i++) {
            if (!segmentMatches(segments.get(i), parts[i])) {
                return false;
            }
        }
        return true;
    }

    private static boolean segmentMatches(String text, String pattern) {
        int pos = 0;
        int part = 0;
        int star = -1;
        int starEnd = 0;
        while (pos < text.length()) {
            if (part < pattern.length() && pattern.charAt(part) == '*') {
                star = part++;
                starEnd = pos;
            } else if (part < pattern.length() && pattern.charAt(part) == text.charAt(pos)) {
                pos++;
                part++;
            } else if (star >= 0) {
                part = star + 1;
                pos = ++starEnd;
            } else {
                return false;
            }
        }
        return part == pattern.length() || part == pattern.length() - 1
                && pattern.charAt(part) == '*';
    }
}
