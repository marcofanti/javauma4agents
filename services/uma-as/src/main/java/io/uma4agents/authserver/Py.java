package io.uma4agents.authserver;

import io.uma4agents.common.PyStr;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Collection;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The few CPython value semantics the owner's policy depends on: truthiness, {@code int()}
 * and {@code float()} of text. Rules arrive as JSON an owner wrote, so a value Python reads
 * one way must read the same way here, or a rule that saves at the pin would not save in
 * Java, or would fire differently.
 */
final class Py {

    private static final Pattern DIGITS = Pattern.compile("[0-9](?:_?[0-9])*");
    private static final Pattern FLOAT = Pattern.compile(
            "[+-]?(?:(?:[0-9](?:_?[0-9])*)?\\.[0-9](?:_?[0-9])*|[0-9](?:_?[0-9])*\\.?)"
                    + "(?:[eE][+-]?[0-9](?:_?[0-9])*)?");

    private Py() {}

    /** Python truthiness of a JSON value. */
    static boolean truthy(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof Number n) {
            return n instanceof Double || n instanceof Float
                    ? n.doubleValue() != 0.0 : new BigDecimal(n.toString()).signum() != 0;
        }
        if (value instanceof String s) {
            return !s.isEmpty();
        }
        if (value instanceof Collection<?> c) {
            return !c.isEmpty();
        }
        if (value instanceof Map<?, ?> m) {
            return !m.isEmpty();
        }
        return true;
    }

    /**
     * {@code int(value)} for text, a bool or a number: surrounding Unicode whitespace,
     * a sign, Unicode decimal digits and single underscores between digits.
     *
     * @throws IllegalArgumentException where Python raises ValueError or TypeError
     */
    static BigInteger toInt(Object value) {
        if (value instanceof Boolean b) {
            return b ? BigInteger.ONE : BigInteger.ZERO;
        }
        if (value instanceof Double || value instanceof Float) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("cannot convert float to integer");
            }
            return new BigDecimal(d).setScale(0, RoundingMode.DOWN).toBigIntegerExact();
        }
        if (value instanceof Number n) {
            return new BigDecimal(n.toString()).toBigInteger();
        }
        if (!(value instanceof String text)) {
            throw new IllegalArgumentException("int() argument must be a string or a number");
        }
        String body = asciiDigits(PyStr.strip(text));
        String sign = "";
        if (body.startsWith("+") || body.startsWith("-")) {
            sign = body.substring(0, 1);
            body = body.substring(1);
        }
        if (!DIGITS.matcher(body).matches()) {
            throw new IllegalArgumentException(
                    "invalid literal for int() with base 10: " + io.uma4agents.common.PyRepr.of(text));
        }
        return new BigInteger(sign + body.replace("_", ""));
    }

    /**
     * {@code float(text)} as an exact decimal. Python also accepts {@code inf} and
     * {@code nan}; neither yields an integer, so both are refused here as {@code int()}
     * of them would be.
     */
    static BigDecimal toFloat(String text) {
        String body = asciiDigits(PyStr.strip(text));
        if (!FLOAT.matcher(body).matches()) {
            throw new IllegalArgumentException(
                    "could not convert string to float: " + io.uma4agents.common.PyRepr.of(text));
        }
        return new BigDecimal(new BigDecimal(body.replace("_", "")).doubleValue());
    }

    /** Unicode decimal digits as ASCII, as Python's numeric parsers accept them. */
    private static String asciiDigits(String text) {
        StringBuilder out = new StringBuilder(text.length());
        text.codePoints().forEach(cp -> {
            if (cp > 0x7F && Character.getType(cp) == Character.DECIMAL_DIGIT_NUMBER) {
                out.append((char) ('0' + Character.digit(cp, 10)));
            } else {
                out.appendCodePoint(cp);
            }
        });
        return out.toString();
    }
}
