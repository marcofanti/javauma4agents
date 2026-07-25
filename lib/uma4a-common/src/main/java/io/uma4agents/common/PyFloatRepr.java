package io.uma4agents.common;

/**
 * Reproduces CPython's {@code repr(float)} — shortest round-trip digits with
 * Python's fixed/scientific switchover — so canonical JSON hashes match across
 * the two implementations.
 *
 * <p>Java 19+ {@code Double.toString} already produces shortest round-trip
 * digits; this class only re-formats them the way CPython does: fixed notation
 * for decimal exponents in [-4, 16), otherwise {@code <mantissa>e±XX} with a
 * signed, zero-padded (min two digit) exponent and no trailing {@code .0} on
 * the mantissa.
 */
final class PyFloatRepr {

    private PyFloatRepr() {}

    static String repr(double value) {
        if (Double.isNaN(value)) {
            return "NaN";
        }
        if (Double.isInfinite(value)) {
            return value > 0 ? "Infinity" : "-Infinity";
        }
        if (value == 0.0) {
            return (1.0 / value < 0) ? "-0.0" : "0.0";
        }

        double abs = Math.abs(value);
        String sign = value < 0 ? "-" : "";

        long[] parsed = parseDecimal(Double.toString(abs));
        String digits = Long.toString(parsed[0]);
        int exp10 = (int) parsed[1];

        // Double.toString is shortest for its own grammar (>= 1 fraction digit);
        // CPython's repr is truly shortest. Probe shorter roundings (e.g. MIN_VALUE
        // is 4.9E-324 in Java but 5e-324 in Python).
        for (int k = 1; k < digits.length(); k++) {
            String candidate = String.format(java.util.Locale.ROOT, "%." + (k - 1) + "e", abs);
            if (Double.parseDouble(candidate) == abs) {
                long[] shorter = parseDecimal(candidate);
                digits = Long.toString(shorter[0]);
                exp10 = (int) shorter[1];
                break;
            }
        }

        if (exp10 >= 16 || exp10 < -4) {
            String mantissa = digits.length() == 1
                    ? digits
                    : digits.charAt(0) + "." + digits.substring(1);
            String expSign = exp10 < 0 ? "-" : "+";
            int absExp = Math.abs(exp10);
            String expDigits = absExp < 10 ? "0" + absExp : Integer.toString(absExp);
            return sign + mantissa + "e" + expSign + expDigits;
        }
        if (exp10 >= 0) {
            if (digits.length() <= exp10 + 1) {
                return sign + digits + "0".repeat(exp10 + 1 - digits.length()) + ".0";
            }
            return sign + digits.substring(0, exp10 + 1) + "." + digits.substring(exp10 + 1);
        }
        return sign + "0." + "0".repeat(-exp10 - 1) + digits;
    }

    /**
     * Normalizes a decimal string (fixed or scientific) to {significant digits as
     * a long, decimal exponent of the first digit}. Input never exceeds 17
     * significant digits for a double, so a long always fits.
     */
    private static long[] parseDecimal(String s) {
        int e = s.indexOf('e');
        if (e < 0) {
            e = s.indexOf('E');
        }
        int exp = 0;
        String mantissa = s;
        if (e >= 0) {
            exp = Integer.parseInt(s.substring(e + 1));
            mantissa = s.substring(0, e);
        }
        int dot = mantissa.indexOf('.');
        String digits;
        int exp10;
        if (dot < 0) {
            digits = mantissa;
            exp10 = exp + mantissa.length() - 1;
        } else {
            String intPart = mantissa.substring(0, dot);
            String fracPart = mantissa.substring(dot + 1);
            if (intPart.equals("0")) {
                int lead = 0;
                while (lead < fracPart.length() && fracPart.charAt(lead) == '0') {
                    lead++;
                }
                digits = fracPart.substring(lead);
                exp10 = exp - lead - 1;
            } else {
                digits = intPart + fracPart;
                exp10 = exp + intPart.length() - 1;
            }
        }
        digits = stripTrailingZeros(digits);
        return new long[] {Long.parseLong(digits), exp10};
    }

    private static String stripTrailingZeros(String digits) {
        int end = digits.length();
        while (end > 1 && digits.charAt(end - 1) == '0') {
            end--;
        }
        return digits.substring(0, end);
    }
}
