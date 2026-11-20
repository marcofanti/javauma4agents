package io.uma4agents.common;

import java.util.Map;

/**
 * The registered-claim checks PyJWT 2.15.1's {@code decode} applies after the signature,
 * in its order and wording: required claims, {@code iat}, {@code nbf}, {@code exp}, the
 * audience, then the {@code sub} and {@code jti} types. Callers choose whether {@code iat}
 * and the audience are checked, as the pinned call sites do.
 */
public final class PyJwtClaims {

    private PyJwtClaims() {}

    /**
     * Validates the claims at {@code now}, with {@code iat} and the audience unchecked.
     *
     * @param claims decoded claims
     * @param now epoch seconds
     * @param required claim names that must be present
     * @throws IllegalArgumentException naming the claim that failed
     */
    public static void validate(Map<String, Object> claims, double now, String... required) {
        check(claims, now, 0, false, null, required);
    }

    /**
     * PyJWT's default decode checks (only {@code verify_aud} off): {@code iat} as an integer
     * not in the future, then everything {@link #validate} checks.
     *
     * @param claims decoded claims
     * @param now epoch seconds
     * @param required claim names that must be present
     * @throws IllegalArgumentException naming the claim that failed
     */
    public static void validateWithIat(Map<String, Object> claims, double now,
                                       String... required) {
        check(claims, now, 0, true, null, required);
    }

    /**
     * PyJWT's full default decode checks with {@code audience=}: required, {@code iat},
     * {@code nbf}, {@code exp}, the audience, then {@code sub} and {@code jti} types, in
     * PyJWT 2.15.1's order and wording.
     *
     * @param claims decoded claims
     * @param now epoch seconds
     * @param audience the one audience this server accepts
     * @param required claim names that must be present
     * @throws IllegalArgumentException naming the claim that failed
     */
    public static void validateWithAudience(Map<String, Object> claims, double now,
                                            String audience, String... required) {
        check(claims, now, 0, true, audience, required);
    }

    /** Default time and type checks over claims already verified for signature and issuer. */
    public static void validateWithLeeway(Map<String, Object> claims, double now, long leeway,
                                          String... required) {
        check(claims, now, leeway, true, null, required);
    }

    private static void check(Map<String, Object> claims, double now, long leeway, boolean iat,
                              String audience, String... required) {
        for (String name : required) {
            if (claims.get(name) == null) {
                throw new IllegalArgumentException(
                        "Token is missing the \"" + name + "\" claim");
            }
        }
        if (iat && claims.containsKey("iat")) {
            long issued = integer(claims.get("iat"), "Issued At claim (iat) must be an integer.");
            if (issued > now + leeway) {
                throw new IllegalArgumentException("The token is not yet valid (iat)");
            }
        }
        if (claims.containsKey("nbf")) {
            long nbf = integer(claims.get("nbf"), "Not Before claim (nbf) must be an integer.");
            if (nbf > now + leeway) {
                throw new IllegalArgumentException("The token is not yet valid (nbf)");
            }
        }
        if (claims.containsKey("exp")) {
            long exp = integer(claims.get("exp"),
                    "Expiration Time claim (exp) must be an integer.");
            if (exp <= now - leeway) {
                throw new IllegalArgumentException("Signature has expired");
            }
        }
        if (audience != null) {
            checkAudience(claims.get("aud"), audience);
        }
        if (claims.containsKey("sub") && !(claims.get("sub") instanceof String)) {
            throw new IllegalArgumentException("Subject must be a string");
        }
        if (claims.containsKey("jti") && !(claims.get("jti") instanceof String)) {
            throw new IllegalArgumentException("JWT ID must be a string");
        }
    }

    private static void checkAudience(Object aud, String audience) {
        boolean empty = aud == null || "".equals(aud)
                || (aud instanceof java.util.Collection<?> c && c.isEmpty())
                || (aud instanceof Map<?, ?> m && m.isEmpty())
                || Boolean.FALSE.equals(aud)
                || (aud instanceof Number n && n.doubleValue() == 0.0);
        if (empty) {
            throw new IllegalArgumentException("Token is missing the \"aud\" claim");
        }
        java.util.List<?> claimed = aud instanceof String s ? java.util.List.of(s)
                : aud instanceof java.util.List<?> l ? l : null;
        if (claimed == null || claimed.stream().anyMatch(c -> !(c instanceof String))) {
            throw new IllegalArgumentException("Invalid claim format in token");
        }
        if (!claimed.contains(audience)) {
            throw new IllegalArgumentException("Audience doesn't match");
        }
    }

    private static long integer(Object value, String message) {
        if (value instanceof Number n) {
            return n.longValue();
        }
        if (value instanceof String s) {
            try {
                return Long.parseLong(s.trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(message, e);
            }
        }
        throw new IllegalArgumentException(message);
    }
}
