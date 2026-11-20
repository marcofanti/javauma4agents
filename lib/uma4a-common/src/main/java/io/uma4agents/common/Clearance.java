package io.uma4agents.common;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** The attested facts and requirements shared by the organization and the owner's AS. */
public final class Clearance {
    public static final String TYPE = "u4a-clearance+jwt";
    public static final String CLAIM = "clearance";

    private Clearance() {}

    public static Map<String, Object> validateRequirement(Object requirement, String label) {
        if (requirement == null) {
            return new LinkedHashMap<>();
        }
        if (!(requirement instanceof Map<?, ?> claims)) {
            throw new IllegalArgumentException(
                    label + " must be an object of claim -> accepted values");
        }
        Map<String, Object> ordered = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : claims.entrySet()) {
            String claim = String.valueOf(e.getKey());
            if (PyStr.strip(claim).isEmpty()) {
                throw new IllegalArgumentException(label + " has a claim name that is not a name");
            }
            if (!(e.getValue() instanceof List<?> accepted)) {
                throw new IllegalArgumentException(label + "." + claim + " must be a list of "
                        + "acceptable values — one value on its own is a list of one, and "
                        + "writing it bare is how a requirement ends up matching a string "
                        + "character by character");
            }
            for (Object value : accepted) {
                if (!(value instanceof String || value instanceof Number
                        || value instanceof Boolean)) {
                    throw new IllegalArgumentException(label + "." + claim + " may only accept "
                            + "strings, numbers or booleans — an attestation is a set of "
                            + "simple facts");
                }
            }
            ordered.put(PyStr.strip(claim), new ArrayList<>(accepted));
        }
        return ordered;
    }

    public static Map<String, Object> tighten(Object base, Object addition) {
        Map<String, Object> effective = validateRequirement(base, CLAIM);
        validateRequirement(addition, CLAIM).forEach((claim, allowed) -> {
            if (effective.get(claim) instanceof List<?> existing) {
                List<?> narrowed = existing.stream()
                        .filter(value -> allows((List<?>) allowed, value)).toList();
                effective.put(claim, narrowed);
            } else {
                effective.put(claim, allowed);
            }
        });
        return effective;
    }

    public static List<String> unmet(Map<String, Object> requirements, Map<String, Object> facts) {
        List<String> reasons = new ArrayList<>();
        requirements.forEach((claim, accepted) -> {
            List<?> allowed = (List<?>) accepted;
            if (!facts.containsKey(claim)) {
                reasons.add("the clearance says nothing about " + claim);
            } else if (allowed.isEmpty()) {
                reasons.add("no value of " + claim + " is accepted here, so nothing satisfies it");
            } else if (!allows(allowed, facts.get(claim))) {
                String want = allowed.stream().map(PyRepr::of).collect(Collectors.joining(" or "));
                reasons.add(claim + " is " + PyRepr.of(facts.get(claim)) + ", and this requires "
                        + want);
            }
        });
        return reasons;
    }

    private static boolean allows(List<?> accepted, Object fact) {
        Number numericFact = number(fact);
        for (Object value : accepted) {
            Number numericValue = number(value);
            if (numericValue != null && numericFact != null) {
                if (equalNumbers(numericFact, numericValue)) {
                    return true;
                }
            } else if (value.equals(fact)) {
                return true;
            }
        }
        return false;
    }

    private static Number number(Object value) {
        if (value instanceof Boolean flag) {
            return flag ? 1 : 0;
        }
        return value instanceof Number numeric ? numeric : null;
    }

    private static boolean equalNumbers(Number first, Number second) {
        try {
            return exact(first).compareTo(exact(second)) == 0;
        } catch (NumberFormatException nonfinite) {
            return first.doubleValue() == second.doubleValue();
        }
    }

    private static BigDecimal exact(Number value) {
        return value instanceof Double || value instanceof Float
                ? new BigDecimal(value.doubleValue()) : new BigDecimal(value.toString());
    }

    public static String digest(Map<String, Object> facts) {
        return S256.of(PyJson.compactSortedUnicode(facts));
    }

    public static Map<String, Object> verify(String token, List<Map<String, Object>> keys,
                                              String issuer, String audience, String subject,
                                              double now) {
        CompactJws.Parsed parsed;
        try {
            parsed = CompactJws.parse(token);
        } catch (RuntimeException malformed) {
            throw new IllegalArgumentException("that is not an attestation: " + malformed.getMessage(),
                    malformed);
        }
        Object type = parsed.header().get("typ");
        if (!TYPE.equals(type)) {
            throw new IllegalArgumentException("expected a clearance (typ " + TYPE + "), got typ "
                    + PyRepr.of(type));
        }
        Map<String, Object> claims = verifiedClaims(token, parsed, keys, issuer, now);
        if (!subject.equals(claims.get("sub"))) {
            throw new IllegalArgumentException("the clearance is about " + PyRepr.of(claims.get("sub"))
                    + ", and this negotiation is about " + PyRepr.of(subject));
        }
        Object aud = claims.get("aud");
        List<?> audiences = aud instanceof String one ? List.of(one)
                : aud instanceof List<?> list ? list : List.of();
        if (!audiences.contains(audience)) {
            String names = audiences.isEmpty() ? "'nothing'" : audiences.stream().map(PyRepr::of)
                    .collect(Collectors.joining(", "));
            throw new IllegalArgumentException("the clearance is audienced at [" + names
                    + "] rather than at " + PyRepr.of(audience)
                    + " — an attestation is issued to one authority");
        }
        if (!(claims.get(CLAIM) instanceof Map<?, ?> facts)) {
            throw new IllegalArgumentException("the clearance carries no facts");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> typed = (Map<String, Object>) facts;
        return typed;
    }

    private static Map<String, Object> verifiedClaims(String token, CompactJws.Parsed parsed,
                                                       List<Map<String, Object>> keys,
                                                       String issuer, double now) {
        Object kid = parsed.header().get("kid");
        String lastError = null;
        for (Map<String, Object> key : keys) {
            if (kid != null && !"".equals(kid) && !kid.equals(key.get("kid"))) {
                continue;
            }
            try {
                Map<String, Object> claims = CompactJws.verifyWith(token, Jwks.toPublicKey(key),
                        "EdDSA").claims();
                if (!issuer.equals(claims.get("iss"))) {
                    throw new IllegalArgumentException("Invalid issuer");
                }
                PyJwtClaims.validateWithLeeway(claims, now, 60, "exp", "iat", "jti");
                return claims;
            } catch (IllegalArgumentException | SecurityException invalid) {
                lastError = invalid.getMessage();
            }
        }
        throw new IllegalArgumentException("the clearance does not verify against " + issuer
                + (lastError == null ? "" : ": " + lastError));
    }
}
