package io.uma4agents.common;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.DoubleSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An AAuth agent token ({@code aa-agent+jwt}) accepted as an agent's identity, in the
 * current shape (draft-hardt-oauth-aauth-protocol-10: {@code alg: Ed25519}, and
 * {@code dwk}, {@code jti} and {@code iat} required) and the earlier one ({@code EdDSA},
 * keys that may name no algorithm, those claims optional). A port of the pinned
 * {@code lib/uma4a_aauth.py}: the same checks in the same order, with the same refusal
 * wording.
 *
 * <p>Only issuers the deployment names are fetched or believed. An issuer's keys are
 * fetched at most once a minute and kept five minutes; a kid not in the cached set asks
 * again after the minute. An issuer that could not be read is not asked again for a
 * minute either.
 */
public final class AgentTokens {

    public static final String AGENT_TYP = "aa-agent+jwt";
    public static final String AGENT_DWK = "aauth-agent.json";
    public static final double REFETCH_FLOOR_S = 60;
    public static final double CACHE_TTL_S = 300;

    private static final Pattern AGENT_ID =
            Pattern.compile("aauth:([A-Za-z0-9_.+-]{1,255})@([a-z0-9.-]+)");

    /** A refusal naming the step that failed. */
    public static final class Refused extends IllegalArgumentException {
        public Refused(String message) {
            super(message);
        }
    }

    /** Reads a URL's JSON object, raising on anything else; where TLS policy lives. */
    @FunctionalInterface
    public interface Fetch {
        Map<String, Object> get(String url) throws Exception;
    }

    private record Cached(double fetched, double expires, List<Map<String, Object>> keys) {}

    private record Failed(double at, String reason) {}

    private final Fetch fetch;
    private final Set<String> issuers;
    private final DoubleSupplier clock;
    private final Map<String, Cached> keys = new ConcurrentHashMap<>();
    private final Map<String, Failed> failed = new ConcurrentHashMap<>();

    /**
     * Creates a verifier that believes the named issuers only.
     *
     * @param fetch reads an issuer document
     * @param issuers https origins to believe; each is validated
     * @param clock epoch seconds, for the cache and the token's time claims
     * @throws Refused when a configured issuer is not an https origin
     */
    public AgentTokens(Fetch fetch, Collection<String> issuers, DoubleSupplier clock) {
        this.fetch = fetch;
        Set<String> origins = new LinkedHashSet<>();
        for (String issuer : issuers) {
            origins.add(issuerOrigin(issuer));
        }
        this.issuers = Set.copyOf(origins);
        this.clock = clock;
    }

    /** Creates a verifier on the wall clock. */
    public AgentTokens(Fetch fetch, Collection<String> issuers) {
        this(fetch, issuers, () -> System.currentTimeMillis() / 1000.0);
    }

    /**
     * An https issuer with a lowercase host and no credentials, query or fragment,
     * returned without trailing slashes.
     *
     * @param value the claimed issuer
     * @return the issuer origin
     * @throws Refused when it is not one
     */
    public static String issuerOrigin(Object value) {
        if (!(value instanceof String s)) {
            throw new Refused("issuer is not a string");
        }
        if (!isHttpsIssuer(s)) {
            throw new Refused(PyRepr.of(s) + " is not an https issuer");
        }
        return s.replaceAll("/+$", "");
    }

    private static boolean isHttpsIssuer(String s) {
        URI u;
        try {
            u = new URI(s);
        } catch (URISyntaxException e) {
            return false;
        }
        String host = u.getHost();
        return "https".equalsIgnoreCase(u.getScheme())
                && host != null && !host.isEmpty() && !host.startsWith("[")
                && host.equals(host.toLowerCase(Locale.ROOT))
                && isEmpty(u.getRawQuery()) && isEmpty(u.getRawFragment())
                && u.getRawUserInfo() == null;
    }

    private static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    /**
     * A subject, held to AAuth's {@code aauth:local@domain} form when it uses it.
     *
     * @param value the claimed subject
     * @param host the issuer's host
     * @return the subject unchanged
     * @throws Refused when it is malformed or names another domain
     */
    public static String agentIdentifier(Object value, String host) {
        if (!(value instanceof String s) || s.isEmpty()) {
            throw new Refused("the token names no subject");
        }
        if (s.startsWith("aauth:")) {
            Matcher m = AGENT_ID.matcher(s);
            if (!m.matches()) {
                throw new Refused(PyRepr.of(s) + " is not an AAuth agent identifier");
            }
            if (!m.group(2).equals(host)) {
                throw new Refused(PyRepr.of(s) + " is not an agent of " + host);
            }
        }
        return s;
    }

    /**
     * Verifies an agent token against the keys its issuer publishes.
     *
     * @param token the compact {@code aa-agent+jwt}
     * @return its claims
     * @throws Refused naming the step that failed
     */
    public Map<String, Object> verify(String token) {
        CompactJws.Parsed unverified;
        try {
            unverified = CompactJws.parse(token);
        } catch (IllegalArgumentException e) {
            throw new Refused("not a JWT: " + e.getMessage());
        }
        Map<String, Object> header = unverified.header();
        if (!AGENT_TYP.equals(header.get("typ"))) {
            throw new Refused("typ must be " + PyRepr.of(AGENT_TYP) + ", not "
                    + PyRepr.of(header.get("typ")));
        }
        Object alg = header.get("alg");
        if (!Jose.ED25519.equals(alg) && !Jose.EDDSA.equals(alg)) {
            throw new Refused("alg must be 'Ed25519' or 'EdDSA', not " + PyRepr.of(alg));
        }
        Object kid = header.get("kid");
        String iss = issuerOrigin(unverified.claims().get("iss"));
        if (!issuers.contains(iss)) {
            throw new Refused(iss + " is not an agent-token issuer this server "
                    + "has been told to believe");
        }
        Map<String, Object> pre = unverified.claims();
        if (pre.containsKey("dwk") && !AGENT_DWK.equals(pre.get("dwk"))) {
            throw new Refused("dwk must be " + PyRepr.of(AGENT_DWK) + ", not "
                    + PyRepr.of(pre.get("dwk")));
        }
        Map<String, Object> jwk = chooseKey(iss, kid);
        Map<String, Object> claims = checkSignature(token, iss, kid, jwk, (String) alg);
        if (Jose.ED25519.equals(alg)) {
            checkCurrentShape(claims, iss, kid, jwk);
        }
        String host = URI.create(iss).getHost();
        agentIdentifier(claims.get("sub"), host);
        checkBinding(claims, host);
        return claims;
    }

    private Map<String, Object> chooseKey(String iss, Object kid) {
        List<Map<String, Object>> published = issuerKeys(iss, kid);
        List<Map<String, Object>> chosen = new ArrayList<>();
        if (kid != null) {
            for (Map<String, Object> k : published) {
                if (kid.equals(k.get("kid"))) {
                    chosen.add(k);
                }
            }
        } else if (published.size() == 1) {
            chosen.add(published.get(0));
        }
        if (chosen.isEmpty()) {
            throw new Refused(kid != null
                    ? iss + " publishes no key " + PyRepr.of(kid)
                    : "the token names no kid and " + iss + " publishes "
                            + published.size() + " keys");
        }
        return chosen.get(0);
    }

    private Map<String, Object> checkSignature(String token, String iss, Object kid,
                                               Map<String, Object> jwk, String alg) {
        String keyName = iss + "'s key " + PyRepr.of(kid);
        java.security.PublicKey key;
        try {
            if (jwk.containsKey("alg") && !Jose.algOf(jwk).equals(alg)) {
                throw new IllegalArgumentException("it names " + PyRepr.of(jwk.get("alg"))
                        + " and the token " + PyRepr.of(alg));
            }
            Map<String, Object> bare = new java.util.LinkedHashMap<>(jwk);
            bare.remove("alg");
            Jose.algOf(bare);
            key = Jwks.toPublicKey(bare);
        } catch (IllegalArgumentException e) {
            throw new Refused(keyName + ": " + e.getMessage());
        }
        Map<String, Object> claims;
        try {
            claims = CompactJws.verifyWith(token, key, alg).claims();
            PyJwtClaims.validate(claims, clock.getAsDouble(), "sub", "exp");
        } catch (SecurityException | IllegalArgumentException e) {
            throw new Refused("did not verify against " + keyName + ": " + e.getMessage());
        }
        return claims;
    }

    @SuppressWarnings("unchecked")
    private static void checkCurrentShape(Map<String, Object> claims, String iss, Object kid,
                                          Map<String, Object> jwk) {
        List<String> missing = new ArrayList<>();
        for (String c : List.of("dwk", "jti", "iat")) {
            if (!claims.containsKey(c)) {
                missing.add(c);
            }
        }
        if (!missing.isEmpty()) {
            throw new Refused("an Ed25519 agent token must carry " + String.join(", ", missing));
        }
        if (!Jose.ED25519.equals(jwk.get("alg"))) {
            throw new Refused(iss + "'s key " + PyRepr.of(kid) + " must name 'Ed25519'");
        }
        Object cnfAlg = claims.get("cnf") instanceof Map<?, ?> cnf
                && cnf.get("jwk") instanceof Map<?, ?> cj
                ? ((Map<String, Object>) cj).get("alg") : null;
        if (!Jose.ED25519.equals(cnfAlg)) {
            throw new Refused("cnf.jwk must name 'Ed25519' in an Ed25519 agent token");
        }
    }

    @SuppressWarnings("unchecked")
    private static void checkBinding(Map<String, Object> claims, String host) {
        if (!(claims.get("cnf") instanceof Map<?, ?> cnf) || !(cnf.get("jwk") instanceof Map)) {
            throw new Refused("no cnf.jwk binds the token to a key");
        }
        try {
            Jose.algOf((Map<String, Object>) cnf.get("jwk"));
        } catch (IllegalArgumentException e) {
            throw new Refused("cnf.jwk: " + e.getMessage());
        }
        if (claims.containsKey("parent_agent")) {
            agentIdentifier(claims.get("parent_agent"), host);
            if (claims.get("parent_agent").equals(claims.get("sub"))) {
                throw new Refused("an agent cannot be its own parent");
            }
        }
    }

    private List<Map<String, Object>> issuerKeys(String iss, Object kid) {
        double now = clock.getAsDouble();
        Cached cached = keys.get(iss);
        Failed failure = failed.get(iss);
        if (cached != null) {
            boolean known = kid == null
                    || cached.keys().stream().anyMatch(k -> kid.equals(k.get("kid")));
            if ((known && now < cached.expires()) || now - cached.fetched() < REFETCH_FLOOR_S) {
                return cached.keys();
            }
        }
        if (failure != null && now - failure.at() < REFETCH_FLOOR_S) {
            throw new Refused(failure.reason());
        }
        List<Map<String, Object>> read;
        try {
            read = readKeys(iss);
        } catch (Refused e) {
            failed.put(iss, new Failed(now, e.getMessage()));
            throw e;
        }
        keys.put(iss, new Cached(now, now + CACHE_TTL_S, read));
        failed.remove(iss);
        return read;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> readKeys(String iss) {
        Map<String, Object> meta;
        try {
            meta = fetch.get(iss + "/.well-known/" + AGENT_DWK);
        } catch (Exception e) {
            throw new Refused("the issuer's " + AGENT_DWK + " could not be read: "
                    + e.getMessage());
        }
        Object named = meta.get("issuer");
        if (named != null && !String.valueOf(named).replaceAll("/+$", "").equals(iss)) {
            throw new Refused("the issuer's " + AGENT_DWK + " names " + PyRepr.of(named)
                    + ", not " + PyRepr.of(iss));
        }
        try {
            Object jwksUri = meta.get("jwks_uri");
            if (!(jwksUri instanceof String uri)) {
                throw new IllegalStateException("'jwks_uri'");
            }
            Object list = fetch.get(uri).get("keys");
            if (!(list instanceof List<?> raw)) {
                throw new IllegalStateException("'keys'");
            }
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object k : raw) {
                if (k instanceof Map<?, ?>) {
                    out.add((Map<String, Object>) k);
                }
            }
            return out;
        } catch (Exception e) {
            throw new Refused("the issuer's keys could not be read: " + e.getMessage());
        }
    }
}
