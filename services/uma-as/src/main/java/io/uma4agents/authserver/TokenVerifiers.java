package io.uma4agents.authserver;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.Jwks;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * Inbound token verification: Alice's Keycloak OIDC token (owner API, RS256
 * against the realm's published keys) and agents' {@code aa-agent+jwt} (EdDSA
 * against the AAuth issuer's discovered keys, https origins only).
 */
@Component
public class TokenVerifiers {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AsConfig config;
    private final HttpClient http;
    private final Map<String, CachedKeys> jwksCache = new ConcurrentHashMap<>();

    private record CachedKeys(long expires, List<Map<String, Object>> keys) {}

    public TokenVerifiers(AsConfig config, HttpClient http) {
        this.config = config;
        this.http = http;
    }

    /** Extracts the bearer token or raises 401 — the Python _bearer(). */
    public static String bearer(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bearer token required");
        }
        return authorization.substring(7);
    }

    /**
     * The owner API takes Alice's own OIDC access token, validated against her
     * realm's published keys. Raises 401/403 with FastAPI-shaped details.
     */
    public void requireOwner(String authorization) {
        String token = bearer(authorization);
        Map<String, Object> claims;
        try {
            claims = verifyRs256(token, ownerIssuerKeys());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "owner API requires the owner's OIDC token: " + e.getMessage());
        }
        if (!config.ownerAudiences.contains(String.valueOf(claims.get("azp")))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "token was not issued to an owner-surface client");
        }
        if (!config.ownerUsername.equals(claims.get("preferred_username"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "this authorization server serves a different owner");
        }
    }

    /** Validates an aa-agent+jwt against its issuer's published keys. */
    public Map<String, Object> verifyAgentToken(String agentToken) {
        CompactJws.Parsed parsed = CompactJws.parse(agentToken);
        Object typ = parsed.header().get("typ");
        if (!"aa-agent+jwt".equals(typ)) {
            throw new IllegalArgumentException(
                    "agent token typ must be aa-agent+jwt, got '" + typ + "'");
        }
        Object iss = parsed.claims().get("iss");
        if (!(iss instanceof String issuer) || issuer.isBlank()) {
            throw new IllegalArgumentException("agent token has no issuer");
        }
        List<Map<String, Object>> candidates;
        try {
            candidates = agentIssuerKeys(issuer);
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "agent token issuer discovery failed for " + issuer + ": " + e.getMessage());
        }
        Object kid = parsed.header().get("kid");
        Exception lastError = null;
        for (Map<String, Object> jwk : candidates) {
            if (kid != null && jwk.get("kid") != null && !kid.equals(jwk.get("kid"))) {
                continue;
            }
            try {
                CompactJws.verify(agentToken, Jwks.toPublicKey(jwk));
                checkExpiry(parsed.claims());
                Object cnf = parsed.claims().get("cnf");
                if (!(cnf instanceof Map<?, ?> cnfMap) || !(cnfMap.get("jwk") instanceof Map)) {
                    throw new IllegalArgumentException(
                            "agent token carries no cnf.jwk key binding");
                }
                return parsed.claims();
            } catch (SecurityException | IllegalArgumentException e) {
                lastError = e;
            }
        }
        throw new IllegalArgumentException("agent token signature did not verify against "
                + issuer + "'s published keys: "
                + (lastError == null ? "no candidate keys" : lastError.getMessage()));
    }

    static void checkExpiry(Map<String, Object> claims) {
        if (claims.get("exp") instanceof Number exp
                && exp.longValue() < java.time.Instant.now().getEpochSecond()) {
            throw new IllegalArgumentException("token expired");
        }
    }

    /**
     * Resolve an agent-token issuer's signing keys via AAuth discovery.
     * TLS on the issuer origin is the trust root, so non-https issuers are
     * rejected outright.
     */
    public List<Map<String, Object>> agentIssuerKeys(String issuer) {
        if (!issuer.startsWith("https://")) {
            throw new IllegalArgumentException("agent token issuer must be an https origin");
        }
        return cachedJwks(issuer, issuer + "/.well-known/aauth-agent.json");
    }

    private List<Map<String, Object>> ownerIssuerKeys() {
        return cachedJwks(config.ownerIssuer,
                config.ownerIssuer + "/.well-known/openid-configuration");
    }

    private List<Map<String, Object>> cachedJwks(String cacheKey, String discoveryUrl) {
        CachedKeys cached = jwksCache.get(cacheKey);
        if (cached != null && cached.expires() > AsState.now()) {
            return cached.keys();
        }
        Map<String, Object> meta = getJson(discoveryUrl);
        Map<String, Object> jwks = getJson(String.valueOf(meta.get("jwks_uri")));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        if (keys == null) {
            throw new IllegalStateException("no keys at " + meta.get("jwks_uri"));
        }
        jwksCache.put(cacheKey, new CachedKeys(AsState.now() + AsConfig.JWKS_CACHE_TTL, keys));
        return keys;
    }

    private Map<String, Object> getJson(String url) {
        try {
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder().uri(URI.create(url)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("HTTP " + response.statusCode() + " from " + url);
            }
            return MAPPER.readValue(response.body(), new TypeReference<>() {});
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("fetch failed for " + url + ": " + e.getMessage(), e);
        }
    }

    /** RS256 compact-JWS verification against realm JWKS (kid-filtered, enc skipped). */
    private Map<String, Object> verifyRs256(String token, List<Map<String, Object>> keys)
            throws GeneralSecurityException, IOException {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("not a compact JWS");
        }
        Map<String, Object> header = MAPPER.readValue(
                Base64.getUrlDecoder().decode(parts[0]), new TypeReference<>() {});
        Object kid = header.get("kid");
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);

        Exception lastError = null;
        for (Map<String, Object> jwk : keys) {
            if ("enc".equals(jwk.get("use"))) {
                continue;
            }
            if (kid != null && jwk.get("kid") != null && !kid.equals(jwk.get("kid"))) {
                continue;
            }
            try {
                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(rsaKey(jwk));
                verifier.update(signingInput);
                if (!verifier.verify(signature)) {
                    throw new SecurityException("signature mismatch");
                }
                Map<String, Object> claims = MAPPER.readValue(
                        Base64.getUrlDecoder().decode(parts[1]), new TypeReference<>() {});
                if (!config.ownerIssuer.equals(claims.get("iss"))) {
                    throw new SecurityException("unexpected issuer " + claims.get("iss"));
                }
                checkExpiry(claims);
                return claims;
            } catch (Exception e) {
                lastError = e;
            }
        }
        throw new SecurityException("no matching realm key: "
                + (lastError == null ? "none tried" : lastError.getMessage()));
    }

    private static PublicKey rsaKey(Map<String, Object> jwk) throws GeneralSecurityException {
        BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("n")));
        BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("e")));
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    }
}
