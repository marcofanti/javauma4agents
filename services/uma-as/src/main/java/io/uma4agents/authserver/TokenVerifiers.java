package io.uma4agents.authserver;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.uma4agents.common.AgentTokens;
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
import java.util.function.LongSupplier;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * Inbound token verification: Alice's Keycloak OIDC token (one owner credential, RS256
 * against the realm's published keys) and agents' {@code aa-agent+jwt} (Ed25519 or
 * EdDSA, against the keys of an issuer the deployment names).
 */
@Component
public class TokenVerifiers {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AsConfig config;
    private final HttpClient http;
    private final Map<String, CachedKeys> jwksCache = new ConcurrentHashMap<>();
    private final AgentTokens agentTokens;

    private record CachedKeys(long expires, List<Map<String, Object>> keys) {}

    public TokenVerifiers(AsConfig config, HttpClient http, PeerFetch peerFetch) {
        this.config = config;
        this.http = http;
        this.agentTokens = new AgentTokens(peerFetch::getJson, config.agentIssuers);
    }

    /** Extracts the bearer token or raises 401 — the Python _bearer(). */
    public static String bearer(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bearer token required");
        }
        return authorization.substring(7);
    }

    /**
     * One owner credential: Alice's own OIDC access token, validated against her realm's
     * published keys. Returns the owner it proves; whether this server serves that owner
     * is decided by {@link OwnerAuth}.
     *
     * @param authorization the Authorization header, or null
     * @return the token's {@code preferred_username}
     * @throws ResponseStatusException 401 or 403 with the pinned details
     */
    public String oidcOwner(String authorization) {
        String token = bearer(authorization);
        Map<String, Object> claims;
        try {
            List<Map<String, Object>> keys = ownerIssuerKeys(false);
            Object kid = headerKid(token);
            // Her identity provider rotates keys: a token naming one not cached earns one
            // fresh read, at most once a minute.
            if (kid != null && keys.stream().noneMatch(k -> kid.equals(k.get("kid")))) {
                keys = ownerIssuerKeys(true);
            }
            claims = verifyRs256(token, keys);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "owner API requires the owner's OIDC token: " + e.getMessage());
        }
        if (!config.ownerAudiences.contains(String.valueOf(claims.get("azp")))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "token was not issued to an owner-surface client");
        }
        if (!(claims.get("preferred_username") instanceof String owner) || owner.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "owner token carries no preferred_username");
        }
        return owner;
    }

    /**
     * An AAuth agent token, verified against the keys its issuer publishes, if the
     * deployment named that issuer.
     *
     * @param agentToken the compact {@code aa-agent+jwt}
     * @return its claims
     * @throws AgentTokens.Refused naming the check that failed
     */
    public Map<String, Object> verifyAgentToken(String agentToken) {
        return agentTokens.verify(agentToken);
    }

    static void checkExpiry(Map<String, Object> claims) {
        if (claims.get("exp") instanceof Number exp
                && exp.longValue() < java.time.Instant.now().getEpochSecond()) {
            throw new IllegalArgumentException("token expired");
        }
    }

    /** Seconds between forced reads of her realm's keys. */
    static final long KEY_REFETCH_FLOOR_S = 60;

    /** Epoch seconds; replaceable so the refetch floor can be tested without waiting. */
    LongSupplier clock = AsState::now;

    private List<Map<String, Object>> ownerIssuerKeys(boolean fresh) {
        return cachedJwks(config.ownerIssuer,
                config.ownerIssuer + "/.well-known/openid-configuration", fresh);
    }

    private static Object headerKid(String token) {
        try {
            String head = token.substring(0, token.indexOf('.'));
            Map<String, Object> header = MAPPER.readValue(Base64.getUrlDecoder().decode(head),
                    new TypeReference<>() {});
            return header.get("kid");
        } catch (RuntimeException e) {
            return null;
        }
    }

    private List<Map<String, Object>> cachedJwks(String cacheKey, String discoveryUrl,
                                                 boolean fresh) {
        CachedKeys cached = jwksCache.get(cacheKey);
        long now = clock.getAsLong();
        if (cached != null && cached.expires() > now && !fresh) {
            return cached.keys();
        }
        if (fresh && cached != null
                && now - (cached.expires() - AsConfig.JWKS_CACHE_TTL) < KEY_REFETCH_FLOOR_S) {
            return cached.keys();
        }
        Map<String, Object> meta = getJson(discoveryUrl);
        Map<String, Object> jwks = getJson(String.valueOf(meta.get("jwks_uri")));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        if (keys == null) {
            throw new IllegalStateException("no keys at " + meta.get("jwks_uri"));
        }
        jwksCache.put(cacheKey, new CachedKeys(now + AsConfig.JWKS_CACHE_TTL, keys));
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
