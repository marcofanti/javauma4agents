package io.uma4agents.portal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Hand-rolled OIDC authorization-code flow with PKCE (S256) for the public
 * client {@code alice-portal}, plus the server-side token store — a direct port
 * of the authlib wiring in the Python portal. Alice's Keycloak tokens live only
 * here; the session cookie carries an opaque {@code sid}.
 */
@Component
public class OidcService {

    /** Alice's OIDC tokens, keyed by session id. */
    public static final class Tokens {
        volatile String accessToken;
        volatile String refreshToken;
        volatile long expiresAt;
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final PortalConfig config;
    private final HttpClient http;
    private final Map<String, Tokens> tokens = new ConcurrentHashMap<>();
    private final Map<String, String> pendingVerifiers = new ConcurrentHashMap<>();
    private volatile Map<String, Object> metadata;

    public OidcService(PortalConfig config, HttpClient http) {
        this.config = config;
        this.http = http;
    }

    public boolean hasTokens(String sid) {
        return sid != null && tokens.containsKey(sid);
    }

    public void drop(String sid) {
        if (sid != null) {
            tokens.remove(sid);
        }
    }

    /** Builds the authorization redirect and remembers the PKCE verifier by state. */
    public String authorizationUrl(String redirectUri) {
        String state = randomToken(16);
        String verifier = randomToken(32);
        pendingVerifiers.put(state, verifier);
        String challenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(sha256(verifier.getBytes(StandardCharsets.US_ASCII)));
        Map<String, String> params = Map.of(
                "response_type", "code",
                "client_id", config.oidcClientId,
                "redirect_uri", redirectUri,
                "scope", "openid profile",
                "state", state,
                "code_challenge", challenge,
                "code_challenge_method", "S256");
        return metadata().get("authorization_endpoint") + "?" + form(params);
    }

    /**
     * Exchanges the callback code; returns the session id under which the tokens
     * were stored plus the display name from the ID token, or null on failure.
     */
    public Map<String, String> handleCallback(String code, String state, String redirectUri) {
        String verifier = state == null ? null : pendingVerifiers.remove(state);
        if (code == null || verifier == null) {
            return null;
        }
        Map<String, Object> token = postToken(Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", redirectUri,
                "client_id", config.oidcClientId,
                "code_verifier", verifier));
        if (token == null || !(token.get("access_token") instanceof String access)) {
            return null;
        }
        String sid = randomToken(16);
        Tokens t = new Tokens();
        t.accessToken = access;
        t.refreshToken = (String) token.get("refresh_token");
        t.expiresAt = Instant.now().getEpochSecond() + expiresIn(token);
        tokens.put(sid, t);

        Map<String, Object> claims = idTokenClaims((String) token.get("id_token"));
        String name = firstNonBlank(
                (String) claims.get("name"), (String) claims.get("preferred_username"), "Alice");
        return Map.of("sid", sid, "user", name);
    }

    /** Alice's current access token, refreshed against Keycloak when stale. */
    public String ownerToken(String sid) {
        Tokens t = sid == null ? null : tokens.get(sid);
        if (t == null) {
            return null;
        }
        if (t.expiresAt > Instant.now().getEpochSecond() + 15) {
            return t.accessToken;
        }
        if (t.refreshToken == null) {
            return null;
        }
        Map<String, Object> fresh = postToken(Map.of(
                "grant_type", "refresh_token",
                "refresh_token", t.refreshToken,
                "client_id", config.oidcClientId));
        if (fresh == null || !(fresh.get("access_token") instanceof String access)) {
            return null;
        }
        t.accessToken = access;
        if (fresh.get("refresh_token") instanceof String refreshed) {
            t.refreshToken = refreshed;
        }
        t.expiresAt = Instant.now().getEpochSecond() + expiresIn(fresh);
        return t.accessToken;
    }

    private Map<String, Object> postToken(Map<String, String> params) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create((String) metadata().get("token_endpoint")))
                .header("content-type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(params)))
                .build();
        try {
            HttpResponse<String> response =
                    http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return null;
            }
            return MAPPER.readValue(response.body(), new TypeReference<>() {});
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    /** OIDC discovery, fetched lazily and cached (Keycloak may boot after us). */
    private Map<String, Object> metadata() {
        Map<String, Object> cached = metadata;
        if (cached != null) {
            return cached;
        }
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.oidcIssuer + "/.well-known/openid-configuration"))
                .GET().build();
        try {
            HttpResponse<String> response =
                    http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException(
                        "OIDC discovery failed: HTTP " + response.statusCode());
            }
            Map<String, Object> fetched = MAPPER.readValue(response.body(), new TypeReference<>() {});
            metadata = fetched;
            return fetched;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("OIDC discovery unreachable at "
                    + config.oidcIssuer + ": " + e.getMessage(), e);
        }
    }

    /** Claims from the ID token payload (issued over TLS in a direct exchange). */
    private static Map<String, Object> idTokenClaims(String idToken) {
        if (idToken == null) {
            return Map.of();
        }
        String[] parts = idToken.split("\\.");
        if (parts.length < 2) {
            return Map.of();
        }
        try {
            return MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]),
                    new TypeReference<>() {});
        } catch (IOException | IllegalArgumentException e) {
            return Map.of();
        }
    }

    private static long expiresIn(Map<String, Object> token) {
        return token.get("expires_in") instanceof Number n ? n.longValue() : 300;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "Alice";
    }

    private static String form(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private static String randomToken(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
