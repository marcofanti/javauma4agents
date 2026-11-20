package io.uma4agents.organization;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
final class OrganizationAdminAuth {
    private static final long KEY_TTL_S = 300;
    private static final long KEY_REFETCH_FLOOR_S = 60;

    private final OrgConfig config;
    private final OrgHttp http;
    private volatile List<Map<String, Object>> keys = List.of();
    private volatile long loadedAt;

    OrganizationAdminAuth(OrgConfig config, OrgHttp http) {
        this.config = config;
        this.http = http;
    }

    String requireAdmin(HttpServletRequest request) {
        String token = bearer(request);
        if (!config.adminToken.isEmpty() && constantTime(config.adminToken, token)) {
            return "console";
        }
        if (config.adminIssuer.isEmpty()) {
            throw unauthorized();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
                throw unauthorized();
            }
            String kid = jwt.getHeader().getKeyID();
            List<Map<String, Object>> current = keys(false);
            if (kid != null && current.stream().noneMatch(key -> kid.equals(key.get("kid")))) {
                current = keys(true);
            }
            for (Map<String, Object> key : current) {
                if ("enc".equals(key.get("use")) || kid != null && !kid.equals(key.get("kid"))) {
                    continue;
                }
                if (jwt.verify(new RSASSAVerifier(RSAKey.parse(key)))) {
                    return checkAdmin(jwt.getJWTClaimsSet().getClaims());
                }
            }
        } catch (ResponseStatusException failure) {
            throw failure;
        } catch (Exception failure) {
            throw unauthorized();
        }
        throw unauthorized();
    }

    private String checkAdmin(Map<String, Object> claims) {
        if (!config.adminIssuer.equals(claims.get("iss"))) {
            throw unauthorized();
        }
        if (claims.get("exp") instanceof java.util.Date exp && !exp.toInstant().isAfter(Instant.now())) {
            throw unauthorized();
        }
        if (!config.adminAudiences.isEmpty()) {
            Object aud = claims.get("aud");
            boolean matches = aud instanceof List<?> list
                    && list.stream().anyMatch(config.adminAudiences::contains);
            Object azp = claims.get("azp");
            if (!matches && (!(azp instanceof String client)
                    || !config.adminAudiences.contains(client))) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "that token was issued for a different client");
            }
        }
        if (claims.get("preferred_username") instanceof String name && !name.isEmpty()) {
            return name;
        }
        if (claims.get("sub") instanceof String sub && !sub.isEmpty()) {
            return sub;
        }
        throw unauthorized();
    }

    @SuppressWarnings("unchecked")
    private synchronized List<Map<String, Object>> keys(boolean refresh) {
        long now = Instant.now().getEpochSecond();
        long age = now - loadedAt;
        if (!keys.isEmpty() && age < (refresh ? KEY_REFETCH_FLOOR_S : KEY_TTL_S)) {
            return keys;
        }
        Map<String, Object> meta = http.get(config.adminMetadata);
        if (!(meta.get("jwks_uri") instanceof String jwksUri)) {
            throw unauthorized();
        }
        Map<String, Object> jwks = http.get(jwksUri);
        if (!(jwks.get("keys") instanceof List<?> list)) {
            throw unauthorized();
        }
        List<Map<String, Object>> replacement = list.stream()
                .filter(Map.class::isInstance).map(value -> (Map<String, Object>) value).toList();
        keys = replacement;
        loadedAt = now;
        return replacement;
    }

    void requireResourceServer(HttpServletRequest request) {
        if (!constantTime(config.rsToken, bearer(request))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "unknown enforcement point");
        }
    }

    static String bearer(HttpServletRequest request) {
        String header = request.getHeader("authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bearer token required");
        }
        return header.substring(7);
    }

    static boolean constantTime(String first, String second) {
        return MessageDigest.isEqual(first.getBytes(StandardCharsets.UTF_8),
                second.getBytes(StandardCharsets.UTF_8));
    }

    private static ResponseStatusException unauthorized() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "admin token did not verify");
    }
}
