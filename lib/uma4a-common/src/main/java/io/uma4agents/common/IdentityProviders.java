package io.uma4agents.common;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** Metadata and JWKS of administratively configured identity providers. */
public final class IdentityProviders {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long TTL_MS = Duration.ofMinutes(5).toMillis();
    private static final long REFRESH_FLOOR_MS = Duration.ofMinutes(1).toMillis();

    private final HttpClient http;
    private final Map<String, Cached<Map<String, Object>>> metadata = new ConcurrentHashMap<>();
    private final Map<String, Cached<List<Map<String, Object>>>> signingKeys = new ConcurrentHashMap<>();
    private record Cached<T>(T value, long time) {}

    public IdentityProviders(HttpClient http) {
        this.http = http;
    }

    public Map<String, Object> metadata(String issuer) {
        return metadata.compute(issuer, (key, cached) -> {
            long now = System.currentTimeMillis();
            if (cached != null && now - cached.time() < TTL_MS) {
                return cached;
            }
            for (String suffix : List.of("/.well-known/openid-configuration",
                    "/.well-known/oauth-authorization-server")) {
                try {
                    var doc = get(base(issuer) + suffix);
                    if (issuer.equals(doc.get("issuer"))) {
                        return new Cached<>(doc, now);
                    }
                } catch (IllegalArgumentException unavailable) {
                    // Some providers publish only OAuth discovery.
                }
            }
            return new Cached<>(Map.of(), now);
        }).value();
    }

    public List<Map<String, Object>> keys(String issuer, boolean refresh) {
        return signingKeys.compute(issuer, (key, cached) -> {
            long now = System.currentTimeMillis();
            if (cached != null && now - cached.time() < (refresh ? REFRESH_FLOOR_MS : TTL_MS)) {
                return cached;
            }
            Object uri = metadata(issuer).get("jwks_uri");
            if (uri instanceof String location && !location.isEmpty()) {
                try {
                    var found = readKeys(get(location));
                    if (!found.isEmpty()) {
                        return new Cached<>(found, now);
                    }
                } catch (IllegalArgumentException unavailable) {
                    // The lab also supports an issuer's conventional /jwks endpoint.
                }
            }
            return new Cached<>(readKeys(get(base(issuer) + "/jwks")), now);
        }).value();
    }

    public Map<String, Object> claims(String token, String issuer) {
        Object kid = CompactJws.parse(token).header().get("kid");
        return IdentityTokens.verify(token, issuer, keysFor(issuer, kid));
    }

    public List<Map<String, Object>> keysFor(String issuer, Object kid) {
        List<Map<String, Object>> candidates = keys(issuer, false);
        if (kid != null && candidates.stream().noneMatch(key -> kid.equals(key.get("kid")))) {
            candidates = keys(issuer, true);
        }
        return candidates;
    }

    public static boolean https(String url) {
        try {
            URI uri = URI.create(url);
            return "https".equals(uri.getScheme()) && uri.getHost() != null
                    && uri.getUserInfo() == null && uri.getFragment() == null;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private Map<String, Object> get(String url) {
        if (!https(url)) {
            throw new IllegalArgumentException("identity provider endpoints must use HTTPS");
        }
        URI uri = URI.create(url);
        try {
            var request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build();
            var response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalArgumentException("identity provider returned HTTP " + response.statusCode());
            }
            return JSON.readValue(response.body(), new TypeReference<Map<String, Object>>() {});
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalArgumentException("identity provider read interrupted");
        } catch (java.io.IOException | tools.jackson.core.JacksonException unreachable) {
            throw new IllegalArgumentException("identity provider could not be reached");
        }
    }

    private static String base(String issuer) { return issuer.replaceFirst("/+$", ""); }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> readKeys(Map<String, Object> jwks) {
        return jwks.get("keys") instanceof List<?> list ? list.stream().filter(Map.class::isInstance)
                .map(value -> (Map<String, Object>) value).toList() : List.of();
    }
}
