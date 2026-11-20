package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJwtClaims;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * Declarative registration (pull mode): this AS reads what the resource servers she
 * approved publish and materializes its registry from it, instead of receiving pushes.
 * Only an active registration writes her registry; a listing replaces what that server
 * published before, so a withdrawn resource is withdrawn here too.
 */
@Component
public class RegistrationPuller {

    /** The most any document a resource server names may weigh. */
    static final int FETCH_LIMIT = 1024 * 1024;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AsConfig config;
    private final AsState state;
    private final OwnerStore store;
    private final SigningKeys keys;
    private final HttpClient http;
    private volatile long lastPullMillis;

    public RegistrationPuller(AsConfig config, AsState state, OwnerStore store,
                              SigningKeys keys, HttpClient httpClient) {
        this.config = config;
        this.state = state;
        this.store = store;
        this.keys = keys;
        this.http = httpClient;
    }

    /** RFC 9728 §3: the well-known path goes between host and resource path. */
    static String wellKnownPrmUrl(String resourceUri) {
        URI u = URI.create(resourceUri);
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return u.getScheme() + "://" + u.getRawAuthority()
                + "/.well-known/oauth-protected-resource" + path;
    }

    /** Both https, and the same scheme and authority. */
    static boolean sameOrigin(String a, String b) {
        try {
            URI ua = URI.create(a);
            URI ub = URI.create(b);
            return "https".equals(ua.getScheme()) && "https".equals(ub.getScheme())
                    && ua.getRawAuthority() != null
                    && ua.getRawAuthority().equals(ub.getRawAuthority());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void ownHttps(String url, String resourceUri, String what) {
        if (url == null || !url.startsWith("https://") || !sameOrigin(url, resourceUri)) {
            throw new IllegalStateException(what + " '" + url
                    + "' is not https on the resource's own origin");
        }
    }

    /**
     * Reads one resource server's published metadata and its owner listing.
     *
     * <p>1. Fetch the public RFC 9728 document (TLS-anchored) and verify its
     * signed_metadata against the resource's jwks_uri, which must be https on the
     * resource's own origin.
     *
     * <p>2. Query the protected owner-resources endpoint it advertises (same rule),
     * signing the request with this AS's current key (RFC 9421).
     *
     * @return how many resources the listing carried
     */
    public int pullRegistrations(String clientId, Map<String, Object> rs) {
        String resourceUri = String.valueOf(rs.get("resource_uri"));
        Map<String, Object> doc = getJson(wellKnownPrmUrl(resourceUri), Map.of());
        if (!resourceUri.equals(doc.get("resource"))) {
            throw new IllegalStateException("metadata is for " + doc.get("resource"));
        }
        if (!(doc.get("authorization_servers") instanceof List<?> servers)
                || !servers.contains(config.issuer)) {
            throw new IllegalStateException("the RS's metadata does not name this AS");
        }
        String jwksUri = doc.get("jwks_uri") instanceof String j ? j : null;
        ownHttps(jwksUri, resourceUri, "jwks_uri");
        Map<String, Object> verified = verifiedMetadata(doc, getJson(jwksUri, Map.of()));
        if (verified == null || !resourceUri.equals(verified.get("iss"))) {
            throw new IllegalStateException(
                    "signed_metadata did not verify against the resource's published keys");
        }
        String endpoint = verified.get("owner_resources_endpoint") instanceof String e
                ? e : null;
        if (endpoint == null) {
            throw new IllegalStateException("no owner_resources_endpoint in signed metadata");
        }
        ownHttps(endpoint, resourceUri, "owner_resources_endpoint");
        URI u = URI.create(endpoint);
        Map<String, String> headers = HttpSignature.sign("GET", u.getRawAuthority(),
                u.getRawPath(), "", keys.current().getPrivate(), keys.kid(),
                HttpSignature.SignOptions.none());
        Map<String, Object> listing = getJson(endpoint, headers);
        if (listing.get("owner") != null && !config.ownerUsername.equals(listing.get("owner"))) {
            throw new IllegalStateException("the listing names " + listing.get("owner")
                    + ", and this pull was made for " + config.ownerUsername);
        }
        return apply(clientId, listing, endpoint);
    }

    private static Map<String, Object> verifiedMetadata(Map<String, Object> doc,
                                                        Map<String, Object> jwks) {
        if (!(doc.get("signed_metadata") instanceof String signed)) {
            throw new IllegalStateException("published metadata is not signed");
        }
        if (jwks.get("keys") instanceof List<?> keyList) {
            for (Object key : keyList) {
                if (!(key instanceof Map<?, ?> jwk)) {
                    continue;
                }
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> typed = (Map<String, Object>) jwk;
                    Map<String, Object> claims =
                            CompactJws.verify(signed, Jwks.toPublicKey(typed)).claims();
                    // A JWT decode's default claim checks, audience aside: a signature
                    // over metadata that has expired, or is not yet valid, verifies nothing.
                    PyJwtClaims.validateWithIat(claims, System.currentTimeMillis() / 1000.0);
                    return claims;
                } catch (RuntimeException e) {
                    // Try the next published key.
                }
            }
        }
        return null;
    }

    /**
     * The listing replaces what this resource server publishes for her. A resource may be
     * served by several approved servers; each is recorded as a source, only sources may
     * ask about it, and withdrawal from one leaves it for the others.
     */
    private int apply(String clientId, Map<String, Object> listing, String endpoint) {
        List<Map<String, Object>> items = listedResources(listing);
        List<String> withdrawn = new ArrayList<>();
        state.updateResources(registry -> {
            Set<String> seen = new LinkedHashSet<>();
            for (Map<String, Object> res : items) {
                String id = (String) res.get("_id");
                Map<String, Object> held = registry.get(id);
                Set<String> sources = new TreeSet<>();
                if (held != null && held.get("sources") instanceof List<?> s) {
                    s.forEach(x -> sources.add(String.valueOf(x)));
                }
                sources.add(clientId);
                Map<String, Object> desc = new LinkedHashMap<>();
                desc.put("resource_scopes", new ArrayList<>((List<?>) res.get("resource_scopes")));
                desc.put("name", res.get("name"));
                desc.put("type", res.get("type"));
                // What the resource server says this operation leaves behind, normalised
                // on the way in: a word this server does not know is no declaration.
                desc.put("consequence", io.uma4agents.common.Consequence.normalise(
                        res.get("consequence")));
                desc.put("icon_uri", null);
                desc.put("description", null);
                desc.put("registered_via", "pull");
                desc.put("owner", config.ownerUsername);
                desc.put("sources", new ArrayList<>(sources));
                registry.put(id, desc);
                seen.add(id);
            }
            for (String id : new ArrayList<>(registry.keySet())) {
                Map<String, Object> d = registry.get(id);
                if (seen.contains(id) || !(d.get("sources") instanceof List<?> s)
                        || !s.contains(clientId)) {
                    continue;
                }
                List<Object> left = new ArrayList<>(s);
                left.remove(clientId);
                withdrawn.add(id);
                if (left.isEmpty()) {
                    registry.remove(id);
                } else {
                    d.put("sources", left);
                }
            }
        });
        state.log.event("resources.pulled", null, "client_id", clientId,
                "owner", listing.get("owner"), "count", items.size(),
                "withdrawn", withdrawn.isEmpty() ? null : withdrawn, "endpoint", endpoint);
        return items.size();
    }

    /**
     * The listing's entries, every one of them well formed, or a refusal of the whole
     * listing. Absences in a listing are withdrawals, so a malformed entry must fail the
     * pull before anything is applied: otherwise the resources it failed to describe would
     * be retired as if the server had stopped publishing them. A listing with no
     * {@code resources} member publishes nothing.
     */
    static List<Map<String, Object>> listedResources(Map<String, Object> listing) {
        Object resources = listing.getOrDefault("resources", List.of());
        if (!(resources instanceof List<?> entries)) {
            throw new IllegalStateException("the listing's resources is not an array");
        }
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object item : entries) {
            if (!(item instanceof Map<?, ?> res)) {
                throw new IllegalStateException("a listed resource is not an object");
            }
            if (!(res.get("_id") instanceof String id) || id.isEmpty()) {
                throw new IllegalStateException("a listed resource has no _id");
            }
            if (!(res.get("resource_scopes") instanceof List<?> scopes)
                    || !scopes.stream().allMatch(String.class::isInstance)) {
                throw new IllegalStateException("listed resource " + id
                        + " has no resource_scopes array");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> typed = (Map<String, Object>) res;
            items.add(typed);
        }
        return items;
    }

    /**
     * Re-reads every resource server she approved, logging failures. Used by /perm on a
     * miss and by her listing on a clock.
     *
     * @return whether every approved server answered
     */
    public boolean pullAll() {
        lastPullMillis = System.currentTimeMillis();
        boolean all = true;
        for (Map.Entry<String, Map<String, Object>> e : approved().entrySet()) {
            try {
                pullRegistrations(e.getKey(), e.getValue());
            } catch (RuntimeException ex) {
                all = false;
                state.log.event("resources.pull_retry", null, "client_id", e.getKey(),
                        "error", truncate(ex.getMessage()));
            }
        }
        return all;
    }

    /** Pulls again when the last pull is older than {@code UMA_AS_RESOURCE_REFRESH_S}. */
    public void pullIfStale() {
        long age = System.currentTimeMillis() - lastPullMillis;
        if (age >= (long) (config.resourceRefreshSeconds * 1000)) {
            pullAll();
        }
    }

    /** Only a resource server she has approved writes her registry. */
    private Map<String, Map<String, Object>> approved() {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        store.resourceServers().forEach((cid, rs) -> {
            if ("active".equals(rs.getOrDefault("status", "active"))) {
                out.put(cid, rs);
            }
        });
        return out;
    }

    /**
     * Startup pull on a background thread, until every approved server has answered. The
     * RS authenticates this AS's signed query by fetching our JWKS, so the pull must never
     * block request serving, and /health must not wait for it.
     */
    @Bean
    public ApplicationRunner pullAtStartup() {
        return args -> {
            Thread loop = new Thread(() -> {
                for (int attempt = 0; attempt < 60; attempt++) {
                    if (!approved().isEmpty() && pullAll()) {
                        return;
                    }
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                state.log.event("resources.pull_failed", null,
                        "note", "lazy pull on first /perm remains");
            }, "registration-pull");
            loop.setDaemon(true);
            loop.start();
        };
    }

    private Map<String, Object> getJson(String url, Map<String, String> headers) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url)).timeout(Duration.ofSeconds(10)).GET();
        headers.forEach(builder::header);
        try {
            HttpResponse<InputStream> response =
                    http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                if (response.statusCode() >= 400) {
                    throw new IllegalStateException("HTTP " + response.statusCode()
                            + " from " + url);
                }
                if (response.statusCode() >= 300) {
                    throw new IllegalStateException("HTTP " + response.statusCode()
                            + " from " + url + ": redirects are not followed");
                }
                byte[] data = body.readNBytes(FETCH_LIMIT + 1);
                if (data.length > FETCH_LIMIT) {
                    throw new IllegalStateException(url + " returned more than "
                            + FETCH_LIMIT + " bytes");
                }
                return MAPPER.readValue(data, new TypeReference<>() {});
            }
        } catch (IOException | JacksonException e) {
            throw new IllegalStateException(url + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(url + ": interrupted", e);
        }
    }

    private static String truncate(String value) {
        return value == null ? "" : value.substring(0, Math.min(200, value.length()));
    }
}
