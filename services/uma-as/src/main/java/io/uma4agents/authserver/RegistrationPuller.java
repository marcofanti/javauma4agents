package io.uma4agents.authserver;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * Declarative registration (pull mode): this AS reads the RS's published
 * metadata and materializes its registry from it, instead of receiving pushes.
 */
@Component
public class RegistrationPuller {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AsConfig config;
    private final AsState state;
    private final HttpClient http;

    public RegistrationPuller(AsConfig config, AsState state, HttpClient httpClient) {
        this.config = config;
        this.state = state;
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

    /**
     * Reads the RS's published metadata and materializes the registry.
     *
     * <p>1. Fetch the public RFC 9728 document (TLS-anchored) and verify its
     * signed_metadata against the resource's jwks_uri — the pulled copy is
     * attributable, not just transport-secure.
     *
     * <p>2. Query the protected owner-resources endpoint it advertises,
     * signing the request with this AS's key (RFC 9421) — "protected
     * webfinger": the RS serves the owner-bound instances only to her AS.
     */
    public int pullRegistrations(String clientId) {
        Map<String, Object> rs = state.rsClients.get(clientId);
        String resourceUri = String.valueOf(rs.get("resource_uri"));

        Map<String, Object> doc = getJson(wellKnownPrmUrl(resourceUri));
        if (!resourceUri.equals(doc.get("resource"))) {
            throw new IllegalStateException("metadata is for " + doc.get("resource"));
        }
        if (!(doc.get("authorization_servers") instanceof List<?> servers)
                || !servers.contains(config.issuer)) {
            throw new IllegalStateException("the RS's metadata does not name this AS");
        }

        Map<String, Object> jwks = getJson(String.valueOf(doc.get("jwks_uri")));
        String signed = doc.get("signed_metadata") instanceof String s ? s : null;
        if (signed == null) {
            throw new IllegalStateException("published metadata is not signed");
        }
        Map<String, Object> verified = null;
        if (jwks.get("keys") instanceof List<?> keys) {
            for (Object key : keys) {
                if (!(key instanceof Map<?, ?> jwk)) {
                    continue;
                }
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> typed = (Map<String, Object>) jwk;
                    verified = CompactJws.verify(signed, Jwks.toPublicKey(typed)).claims();
                    break;
                } catch (RuntimeException e) {
                    // Try the next published key.
                }
            }
        }
        if (verified == null || !resourceUri.equals(verified.get("iss"))) {
            throw new IllegalStateException(
                    "signed_metadata did not verify against the resource's published keys");
        }

        String endpoint = verified.get("owner_resources_endpoint") instanceof String e
                ? e : null;
        if (endpoint == null) {
            throw new IllegalStateException("no owner_resources_endpoint in signed metadata");
        }
        URI u = URI.create(endpoint);
        Map<String, String> headers = HttpSignature.sign("GET", u.getRawAuthority(),
                u.getRawPath(), "", state.signingKey.getPrivate(), AsConfig.KID);
        Map<String, Object> listing = getJson(endpoint, headers);

        int count = 0;
        if (listing.get("resources") instanceof List<?> resources) {
            for (Object item : resources) {
                if (!(item instanceof Map<?, ?> res)) {
                    continue;
                }
                Map<String, Object> desc = new LinkedHashMap<>();
                desc.put("resource_scopes", res.get("resource_scopes") instanceof List<?> ss
                        ? new ArrayList<>(ss) : List.of());
                desc.put("name", res.get("name"));
                desc.put("type", res.get("type"));
                desc.put("icon_uri", null);
                desc.put("description", null);
                desc.put("registered_via", "pull");
                desc.put("owner", listing.get("owner"));
                state.resources.put(String.valueOf(res.get("_id")), desc);
                count++;
            }
        }
        state.log.event("resources.pulled", null, "client_id", clientId,
                "owner", listing.get("owner"), "count", count, "endpoint", endpoint);
        return count;
    }

    /** Re-pulls every RS, logging failures — used by /perm's stale-registry repair. */
    public void pullAll() {
        for (String clientId : state.rsClients.keySet()) {
            try {
                pullRegistrations(clientId);
            } catch (RuntimeException e) {
                state.log.event("resources.pull_retry", null, "client_id", clientId,
                        "error", truncate(e.getMessage()));
            }
        }
    }

    /**
     * Startup pull on a background thread. The RS authenticates this AS's
     * signed query by fetching <em>our</em> JWKS, so the pull and the
     * verification form a call cycle — it must never block request serving.
     * (The Python reference deadlocked on a single-threaded event loop here;
     * the servlet pool is immune, but the retry loop still belongs off the
     * startup path so /health answers while the gateway is coming up.)
     */
    @Bean
    public ApplicationRunner pullAtStartup() {
        return args -> {
            if (!"pull".equals(config.registrationMode)) {
                return;
            }
            Thread loop = new Thread(() -> {
                for (int attempt = 0; attempt < 60; attempt++) {
                    for (String clientId : state.rsClients.keySet()) {
                        try {
                            pullRegistrations(clientId);
                            return;
                        } catch (RuntimeException e) {
                            state.log.event("resources.pull_retry", null,
                                    "client_id", clientId, "error", truncate(e.getMessage()));
                        }
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

    private Map<String, Object> getJson(String url) {
        return getJson(url, Map.of());
    }

    private Map<String, Object> getJson(String url, Map<String, String> headers) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url)).timeout(Duration.ofSeconds(10)).GET();
        headers.forEach(builder::header);
        try {
            HttpResponse<String> response =
                    http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 400) {
                throw new IllegalStateException("HTTP " + response.statusCode()
                        + " from " + url);
            }
            return MAPPER.readValue(response.body(), new TypeReference<>() {});
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException(url + ": " + e.getMessage(), e);
        }
    }

    private static String truncate(String value) {
        return value == null ? "" : value.substring(0, Math.min(200, value.length()));
    }
}
