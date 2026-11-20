package io.uma4agents.pep.core;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import io.uma4agents.pep.core.EnforcerSettings.ToolSurface;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * What a resource server publishes about itself, shared by the gateway and the embedded
 * vault: the public RFC 9728 document and the owner-resources listing served only to the
 * owner's authorization server. Ported from the pinned {@code lib/uma4a_publish.py}.
 */
public final class Publication {

    private Publication() {}

    /** RFC 9728 Protected Resource Metadata: structural only, never whose instances. */
    public static Map<String, Object> prmDocument(String publicBase, String asPublic,
                                                  Map<String, ToolSurface> tools, String leaf,
                                                  String ownerResourcesPath) {
        TreeSet<String> scopes = new TreeSet<>();
        List<Map<String, Object>> surfaces = new ArrayList<>();
        tools.forEach((tool, surface) -> {
            scopes.addAll(surface.scopes());
            Map<String, Object> ts = new LinkedHashMap<>();
            ts.put("tool", tool);
            ts.put("resource_scopes", surface.scopes());
            if (surface.consequence() != null) {
                ts.put("consequence", surface.consequence());
            }
            surfaces.add(ts);
        });
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", publicBase + "/" + leaf);
        doc.put("authorization_servers", List.of(asPublic));
        doc.put("jwks_uri", publicBase + "/jwks");
        doc.put("scopes_supported", List.copyOf(scopes));
        doc.put("bearer_methods_supported", List.of("header"));
        doc.put("resource_signing_alg_values_supported", List.of("EdDSA"));
        doc.put("tool_surfaces", surfaces);
        doc.put("owner_resources_endpoint", publicBase + ownerResourcesPath);
        return doc;
    }

    /** Adds {@code signed_metadata}: the same claims as a JWT under the resource's key. */
    public static Map<String, Object> signMetadata(Map<String, Object> doc, KeyPair key,
                                                   String kid) {
        Map<String, Object> claims = new LinkedHashMap<>(doc);
        claims.put("iss", doc.get("resource"));
        claims.put("iat", Instant.now().getEpochSecond());
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "oauth-protected-resource+jwt");
        header.put("kid", kid);
        Map<String, Object> signed = new LinkedHashMap<>(doc);
        signed.put("signed_metadata", CompactJws.sign(header, claims, key.getPrivate()));
        return signed;
    }

    /** The resource's JWKS: its one signing key under {@code kid}. */
    public static Map<String, Object> jwks(KeyPair key, String kid) {
        Map<String, Object> jwk = Jwks.okpPublicJwk(key.getPublic());
        jwk.put("kid", kid);
        jwk.put("use", "sig");
        return Map.of("keys", List.of(jwk));
    }

    /** The protected half: whose instances sit behind this resource. */
    public static Map<String, Object> ownerResourcesDocument(String publicBase, String owner,
                                                             Map<String, ToolSurface> tools,
                                                             String leaf) {
        String title = owner.isEmpty() ? owner
                : owner.substring(0, 1).toUpperCase(Locale.ROOT) + owner.substring(1);
        List<Map<String, Object>> resources = new ArrayList<>();
        tools.forEach((tool, surface) -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("_id", surface.resourceId());
            item.put("tool", tool);
            item.put("resource_scopes", surface.scopes());
            item.put("type", "mcp-tool");
            item.put("name", title + "'s vault: " + tool);
            if (surface.consequence() != null) {
                item.put("consequence", surface.consequence());
            }
            resources.add(item);
        });
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("owner", owner);
        body.put("resource", publicBase + "/" + leaf);
        body.put("resources", resources);
        return body;
    }

    /**
     * One authorization server's published keys, cached for {@code ttl}. A failure may force
     * a refetch (rotation), but not within {@code minRefresh} of the last forced one.
     */
    public static final class AuthorityKeys {
        private static final ObjectMapper MAPPER = new ObjectMapper();
        private final String jwksUrl;
        private final Duration ttl;
        private final Duration minRefresh;
        private final HttpClient http;
        private List<Map<String, Object>> keys = List.of();
        private Instant expires = Instant.EPOCH;
        private Instant forced = Instant.EPOCH;

        public AuthorityKeys(String jwksUrl) {
            this(jwksUrl, Duration.ofSeconds(300), Duration.ofSeconds(5));
        }

        public AuthorityKeys(String jwksUrl, Duration ttl, Duration minRefresh) {
            this(jwksUrl, ttl, minRefresh, HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5)).build());
        }

        public AuthorityKeys(String jwksUrl, HttpClient http) {
            this(jwksUrl, Duration.ofSeconds(300), Duration.ofSeconds(5), http);
        }

        private AuthorityKeys(String jwksUrl, Duration ttl, Duration minRefresh, HttpClient http) {
            this.http = http;
            this.jwksUrl = jwksUrl;
            this.ttl = ttl;
            this.minRefresh = minRefresh;
        }

        synchronized boolean mayRefresh() {
            return !Instant.now().isBefore(forced.plus(minRefresh));
        }

        synchronized List<Map<String, Object>> get(boolean refresh) throws IOException {
            boolean force = refresh && mayRefresh();
            if (force) {
                forced = Instant.now();
            }
            if (force || !Instant.now().isBefore(expires)) {
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(jwksUrl))
                        .timeout(Duration.ofSeconds(5)).GET().build();
                HttpResponse<String> r;
                try {
                    r = http.send(request, HttpResponse.BodyHandlers.ofString());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted fetching " + jwksUrl, e);
                }
                if (r.statusCode() >= 400) {
                    throw new IOException("HTTP " + r.statusCode() + " from " + jwksUrl);
                }
                keys = parseKeys(r.body());
                expires = Instant.now().plus(ttl);
            }
            return keys;
        }

        private static List<Map<String, Object>> parseKeys(String body) throws IOException {
            try {
                Map<String, List<Map<String, Object>>> doc =
                        MAPPER.readValue(body, new TypeReference<>() {});
                List<Map<String, Object>> parsed = doc == null ? null : doc.get("keys");
                if (parsed == null) {
                    throw new IOException("JWKS has no keys");
                }
                return parsed;
            } catch (JacksonException e) {
                throw new IOException("unreadable JWKS", e);
            }
        }
    }

    /**
     * Is this query really from the owner's authorization server? Returns null when the
     * RFC 9421 signature verifies under one of its keys, else the reason.
     */
    public static String verifyOwnerAsQuery(String method, String authority, String path,
                                            String signatureInput, String signature,
                                            AuthorityKeys keys) {
        if (signatureInput == null || signatureInput.isEmpty() || signature == null
                || signature.isEmpty()) {
            return "no signature";
        }
        String last = "no signature";
        for (boolean refresh : new boolean[] {false, true}) {
            if (refresh && !keys.mayRefresh()) {
                break;
            }
            List<Map<String, Object>> jwks;
            try {
                jwks = keys.get(refresh);
            } catch (IOException e) {
                return "the authorization server's keys could not be read ("
                        + e.getClass().getSimpleName() + ")";
            }
            for (Map<String, Object> jwk : jwks) {
                try {
                    HttpSignature.verify(new HttpSignature.VerifyRequest(method, authority, path,
                            "", signatureInput, signature, Jwks.toPublicKey(jwk), 60, null,
                            null, false, null));
                    return null;
                } catch (HttpSignature.VerifyException | IllegalArgumentException e) {
                    last = e.getMessage();
                }
            }
        }
        return last;
    }
}
