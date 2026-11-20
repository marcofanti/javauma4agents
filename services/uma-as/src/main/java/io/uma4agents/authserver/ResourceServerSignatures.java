package io.uma4agents.authserver;

import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/** An unprovisioned resource server proves control of its own TLS origin. */
@Component
final class ResourceServerSignatures {
    private final AsConfig config;
    private final PeerFetch fetch;
    private final LinkedHashMap<String, Metadata> cache = new LinkedHashMap<>();

    private record Metadata(String keysUrl, String refusal, long expires) {}

    ResourceServerSignatures(AsConfig config, PeerFetch fetch) {
        this.config = config;
        this.fetch = fetch;
    }

    String verify(HttpServletRequest request, byte[] body, String resource) {
        String input = request.getHeader("signature-input");
        String signature = request.getHeader("signature");
        if (input == null || input.isEmpty() || signature == null || signature.isEmpty()) {
            return "the request is not signed";
        }
        Metadata metadata = metadata(resource);
        if (metadata.refusal() != null) {
            return metadata.refusal();
        }
        Map<String, Object> doc = fetchDocument(metadata.keysUrl());
        if (doc == null || !(doc.get("keys") instanceof List<?> keys)) {
            return "its jwks_uri could not be read";
        }
        String path = request.getRequestURI();
        if (request.getQueryString() != null) {
            path += "?" + request.getQueryString();
        }
        String refusal = "that origin publishes no key this could be checked against";
        for (Object jwk : keys) {
            PublicKey key = publicKey(jwk);
            if (key == null) {
                continue;
            }
            try {
                HttpSignature.verify(new HttpSignature.VerifyRequest(request.getMethod(),
                        AsConfig.issuerAuthority(config.issuer), path,
                        request.getHeader("authorization"), input, signature, key, 60, null,
                        body.length == 0 ? null : body, body.length > 0,
                        request.getHeader("content-digest")));
                return null;
            } catch (HttpSignature.VerifyException invalid) {
                refusal = "signature verification failed".equals(invalid.getMessage())
                        ? "no key that origin publishes verifies the signature"
                        : invalid.getMessage();
            }
        }
        return refusal;
    }

    @SuppressWarnings("unchecked")
    private static PublicKey publicKey(Object jwk) {
        try {
            return jwk instanceof Map<?, ?> map ? Jwks.toPublicKey((Map<String, Object>) map)
                    : null;
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }

    static String origin(String resource) {
        try {
            URI url = URI.create(resource);
            if ("https".equals(url.getScheme()) && url.getHost() != null
                    && url.getUserInfo() == null && url.getFragment() == null) {
                return "https://" + url.getRawAuthority();
            }
        } catch (IllegalArgumentException invalid) {
            return null;
        }
        return null;
    }

    private Metadata metadata(String resource) {
        long now = System.currentTimeMillis();
        synchronized (cache) {
            Metadata cached = cache.get(resource);
            if (cached != null && now < cached.expires()) {
                return cached;
            }
        }
        Metadata fresh = fetchMetadata(resource, now);
        synchronized (cache) {
            if (cache.size() >= 1024) {
                cache.pollFirstEntry();
            }
            cache.put(resource, fresh);
        }
        return fresh;
    }

    private Metadata fetchMetadata(String resource, long now) {
        String origin = origin(resource);
        if (origin == null) {
            return refused("the resource is not an https URL", now);
        }
        Map<String, Object> doc = fetchDocument(RegistrationPuller.wellKnownPrmUrl(resource));
        if (doc == null) {
            return refused("that origin publishes no resource metadata for it", now);
        }
        if (!resource.equals(doc.get("resource"))) {
            return refused("its metadata claims resource " + doc.get("resource"), now);
        }
        if (!(doc.get("jwks_uri") instanceof String keysUrl) || !origin.equals(origin(keysUrl))) {
            return refused("its metadata jwks_uri is not same-origin", now);
        }
        if (!(doc.get("authorization_servers") instanceof List<?> authorities)
                || !authorities.contains(config.issuer)) {
            return refused("its metadata does not name this authorization server", now);
        }
        return new Metadata(keysUrl, null, now + (long) (1_000 * config.rsMetadataTtl));
    }

    private Metadata refused(String error, long now) {
        return new Metadata(null, error, now + (long) (1_000 * config.rsMissTtl));
    }

    private Map<String, Object> fetchDocument(String url) {
        try {
            return fetch.getJson(url, config.rsMaxBytes);
        } catch (IllegalArgumentException | IllegalStateException unavailable) {
            return null;
        }
    }
}
