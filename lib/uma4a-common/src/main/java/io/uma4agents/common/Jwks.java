package io.uma4agents.common;

import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** OKP (Ed25519) JWK conversions and the lab's {@code jkt:} RFC 7638 thumbprint. */
public final class Jwks {

    private Jwks() {}

    /** Bare public OKP JWK, matching PyJWT's {@code OKPAlgorithm.to_jwk} members. */
    public static Map<String, Object> okpPublicJwk(PublicKey publicKey) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("x", b64url(EdDsa.rawPublic(publicKey)));
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        return jwk;
    }

    public static PublicKey toPublicKey(Map<String, Object> jwk) {
        if (!"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv"))) {
            throw new IllegalArgumentException("expected an Ed25519 OKP JWK, got: " + jwk);
        }
        Object x = jwk.get("x");
        if (!(x instanceof String xs)) {
            throw new IllegalArgumentException("OKP JWK missing 'x'");
        }
        return EdDsa.publicFromRaw(Base64.getUrlDecoder().decode(xs));
    }

    /**
     * RFC 7638 thumbprint over the required OKP members, prefixed {@code jkt:} —
     * the connection handle for pseudonymous agents. Canonical form is compact
     * separators with sorted keys, exactly as the Python reference computes it.
     */
    public static String thumbprint(Map<String, Object> jwk) {
        Map<String, Object> canonical = new LinkedHashMap<>();
        canonical.put("crv", jwk.get("crv"));
        canonical.put("kty", jwk.get("kty"));
        canonical.put("x", jwk.get("x"));
        byte[] digest = S256.sha256(
                PyJson.compactSorted(canonical).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return "jkt:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] b64urlDecode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }
}
