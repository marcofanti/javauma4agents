package io.uma4agents.common;

import java.util.Map;

/**
 * {@code Ed25519} as a JOSE algorithm (RFC 9864) beside the older {@code EdDSA}, and the
 * rule that a signature is verified with the algorithm its key names, never the one the
 * token's header asks for. Mirrors the pinned {@code uma4a_jose}.
 */
public final class Jose {

    public static final String ED25519 = "Ed25519";
    public static final String EDDSA = "EdDSA";

    private Jose() {}

    /**
     * The one algorithm a signature by this key may be verified with.
     *
     * @param jwk a public JWK
     * @return {@code Ed25519} or {@code EdDSA}; a bare Ed25519 key that names none is
     *     {@code EdDSA}, U4A's pseudonymous agent
     * @throws IllegalArgumentException when the key is not an Ed25519 key or names
     *     another algorithm, with the pinned module's wording
     */
    public static String algOf(Map<String, Object> jwk) {
        Object alg = jwk.get("alg");
        if (!"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv"))) {
            throw new IllegalArgumentException("the key is not an Ed25519 key");
        }
        if (alg == null) {
            return EDDSA;
        }
        if (!ED25519.equals(alg) && !EDDSA.equals(alg)) {
            throw new IllegalArgumentException("the key names " + PyRepr.of(alg)
                    + ", which this server does not verify");
        }
        return (String) alg;
    }
}
