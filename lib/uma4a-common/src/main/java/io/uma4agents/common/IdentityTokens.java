package io.uma4agents.common;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Verification against a publisher's asymmetric keys, without trusting a token to pick a key type. */
public final class IdentityTokens {
    public static final String EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String ID_JAG = "urn:ietf:params:oauth:token-type:id-jag";
    public static final String ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    public static final String JAG_TYPE = "oauth-id-jag+jwt";

    private static final Map<String, Set<String>> ALGORITHMS = Map.of(
            "OKP", Set.of("EdDSA"),
            "RSA", Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"),
            "EC", Set.of("ES256", "ES384", "ES512"));

    private IdentityTokens() {}

    public static Map<String, Object> verify(String token, String issuer, List<Map<String, Object>> keys) {
        var claims = verifySignature(token, keys);
        if (!issuer.equals(claims.get("iss"))) {
            throw new IllegalArgumentException("Invalid issuer");
        }
        return claims;
    }

    public static Map<String, Object> verifySignature(String token, List<Map<String, Object>> keys) {
        CompactJws.Parsed parsed = CompactJws.parse(token);
        Object kid = parsed.header().get("kid");
        Object algorithm = parsed.header().get("alg");
        for (Map<String, Object> key : keys) {
            Object declared = key.get("alg");
            if (kid != null && !kid.equals(key.get("kid")) || "enc".equals(key.get("use"))
                    || declared != null && !declared.equals(algorithm)
                    || algorithm == null || !ALGORITHMS.getOrDefault(String.valueOf(key.get("kty")), Set.of())
                            .contains(algorithm)) {
                continue;
            }
            try {
                boolean valid = switch (String.valueOf(key.get("kty"))) {
                    case "OKP" -> {
                        CompactJws.verifyWith(token, Jwks.toPublicKey(key), "EdDSA");
                        yield true;
                    }
                    case "RSA" -> JWSObject.parse(token).verify(new RSASSAVerifier(RSAKey.parse(key)));
                    case "EC" -> JWSObject.parse(token).verify(new ECDSAVerifier(ECKey.parse(key)));
                    default -> false;
                };
                if (valid) {
                    return parsed.claims();
                }
            } catch (Exception invalid) {
                // Keys occasionally overlap during a rotation.
            }
        }
        throw new IllegalArgumentException("it does not verify against the realm");
    }
}
