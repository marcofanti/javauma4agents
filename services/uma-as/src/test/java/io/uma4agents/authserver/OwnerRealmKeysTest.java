package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.databind.ObjectMapper;

/**
 * Her identity provider rotates its keys. An owner token naming a key the cache does not
 * hold earns one fresh read of the realm's keys, at most once a minute (the pinned
 * {@code owner_issuer_keys(fresh=True)} and {@code KEY_REFETCH_FLOOR_S}).
 */
class OwnerRealmKeysTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AsConfig config = new AsConfig();
    private final FakeHttp http = new FakeHttp();
    private final TokenVerifiers verifiers = new TokenVerifiers(config, http, new PeerFetch(http));
    private final String jwksUrl = config.ownerIssuer + "/protocol/openid-connect/certs";

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static String b64(BigInteger n) {
        byte[] raw = n.toByteArray();
        return b64(raw[0] == 0 ? java.util.Arrays.copyOfRange(raw, 1, raw.length) : raw);
    }

    private void publish(Map<String, KeyPair> keys) {
        http.json(config.ownerIssuer + "/.well-known/openid-configuration",
                Map.of("jwks_uri", jwksUrl));
        http.json(jwksUrl, Map.of("keys", keys.entrySet().stream().map(e -> {
            RSAPublicKey pub = (RSAPublicKey) e.getValue().getPublic();
            return Map.of("kty", "RSA", "kid", e.getKey(), "use", "sig",
                    "n", b64(pub.getModulus()), "e", b64(pub.getPublicExponent()));
        }).toList()));
    }

    private String token(KeyPair key, String kid) throws Exception {
        String header = b64(MAPPER.writeValueAsBytes(Map.of("alg", "RS256", "kid", kid)));
        String claims = b64(MAPPER.writeValueAsBytes(Map.of("iss", config.ownerIssuer,
                "azp", "meridian-portal", "preferred_username", "alice",
                "exp", AsState.now() + 300)));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key.getPrivate());
        s.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
        return "Bearer " + header + "." + claims + "." + b64(s.sign());
    }

    private long jwksReads() {
        return http.requests.stream().filter(r -> r.uri().toString().equals(jwksUrl)).count();
    }

    @Test
    void aRotatedRealmKeyIsReadOnceAndForcedReadsWaitAMinute() throws Exception {
        KeyPair first = rsa();
        KeyPair second = rsa();
        publish(Map.of("k1", first));
        assertEquals("alice", verifiers.oidcOwner(token(first, "k1")));
        assertEquals(1, jwksReads());

        publish(Map.of("k1", first, "k2", second));
        // Filled moments ago, so inside the floor: a key it has never seen is refused.
        ResponseStatusException early = assertThrows(ResponseStatusException.class,
                () -> verifiers.oidcOwner(token(second, "k2")));
        assertEquals(401, early.getStatusCode().value());
        assertEquals(1, jwksReads(), "a forced read inside the floor reached the provider");

        long later = AsState.now() + TokenVerifiers.KEY_REFETCH_FLOOR_S + 1;
        verifiers.clock = () -> later;
        assertEquals("alice", verifiers.oidcOwner(token(second, "k2")),
                "the rotated key was not learned once the floor had passed");
        assertEquals(2, jwksReads());
    }

    @Test
    void aTokenNamingAKnownKeyNeverForcesARead() throws Exception {
        KeyPair first = rsa();
        publish(Map.of("k1", first));
        for (int i = 0; i < 3; i++) {
            verifiers.oidcOwner(token(first, "k1"));
        }
        assertEquals(1, jwksReads());
    }
}
