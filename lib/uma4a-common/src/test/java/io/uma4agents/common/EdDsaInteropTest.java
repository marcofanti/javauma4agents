package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EdDsaInteropTest {

    private static JsonNode fixture(String name) throws Exception {
        try (InputStream in = EdDsaInteropTest.class.getResourceAsStream(name)) {
            return new ObjectMapper().readTree(in);
        }
    }

    @Test
    void derivesSamePublicKeyAsJdkKeypair() {
        for (int i = 0; i < 5; i++) {
            KeyPair pair = EdDsa.generate();
            assertArrayEquals(EdDsa.rawPublic(pair.getPublic()),
                    EdDsa.rawPublic(EdDsa.publicFrom(pair.getPrivate())),
                    "RFC 8032 derivation diverged from the JDK on iteration " + i);
        }
    }

    @Test
    void readsPythonCryptographyPkcs8Pem() throws Exception {
        JsonNode fx = fixture("/key-fixture.json");
        PrivateKey priv = EdDsa.privateFromPem(fx.get("pkcs8_pem").textValue());
        byte[] expectedPub = Base64.getUrlDecoder().decode(fx.get("raw_public_b64url").textValue());
        assertArrayEquals(expectedPub, EdDsa.rawPublic(EdDsa.publicFrom(priv)));
    }

    @Test
    void pemRoundTripAndLoadOrCreate(@TempDir Path dir) {
        Path keyPath = dir.resolve("keys/agent.pem");
        KeyPair created = EdDsa.loadOrCreate(keyPath);
        assertTrue(Files.exists(keyPath));
        KeyPair reloaded = EdDsa.loadOrCreate(keyPath);
        assertArrayEquals(EdDsa.rawPublic(created.getPublic()),
                EdDsa.rawPublic(reloaded.getPublic()), "reload returned a different key");

        byte[] msg = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
        byte[] sig = EdDsa.sign(reloaded.getPrivate(), msg);
        assertTrue(EdDsa.verify(created.getPublic(), msg, sig));
        assertFalse(EdDsa.verify(created.getPublic(), "tampered".getBytes(StandardCharsets.UTF_8), sig));
    }

    @Test
    void thumbprintMatchesPythonReference() throws Exception {
        JsonNode fx = fixture("/thumbprint-fixture.json");
        java.util.Map<String, Object> jwk = new java.util.LinkedHashMap<>();
        fx.get("jwk").properties().forEach(e -> jwk.put(e.getKey(), e.getValue().textValue()));
        assertEquals(fx.get("thumbprint").textValue(), Jwks.thumbprint(jwk));

        // And the JWK built by Java from the same key must thumbprint identically.
        PrivateKey priv = EdDsa.privateFromPem(
                fixture("/key-fixture.json").get("pkcs8_pem").textValue());
        assertEquals(fx.get("thumbprint").textValue(),
                Jwks.thumbprint(Jwks.okpPublicJwk(EdDsa.publicFrom(priv))));
    }
}
