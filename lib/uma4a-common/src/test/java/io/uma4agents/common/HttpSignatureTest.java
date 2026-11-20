package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.common.HttpSignature.SignOptions;
import io.uma4agents.common.HttpSignature.VerifyException;
import io.uma4agents.common.HttpSignature.VerifyRequest;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

class HttpSignatureTest {

    private static final byte[] BODY = "{\"jsonrpc\":\"2.0\"}".getBytes(StandardCharsets.UTF_8);

    private static JsonNode resource(String name) throws Exception {
        try (InputStream in = HttpSignatureTest.class.getResourceAsStream(name)) {
            return new ObjectMapper().readTree(in);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.textValue();
    }

    private static VerifyRequest request(JsonNode c, PublicKey key, byte[] body) {
        return new VerifyRequest(text(c, "method"), text(c, "authority"), text(c, "path"),
                text(c, "authorization"), text(c, "signature_input"), text(c, "signature"),
                key, 60, text(c, "signature_agent"), body, false, text(c, "content_digest"));
    }

    @Test
    void verifiesEveryPinnedCPythonSignatureShape() throws Exception {
        JsonNode fx = resource("/pinned/httpsig-vectors.json");
        PublicKey pub = EdDsa.publicFromRaw(
                Base64.getUrlDecoder().decode(fx.get("raw_public_b64url").textValue()));
        long now = fx.get("now").longValue();
        int count = 0;
        for (JsonNode c : fx.get("cases")) {
            String bodyB64 = text(c, "body_b64");
            byte[] body = bodyB64 == null ? null : Base64.getDecoder().decode(bodyB64);
            assertEquals(fx.get("keyid").textValue(),
                    HttpSignature.verify(request(c, pub, body), now), text(c, "name"));
            count++;
        }
        assertEquals(5, count);
    }

    @Test
    void refusesPinnedDigestSignatureOverChangedBodyOrMissingBody() throws Exception {
        JsonNode fx = resource("/pinned/httpsig-vectors.json");
        PublicKey pub = EdDsa.publicFromRaw(
                Base64.getUrlDecoder().decode(fx.get("raw_public_b64url").textValue()));
        long now = fx.get("now").longValue();
        JsonNode digestCase = null;
        for (JsonNode c : fx.get("cases")) {
            if ("content_digest".equals(text(c, "name"))) {
                digestCase = c;
            }
        }
        JsonNode c = digestCase;
        assertThrows(VerifyException.class,
                () -> HttpSignature.verify(request(c, pub, BODY), now));
        assertThrows(VerifyException.class,
                () -> HttpSignature.verify(request(c, pub, null), now));
    }

    @Test
    void refusesPinnedSignaturesOutsideTheirTimes() throws Exception {
        JsonNode fx = resource("/pinned/httpsig-vectors.json");
        PublicKey pub = EdDsa.publicFromRaw(
                Base64.getUrlDecoder().decode(fx.get("raw_public_b64url").textValue()));
        long now = fx.get("now").longValue();
        for (JsonNode c : fx.get("cases")) {
            if ("expires".equals(text(c, "name"))) {
                assertThrows(VerifyException.class,
                        () -> HttpSignature.verify(request(c, pub, null), now + 31));
            }
            if ("required_only".equals(text(c, "name"))) {
                assertThrows(VerifyException.class,
                        () -> HttpSignature.verify(request(c, pub, null), now + 61));
            }
        }
    }

    @Test
    void verifiesLegacyPythonFixtureWithoutNonce() throws Exception {
        JsonNode fx = resource("/httpsig-fixture.json");
        PublicKey pub = EdDsa.publicFromRaw(
                Base64.getUrlDecoder().decode(fx.get("raw_public_b64url").textValue()));
        long created = Long.parseLong(
                text(fx, "signature_input").split("created=")[1].split(";")[0]);
        VerifyRequest r = new VerifyRequest(text(fx, "method"), text(fx, "authority"),
                text(fx, "path"), text(fx, "authorization"), text(fx, "signature_input"),
                text(fx, "signature"), pub, 60, null, null, false, null);
        assertEquals(text(fx, "keyid"), HttpSignature.verify(r, created));
    }

    @Test
    void roundTripsEveryOption() {
        KeyPair pair = EdDsa.generate();
        String agent = "https://agent.uma.lab/.well-known/http-message-signatures-directory";
        Map<String, String> h = HttpSignature.sign("post", "gateway.uma.lab", "/mcp", "PoP t",
                pair.getPrivate(), "k1", new SignOptions(agent, 30, null, "web-bot-auth", BODY));
        assertTrue(h.get("Signature-Input").contains("\"signature-agent\" \"content-digest\")"));
        assertTrue(h.get("Signature-Input").contains(";nonce=\""));
        assertEquals(agent, h.get("Signature-Agent"));
        assertEquals(HttpSignature.contentDigest(BODY), h.get("Content-Digest"));
        VerifyRequest r = new VerifyRequest("POST", "gateway.uma.lab", "/mcp", "PoP t",
                h.get("Signature-Input"), h.get("Signature"), pair.getPublic(), 60, agent, BODY,
                true, h.get("Content-Digest"));
        assertEquals("k1", HttpSignature.verify(r));
    }

    @Test
    void refusesTamperingWrongKeyAndUncoveredHeaders() {
        KeyPair pair = EdDsa.generate();
        Map<String, String> h = HttpSignature.sign("POST", "gateway.uma.lab", "/mcp", "PoP t",
                pair.getPrivate(), "k1", SignOptions.none());
        String in = h.get("Signature-Input");
        String sig = h.get("Signature");
        assertThrows(VerifyException.class, () -> HttpSignature.verify(new VerifyRequest(
                "POST", "gateway.uma.lab", "/mcp", "PoP other", in, sig, pair.getPublic(), 60,
                null, null, false, null)));
        assertThrows(VerifyException.class, () -> HttpSignature.verify(new VerifyRequest(
                "POST", "gateway.uma.lab", "/mcp", "PoP t", in, sig,
                EdDsa.generate().getPublic(), 60, null, null, false, null)));
        assertThrows(VerifyException.class, () -> HttpSignature.verify(new VerifyRequest(
                "POST", "gateway.uma.lab", "/mcp", "PoP t", in, sig, pair.getPublic(), 60,
                "https://evil.example/dir", null, false, null)));
        assertThrows(VerifyException.class, () -> HttpSignature.verify(new VerifyRequest(
                "POST", "gateway.uma.lab", "/mcp", "PoP t", in, sig, pair.getPublic(), 60,
                null, BODY, true, null)));
    }

    @Test
    void refusesMissingComponentsAndForeignAlgorithm() {
        KeyPair pair = EdDsa.generate();
        String partial = "sig1=(\"@method\" \"@authority\" \"@path\");created="
                + (System.currentTimeMillis() / 1000) + ";keyid=\"k\";alg=\"ed25519\"";
        assertThrows(VerifyException.class, () -> HttpSignature.verify(new VerifyRequest(
                "POST", "a", "/p", "x", partial, "sig1=:AAAA:", pair.getPublic(), 60, null,
                null, false, null)));
        String rsa = partial.replace("\"@path\")", "\"@path\" \"authorization\")")
                .replace("ed25519", "rsa-pss-sha512");
        VerifyException e = assertThrows(VerifyException.class, () -> HttpSignature.verify(
                new VerifyRequest("POST", "a", "/p", "x", rsa, "sig1=:AAAA:", pair.getPublic(),
                        60, null, null, false, null)));
        assertTrue(e.getMessage().contains("not ed25519"));
    }
}
