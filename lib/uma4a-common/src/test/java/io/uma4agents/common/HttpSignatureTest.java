package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HttpSignatureTest {

    @Test
    void verifiesSignatureProducedByPythonLabCode() throws Exception {
        JsonNode fx;
        try (InputStream in = getClass().getResourceAsStream("/httpsig-fixture.json")) {
            fx = new ObjectMapper().readTree(in);
        }
        PublicKey pub = EdDsa.publicFromRaw(
                Base64.getUrlDecoder().decode(fx.get("raw_public_b64url").textValue()));
        // The fixture's created timestamp is from generation time; disable freshness.
        String keyid = HttpSignature.verify(
                fx.get("method").textValue(),
                fx.get("authority").textValue(),
                fx.get("path").textValue(),
                fx.get("authorization").textValue(),
                fx.get("signature_input").textValue(),
                fx.get("signature").textValue(),
                pub, Long.MAX_VALUE / 2);
        assertEquals(fx.get("keyid").textValue(), keyid);
    }

    @Test
    void signVerifyRoundTrip() {
        KeyPair pair = EdDsa.generate();
        Map<String, String> headers = HttpSignature.sign(
                "post", "gateway.uma.lab", "/mcp", "PoP some.rpt", pair.getPrivate(), "agent-req-1");
        String keyid = HttpSignature.verify("POST", "gateway.uma.lab", "/mcp", "PoP some.rpt",
                headers.get("Signature-Input"), headers.get("Signature"), pair.getPublic());
        assertEquals("agent-req-1", keyid);
    }

    @Test
    void rejectsTamperedAuthorizationAndWrongKey() {
        KeyPair pair = EdDsa.generate();
        Map<String, String> headers = HttpSignature.sign(
                "POST", "gateway.uma.lab", "/mcp", "PoP some.rpt", pair.getPrivate(), "agent-req-1");

        assertThrows(HttpSignature.VerifyException.class, () -> HttpSignature.verify(
                "POST", "gateway.uma.lab", "/mcp", "PoP other.rpt",
                headers.get("Signature-Input"), headers.get("Signature"), pair.getPublic()));

        KeyPair other = EdDsa.generate();
        assertThrows(HttpSignature.VerifyException.class, () -> HttpSignature.verify(
                "POST", "gateway.uma.lab", "/mcp", "PoP some.rpt",
                headers.get("Signature-Input"), headers.get("Signature"), other.getPublic()));
    }

    @Test
    void rejectsStaleSignature() {
        KeyPair pair = EdDsa.generate();
        String staleParams = "(\"@method\" \"@authority\" \"@path\" \"authorization\")"
                + ";created=1000000000;keyid=\"agent-req-1\";alg=\"ed25519\"";
        assertThrows(HttpSignature.VerifyException.class, () -> HttpSignature.verify(
                "POST", "gateway.uma.lab", "/mcp", "PoP some.rpt",
                "sig1=" + staleParams, "sig1=:AAAA:", pair.getPublic()));
    }
}
