package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CompactJwsTest {

    @Test
    void signParseVerifyRoundTripWithCustomHeaders() {
        KeyPair pair = EdDsa.generate();
        Map<String, Object> header = Map.of(
                "typ", "myterms-agreement-v1+jws",
                "kid", "agent-req-1",
                "jwk", Jwks.okpPublicJwk(pair.getPublic()));
        Map<String, Object> claims = Map.of(
                "iss", "aauth:agent:agent-req-1",
                "nonce", "abc123",
                "expires_in", 172800);

        String compact = CompactJws.sign(header, claims, pair.getPrivate());
        CompactJws.Parsed parsed = CompactJws.verify(compact, pair.getPublic());

        assertEquals("EdDSA", parsed.header().get("alg"));
        assertEquals("myterms-agreement-v1+jws", parsed.header().get("typ"));
        assertEquals("aauth:agent:agent-req-1", parsed.claims().get("iss"));
        assertEquals(172800, parsed.claims().get("expires_in"));

        @SuppressWarnings("unchecked")
        Map<String, Object> headerJwk = (Map<String, Object>) parsed.header().get("jwk");
        assertEquals(Jwks.thumbprint(Jwks.okpPublicJwk(pair.getPublic())),
                Jwks.thumbprint(headerJwk));
    }

    @Test
    void verifyRejectsWrongKeyAndGarbage() {
        KeyPair pair = EdDsa.generate();
        KeyPair other = EdDsa.generate();
        String compact = CompactJws.sign(Map.of("typ", "t"), Map.of("a", 1), pair.getPrivate());

        assertThrows(SecurityException.class, () -> CompactJws.verify(compact, other.getPublic()));
        assertThrows(IllegalArgumentException.class, () -> CompactJws.parse("not-a-jws"));
    }
}
