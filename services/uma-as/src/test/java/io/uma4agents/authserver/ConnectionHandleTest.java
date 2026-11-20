package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Two identity levels and nothing else: a key-level agent is filed under its key's
 * thumbprint whatever it says about its operator, an identified one under its
 * issuer-qualified subject.
 */
class ConnectionHandleTest {

    private final GrantService grants = new GrantService(null, null, null, null, null, null, null);
    private final Map<String, Object> key = Jwks.okpPublicJwk(EdDsa.generate().getPublic());

    @Test
    void aKeyLevelAgentIsItsThumbprintHoweverItIsDescribed() {
        String bare = grants.connectionHandle(Map.of("level", "pseudonymous"), key);
        Map<String, Object> described = new LinkedHashMap<>();
        described.put("level", "pseudonymous");
        described.put("client_metadata", Map.of("client_id", "https://agent.uma.lab/agent.json",
                "verified", true));
        described.put("operator_attested", true);
        described.put("operator_directory",
                "https://agent.uma.lab/.well-known/http-message-signatures-directory");
        Map<String, Object> withAlg = new LinkedHashMap<>(key);
        withAlg.put("alg", "Ed25519");
        assertTrue(bare.startsWith("jkt:"));
        assertEquals(bare, grants.connectionHandle(described, key));
        assertEquals(bare, grants.connectionHandle(described, withAlg));
    }

    @Test
    void anIdentifiedAgentIsItsIssuerQualifiedSubject() {
        assertEquals("aauth:bob@ps.uma.lab", grants.connectionHandle(Map.of("level",
                "identified", "iss", "https://ps.uma.lab", "sub", "aauth:bob@ps.uma.lab"), key));
        assertEquals("delegate-7@ps.uma.lab", grants.connectionHandle(Map.of("level",
                "identified", "iss", "https://ps.uma.lab/", "sub", "delegate-7"), key));
    }

    @Test
    void twoTenantsOfOneHostAreNotOneConnection() {
        String a = grants.connectionHandle(Map.of("level", "identified",
                "iss", "https://ap.example/tenants/a", "sub", "agent"), key);
        String b = grants.connectionHandle(Map.of("level", "identified",
                "iss", "https://ap.example/tenants/b", "sub", "agent"), key);
        assertEquals("agent@ap.example/tenants/a", a);
        assertFalse(a.equals(b));
        assertEquals("agent@ap.example:8443", grants.connectionHandle(Map.of("level",
                "identified", "iss", "https://ap.example:8443", "sub", "agent"), key));
    }
}
