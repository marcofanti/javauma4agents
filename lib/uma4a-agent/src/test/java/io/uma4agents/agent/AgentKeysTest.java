package io.uma4agents.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jose;
import io.uma4agents.common.Jwks;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The requesting side signs with the algorithm its bound key names, and computes the
 * same handle the authorization server files it under.
 */
class AgentKeysTest {

    @TempDir
    Path dir;

    private static String token(Map<String, Object> cnfJwk, String iss, String sub) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", iss);
        claims.put("sub", sub);
        claims.put("cnf", Map.of("jwk", cnfJwk));
        return CompactJws.sign(Map.of("typ", "aa-agent+jwt"), claims,
                EdDsa.generate().getPrivate());
    }

    @Test
    void aBareKeySignsEdDsaAndIsItsThumbprint() {
        AgentKeys keys = AgentKeys.loadOrCreate(dir.resolve("k.pem"));
        assertEquals(Jose.EDDSA, keys.jwsAlg());
        assertFalse(keys.publicJwk().containsKey("alg"));
        assertEquals(keys.thumbprint(), keys.connectionHandle());
    }

    @Test
    void aTokenWhoseKeyNamesEd25519SignsEd25519() {
        AgentKeys keys = AgentKeys.loadOrCreateIdentified(dir.resolve("stable.pem"));
        Map<String, Object> cnf = new LinkedHashMap<>(keys.publicJwk());
        cnf.put("alg", Jose.ED25519);
        keys.agentToken = token(cnf, "https://ps.uma.lab", "aauth:bob@ps.uma.lab");
        assertEquals(Jose.ED25519, keys.jwsAlg());
        assertEquals(Jose.ED25519, keys.publicJwk().get("alg"));
        String jws = CompactJws.signWith(Map.of(), Map.of("a", 1), keys.key.getPrivate(),
                keys.jwsAlg());
        CompactJws.verifyWith(jws, Jwks.toPublicKey(keys.publicJwk()),
                Jose.algOf(keys.publicJwk()));
        assertEquals("aauth:bob@ps.uma.lab", keys.connectionHandle());
    }

    @Test
    void anEarlierTokenSignsEdDsaAndIsQualifiedByItsWholeIssuer() {
        AgentKeys keys = AgentKeys.loadOrCreateIdentified(dir.resolve("stable.pem"));
        keys.agentToken = token(Jwks.okpPublicJwk(keys.key.getPublic()),
                "https://ap.example:8443/tenants/a/", "agent");
        assertEquals(Jose.EDDSA, keys.jwsAlg());
        assertEquals("agent@ap.example:8443/tenants/a", keys.connectionHandle());
    }
}
