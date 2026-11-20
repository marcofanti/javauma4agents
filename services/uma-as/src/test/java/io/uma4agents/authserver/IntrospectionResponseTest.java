package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The active introspection response has the pinned members, and only those. */
class IntrospectionResponseTest {

    @Test
    void activeResponseMatchesThePinnedMembers() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "https://alice-as.uma.lab");
        claims.put("sub", "jkt:abc");
        claims.put("client_id", "jkt:abc");
        claims.put("owner", "alice");
        claims.put("exp", 1_900_000_000L);
        claims.put("permissions", List.of());
        claims.put("cnf", Map.of("jwk", Map.of()));
        claims.put("contract", "s256:x");
        Map<String, Object> out = ProtectionController.activeResponse(claims,
                Map.of("family", "fam_1"));
        assertEquals(List.of("active", "family", "iss", "sub", "exp", "permissions", "cnf",
                "contract", "single_use", "operation", "consequence"),
                List.copyOf(out.keySet()));
        assertTrue(out.containsKey("consequence"));
        assertEquals(null, out.get("consequence"));
        assertEquals(false, out.get("single_use"));
    }
}
