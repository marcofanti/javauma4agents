package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EnterpriseFederationTest {
    @Test
    void privateAndJointResourcesDoNotAcquireAnEnterpriseIdentityBeat() {
        var provider = Map.<String, Object>of("issuer", "https://id.example");
        var charter = Map.<String, Object>of("claims", List.of("firm/*", "joint/*"),
                "excluded", List.of("joint/*"), "identity_provider", provider);
        assertEquals(provider, EnterpriseFederation.provider(charter, "firm/read"));
        assertEquals(Map.of(), EnterpriseFederation.provider(charter, "joint/read"));
        assertEquals(Map.of(), EnterpriseFederation.provider(charter, "personal/read"));
    }

    @Test
    void identityAssertionCoversTheRegisteredResourceAndMapsTheNamedMember() {
        var config = new AsConfig();
        var federation = new EnterpriseFederation(config);
        var provider = Map.<String, Object>of("issuer", "https://id.example",
                "subject_claim", "sub", "subject_map", Map.of("worker-15", config.ownerUsername));
        var claims = new LinkedHashMap<>(Map.of(
                "iss", provider.get("issuer"), "aud", List.of(config.issuer),
                "exp", AsState.now() + 120, "jti", "fixture-id", "sub", "worker-15",
                "resource", config.rsResourceUri, "scope", "read"));
        assertDoesNotThrow(() -> federation.validateClaims(claims, provider, "firm/read"));
        claims.put("resource", "https://other.example/mcp");
        assertEquals("the assertion was issued for a different resource",
                assertThrows(IllegalArgumentException.class,
                        () -> federation.validateClaims(claims, provider, "firm/read")).getMessage());
    }
}
