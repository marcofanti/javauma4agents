package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

class OrganizationVectorsTest {
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void charterPatternsMatchTheSameCasesAsPinnedPythonAndRego() throws Exception {
        Path vectors = Path.of("../../conformance/upstream/lib/pattern_vectors.json");
        var all = json.readTree(Files.readString(vectors));
        for (var vector : all.get("vectors")) {
            String pattern = vector.get("pattern").asString();
            String resource = vector.get("resource").asString();
            assertEquals(vector.get("match").asBoolean(),
                    OrganizationPatterns.matches(resource, List.of(pattern)), pattern + " at " + resource);
        }
    }

    @Test
    void clearanceDigestMatchesCpythonUtf8NumbersAndSupplementaryScalarOrdering() throws Exception {
        try (var input = getClass().getResourceAsStream("/pinned/clearance-digest-vectors.json")) {
            assertNotNull(input);
            List<Map<String, Object>> rows = json.readValue(input, new TypeReference<>() {});
            for (Map<String, Object> row : rows) {
                @SuppressWarnings("unchecked")
                Map<String, Object> facts = (Map<String, Object>) row.get("facts");
                assertEquals(row.get("canonical"), PyJson.compactSortedUnicode(facts));
                assertEquals(row.get("digest"), Clearance.digest(facts));
            }
        }
    }

    @Test
    void tighteningIntersectsValuesAndAnEmptyIntersectionRefusesAll() {
        Map<String, Object> requirements = Clearance.tighten(Map.of("license", List.of(true),
                        "state", List.of("NY", "VA")),
                Map.of("license", List.of(1.0), "state", List.of("CA")));
        assertEquals(Map.of("license", List.of(true), "state", List.of()), requirements);
        assertFalse(Clearance.unmet(requirements, Map.of("license", true, "state", "NY")).isEmpty());
    }

    @Test
    void anAttestationHasItsOwnTypeIssuerAudienceSubjectAndTimeWindow() {
        String issuer = "https://org.example";
        String audience = "https://as.example";
        var key = EdDsa.generate();
        var jwk = Jwks.okpPublicJwk(key.getPublic());
        jwk.put("kid", "previous");
        List<Map<String, Object>> keys = List.of(jwk);
        var claims = new LinkedHashMap<>(Map.of("iss", issuer, "aud", audience, "sub", "alice",
                "iat", 1_800_000_000, "exp", 1_800_000_120, "jti", "one",
                "clearance", Map.of("license", true)));
        String valid = CompactJws.sign(Map.of("typ", Clearance.TYPE, "kid", "previous"),
                claims, key.getPrivate());
        assertEquals(Map.of("license", true), Clearance.verify(valid, keys, issuer, audience,
                "alice", 1_800_000_179));
        assertThrows(IllegalArgumentException.class, () -> Clearance.verify(valid, keys, issuer,
                audience, "alice", 1_800_000_180));
        assertThrows(IllegalArgumentException.class, () -> Clearance.verify(valid, keys, issuer,
                audience, "carol", 1_800_000_001));
        assertThrows(IllegalArgumentException.class, () -> Clearance.verify(valid, keys, issuer,
                "https://other.example", "alice", 1_800_000_001));
        assertThrows(IllegalArgumentException.class, () -> Clearance.verify(valid, keys,
                "https://other.example", audience, "alice", 1_800_000_001));
        String wrongType = CompactJws.sign(Map.of("typ", "u4a-membership+jwt", "kid", "previous"),
                claims, key.getPrivate());
        assertThrows(IllegalArgumentException.class, () -> Clearance.verify(wrongType, keys,
                issuer, audience, "alice", 1_800_000_001));
    }
}
