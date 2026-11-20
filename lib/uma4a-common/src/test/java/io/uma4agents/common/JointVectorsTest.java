package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

class JointVectorsTest {
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void mandateNormalizationDigestAndCountsMatchThePinnedOracle() throws Exception {
        try (var input = getClass().getResourceAsStream("/pinned/joint-vectors.json")) {
            Map<String, Object> root = json.readValue(input, new TypeReference<>() {});
            for (Map<String, Object> item : maps(root.get("mandates"))) {
                var mandate = JointMandate.parse(item.get("input"), 0);
                assertEquals(item.get("digest"), mandate.digest());
                assertEquals(PyJson.compactSorted(item.get("normal")), PyJson.compactSorted(mandate.wire()));
                assertEquals(item.get("summary"), mandate.describe());
                for (Map<String, Object> vote : maps(item.get("counts"))) {
                    @SuppressWarnings("unchecked")
                    var votes = (Map<String, String>) vote.get("votes");
                    assertEquals(PyJson.compactSorted(vote.get("result")),
                            PyJson.compactSorted(mandate.count(votes).wire()));
                }
            }
            for (Map<String, Object> malformed : maps(root.get("invalid"))) {
                var refused = assertThrows(IllegalArgumentException.class,
                        () -> JointMandate.parse(malformed.get("input"),
                                ((Number) malformed.get("floor")).longValue()));
                assertEquals(malformed.get("error"), refused.getMessage());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> fold = (Map<String, Object>) root.get("fold");
            @SuppressWarnings("unchecked")
            List<String> resources = (List<String>) fold.get("resources");
            assertEquals(PyJson.compactSorted(fold.get("result")), PyJson.compactSorted(
                    JointMandate.fold(maps(fold.get("quotes")), resources)));
        }
    }

    @Test
    void grantMustCarryEnoughVerifiedHoldersBoundToTheSameResourceKeyAndMandate() {
        String aliceIssuer = "https://alice-as.uma.lab";
        String carolIssuer = "https://carol-as.uma.lab";
        String resource = "account/read";
        var mandate = JointMandate.parse(Map.of("resources", List.of(resource), "holders", List.of(
                Map.of("owner", "alice", "issuer", aliceIssuer),
                Map.of("owner", "carol", "issuer", carolIssuer))), 0);
        var alice = EdDsa.generate();
        var carol = EdDsa.generate();
        var agent = EdDsa.generate();
        var agentJwk = Jwks.okpPublicJwk(agent.getPublic());
        var trusted = Map.of("alice", aliceIssuer, "carol", carolIssuer);
        var peerKeys = Map.of(aliceIssuer, List.of(Jwks.okpPublicJwk(alice.getPublic())),
                carolIssuer, List.of(Jwks.okpPublicJwk(carol.getPublic())));
        JointVerdicts.Keys keys = (issuer, fresh) -> peerKeys.get(issuer);
        double now = 1_800_000_000;
        var template = new LinkedHashMap<String, Object>();
        template.putAll(Map.of("exp", (long) now + 90, "iat", (long) now, "account", "account",
                "negotiation", "family", "effect", "allow", "resource_id", resource,
                "contract", "digest", "mandate_s256", mandate.digest()));
        template.putAll(Map.of("scope", List.of("read"), "cnf_jkt", Jwks.thumbprint(agentJwk),
                "expires_in", 90));
        String a = verdict(template, "alice", aliceIssuer, alice.getPrivate());
        String b = verdict(template, "carol", carolIssuer, carol.getPrivate());
        var claims = new LinkedHashMap<>(Map.of("owner", "account", "family", "family",
                "contract", "digest", "exp", (long) now + 90, "cnf", Map.of("jwk", agentJwk),
                "permissions", List.of(Map.of("resource_id", resource, "exp", (long) now + 90,
                        "resource_scopes", List.of("read"))), "joint",
                Map.of("account", "account", "verdicts", List.of(a, b))));
        assertNull(JointVerdicts.checkGrant(claims, "account", resource, mandate, trusted, keys, now));
        claims.put("joint", Map.of("account", "account", "verdicts", List.of(a, a)));
        assertTrue(JointVerdicts.checkGrant(claims, "account", resource, mandate, trusted,
                keys, now).contains("1 of the 2"));
        claims.put("joint", Map.of("account", "account", "verdicts", List.of(a, b)));
        claims.put("contract", "a later agreement");
        assertTrue(JointVerdicts.checkGrant(claims, "account", resource, mandate, trusted,
                keys, now).contains("different agreement"));
    }

    private static String verdict(Map<String, Object> template, String holder, String issuer,
                                  java.security.PrivateKey privateKey) {
        var fields = new LinkedHashMap<>(template);
        fields.put("holder", holder);
        fields.put("iss", issuer);
        return CompactJws.sign(Map.of("typ", "u4a-verdict+jwt"), fields, privateKey);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> maps(Object value) {
        return (List<Map<String, Object>>) value;
    }
}
