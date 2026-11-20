package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.common.AgentTokens.Refused;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * AAuth agent tokens in the current and earlier shapes. The vectors are minted by CPython,
 * including by the {@code aauth} package the pinned person server uses, and carry the
 * verdict the pinned {@code uma4a_aauth} reached; the rest ports {@code lib/test_aauth.py}.
 */
class AgentTokensTest {

    private static final String ISS = "https://ap.example";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, Map<String, Object>> docs = new HashMap<>();
    private final List<String> fetches = new ArrayList<>();
    private final double[] clock = {1000.0};
    private final KeyPair issuerKey = EdDsa.generate();
    private final KeyPair agentKey = EdDsa.generate();

    @SuppressWarnings("unchecked")
    private static Map<String, Object> vectors() throws Exception {
        try (InputStream in = AgentTokensTest.class.getResourceAsStream(
                "/pinned/aauth-vectors.json")) {
            return MAPPER.readValue(in, new TypeReference<Map<String, Object>>() {});
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void reachesThePinnedVerdictOnEveryCPythonToken() throws Exception {
        Map<String, Object> fx = vectors();
        double now = ((Number) fx.get("now")).doubleValue();
        List<Map<String, Object>> cases = (List<Map<String, Object>>) fx.get("cases");
        assertTrue(cases.size() >= 30);
        for (Map<String, Object> c : cases) {
            Map<String, Map<String, Object>> served =
                    (Map<String, Map<String, Object>>) c.get("docs");
            AgentTokens tokens = new AgentTokens(served::get, List.of(ISS), () -> now);
            String name = (String) c.get("name");
            if (c.containsKey("claims")) {
                assertEquals(c.get("claims"), tokens.verify((String) c.get("token")), name);
            } else {
                Refused refused = assertThrows(Refused.class,
                        () -> tokens.verify((String) c.get("token")), name);
                assertEquals(c.get("refused"), refused.getMessage(), name);
            }
        }
    }

    private Map<String, Object> issuerJwk(String kid) {
        Map<String, Object> jwk = new LinkedHashMap<>(Jwks.okpPublicJwk(issuerKey.getPublic()));
        jwk.put("alg", Jose.ED25519);
        jwk.put("kid", kid);
        return jwk;
    }

    private void publish(List<Map<String, Object>> keys) {
        docs.put(ISS + "/.well-known/aauth-agent.json",
                Map.of("issuer", ISS, "jwks_uri", ISS + "/jwks.json"));
        docs.put(ISS + "/jwks.json", Map.of("keys", new ArrayList<>(keys)));
    }

    private Map<String, Object> fetch(String url) {
        fetches.add(url);
        Map<String, Object> doc = docs.get(url);
        if (doc == null) {
            throw new IllegalStateException("404 " + url);
        }
        return doc;
    }

    private String mint(String kid) {
        Map<String, Object> cnf = new LinkedHashMap<>(Jwks.okpPublicJwk(agentKey.getPublic()));
        cnf.put("alg", Jose.ED25519);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISS);
        claims.put("dwk", "aauth-agent.json");
        claims.put("sub", "aauth:planner@ap.example");
        claims.put("jti", "at-1");
        claims.put("iat", (long) clock[0]);
        claims.put("exp", (long) clock[0] + 3600);
        claims.put("cnf", Map.of("jwk", cnf));
        String header = Jwks.b64url(PyJson.compactOrdered(Map.of(
                "typ", "aa-agent+jwt", "kid", kid, "alg", Jose.ED25519))
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String payload = Jwks.b64url(PyJson.compactOrdered(claims)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String input = header + "." + payload;
        return input + "." + Jwks.b64url(EdDsa.sign(issuerKey.getPrivate(),
                input.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    }

    private AgentTokens tokens() {
        return new AgentTokens(this::fetch, List.of(ISS), () -> clock[0]);
    }

    @Test
    void cachesKeysAndRefetchesAnUnknownKidOnlyAfterAMinute() {
        publish(List.of(issuerJwk("ap-1")));
        AgentTokens tokens = tokens();
        tokens.verify(mint("ap-1"));
        tokens.verify(mint("ap-1"));
        assertEquals(2, fetches.size(), "fetched once, then cached");
        assertThrows(Refused.class, () -> tokens.verify(mint("ap-2")));
        assertEquals(2, fetches.size(), "an unknown kid does not refetch inside a minute");
        clock[0] += AgentTokens.REFETCH_FLOOR_S;
        publish(List.of(issuerJwk("ap-1"), issuerJwk("ap-2")));
        tokens.verify(mint("ap-2"));
        assertEquals(4, fetches.size(), "after a minute it does: a rotation is noticed");
    }

    @Test
    void anIssuerTheDeploymentDidNotNameIsNeverFetched() {
        publish(List.of(issuerJwk("ap-1")));
        AgentTokens other = new AgentTokens(this::fetch, List.of("https://other.example"),
                () -> clock[0]);
        Refused refused = assertThrows(Refused.class, () -> other.verify(mint("ap-1")));
        assertTrue(refused.getMessage().contains("not an agent-token issuer this server"));
        assertEquals(List.of(), fetches);
        AgentTokens none = new AgentTokens(this::fetch, List.of(), () -> clock[0]);
        assertThrows(Refused.class, () -> none.verify(mint("ap-1")));
        assertEquals(List.of(), fetches);
    }

    @Test
    void anUnreadableIssuerIsAskedOnceAMinute() {
        clock[0] = 5000.0;
        AgentTokens tokens = tokens();
        String token = mint("ap-1");
        Refused first = assertThrows(Refused.class, () -> tokens.verify(token));
        assertThrows(Refused.class, () -> tokens.verify(token));
        Refused third = assertThrows(Refused.class, () -> tokens.verify(token));
        assertTrue(first.getMessage().contains("could not be read"), first.getMessage());
        assertTrue(third.getMessage().contains("could not be read"), third.getMessage());
        assertEquals(1, fetches.size(), String.valueOf(fetches));
        publish(List.of(issuerJwk("ap-1")));
        clock[0] += AgentTokens.REFETCH_FLOOR_S;
        tokens.verify(mint("ap-1"));
        assertEquals(3, fetches.size(), String.valueOf(fetches));
    }

    @Test
    void configuredIssuersMustBeHttpsOrigins() {
        assertThrows(Refused.class,
                () -> new AgentTokens(this::fetch, List.of("http://ps.uma.lab")));
        assertThrows(Refused.class,
                () -> new AgentTokens(this::fetch, List.of("https://PS.uma.lab")));
        assertThrows(Refused.class,
                () -> new AgentTokens(this::fetch, List.of("https://u:p@ps.uma.lab")));
        assertEquals("https://ps.uma.lab/t", AgentTokens.issuerOrigin("https://ps.uma.lab/t//"));
    }

    @Test
    void notAJwtIsRefusedByName() {
        Refused refused = assertThrows(Refused.class, () -> tokens().verify("abc"));
        assertTrue(refused.getMessage().startsWith("not a JWT"), refused.getMessage());
    }
}
