package io.uma4agents.authserver;

import static io.uma4agents.authserver.AsHarness.body;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

/**
 * What a pull believes about a resource server, and who may then ask for a ticket: the
 * pinned {@code lib/test_as.py} sections of those names, plus the pinned refusals of
 * metadata a JWT decode would reject and of listings that are not well formed.
 */
class RegistryPullTest {

    private static final String RU = "https://rs.example/mcp";
    private static final String JWKS = "https://rs.example/jwks";
    private static final String LISTING = "https://rs.example/owner-resources/alice";

    private final AsHarness as = new AsHarness();
    private final KeyPair rsKey = EdDsa.generate();
    private final Map<String, Object> rs = Map.of("resource_uri", RU);

    private Map<String, Object> claims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", RU);
        claims.put("owner_resources_endpoint", LISTING);
        return claims;
    }

    private static Map<String, Object> entry(String id) {
        return Map.of("_id", id, "resource_scopes", List.of("s"));
    }

    /** Publishes the three documents a pull reads. */
    private void publish(KeyPair signer, Map<String, Object> claims, Object listing) {
        String signed = CompactJws.sign(Map.of("typ", "JWT"), claims, signer.getPrivate());
        as.http.json(RegistrationPuller.wellKnownPrmUrl(RU), Map.of("resource", RU,
                "authorization_servers", List.of(as.config.issuer), "jwks_uri", JWKS,
                "signed_metadata", signed));
        as.http.json(JWKS, Map.of("keys", List.of(Jwks.okpPublicJwk(rsKey.getPublic()))));
        as.http.json(LISTING, listing);
    }

    private void publish(Object listing) {
        publish(rsKey, claims(), listing);
    }

    private static Map<String, Object> listing(Object resources) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("owner", "alice");
        out.put("resources", resources);
        return out;
    }

    @SuppressWarnings("unchecked")
    private List<String> sources(String id) {
        Map<String, Object> d = as.state.resource(id);
        return d == null ? null : (List<String>) d.get("sources");
    }

    // --- what a pull believes -----------------------------------------------

    @Test
    void aResourceServersOwnSignedListingIsRegisteredForHer() {
        publish(listing(List.of(entry("x/get"))));
        assertEquals(1, as.puller.pullRegistrations("rs-a", rs));
        assertEquals(List.of("rs-a"), sources("x/get"));
        String signedWith = as.http.requests.getLast().headers()
                .firstValue("signature-input").orElse("");
        assertTrue(signedWith.contains("keyid=\"uma-as-1\""), signedWith);
    }

    @Test
    void metadataSignedByAKeyTheResourceDoesNotPublishIsRefused() {
        publish(EdDsa.generate(), claims(), listing(List.of(entry("x/get"))));
        refused();
    }

    @Test
    void metadataNamingAnotherResourceAsItsIssuerIsRefused() {
        Map<String, Object> claims = claims();
        claims.put("iss", "https://other.example/mcp");
        publish(rsKey, claims, listing(List.of(entry("x/get"))));
        refused();
    }

    @Test
    void aListingThatNamesAnotherOwnerIsRefused() {
        Map<String, Object> carols = listing(List.of(entry("x/get")));
        carols.put("owner", "carol");
        publish(carols);
        refused();
    }

    @Test
    void metadataAJwtDecodeWouldRejectVerifiesNothing() {
        long now = AsState.now();
        for (Map.Entry<String, Object> bad : Map.<String, Object>of("exp", now - 1,
                "nbf", now + 600, "iat", now + 600, "sub", 7).entrySet()) {
            Map<String, Object> claims = claims();
            claims.put(bad.getKey(), bad.getValue());
            publish(rsKey, claims, listing(List.of(entry("x/get"))));
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> as.puller.pullRegistrations("rs-a", rs), bad.getKey());
            assertTrue(e.getMessage().contains("did not verify"), e.getMessage());
        }
        Map<String, Object> current = claims();
        current.put("iat", now - 5);
        current.put("exp", now + 600);
        publish(rsKey, current, listing(List.of(entry("x/get"))));
        assertEquals(1, as.puller.pullRegistrations("rs-a", rs));
    }

    @Test
    void documentsOffTheResourcesOwnHttpsOriginAreRefused() {
        publish(listing(List.of(entry("x/get"))));
        Map<String, Object> doc = Map.of("resource", RU,
                "authorization_servers", List.of(as.config.issuer),
                "jwks_uri", "https://elsewhere.example/jwks", "signed_metadata", "x");
        as.http.json(RegistrationPuller.wellKnownPrmUrl(RU), doc);
        assertTrue(refused().contains("jwks_uri"));

        publish(listing(List.of(entry("x/get"))));
        Map<String, Object> claims = claims();
        claims.put("owner_resources_endpoint", "http://rs.example/owner-resources/alice");
        publish(rsKey, claims, listing(List.of(entry("x/get"))));
        assertTrue(refused().contains("owner_resources_endpoint"));
    }

    @Test
    void anOversizedDocumentIsRefused() {
        publish(listing(List.of(entry("x/get"))));
        as.http.documents.put(LISTING, ("{\"pad\":\"" + "x".repeat(RegistrationPuller.FETCH_LIMIT)
                + "\"}").getBytes(StandardCharsets.UTF_8));
        assertTrue(refused().contains("more than"));
    }

    // --- several servers, and withdrawal --------------------------------------

    @Test
    void aResourceStaysRegisteredForTheServerStillPublishingIt() {
        publish(listing(List.of(entry("x/get"))));
        as.puller.pullRegistrations("rs-a", rs);
        as.puller.pullRegistrations("rs-b", rs);
        assertEquals(List.of("rs-a", "rs-b"), sources("x/get"));

        publish(listing(List.of(entry("y/get"))));
        as.puller.pullRegistrations("rs-a", rs);
        assertEquals(List.of("rs-b"), sources("x/get"));
        as.puller.pullRegistrations("rs-b", rs);
        assertNull(as.state.resource("x/get"), "a resource nobody publishes stayed registered");
    }

    @Test
    void aListingThatPublishesNothingWithdrawsWhatItPublishedBefore() {
        publish(listing(List.of(entry("x/get"))));
        as.puller.pullRegistrations("rs-a", rs);
        publish(listing(List.of()));
        assertEquals(0, as.puller.pullRegistrations("rs-a", rs));
        assertNull(as.state.resource("x/get"));
    }

    @Test
    void aMalformedListingIsRefusedAndWithdrawsNothing() {
        publish(listing(List.of(entry("x/get"), entry("y/get"))));
        as.puller.pullRegistrations("rs-a", rs);
        for (Object malformed : List.of(
                List.of(entry("x/get"), Map.of("_id", "y/get")),
                List.of(entry("x/get"), Map.of("_id", "y/get", "resource_scopes", "s")),
                List.of(entry("x/get"), Map.of("resource_scopes", List.of("s"))),
                List.of(entry("x/get"), "y/get"),
                Map.of("x/get", entry("x/get")))) {
            publish(listing(malformed));
            refused();
            assertEquals(List.of("rs-a"), sources("x/get"), String.valueOf(malformed));
            assertEquals(List.of("rs-a"), sources("y/get"),
                    "a malformed entry was taken as a withdrawal: " + malformed);
        }
    }

    // --- who may ask for a ticket ---------------------------------------------

    private ResponseEntity<Object> perm() {
        return as.protection.registerPermission(as.pat(),
                Map.of("resource_id", "x/get", "resource_scopes", List.of("s")));
    }

    @Test
    void onlyAServerThatPublishesTheResourceMayAskAboutIt() {
        as.state.updateResources(r -> r.put("x/get", new LinkedHashMap<>(Map.of(
                "resource_scopes", List.of("s"), "sources", List.of("someone-else")))));
        ResponseEntity<Object> refused = perm();
        assertEquals(400, refused.getStatusCode().value());
        assertEquals("invalid_resource_id", body(refused).get("error"));

        as.state.updateResources(r -> r.put("x/get", new LinkedHashMap<>(Map.of(
                "resource_scopes", List.of("s"),
                "sources", List.of("someone-else", as.config.rsClientId)))));
        assertEquals(201, perm().getStatusCode().value());
    }

    @Test
    void aResourceThisReplicaHadNotYetReadIsReadAgainThenAnswered() {
        Map<String, Object> gateway = new LinkedHashMap<>(as.store.resourceServer(
                as.config.rsClientId));
        gateway.put("resource_uri", RU);
        as.store.putResourceServer(as.config.rsClientId, gateway);
        publish(listing(List.of(entry("x/get"))));
        assertEquals(201, perm().getStatusCode().value());
    }

    @Test
    void aRevokedServerWritesNothingToHerRegistry() {
        Map<String, Object> gateway = new LinkedHashMap<>(as.store.resourceServer(
                as.config.rsClientId));
        gateway.put("resource_uri", RU);
        as.store.putResourceServer(as.config.rsClientId, gateway);
        publish(listing(List.of(entry("x/get"))));
        as.store.revokeResourceServer(as.config.rsClientId);
        as.puller.pullAll();
        assertNull(as.state.resource("x/get"));
    }

    private String refused() {
        return assertThrows(IllegalStateException.class,
                () -> as.puller.pullRegistrations("rs-a", rs)).getMessage();
    }
}
