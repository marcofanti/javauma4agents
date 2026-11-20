package io.uma4agents.authserver;

import static io.uma4agents.authserver.AsHarness.REMOVE;
import static io.uma4agents.authserver.AsHarness.body;
import static io.uma4agents.authserver.AsHarness.template;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

/**
 * The grant loop over the store, ported from the pinned {@code lib/test_as.py} sections
 * this phase owns: what an agreement may say and what the grant then is, who may ask about
 * a grant, a revoked grant staying revoked, an approval not outliving what she withdrew,
 * and a provisioned secret following the deployment.
 */
class GrantLoopTest {

    private static final String POSITIONS = "alice-vault/get_positions";
    private static final String TRADE = "alice-vault/execute_trade";

    private final AsHarness as = new AsHarness();

    private String refusal(Map<String, Object> edit) {
        Map<String, Object> needInfo = as.dictated(POSITIONS, "positions:read");
        ResponseEntity<Object> r = as.commit(needInfo, as.agreement(template(needInfo), edit));
        assertEquals(403, r.getStatusCode().value());
        assertEquals("request_denied", body(r).get("error"));
        return String.valueOf(body(r).get("error_description"));
    }

    @Test
    void ownerMarkerIsPresentOnMintAndRotationAndCheckedBeforeSpending() {
        as.registered(POSITIONS, "positions:read");
        String issued = (String) body(as.protection.registerPermission(as.pat(),
                Map.of("resource_id", POSITIONS,
                        "resource_scopes", List.of("positions:read")))).get("ticket");
        assertTrue(issued.startsWith("YWxpY2U~tkt_"));
        String raw = issued.substring(issued.indexOf('~') + 1);
        assertEquals("invalid_grant", body(as.poll("Y2Fyb2w~" + raw)).get("error"));
        assertEquals("invalid_grant", body(as.poll("!~" + raw)).get("error"));
        Map<String, Object> rotated = body(as.poll(issued));
        assertEquals("need_info", rotated.get("error"));
        assertTrue(((String) rotated.get("ticket")).startsWith("YWxpY2U~tkt_"));
        assertEquals("invalid_grant", body(as.poll(issued)).get("error"));
    }

    @Test
    void anOlderUnmarkedTicketStillResolvesInTheSameStore() {
        String legacy = as.store.mintTicket(new LinkedHashMap<>(Map.of(
                "family", "fam_legacy", "state", "issued", "resource_id", POSITIONS,
                "resource_scopes", List.of("positions:read"))), 300);
        as.registered(POSITIONS, "positions:read");
        assertEquals("need_info", body(as.poll(legacy)).get("error"));
    }

    // --- what an agreement may say ------------------------------------------

    @Test
    void anAgreementThatAddsAScopeIsRefused() {
        assertTrue(refusal(Map.of("scope", List.of("positions:read", "trades:execute")))
                .contains("scope was widened"));
    }

    @Test
    void anAgreementWithNoLifetimeIsRefused() {
        assertTrue(refusal(Map.of("expires_in", 0)).contains("positive number"));
        assertTrue(refusal(Map.of("expires_in", 60.0)).contains("positive number"));
    }

    @Test
    void anAgreementWithNoScopeArrayIsRefused() {
        Map<String, Object> edit = new LinkedHashMap<>();
        edit.put("scope", REMOVE);
        assertTrue(refusal(edit).contains("array of strings"));
    }

    @Test
    void anAgreementToNoScopeOfThoseOfferedIsRefused() {
        assertTrue(refusal(Map.of("scope", List.of())).contains("names no scope"));
    }

    @Test
    void aPerOperationAgreementNamingNoToolIsRefusedBeforeSheIsAsked() {
        Map<String, Object> needInfo = as.dictated(TRADE, "trades:execute");
        ResponseEntity<Object> r = as.commit(needInfo, as.agreement(template(needInfo),
                Map.of("operation", Map.of("params", Map.of("qty", 1)))));
        assertEquals(403, r.getStatusCode().value());
        assertTrue(String.valueOf(body(r).get("error_description")).contains("naming a tool"));
        assertTrue(as.store.pendingNegotiations().isEmpty(), "she was asked anyway");
    }

    @Test
    void termsChangedBeforeCommitAreDictatedAgain() {
        Map<String, Object> needInfo = as.dictated(POSITIONS, "positions:read");
        as.policy.updateTier("tier1", Map.of("terms", Map.of("purpose", "changed")));
        ResponseEntity<Object> r = as.commit(needInfo, as.agreement(template(needInfo),
                Map.of()));
        assertEquals("need_info", body(r).get("error"));
        assertEquals("changed", template(body(r)).get("purpose"));
        assertNotEquals(template(needInfo).get("template_id"),
                template(body(r)).get("template_id"));
    }

    // --- the grant ----------------------------------------------------------

    @SuppressWarnings("unchecked")
    @Test
    void aGrantLastsNoLongerThanAgreedAndCoversTheNegotiationsResource() {
        as.connected();
        Map<String, Object> needInfo = as.dictated(POSITIONS, "positions:read");
        ResponseEntity<Object> r = as.commit(needInfo, as.agreement(template(needInfo),
                Map.of("expires_in", 60, "resource_id", TRADE)));
        assertEquals(200, r.getStatusCode().value(), String.valueOf(r.getBody()));
        String rpt = String.valueOf(body(r).get("access_token"));
        Map<String, Object> claims = CompactJws.parse(rpt).claims();
        long now = AsState.now();
        assertTrue(((Number) claims.get("exp")).longValue() - now <= 61);
        Map<String, Object> permission = ((List<Map<String, Object>>) claims.get("permissions"))
                .getFirst();
        assertTrue(((Number) permission.get("exp")).longValue() - now <= 61);
        assertEquals(POSITIONS, permission.get("resource_id"));
        for (String k : List.of("iss", "aud", "jti", "exp", "iat")) {
            assertTrue(claims.get(k) != null, "the grant has no " + k);
        }
        assertEquals("at+jwt", CompactJws.parse(rpt).header().get("typ"));
        assertEquals(as.handle(), claims.get("sub"));
        assertEquals(as.handle(), claims.get("client_id"));
        assertNull(as.store.negotiation(String.valueOf(template(needInfo).get("family"))),
                "the negotiation outlived its grant");
    }

    // --- who may ask about a grant ------------------------------------------

    private String grant() {
        as.connected();
        Map<String, Object> needInfo = as.dictated(POSITIONS, "positions:read");
        ResponseEntity<Object> r = as.commit(needInfo, as.agreement(template(needInfo),
                Map.of()));
        return String.valueOf(body(r).get("access_token"));
    }

    @Test
    void theOwnersResourceServerIsToldTheGrantIsLiveWithWhatEnforcementReads() {
        String rpt = grant();
        Map<String, Object> answer = as.protection.introspect(as.pat(), rpt, null);
        Map<String, Object> claims = CompactJws.parse(rpt).claims();
        assertEquals(true, answer.get("active"));
        assertEquals(claims.get("cnf"), answer.get("cnf"));
        assertEquals(claims.get("permissions"), answer.get("permissions"));
        assertEquals(claims.get("contract"), answer.get("contract"));
    }

    @Test
    void aResourceServerHoldingAnotherOwnersPatIsToldNothing() {
        String rpt = grant();
        Map<String, Object> claims = new LinkedHashMap<>(CompactJws.parse(rpt).claims());
        claims.put("owner", "carol");
        String carols = CompactJws.sign(as.keys.header("at+jwt"), claims,
                as.keys.current().getPrivate());
        assertEquals(Map.of("active", false, "error", "unknown_token"),
                as.protection.introspect(as.pat(), carols, null));
        assertEquals(Map.of("consumed", false, "error", "unknown_token"),
                as.protection.consumeRpt(as.pat(), carols));
        as.store.revokeConnection(as.handle());
        assertEquals(Map.of("active", false, "error", "unknown_token"),
                as.protection.introspect(as.pat(), carols, null),
                "another owner's resource server was told it was revoked");
    }

    @Test
    void admittingTheSameAgentAgainDoesNotReviveWhatRevocationEnded() {
        String rpt = grant();
        as.store.revokeConnection(as.handle());
        as.connected();
        assertEquals(Map.of("active", false, "error", "revoked"),
                as.protection.introspect(as.pat(), rpt, null));
    }

    @Test
    void anAllowedCallIsAttributedFromTheGrantNotTheCaller() {
        String rpt = grant();
        String family = String.valueOf(as.protection.introspect(as.pat(), rpt, null)
                .get("family"));
        as.protection.auditAccess(as.pat(), Map.of("family", family, "tool", "get_positions"));
        Map<String, Object> touched = as.store.ledger(as.handle()).getLast();
        assertEquals("touched", touched.get("kind"));
        assertEquals("tier1", touched.get("tier"));
    }

    // --- an approval does not outlive what she withdrew ---------------------

    /** An operation pend for an admitted agent, approved by her. Returns its ticket. */
    private String approvedOperation() {
        as.connected();
        Map<String, Object> needInfo = as.dictated(TRADE, "trades:execute");
        Map<String, Object> op = Map.of("tool", "execute_trade", "params", Map.of("qty", 1));
        ResponseEntity<Object> pend = as.commit(needInfo, as.agreement(template(needInfo),
                Map.of("operation", op)));
        assertEquals("request_submitted", body(pend).get("error"));
        String family = String.valueOf(as.store.pendingNegotiations().getFirst().get("family"));
        assertTrue(as.store.decide(family, "approved", Map.of("kind", "owner", "owner", "alice")));
        return String.valueOf(body(pend).get("ticket"));
    }

    @Test
    void anApprovalCollectedAfterSheRevokedTheAgentIssuesNothing() {
        String ticket = approvedOperation();
        as.store.revokeConnection(as.handle());
        ResponseEntity<Object> r = as.poll(ticket);
        assertEquals(403, r.getStatusCode().value());
        assertEquals("this agent was revoked after it asked", body(r).get("error_description"),
                String.valueOf(r.getBody()));
        assertEquals("refused", as.store.ledger(as.handle()).getLast().get("kind"));
    }

    @Test
    void aRevocationBetweenAskingAndCollectingIsNotUndoneByReadmission() {
        String ticket = approvedOperation();
        as.store.revokeConnection(as.handle());
        Map<String, Object> readmitted = as.store.connection(as.handle());
        readmitted.put("status", "active");
        as.store.putConnection(readmitted);
        ResponseEntity<Object> r = as.poll(ticket);
        assertEquals(403, r.getStatusCode().value());
    }

    @Test
    void anApprovalWithNothingWithdrawnIsGranted() {
        String ticket = approvedOperation();
        ResponseEntity<Object> r = as.poll(ticket);
        assertEquals(200, r.getStatusCode().value(), String.valueOf(r.getBody()));
        assertEquals(true, CompactJws.parse(String.valueOf(body(r).get("access_token")))
                .claims().get("single_use"));
    }

    @Test
    void admittingAPreviouslyRevokedAgentKeepsItsRecord() {
        as.connected();
        as.store.revokeConnection(as.handle());
        Map<String, Object> needInfo = as.dictated(POSITIONS, "positions:read");
        ResponseEntity<Object> pend = as.commit(needInfo, as.agreement(template(needInfo),
                Map.of()));
        String family = String.valueOf(as.store.pendingNegotiations().getFirst().get("family"));
        assertEquals("connection", as.store.negotiation(family).get("pending_kind"));
        as.store.decide(family, "approved", Map.of("kind", "owner", "owner", "alice"));
        ResponseEntity<Object> r = as.poll(String.valueOf(body(pend).get("ticket")));
        assertEquals(200, r.getStatusCode().value(), String.valueOf(r.getBody()));
        assertEquals(1, ((Number) as.store.connection(as.handle()).get("revocations")).intValue());
    }

    @Test
    void anUndecidedPollKeepsItsTicketAndADecisionIsCollectedOnce() {
        as.connected();
        Map<String, Object> needInfo = as.dictated(TRADE, "trades:execute");
        ResponseEntity<Object> pend = as.commit(needInfo, as.agreement(template(needInfo),
                Map.of("operation", Map.of("tool", "execute_trade", "params", Map.of()))));
        String ticket = String.valueOf(body(pend).get("ticket"));
        assertEquals(ticket, body(as.poll(ticket)).get("ticket"));
        String family = String.valueOf(as.store.pendingNegotiations().getFirst().get("family"));
        as.store.decide(family, "approved", Map.of("kind", "owner", "owner", "alice"));
        assertEquals(200, as.poll(ticket).getStatusCode().value());
        assertEquals("invalid_grant", body(as.poll(ticket)).get("error"));
    }

    // --- a revocation landing inside the grant's last step --------------------

    /** The real store, with {@code before} run at the moment {@code method} is called. */
    private static OwnerStore interleaved(OwnerStore real, String method, Runnable before) {
        return (OwnerStore) Proxy.newProxyInstance(OwnerStore.class.getClassLoader(),
                new Class<?>[] {OwnerStore.class}, (proxy, m, args) -> {
                    if (method.equals(m.getName())) {
                        before.run();
                    }
                    try {
                        return m.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    @Test
    void aRevocationLandingAsTheApprovedAgentIsAdmittedIsNotOverwritten() {
        // Revoked once before; she approves its renewed first contact knowing that.
        as.connected();
        as.store.revokeConnection(as.handle());
        Map<String, Object> needInfo = as.dictated(POSITIONS, "positions:read");
        String ticket = String.valueOf(body(as.commit(needInfo,
                as.agreement(template(needInfo), Map.of()))).get("ticket"));
        String family = String.valueOf(as.store.pendingNegotiations().getFirst().get("family"));
        as.store.decide(family, "approved", Map.of("kind", "owner", "owner", "alice"));

        // She revokes again between the poll's re-check and its admission.
        AsHarness racing = new AsHarness(as.keys, interleaved(as.store, "admitConnection",
                () -> as.store.revokeConnection(as.handle())));
        racing.registered(POSITIONS, "positions:read");
        ResponseEntity<Object> r = racing.poll(ticket);
        assertEquals(403, r.getStatusCode().value(), "the stale approval admitted the agent");
        assertEquals("revoked", as.store.connection(as.handle()).get("status"));
        assertEquals(2, ((Number) as.store.connection(as.handle()).get("revocations")).intValue());
        assertEquals("refused", as.store.ledger(as.handle()).getLast().get("kind"));
    }

    /** Filled once the racing harness exists; read by the revocation it injects. */
    private final String[] racingHandle = new String[1];

    @Test
    void aRevocationLandingAsTheGrantIsRecordedLeavesNoGrantToRevive() {
        // One agent throughout: the racing harness signs with its own key.
        AsHarness racing = new AsHarness(as.keys, interleaved(as.store, "recordRptIfConnected",
                () -> as.store.revokeConnection(racingHandle[0])));
        racingHandle[0] = racing.handle();
        racing.connected();
        Map<String, Object> needInfo = racing.dictated(POSITIONS, "positions:read");
        ResponseEntity<Object> r = racing.commit(needInfo,
                racing.agreement(template(needInfo), Map.of()));
        assertEquals(403, r.getStatusCode().value(), "a grant was issued after she revoked: "
                + r.getBody());
        assertNull(body(r).get("access_token"));
        assertEquals("this agent was revoked after it asked", body(r).get("error_description"),
                String.valueOf(r.getBody()));
        assertEquals("revoked", as.store.connection(racing.handle()).get("status"));
        assertNull(as.store.grantForFamily(String.valueOf(template(needInfo).get("family"))),
                "a grant was recorded under the revoked connection");
    }

    // --- the resource server's credential -----------------------------------

    @Test
    void aProvisionedSecretTheDeploymentRotatedIsTheOneThatWorks() {
        Map<String, Object> seeded = as.store.resourceServer(as.config.rsClientId);
        Map<String, Object> stale = new LinkedHashMap<>(seeded);
        stale.put("secret", "old-secret");
        as.store.putResourceServer(as.config.rsClientId, stale);
        assertEquals(401, patWith("old-secret").getStatusCode().value());
        assertEquals(200, patWith(as.config.rsClientSecret).getStatusCode().value());

        stale.put("status", "revoked");
        as.store.putResourceServer(as.config.rsClientId, stale);
        assertEquals(403, patWith(as.config.rsClientSecret).getStatusCode().value(),
                "a registration she revoked was reopened by the secret");
    }

    @Test
    void aRevocationLandingWhileTheSecretIsReprovisionedStaysARevocation() {
        OwnerStore real = new AsHarness().store;
        Map<String, Object> stale = new LinkedHashMap<>(real.resourceServer("meridian-gateway"));
        stale.put("secret", "old-secret");
        real.putResourceServer("meridian-gateway", stale);
        // Her revocation commits between the PAT request's read and its secret write.
        OwnerStore racing = (OwnerStore) Proxy.newProxyInstance(
                OwnerStore.class.getClassLoader(), new Class<?>[] {OwnerStore.class},
                (proxy, method, args) -> {
                    if ("updateResourceServerSecret".equals(method.getName())) {
                        real.revokeResourceServer((String) args[0]);
                    }
                    try {
                        return method.invoke(real, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
        AsHarness raced = new AsHarness(new SigningKeys(EdDsa.generate(), "uma-as-1", Map.of()),
                racing);
        ResponseEntity<Object> r = raced.token.token("client_credentials", null, null, null,
                null, raced.config.rsClientId, raced.config.rsClientSecret, "uma_protection");
        assertEquals(403, r.getStatusCode().value(), "a PAT was issued after she revoked");
        assertEquals("revoked", real.resourceServer("meridian-gateway").get("status"));
        assertEquals(raced.config.rsClientSecret,
                real.resourceServer("meridian-gateway").get("secret"));
    }

    @Test
    void aRegistrationWithNoSecretIsNeverOpenedBySendingNone() {
        Map<String, Object> open = new LinkedHashMap<>(as.store.resourceServer(
                as.config.rsClientId));
        open.put("secret", "");
        as.store.putResourceServer("self-registered", open);
        ResponseEntity<Object> r = as.token.token("client_credentials", null, null, null, null,
                "self-registered", "", "uma_protection");
        assertEquals(401, r.getStatusCode().value());
    }

    private ResponseEntity<Object> patWith(String secret) {
        return as.token.token("client_credentials", null, null, null, null,
                as.config.rsClientId, secret, "uma_protection");
    }
}
