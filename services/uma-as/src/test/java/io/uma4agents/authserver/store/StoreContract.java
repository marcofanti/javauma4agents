package io.uma4agents.authserver.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The store properties both backends must hold identically, ported from the pinned
 * {@code lib/test_store.py} for the operations that have callers through Phase D: standing,
 * lineage, operators, trajectory and her own tiers included. Organization and joint
 * operations arrive with their callers in E, and their cases with them.
 */
abstract class StoreContract {

    static final int RACERS = 32;

    Store backing;
    OwnerStore store;

    /** A fresh store over empty state. */
    abstract Store newStore();

    @BeforeEach
    void open() {
        backing = newStore();
        backing.start();
        store = backing.owner("alice");
        store.seed();
    }

    @AfterEach
    void shut() {
        if (backing != null) {
            backing.close();
        }
    }

    // --- shared fixtures ----------------------------------------------------

    static Seeds testSeeds() {
        return new Seeds(owner -> {
            Map<String, Map<String, Object>> tiers = new LinkedHashMap<>();
            for (int i = 1; i <= 3; i++) {
                Map<String, Object> terms = new LinkedHashMap<>();
                terms.put("template_id", owner + "/advisor-tier" + i + "/v2");
                terms.put("purpose", "purpose " + i);
                terms.put("expires_in", 3600);
                Map<String, Object> tier = new LinkedHashMap<>();
                tier.put("name", "Tier " + i);
                tier.put("resources", List.of(owner + "-vault/tool" + i));
                tier.put("ask_me", i == 3);
                tier.put("terms", terms);
                tiers.put("tier" + i, tier);
            }
            return tiers;
        }, owner -> {
            Map<String, Object> rs = new LinkedHashMap<>();
            rs.put("secret", "gateway-dev-secret");
            rs.put("name", "Meridian Wealth API gateway");
            rs.put("status", "active");
            rs.put("consented", "seeded at provisioning");
            rs.put("last_pat_issued", null);
            rs.put("resource_uri", "https://gateway.uma.lab/mcp");
            return Map.of("meridian-gateway", rs);
        });
    }

    static Map<String, Object> negotiation(String family) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("family", family);
        rec.put("state", "issued");
        rec.put("resource_id", "alice-vault/get_positions");
        rec.put("resource_scopes", new ArrayList<>(List.of("positions:read")));
        return rec;
    }

    static Map<String, Object> awaiting(String family) {
        Map<String, Object> rec = negotiation(family);
        rec.put("state", "awaiting-owner");
        rec.put("decision", null);
        return rec;
    }

    static Map<String, Object> conn(String handle) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("handle", handle);
        c.put("status", "active");
        c.put("first_seen", "2026-08-11T00:00:00Z");
        c.put("identity", Map.of("level", "pseudonymous"));
        c.put("label", "test");
        c.put("last_access", null);
        c.put("revocations", 0);
        return c;
    }

    /** Runs {@code n} copies of {@code task} released at the same moment. */
    static <T> List<T> race(int n, Callable<T> task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        try {
            CountDownLatch gate = new CountDownLatch(1);
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                futures.add(pool.submit(() -> {
                    gate.await();
                    return task.call();
                }));
            }
            gate.countDown();
            List<T> out = new ArrayList<>();
            for (Future<T> f : futures) {
                out.add(f.get(30, TimeUnit.SECONDS));
            }
            return out;
        } finally {
            pool.shutdownNow();
        }
    }

    static long winners(List<?> results) {
        return results.stream().filter(r -> r != null && !Boolean.FALSE.equals(r)).count();
    }

    // --- tickets and negotiations -------------------------------------------

    @Test
    void aTicketIsSpentOnceUnderARace() throws Exception {
        String ticket = store.mintTicket(negotiation("fam_ticket_race"), 300);
        List<Map<String, Object>> results = race(RACERS, () -> store.consumeTicket(ticket));
        assertEquals(1, winners(results), "exactly one presentation wins");
        Map<String, Object> winner = results.stream().filter(Objects::nonNull).findFirst()
                .orElseThrow();
        assertEquals("fam_ticket_race", winner.get("family"));
    }

    @Test
    void saveCreatesANegotiationNoTicketMade() {
        store.saveNegotiation(awaiting("fam_no_ticket"));
        assertEquals("fam_no_ticket", store.negotiation("fam_no_ticket").get("family"));
        assertTrue(store.pendingNegotiations().stream()
                .anyMatch(p -> "fam_no_ticket".equals(p.get("family"))));
        assertTrue(store.decide("fam_no_ticket", "approved", null));
    }

    @Test
    void aNegotiationOutlivesItsTicketAndKeepsItsFamilyAcrossRotation() {
        String first = store.mintTicket(awaiting("fam_survives"), 300);
        Map<String, Object> rec = store.consumeTicket(first);
        assertNotNull(store.negotiation("fam_survives"), "the record vanished with its ticket");
        String rotated = store.mintTicket(rec, 300);
        assertNotEquals(first, rotated);
        assertNull(store.consumeTicket(first), "a spent ticket came back with the rotation");
        assertEquals("fam_survives", store.peekTicket(rotated).get("family"));
    }

    @Test
    void peekingSpendsNothing() {
        String ticket = store.mintTicket(awaiting("fam_peek"), 60);
        assertEquals("fam_peek", store.peekTicket(ticket).get("family"));
        assertEquals("fam_peek", store.peekTicket(ticket).get("family"));
        assertEquals("fam_peek", store.consumeTicket(ticket).get("family"));
        assertNull(store.peekTicket(ticket));
    }

    @Test
    void readsAreCopiesAndChangesPersistOnlyThroughWrites() {
        String ticket = store.mintTicket(awaiting("fam_copy"), 60);
        store.peekTicket(ticket).put("state", "tampered");
        store.negotiation("fam_copy").put("decision", "approved");
        Map<String, Object> stored = store.negotiation("fam_copy");
        assertEquals("awaiting-owner", stored.get("state"));
        assertNull(stored.get("decision"));
    }

    @Test
    void expiredNegotiationsAreReapedAndTheirTicketsDie() {
        String stale = store.mintTicket(negotiation("fam_stale"), -1);
        store.mintTicket(negotiation("fam_fresh"), 300);
        assertNull(store.consumeTicket(stale), "an expired ticket was honoured");
        store.reapExpired();
        assertNull(store.negotiation("fam_stale"));
        assertNotNull(store.negotiation("fam_fresh"));
    }

    @Test
    void closingANegotiationDropsEveryTicketIndexedToIt() {
        Map<String, Object> rec = negotiation("fam_close");
        String a = store.mintTicket(rec, 300);
        String b = store.mintTicket(rec, 300);
        store.closeNegotiation("fam_close");
        assertNull(store.peekTicket(a));
        assertNull(store.peekTicket(b));
        assertNull(store.negotiation("fam_close"));
    }

    // --- decisions ----------------------------------------------------------

    @Test
    void theOwnerDecidesOnceUnderARace() throws Exception {
        store.mintTicket(awaiting("fam_decide"), 300);
        List<Boolean> results = race(RACERS, () -> store.decide("fam_decide", "approved",
                Map.of("kind", "owner", "owner", "alice")));
        assertEquals(1, winners(results), "more than one tap was recorded");
        assertFalse(store.decide("fam_decide", "denied", null), "the decision was reversible");
    }

    @Test
    void competingDecisionsLeaveExactlyOneAnswer() throws Exception {
        store.mintTicket(awaiting("fam_compete"), 300);
        List<String> outcomes = race(RACERS, () -> {
            String d = Thread.currentThread().threadId() % 2 == 0 ? "approved" : "denied";
            return store.decide("fam_compete", d, Map.of("kind", "owner", "owner", "alice"))
                    ? d : null;
        });
        List<String> won = outcomes.stream().filter(Objects::nonNull).toList();
        assertEquals(1, won.size());
        assertEquals(won.getFirst(), store.negotiation("fam_compete").get("decision"));
    }

    @Test
    void aDecisionOutlivesAStaleWriteWithItsAuthor() {
        String ticket = store.mintTicket(awaiting("fam_stale_poll"), 300);
        Map<String, Object> snapshot = store.consumeTicket(ticket);
        Map<String, Object> by = Map.of("kind", "owner", "owner", "alice");
        assertTrue(store.decide("fam_stale_poll", "approved", by));

        store.mintTicket(StoreJson.copy(snapshot), 300);
        Map<String, Object> after = store.negotiation("fam_stale_poll");
        assertEquals("approved", after.get("decision"), "rotating a stale copy un-decided it");
        assertEquals(by, after.get("decided_by"));

        store.saveNegotiation(StoreJson.copy(snapshot));
        assertEquals("approved", store.negotiation("fam_stale_poll").get("decision"),
                "saving a stale copy un-decided it");
    }

    @Test
    void aRefusedSecondDecisionLeavesTheAuthorAlone() {
        store.mintTicket(awaiting("fam_author"), 300);
        Map<String, Object> first = Map.of("kind", "owner", "owner", "alice");
        assertTrue(store.decide("fam_author", "approved", first));
        assertFalse(store.decide("fam_author", "approved", Map.of("kind", "someone-else")));
        assertEquals(first, store.negotiation("fam_author").get("decided_by"));
    }

    @Test
    void onlyAnAwaitingNegotiationCanBeDecided() {
        store.mintTicket(negotiation("fam_not_waiting"), 300);
        assertFalse(store.decide("fam_not_waiting", "approved", null));
        assertFalse(store.decide("fam_nowhere", "approved", null));
    }

    // --- RPTs ---------------------------------------------------------------

    @Test
    void anRptIsBurnedOnceUnderARace() throws Exception {
        store.recordRpt("rpt_race", "fam_rpt", "jkt:agent", Map.of("tool", "execute_trade"),
                "tier3");
        List<String> results = race(RACERS, () -> store.consumeRpt("rpt_race"));
        assertEquals(List.of("fam_rpt"), results.stream().filter(Objects::nonNull).toList());
        assertNull(store.consumeRpt("rpt_race"));
        assertEquals(Boolean.TRUE, store.rpt("rpt_race").get("consumed"));
        assertEquals(Map.of("tool", "execute_trade"), store.rpt("rpt_race").get("operation"));
    }

    @Test
    void anUnknownRptCannotBeBurned() {
        assertNull(store.consumeRpt("rpt_never_issued"));
        assertNull(store.rpt("rpt_never_issued"));
    }

    @Test
    void anAllowedCallIsTracedToItsAgentAfterTheGrantIsSpent() {
        store.recordRpt("rpt_trace", "fam_trace", "jkt:traced", null, "tier3");
        assertEquals("jkt:traced", store.grantForFamily("fam_trace").get("handle"));
        store.consumeRpt("rpt_trace");
        assertEquals(Map.of("handle", "jkt:traced", "tier", "tier3"),
                store.grantForFamily("fam_trace"));
        assertNull(store.grantForFamily("fam_missing"));
    }

    // --- revocation ---------------------------------------------------------

    @Test
    void revocationBurnsLiveGrantsInOneStepAndCountsItself() {
        store.putConnection(conn("jkt:revoke-me"));
        for (int i = 0; i < 3; i++) {
            store.recordRpt("rpt_rev" + i, "fam_rev", "jkt:revoke-me", null, "tier1");
        }
        store.consumeRpt("rpt_rev0");
        assertEquals(2, store.revokeConnection("jkt:revoke-me"));
        Map<String, Object> c = store.connection("jkt:revoke-me");
        assertEquals("revoked", c.get("status"));
        assertEquals(1, ((Number) c.get("revocations")).intValue());
        assertNull(store.consumeRpt("rpt_rev1"), "a revoked agent's grant still spends");
        assertNull(store.revokeConnection("jkt:never-seen"));
    }

    @Test
    void revocationRacingASpendLeavesNoGrantLiveAndCountsEachBurnOnce() throws Exception {
        store.putConnection(conn("jkt:racer"));
        store.recordRpt("rpt_racer", "fam_racer", "jkt:racer", null, "tier3");
        List<Object> results = race(RACERS, () ->
                Thread.currentThread().threadId() % 2 == 0
                        ? store.consumeRpt("rpt_racer")
                        : store.revokeConnection("jkt:racer"));
        long spends = results.stream().filter(r -> r instanceof String).count();
        int burnedByRevocation = results.stream().filter(r -> r instanceof Integer)
                .mapToInt(r -> (Integer) r).sum();
        assertEquals(1, spends + burnedByRevocation, "the grant was burned twice or never");
        assertEquals(Boolean.TRUE, store.rpt("rpt_racer").get("consumed"));
    }

    // --- admission and grants, serialized with revocation --------------------

    @Test
    void anAdmissionStandsOnlyAgainstTheRevocationCountSheWasAskedUnder() {
        Map<String, Object> fresh = conn("jkt:new");
        assertFalse(store.admitConnection(fresh, 1), "admitted against a count it never had");
        assertNull(store.connection("jkt:new"), "a refused admission wrote a record");
        assertTrue(store.admitConnection(fresh, 0));
        assertEquals("active", store.connection("jkt:new").get("status"));

        store.revokeConnection("jkt:new");
        Map<String, Object> again = conn("jkt:new");
        assertFalse(store.admitConnection(again, 0), "a revocation was overwritten");
        assertEquals("revoked", store.connection("jkt:new").get("status"));
        again.put("revocations", 1);
        assertTrue(store.admitConnection(again, 1), "readmission knowing of it was refused");
        assertEquals("active", store.connection("jkt:new").get("status"));
    }

    @Test
    void aGrantIsRecordedOnlyUnderTheConnectionItWasDecidedOn() {
        assertFalse(store.recordRptIfConnected("rpt_none", "f", "jkt:nobody", null, "tier1", 0));
        assertNull(store.rpt("rpt_none"));
        store.putConnection(conn("jkt:g"));
        assertTrue(store.recordRptIfConnected("rpt_ok", "f", "jkt:g", null, "tier1", 0));
        assertEquals(Boolean.FALSE, store.rpt("rpt_ok").get("consumed"));

        store.revokeConnection("jkt:g");
        assertFalse(store.recordRptIfConnected("rpt_late", "f", "jkt:g", null, "tier1", 0));
        Map<String, Object> readmitted = store.connection("jkt:g");
        readmitted.put("status", "active");
        store.putConnection(readmitted);
        assertFalse(store.recordRptIfConnected("rpt_stale", "f", "jkt:g", null, "tier1", 0),
                "a decision taken before the revocation was recorded after readmission");
        assertNull(store.rpt("rpt_stale"));
        assertTrue(store.recordRptIfConnected("rpt_new", "f", "jkt:g", null, "tier1", 1));
    }

    @Test
    void noGrantRecordedRacingARevocationOutlivesIt() throws Exception {
        store.putConnection(conn("jkt:race"));
        java.util.concurrent.atomic.AtomicInteger n = new java.util.concurrent.atomic.AtomicInteger();
        race(RACERS, () -> {
            int i = n.getAndIncrement();
            return i == RACERS / 2 ? (Object) store.revokeConnection("jkt:race")
                    : store.recordRptIfConnected("rpt_r" + i, "f", "jkt:race", null, "tier1", 0);
        });
        assertEquals("revoked", store.connection("jkt:race").get("status"));
        for (int i = 0; i < RACERS; i++) {
            Map<String, Object> rpt = store.rpt("rpt_r" + i);
            assertTrue(rpt == null || Boolean.TRUE.equals(rpt.get("consumed")),
                    "rpt_r" + i + " is live under a revoked connection");
        }
    }

    @Test
    void connectionsListNewestFirstAndTouchIsTelemetry() {
        Map<String, Object> older = conn("jkt:older");
        Map<String, Object> newer = conn("jkt:newer");
        newer.put("first_seen", "2026-09-01T00:00:00Z");
        store.putConnection(older);
        store.putConnection(newer);
        assertEquals(List.of("jkt:newer", "jkt:older"),
                store.connections().stream().map(c -> c.get("handle")).toList());
        store.touchConnection("jkt:older", "2026-10-01T00:00:00Z");
        store.touchConnection("jkt:nobody", "2026-10-01T00:00:00Z");
        assertEquals("2026-10-01T00:00:00Z", store.connection("jkt:older").get("last_access"));
    }

    // --- resource servers, seeding, policy, terms ---------------------------

    @Test
    void resourceServerRevocationIsReadableAfterwards() {
        assertEquals("active", store.resourceServer("meridian-gateway").get("status"));
        assertTrue(store.revokeResourceServer("meridian-gateway"));
        assertEquals("revoked", store.resourceServer("meridian-gateway").get("status"));
        assertFalse(store.revokeResourceServer("nobody"));
        store.touchPat("meridian-gateway", "2026-10-01T00:00:00Z");
        assertEquals("2026-10-01T00:00:00Z",
                store.resourceServers().get("meridian-gateway").get("last_pat_issued"));
    }

    @Test
    void aSecretUpdateChangesTheSecretAloneAndReturnsTheLiveRecord() {
        assertTrue(store.revokeResourceServer("meridian-gateway"));
        Map<String, Object> live = store.updateResourceServerSecret("meridian-gateway", "new");
        assertEquals("new", live.get("secret"));
        assertEquals("revoked", live.get("status"), "the secret update reopened it");
        assertEquals("revoked", store.resourceServer("meridian-gateway").get("status"));
        assertEquals("Meridian Wealth API gateway", live.get("name"));
        assertNull(store.updateResourceServerSecret("nobody", "new"));
    }

    @Test
    void aRevocationRacingSecretUpdatesStaysARevocation() throws Exception {
        race(RACERS, () -> Thread.currentThread().threadId() % 4 == 0
                ? store.revokeResourceServer("meridian-gateway")
                : store.updateResourceServerSecret("meridian-gateway", "rotated"));
        assertEquals("revoked", store.resourceServer("meridian-gateway").get("status"));
        assertEquals("rotated", store.resourceServer("meridian-gateway").get("secret"));
    }

    @Test
    void seedingIsOncePerOwnerSoWhatSheChangedStaysChanged() {
        store.updateTier("tier1", t -> withPurpose(t, "her own words"));
        store.revokeResourceServer("meridian-gateway");
        store.seed();
        assertEquals("her own words", terms(store.tiers().get("tier1")).get("purpose"));
        assertEquals("revoked", store.resourceServer("meridian-gateway").get("status"));
        assertEquals(List.of("alice"), backing.owners());
    }

    @Test
    void seedingTwoOwnersAtOnceSeedsEachOnce() throws Exception {
        race(8, () -> {
            backing.owner("carol").seed();
            return null;
        });
        assertEquals(3, backing.owner("carol").tiers().size());
        assertEquals(List.of("alice", "carol"), backing.owners());
    }

    @Test
    void tierEditsApplyInOrderUnderARace() throws Exception {
        race(8, () -> store.updateTier("tier2", StoreContract::bumpVersion));
        assertEquals("alice/advisor-tier2/v10", terms(store.tiers().get("tier2"))
                .get("template_id"), "an edit was lost");
        assertThrows(NoSuchElementException.class,
                () -> store.updateTier("tier-nope", StoreContract::bumpVersion));
    }

    @Test
    void aPublishedTermsVersionNeverChanges() {
        store.publishTerms(Map.of("template_id", "t/v1", "purpose", "original"));
        store.publishTerms(Map.of("template_id", "t/v1", "purpose", "rewritten"));
        assertEquals("original", store.termsDoc("t/v1").get("purpose"));
        store.publishTerms(Map.of("template_id", "a/v1", "purpose", "first"));
        assertEquals(List.of("a/v1", "t/v1"),
                store.termsDocs().stream().map(d -> d.get("template_id")).toList());
    }

    // --- the ledger ---------------------------------------------------------

    @Test
    void theLedgerNamesTheAgentInAColumnNoEntryCanShadow() {
        store.ledgerAdd("promised", "fam_a", "2026-08-01T10:00:00Z", Map.of("tier", "tier1"),
                "jkt:one");
        store.ledgerAdd("touched", "fam_a", "2026-08-01T10:00:01Z",
                Map.of("tool", "get_positions"), "jkt:one");
        store.ledgerAdd("promised", "fam_b", "2026-08-01T11:00:00Z", Map.of("tier", "tier1"),
                "jkt:two");
        store.ledgerAdd("refused", "fam_c", "2026-08-01T12:00:00Z", Map.of("tier", "tier1"),
                null);
        List<Map<String, Object>> all = store.ledger(null);
        assertEquals(4, all.size());
        assertTrue(all.get(3).containsKey("handle"));
        assertNull(all.get(3).get("handle"));
        List<Map<String, Object>> mine = store.ledger("jkt:one");
        assertEquals(List.of("promised", "touched"), mine.stream().map(e -> e.get("kind")).toList());
        assertEquals(List.of(), store.ledger("jkt:nobody"));

        store.ledgerAdd("promised", "fam_d", "2026-08-01T13:00:00Z", Map.of("kind", "spoofed",
                "family", "spoofed", "ts", "spoofed", "handle", "jkt:spoofed"), "jkt:three");
        Map<String, Object> row = store.ledger("jkt:three").getFirst();
        assertEquals(List.of("promised", "fam_d", "2026-08-01T13:00:00Z", "jkt:three"),
                List.of(row.get("kind"), row.get("family"), row.get("ts"), row.get("handle")));
    }

    // --- single-use values ---------------------------------------------------

    @Test
    void aValueSpentAtOnceIsSpentOnceAndOnePastItsExpiryMayBeSpentAgain() throws Exception {
        double later = System.currentTimeMillis() / 1000.0 + 60;
        List<Boolean> results = race(RACERS, () -> store.spendOnce("owner-signature:s1", later));
        assertEquals(1, winners(results));
        assertFalse(store.spendOnce("owner-signature:s1", later), "it did not stay spent");
        store.spendOnce("owner-signature:old", later - 61);
        assertTrue(store.spendOnce("owner-signature:old", later), "an expired value stayed spent");
        assertTrue(backing.owner("carol").spendOnce("owner-signature:s1", later),
                "Alice spending a value spent it for Carol");
    }

    // --- events and owner isolation -----------------------------------------

    @Test
    void anEventReachesASubscriber() throws Exception {
        try (Subscription sub = store.subscribe()) {
            store.notify(Map.of("type", "pending", "family", "fam_evt"));
            Map<String, Object> got = sub.poll(5, TimeUnit.SECONDS);
            assertNotNull(got, "no event arrived");
            assertEquals("fam_evt", got.get("family"));
        }
    }

    @Test
    void ownersCannotSeeEachOther() throws Exception {
        OwnerStore a = store;
        OwnerStore c = backing.owner("carol");
        c.seed();

        a.updateTier("tier1", t -> withPurpose(t, "alice only"));
        assertNotEquals("alice only", terms(c.tiers().get("tier1")).get("purpose"));

        a.putConnection(conn("jkt:alice-agent"));
        assertNull(c.connection("jkt:alice-agent"));
        assertTrue(c.connections().isEmpty());
        assertNull(c.revokeConnection("jkt:alice-agent"));

        a.ledgerAdd("promised", "fam_a", "2026-01-01T00:00:00Z", Map.of("note", "alice"),
                "jkt:alice-agent");
        assertTrue(c.ledger(null).isEmpty());

        a.publishTerms(Map.of("template_id", "alice/advisor-tier1/v9"));
        assertNull(c.termsDoc("alice/advisor-tier1/v9"));

        String ticket = a.mintTicket(negotiation("fam_cross"), 300);
        assertNull(c.peekTicket(ticket));
        assertNull(c.consumeTicket(ticket), "Carol consumed Alice's ticket");
        assertNotNull(a.consumeTicket(ticket), "Carol's attempt burned Alice's ticket");

        a.recordRpt("rpt_cross", "fam_cross", "jkt:alice-agent", null, "tier1");
        assertNull(c.consumeRpt("rpt_cross"));
        assertNull(c.grantForFamily("fam_cross"));
        assertEquals("fam_cross", a.consumeRpt("rpt_cross"));

        a.mintTicket(awaiting("fam_decide_cross"), 300);
        assertFalse(c.decide("fam_decide_cross", "approved", null));
        assertTrue(c.pendingNegotiations().isEmpty());
        assertNull(c.negotiation("fam_decide_cross"));

        String before = String.valueOf(a.resourceServer("meridian-gateway").get("status"));
        assertTrue(c.revokeResourceServer("meridian-gateway"));
        assertEquals(before, a.resourceServer("meridian-gateway").get("status"));

        try (Subscription aliceStream = a.subscribe()) {
            c.notify(Map.of("kind", "carol-only"));
            a.notify(Map.of("kind", "alice-only"));
            Map<String, Object> first = aliceStream.poll(5, TimeUnit.SECONDS);
            assertEquals(Map.of("kind", "alice-only"), first, "Carol's event reached Alice");
            assertNull(aliceStream.poll(300, TimeUnit.MILLISECONDS));
        }
    }

    @Test
    void originRegistrationCannotReplaceAnActiveOrPendingRecord() {
        String client = "https://broker.example";
        Map<String, Object> request = Map.of("resource_uri", client + "/mcp",
                "auth", "origin_signature", "status", "pending", "secret", "");
        Map<String, Object> replacement = Map.of("resource_uri", client + "/different",
                "auth", "origin_signature", "status", "pending", "secret", "");
        assertTrue(store.pendResourceServer(client, request));
        assertFalse(store.pendResourceServer(client, replacement));
        assertTrue(store.approveResourceServer(client, "first consent"));
        assertFalse(store.approveResourceServer(client, "repeat consent"));
        assertFalse(store.pendResourceServer(client, replacement));
        assertEquals(client + "/mcp", store.resourceServer(client).get("resource_uri"));
        assertEquals("first consent", store.resourceServer(client).get("consented"));

        store.touchPat(client, "last issue");
        assertTrue(store.revokeResourceServer(client));
        assertTrue(store.pendResourceServer(client, replacement));
        assertEquals(client + "/different", store.resourceServer(client).get("resource_uri"));
        assertEquals("last issue", store.resourceServer(client).get("last_pat_issued"));
        assertTrue(store.approveResourceServer(client, "second consent"));
        assertEquals("active", store.resourceServer(client).get("status"));
    }

    @Test
    void onlyTheCurrentMembershipCanBeUpdatedOrCleared() {
        store.putOrganization(Map.of("issuer", "https://org.example", "token", "old"));
        store.putOrganization(Map.of("issuer", "https://org.example", "token", "new"));
        assertFalse(store.updateOrganization("old", Map.of("envelope", Map.of())));
        assertFalse(store.clearOrganization("old"));
        assertFalse(store.setOrganizationBlock("old", "handles", "jkt:a", "now"));
        assertTrue(store.setOrganizationBlock("new", "handles", "jkt:a", "now"));
        assertTrue(store.setOrganizationBlock("new", "operators", "https://operator.example", "now"));
        assertTrue(store.updateOrganization("new", Map.of("envelope", Map.of("version", 2))));
        assertEquals(Map.of("handles", Map.of("jkt:a", "now"),
                        "operators", Map.of("https://operator.example", "now")),
                store.organization().get("blocked"));
        assertTrue(store.setOrganizationBlock("new", "handles", "jkt:a", null));
        assertEquals(Map.of("handles", Map.of(), "operators", Map.of("https://operator.example", "now")),
                store.organization().get("blocked"));
        assertTrue(store.clearOrganization("new"));
        assertNull(store.organization());
    }

    @Test
    void mandateChangesOnlyAffectTheCurrentOwnerAndEnrollment() {
        OwnerStore carol = backing.owner("carol");
        String account = "meridian-joint";
        var original = Map.<String, Object>of("account", account, "enrolment", "first");
        var newer = Map.<String, Object>of("account", account, "enrolment", "second");
        store.putMandate(account, original);
        carol.putMandate(account, newer);
        assertTrue(store.markMandateMoved(account, original, List.of("mandate changed")));
        var marked = store.mandates().get(account);
        assertEquals(List.of("mandate changed"), marked.get("moved"));
        assertFalse(store.markMandateMoved(account, marked, List.of("mandate changed")));
        store.putMandate(account, newer);
        assertFalse(store.markMandateMoved(account, original, List.of("stale observation")));
        assertTrue(store.clearMandate(account));
        assertFalse(store.markMandateMoved(account, newer, List.of("stale observation")));
        assertEquals(newer, carol.mandates().get(account));
        assertFalse(store.mandates().containsKey(account));
    }

    @Test
    void onlyTheFirstJointAgreementCanClaimItsFamily() throws Exception {
        String family = "joint_family";
        var digests = race(RACERS, () -> {
            var pending = awaiting(family);
            String digest = "digest-" + Thread.currentThread().threadId();
            pending.put("pending_kind", "joint");
            pending.put("contract_hash", digest);
            pending.put("expires", System.currentTimeMillis() / 1_000.0 + 60);
            return store.beginJointNegotiation(pending) ? digest : "";
        }).stream().filter(digest -> !digest.isEmpty()).toList();
        assertEquals(1, digests.size());
        assertEquals(digests.getFirst(), store.negotiation(family).get("contract_hash"));
        assertTrue(store.decide(family, "approved", Map.of("kind", "owner")));
        var retry = store.negotiation(family);
        retry.put("contract_hash", "other");
        assertFalse(store.beginJointNegotiation(retry));
        assertEquals(digests.getFirst(), store.negotiation(family).get("contract_hash"));
        assertEquals("approved", store.negotiation(family).get("decision"));
        assertNull(backing.owner("carol").negotiation(family));
    }

    // --- Phase D: standing, lineage, operators, trajectory, her tiers ---------
    // Ported from the pinned test_store.py cases for these operations, plus races and
    // owner isolation the replicas rely on.

    static Map<String, Object> member(String handle, String parent) {
        Map<String, Object> conn = new LinkedHashMap<>();
        conn.put("handle", handle);
        conn.put("status", "active");
        conn.put("parent_handle", parent);
        conn.put("first_seen", "2026-09-01T00:00:00Z");
        conn.put("identity", Map.of("level", "pseudonymous"));
        conn.put("label", "test");
        conn.put("last_access", null);
        conn.put("tiers_granted", new ArrayList<>());
        conn.put("tiers_approved", new ArrayList<>());
        conn.put("revocations", 0);
        return conn;
    }

    @Test
    void aTierGrantIsRecordedOnceAndHerApprovalsAreASeparateList() {
        store.putConnection(member("jkt:tiers", null));
        store.noteTierGrant("jkt:tiers", "tier1");
        store.noteTierGrant("jkt:tiers", "tier1");
        store.noteTierGrant("jkt:tiers", "tier2");
        store.noteTierApproval("jkt:tiers", "tier2");
        Map<String, Object> conn = store.connection("jkt:tiers");
        assertEquals(List.of("tier1", "tier2"), conn.get("tiers_granted"));
        assertEquals(List.of("tier2"), conn.get("tiers_approved"));
        store.noteTierGrant("jkt:never-seen", "tier1");
        assertNull(store.connection("jkt:never-seen"), "noting a grant created a connection");
    }

    @Test
    void concurrentGrantsAtDifferentTiersLoseNoneOfThem() throws Exception {
        store.putConnection(member("jkt:race", null));
        List<String> tiers = new ArrayList<>();
        for (int i = 0; i < RACERS; i++) {
            tiers.add("t" + i);
        }
        java.util.concurrent.atomic.AtomicInteger next =
                new java.util.concurrent.atomic.AtomicInteger();
        race(RACERS, () -> {
            String t = tiers.get(next.getAndIncrement());
            store.noteTierGrant("jkt:race", t);
            store.noteTierApproval("jkt:race", t);
            return true;
        });
        Map<String, Object> conn = store.connection("jkt:race");
        assertEquals(new java.util.HashSet<>(tiers),
                new java.util.HashSet<>((List<?>) conn.get("tiers_granted")));
        assertEquals(RACERS, ((List<?>) conn.get("tiers_approved")).size(),
                "a concurrent approval was lost or repeated");
    }

    @Test
    void aLineagePoolsWhatSheApprovedBothWaysAndRevocationWithdrawsIt() {
        store.putConnection(member("jkt:root", null));
        store.putConnection(member("jkt:kid-a", "jkt:root"));
        store.putConnection(member("jkt:kid-b", "jkt:root"));
        store.putConnection(member("jkt:unrelated", null));
        store.noteTierApproval("jkt:root", "tier2");
        store.noteTierApproval("jkt:unrelated", "tier3");
        assertEquals(List.of("tier2"), sorted(store.lineageApprovals("jkt:root")));
        store.noteTierApproval("jkt:kid-a", "tier3");
        assertEquals(List.of("tier2", "tier3"), sorted(store.lineageApprovals("jkt:root")));
        assertEquals(2, store.countChildren("jkt:root"));
        store.revokeConnection("jkt:kid-a");
        assertEquals(List.of("tier2"), sorted(store.lineageApprovals("jkt:root")));
        assertEquals(1, store.countChildren("jkt:root"));
        assertEquals(List.of("tier3"), sorted(store.lineageApprovals("jkt:unrelated")));
    }

    @Test
    void revocationsSurviveReconnection() {
        store.putConnection(member("jkt:again", null));
        store.revokeConnection("jkt:again");
        assertEquals(1, ((Number) store.connection("jkt:again").get("revocations")).intValue());
    }

    @Test
    void tiersCanBeAddedOnceAndRemoved() {
        Map<String, Object> tier = new LinkedHashMap<>();
        tier.put("name", "Statements");
        tier.put("resources", List.of());
        tier.put("ask_me", true);
        tier.put("rules", List.of());
        tier.put("terms", Map.of("template_id", "alice/statements/v1", "purpose", "p",
                "scope", List.of(), "expires_in", 60, "prohibited", List.of()));
        store.createTier("statements", tier);
        assertEquals("Statements", store.tiers().get("statements").get("name"));
        assertThrows(IllegalStateException.class, () -> store.createTier("statements", tier));
        assertTrue(store.deleteTier("statements"));
        assertFalse(store.tiers().containsKey("statements"));
        assertFalse(store.deleteTier("statements"));
    }

    @Test
    void oneOfManyConcurrentCreatesOfOneTierWins() throws Exception {
        Map<String, Object> tier = Map.of("name", "x", "resources", List.of(),
                "terms", Map.of("template_id", "alice/x/v1"));
        List<Boolean> won = race(RACERS, () -> {
            try {
                store.createTier("contested", tier);
                return true;
            } catch (IllegalStateException e) {
                return false;
            }
        });
        assertEquals(1, won.stream().filter(Boolean::booleanValue).count());
    }

    @Test
    void blockedOperatorsRoundTripKeepingTheFirstAnswer() {
        assertEquals(Map.of(), store.blockedOperators());
        store.blockOperator("https://agent.example", "2026-08-11T00:00:00Z");
        store.blockOperator("https://agent.example", "2026-08-12T00:00:00Z");
        assertEquals("2026-08-11T00:00:00Z",
                store.blockedOperators().get("https://agent.example").get("blocked_at"));
        assertTrue(store.unblockOperator("https://agent.example"));
        assertEquals(Map.of(), store.blockedOperators());
        assertFalse(store.unblockOperator("https://agent.example"));
    }

    @Test
    void claimedOriginsAreKeptApartFromBlockedOnes() {
        store.claimOperator("https://alice.example", "2026-08-01T00:00:00Z");
        store.claimOperator("https://alice.example", "2026-08-02T00:00:00Z");
        assertEquals("2026-08-01T00:00:00Z",
                store.ownedOperators().get("https://alice.example").get("claimed_at"));
        store.blockOperator("https://spam.example", "2026-08-01T00:00:00Z");
        assertFalse(store.ownedOperators().containsKey("https://spam.example"));
        assertFalse(store.blockedOperators().containsKey("https://alice.example"));
        assertTrue(store.disclaimOperator("https://alice.example"));
        assertFalse(store.disclaimOperator("https://alice.example"));
        assertFalse(store.ownedOperators().containsKey("https://alice.example"));
    }

    @Test
    void theTrajectoryReadsTheWindowAndOnlyThisAgentsRows() {
        String old = "2026-07-01T00:00:00Z";
        String recent = "2026-08-01T00:00:00Z";
        String since = "2026-07-15T00:00:00Z";
        store.ledgerAdd("denied", "f1", old, Map.of("tier", "tier3"), "jkt:t");
        store.ledgerAdd("denied", "f2", recent, Map.of("tier", "tier3"), "jkt:t");
        store.ledgerAdd("denied", "f3", recent, Map.of("tier", "tier3"), "jkt:t");
        store.ledgerAdd("promised", "f4", recent, Map.of("tier", "tier1"), "jkt:t");
        store.ledgerAdd("denied", "f5", recent, Map.of("tier", "tier3"), "jkt:other");
        store.ledgerAdd("touched", "f4", recent, Map.of("tool", "get_positions", "tier",
                "tier1"), "jkt:t");
        store.ledgerAdd("touched", "f4", recent, Map.of("tool", "get_positions", "tier",
                "tier1"), "jkt:t");
        store.ledgerAdd("touched", "f4", old, Map.of("tool", "get_positions", "tier",
                "tier1"), "jkt:t");
        Map<String, Object> t = store.trajectory("jkt:t", since);
        assertEquals(2, t.get("denials"));
        assertEquals(List.of("tier1", "tier3"), t.get("tiers"));
        assertEquals(2, t.get("calls"));
        assertEquals(1, store.trajectory("jkt:other", since).get("denials"));
        assertEquals(Map.of("denials", 0, "tiers", List.of(), "calls", 0),
                store.trajectory("jkt:none", since));
    }

    @Test
    void aTouchWithNoTierIsNotATierReached() {
        Map<String, Object> noTier = new LinkedHashMap<>();
        noTier.put("tool", "get_positions");
        noTier.put("tier", null);
        store.ledgerAdd("touched", "f", "2026-08-01T00:00:00Z", noTier, "jkt:n");
        store.ledgerAdd("touched", "f", "2026-08-01T00:00:00Z", Map.of("tier", ""), "jkt:n");
        Map<String, Object> t = store.trajectory("jkt:n", "2026-07-01T00:00:00Z");
        assertEquals(List.of(), t.get("tiers"));
        assertEquals(2, t.get("calls"));
    }

    @Test
    void anotherOwnersOperatorsTiersAndLineageAreNotHers() {
        OwnerStore carol = backing.owner("carol");
        carol.seed();
        carol.blockOperator("https://agent.example", "2026-08-01T00:00:00Z");
        carol.claimOperator("https://carol.example", "2026-08-01T00:00:00Z");
        carol.putConnection(member("jkt:root", null));
        carol.putConnection(member("jkt:kid", "jkt:root"));
        carol.noteTierApproval("jkt:root", "tier1");
        carol.createTier("carols", Map.of("name", "c", "resources", List.of(),
                "terms", Map.of("template_id", "carol/carols/v1")));
        carol.ledgerAdd("denied", "f", "2026-08-01T00:00:00Z", Map.of("tier", "tier1"),
                "jkt:root");
        assertEquals(Map.of(), store.blockedOperators());
        assertEquals(Map.of(), store.ownedOperators());
        assertEquals(List.of(), store.lineageApprovals("jkt:root"));
        assertEquals(0, store.countChildren("jkt:root"));
        assertFalse(store.tiers().containsKey("carols"));
        assertFalse(store.deleteTier("carols"));
        assertEquals(0, store.trajectory("jkt:root", "2026-07-01T00:00:00Z").get("denials"));
        store.noteTierGrant("jkt:root", "tier9");
        assertEquals(List.of(), carol.connection("jkt:root").get("tiers_granted"));
    }

    private static List<String> sorted(List<String> values) {
        List<String> out = new ArrayList<>(values);
        java.util.Collections.sort(out);
        return out;
    }

    // --- helpers ------------------------------------------------------------

    @SuppressWarnings("unchecked")
    static Map<String, Object> terms(Map<String, Object> tier) {
        return (Map<String, Object>) tier.get("terms");
    }

    static Map<String, Object> withPurpose(Map<String, Object> tier, String purpose) {
        terms(tier).put("purpose", purpose);
        return bumpVersion(tier);
    }

    static Map<String, Object> bumpVersion(Map<String, Object> tier) {
        String id = String.valueOf(terms(tier).get("template_id"));
        int split = id.lastIndexOf("/v");
        terms(tier).put("template_id", id.substring(0, split) + "/v"
                + (Integer.parseInt(id.substring(split + 2)) + 1));
        return tier;
    }
}
