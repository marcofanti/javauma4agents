package io.uma4agents.authserver.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Two independent store instances on one database, each with its own pool and its own
 * listening connection, as two AS replicas have: single use holds across them, competing
 * decisions resolve once, events cross between them for the right owner only, and state
 * survives a restart without being reseeded over.
 */
@Tag("postgres")
class JdbcReplicaTest {

    private PgDsn dsn;
    private JdbcStore a;
    private JdbcStore b;

    @BeforeEach
    void twoReplicas() throws SQLException {
        dsn = PgTestDb.dsn();
        PgTestDb.reset(dsn);
        a = PgTestDb.store(dsn);
        b = PgTestDb.store(dsn);
        a.start();
        b.start();
        a.owner("alice").seed();
        b.owner("alice").seed();
        a.owner("carol").seed();
    }

    @AfterEach
    void shut() {
        // Either replica may be missing: setup stops early when the database is absent.
        if (a != null) {
            a.close();
        }
        if (b != null) {
            b.close();
        }
    }

    /** Alternates the racers between the two replicas. */
    private <T> List<T> raceAcross(BiFunction<OwnerStore, Integer, T> task) throws Exception {
        List<OwnerStore> sides = List.of(a.owner("alice"), b.owner("alice"));
        AtomicInteger next = new AtomicInteger();
        return StoreContract.race(StoreContract.RACERS, () -> {
            int side = next.getAndIncrement() % 2;
            return task.apply(sides.get(side), side);
        });
    }

    @Test
    void seedingTwiceFromTwoReplicasSeedsOnce() {
        assertEquals(3, b.owner("alice").tiers().size());
        assertEquals(List.of("alice", "carol"), b.owners());
    }

    @Test
    void aTicketMintedOnOneReplicaIsSpentOnceAcrossBoth() throws Exception {
        String ticket = a.owner("alice").mintTicket(StoreContract.negotiation("fam_x"), 300);
        List<Map<String, Object>> results = raceAcross((s, i) -> s.consumeTicket(ticket));
        assertEquals(1, StoreContract.winners(results));
    }

    @Test
    void anRptIsBurnedOnceAcrossBoth() throws Exception {
        a.owner("alice").recordRpt("rpt_x", "fam_x", "jkt:x", Map.of("tool", "t"), "tier3");
        List<String> results = raceAcross((s, i) -> s.consumeRpt("rpt_x"));
        assertEquals(List.of("fam_x"), results.stream().filter(Objects::nonNull).toList());
    }

    @Test
    void aRevocationOnOneReplicaSurvivesSecretUpdatesOnTheOther() throws Exception {
        List<Object> results = raceAcross((s, side) -> side == 1
                ? (Object) s.revokeResourceServer("meridian-gateway")
                : s.updateResourceServerSecret("meridian-gateway", "rotated"));
        assertEquals(StoreContract.RACERS, results.size());
        assertEquals("revoked", a.owner("alice").resourceServer("meridian-gateway")
                .get("status"));
    }

    @Test
    void grantsRecordedOnOneReplicaRacingARevocationOnTheOtherAreAllBurned() throws Exception {
        a.owner("alice").putConnection(StoreContract.conn("jkt:rr"));
        var revokerChosen = new AtomicBoolean();
        var grantsAttempted = new AtomicInteger();
        raceAcross((s, side) -> {
            if (side == 1) {
                if (revokerChosen.compareAndSet(false, true)) {
                    assertNotNull(s.revokeConnection("jkt:rr"));
                }
                return null;
            }
            int i = grantsAttempted.getAndIncrement();
            return s.recordRptIfConnected("rpt_rr" + i, "f", "jkt:rr", null, "tier1", 0);
        });
        assertTrue(revokerChosen.get(), "one racer on replica B must revoke the connection");
        assertEquals(StoreContract.RACERS / 2, grantsAttempted.get());
        OwnerStore onB = b.owner("alice");
        assertEquals("revoked", onB.connection("jkt:rr").get("status"));
        for (int i = 0; i < grantsAttempted.get(); i++) {
            Map<String, Object> rpt = onB.rpt("rpt_rr" + i);
            assertTrue(rpt == null || Boolean.TRUE.equals(rpt.get("consumed")),
                    "rpt_rr" + i + " is live under a revoked connection");
        }
    }

    @Test
    void aValueIsSpentOnceAcrossBoth() throws Exception {
        double later = System.currentTimeMillis() / 1000.0 + 60;
        List<Boolean> results = raceAcross((s, i) -> s.spendOnce("owner-signature:x", later));
        assertEquals(1, StoreContract.winners(results));
    }

    @Test
    void competingDecisionsOnTwoReplicasResolveOnce() throws Exception {
        a.owner("alice").mintTicket(StoreContract.awaiting("fam_d"), 300);
        // Replica A always approves and replica B always denies, so the stored answer
        // says which replica won, and it has to be the one that was told it won.
        List<String> results = raceAcross((s, side) -> {
            String d = side == 0 ? "approved" : "denied";
            return s.decide("fam_d", d, Map.of("kind", "owner", "owner", "alice")) ? d : null;
        });
        List<String> won = results.stream().filter(Objects::nonNull).toList();
        assertEquals(1, won.size(), "more than one replica recorded a decision");
        Map<String, Object> stored = b.owner("alice").negotiation("fam_d");
        assertEquals(won.getFirst(), stored.get("decision"),
                "the durable decision is not the one its replica was told it made");
        assertEquals(won.getFirst(), a.owner("alice").negotiation("fam_d").get("decision"));
    }

    @Test
    void aDecisionOnOneReplicaIsCollectedByAPollOnTheOther() {
        OwnerStore onA = a.owner("alice");
        OwnerStore onB = b.owner("alice");
        String ticket = onA.mintTicket(StoreContract.awaiting("fam_poll"), 300);
        Map<String, Object> polled = onB.consumeTicket(ticket);
        assertTrue(onA.decide("fam_poll", "approved", Map.of("kind", "owner", "owner", "alice")));
        String rotated = onB.mintTicket(polled, 300);
        Map<String, Object> collected = onA.consumeTicket(rotated);
        assertEquals("approved", collected.get("decision"));
        assertEquals("fam_poll", collected.get("family"));
    }

    @Test
    void revocationOnOneReplicaKillsGrantsTheOtherWouldSpend() {
        OwnerStore onA = a.owner("alice");
        onA.putConnection(StoreContract.conn("jkt:r"));
        onA.recordRpt("rpt_r", "fam_r", "jkt:r", null, "tier1");
        assertEquals(1, b.owner("alice").revokeConnection("jkt:r"));
        assertNull(onA.consumeRpt("rpt_r"));
        assertTrue(b.owner("alice").revokeResourceServer("meridian-gateway"));
        assertEquals("revoked", onA.resourceServer("meridian-gateway").get("status"));
    }

    @Test
    void anEventOnOneReplicaReachesItsOwnersStreamOnTheOtherAndNoOneElse() throws Exception {
        try (Subscription aliceOnB = b.owner("alice").subscribe();
             Subscription carolOnB = b.owner("carol").subscribe()) {
            a.owner("carol").notify(Map.of("type", "pending", "family", "fam_carol"));
            a.owner("alice").notify(Map.of("type", "pending", "family", "fam_alice"));
            Map<String, Object> got = aliceOnB.poll(5, TimeUnit.SECONDS);
            assertNotNull(got, "no event crossed between replicas");
            assertEquals("fam_alice", got.get("family"));
            assertNull(aliceOnB.poll(300, TimeUnit.MILLISECONDS), "Carol's event reached Alice");
            assertEquals("fam_carol", carolOnB.poll(5, TimeUnit.SECONDS).get("family"));
        }
    }

    @Test
    void aReplicaWhoseListenerWasCutListensAgain() throws Exception {
        try (Subscription sub = b.owner("alice").subscribe()) {
            b.dropListenerForTest();
            long deadline = System.currentTimeMillis() + 15_000;
            Map<String, Object> got = null;
            int sent = 0;
            while (got == null && System.currentTimeMillis() < deadline) {
                a.owner("alice").notify(Map.of("type", "probe", "n", sent++));
                got = sub.poll(500, TimeUnit.MILLISECONDS);
            }
            assertNotNull(got, "the listener never came back");
        }
    }

    @Test
    void stateSurvivesARestartAndTheRestartDoesNotReseedOverIt() {
        OwnerStore onA = a.owner("alice");
        onA.updateTier("tier1", t -> StoreContract.withPurpose(t, "edited before restart"));
        onA.revokeResourceServer("meridian-gateway");
        onA.putConnection(StoreContract.conn("jkt:kept"));
        onA.recordRpt("rpt_kept", "fam_kept", "jkt:kept", null, "tier1");
        String ticket = onA.mintTicket(StoreContract.awaiting("fam_kept"), 300);
        onA.ledgerAdd("promised", "fam_kept", "2026-01-01T00:00:00Z", Map.of(), "jkt:kept");
        a.close();
        b.close();

        a = PgTestDb.store(dsn);
        b = PgTestDb.store(dsn);
        a.start();
        b.start();
        OwnerStore after = a.owner("alice");
        after.seed();
        assertEquals("edited before restart",
                StoreContract.terms(after.tiers().get("tier1")).get("purpose"));
        assertEquals("revoked", after.resourceServer("meridian-gateway").get("status"));
        assertEquals("active", after.connection("jkt:kept").get("status"));
        assertEquals("fam_kept", after.peekTicket(ticket).get("family"));
        assertEquals(1, after.ledger("jkt:kept").size());
        assertEquals("fam_kept", b.owner("alice").consumeRpt("rpt_kept"));
    }

    @Test
    void aDatabaseFromBeforeMultiOwnerIsRefusedAtStartupByName() throws SQLException {
        PgDsn probe = dsn.withDatabase("u4a_upgrade_probe");
        try (Connection admin = PgTestDb.connect(dsn); Statement s = admin.createStatement()) {
            s.execute("DROP DATABASE IF EXISTS u4a_upgrade_probe");
            s.execute("CREATE DATABASE u4a_upgrade_probe");
        }
        try {
            try (Connection conn = PgTestDb.connect(probe); Statement s = conn.createStatement()) {
                s.execute("CREATE TABLE negotiations (family text PRIMARY KEY, state text, "
                        + "decision text, expires double precision, rec jsonb NOT NULL);"
                        + "CREATE TABLE tickets (ticket text PRIMARY KEY, family text NOT NULL, "
                        + "FOREIGN KEY (family) REFERENCES negotiations(family) "
                        + "ON DELETE CASCADE);"
                        + "CREATE TABLE tiers (tier_id text PRIMARY KEY, tier jsonb NOT NULL);");
            }
            JdbcStore old = PgTestDb.store(probe);
            long started = System.currentTimeMillis();
            SchemaTooOld refused = assertThrows(SchemaTooOld.class, old::start);
            assertTrue(System.currentTimeMillis() - started < 2000,
                    "a stale schema was retried as if the database were unreachable");
            List<String> named = new ArrayList<>();
            for (String t : List.of("negotiations", "tickets", "tiers", "connections", "rpts")) {
                if (refused.getMessage().contains(t)) {
                    named.add(t);
                }
            }
            assertEquals(List.of("negotiations", "tickets", "tiers"), named, refused.getMessage());
            assertTrue(refused.getMessage().contains("Recreate the database"));
            old.close();
        } finally {
            try (Connection admin = PgTestDb.connect(dsn);
                 Statement s = admin.createStatement()) {
                s.execute("DROP DATABASE IF EXISTS u4a_upgrade_probe WITH (FORCE)");
            }
        }
    }

    @Test
    void anUnreachableDatabaseIsRetriedThenReportedWithoutItsPassword() {
        PgDsn nowhere = PgDsn.parse("postgres://u4a:hunter2-secret@127.0.0.1:1/u4a");
        JdbcStore store = PgTestDb.store(nowhere);
        StoreException e = assertThrows(StoreException.class, store::start);
        assertTrue(e.getMessage().contains("after 3 attempts"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2-secret"));
    }
}
