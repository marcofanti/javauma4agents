package io.uma4agents.authserver.store;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.function.UnaryOperator;

/**
 * One owner's state over the shared pool. Every statement filters on {@code owner}; none
 * can see another owner's rows. The SQL follows the pinned Python store statement for
 * statement, so the two runtimes give the same guarantees over the same DDL.
 */
final class JdbcOwnerStore implements OwnerStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Both writers of a negotiation use this. A decision already on the row is kept, with
     * who made it, whatever the incoming record says: it is routinely a copy read before
     * she answered. Parameters: family, expires, state, decision, rec, owner.
     */
    private static final String UPSERT_NEGOTIATION =
            "INSERT INTO negotiations (family, expires, state, decision, rec, owner) "
            + "VALUES (?, ?, ?, ?, ?::jsonb, ?) "
            + "ON CONFLICT (owner, family) DO UPDATE SET "
            + "  expires = EXCLUDED.expires, state = EXCLUDED.state, "
            + "  decision = COALESCE(negotiations.decision, EXCLUDED.decision), "
            + "  rec = CASE WHEN negotiations.decision IS NULL THEN EXCLUDED.rec "
            + "        ELSE EXCLUDED.rec "
            + "             || jsonb_build_object('decision', negotiations.decision) "
            + "             || CASE WHEN (negotiations.rec -> 'decided_by') IS NOT NULL "
            + "                     THEN jsonb_build_object('decided_by', "
            + "                                             negotiations.rec -> 'decided_by') "
            + "                     ELSE '{}'::jsonb END "
            + "        END";

    private final JdbcStore parent;
    private final String owner;

    JdbcOwnerStore(JdbcStore parent, String owner) {
        this.parent = parent;
        this.owner = owner;
    }

    private Sql sql() {
        return parent.sql();
    }

    private static double now() {
        return System.currentTimeMillis() / 1000.0;
    }

    /**
     * The {@code owners} row is the claim. Replicas racing to seed one owner contend on
     * its primary key; one inserts and seeds, the others wait on the row and find it
     * taken. An owner with policy and no row (a database from before the marker) is
     * claimed without defaults: a table already holding her tiers is one she edits.
     */
    @Override
    public void seed() {
        sql().inTransaction(conn -> {
            String claimed = Sql.one(conn,
                    "INSERT INTO owners (owner) VALUES (?) "
                            + "ON CONFLICT (owner) DO NOTHING RETURNING owner",
                    rs -> rs.getString(1), owner);
            if (claimed == null) {
                return null;
            }
            if (!Boolean.TRUE.equals(Sql.one(conn,
                    "SELECT EXISTS (SELECT 1 FROM tiers WHERE owner = ?)",
                    rs -> rs.getBoolean(1), owner))) {
                for (Map.Entry<String, Map<String, Object>> e
                        : parent.seeds().tiers().apply(owner).entrySet()) {
                    Sql.update(conn, "INSERT INTO tiers (owner, tier_id, tier) "
                            + "VALUES (?, ?, ?::jsonb) ON CONFLICT (owner, tier_id) DO NOTHING",
                            owner, e.getKey(), StoreJson.write(e.getValue()));
                }
            }
            if (!Boolean.TRUE.equals(Sql.one(conn,
                    "SELECT EXISTS (SELECT 1 FROM resource_servers WHERE owner = ?)",
                    rs -> rs.getBoolean(1), owner))) {
                for (Map.Entry<String, Map<String, Object>> e
                        : parent.seeds().resourceServers().apply(owner).entrySet()) {
                    Sql.update(conn, "INSERT INTO resource_servers (owner, client_id, rs) "
                            + "VALUES (?, ?, ?::jsonb) "
                            + "ON CONFLICT (owner, client_id) DO NOTHING",
                            owner, e.getKey(), StoreJson.write(e.getValue()));
                }
            }
            return null;
        });
    }

    // --- negotiations and tickets -------------------------------------------

    @Override
    public String mintTicket(Map<String, Object> rec, double ttlSeconds) {
        String ticket = "tkt_" + randomToken();
        rec.put("expires", now() + ttlSeconds);
        String family = String.valueOf(rec.get("family"));
        sql().inTransaction(conn -> {
            Sql.update(conn, UPSERT_NEGOTIATION, family, (Double) rec.get("expires"),
                    String.valueOf(rec.get("state")), decisionOf(rec), StoreJson.write(rec),
                    owner);
            Sql.update(conn, "INSERT INTO tickets (owner, ticket, family) VALUES (?, ?, ?)",
                    owner, ticket, family);
            return null;
        });
        return ticket;
    }

    @Override
    public Map<String, Object> peekTicket(String ticket) {
        return sql().one(
                "SELECT n.rec::text FROM tickets t JOIN negotiations n "
                        + "ON n.family = t.family AND n.owner = t.owner "
                        + "WHERE t.ticket = ? AND t.owner = ? AND n.expires >= ?",
                rs -> StoreJson.readMap(rs.getString(1)), nonNull(ticket), owner, now());
    }

    /** One statement: the ticket is spent by asking; only the index row is deleted. */
    @Override
    public Map<String, Object> consumeTicket(String ticket) {
        return sql().one(
                "WITH popped AS ("
                        + "  DELETE FROM tickets WHERE ticket = ? AND owner = ? "
                        + "  RETURNING family) "
                        + "SELECT n.rec::text FROM negotiations n "
                        + "  JOIN popped p ON n.family = p.family "
                        + " WHERE n.expires >= ? AND n.owner = ?",
                rs -> StoreJson.readMap(rs.getString(1)), nonNull(ticket), owner, now(), owner);
    }

    @Override
    public Map<String, Object> negotiation(String family) {
        return sql().one("SELECT rec::text FROM negotiations WHERE family = ? AND owner = ?",
                rs -> StoreJson.readMap(rs.getString(1)), family, owner);
    }

    /** An upsert: a negotiation may be stored that no ticket created. */
    @Override
    public void saveNegotiation(Map<String, Object> rec) {
        double expires = rec.get("expires") instanceof Number n ? n.doubleValue() : now() + 3600;
        sql().update(UPSERT_NEGOTIATION, String.valueOf(rec.get("family")), expires,
                String.valueOf(rec.get("state")), decisionOf(rec), StoreJson.write(rec), owner);
    }

    @Override
    public boolean beginJointNegotiation(Map<String, Object> rec) {
        return sql().update("INSERT INTO negotiations (family, expires, state, decision, rec, owner) "
                        + "VALUES (?, ?, ?, ?, ?::jsonb, ?) ON CONFLICT (owner, family) DO NOTHING",
                String.valueOf(rec.get("family")), ((Number) rec.get("expires")).doubleValue(),
                String.valueOf(rec.get("state")), decisionOf(rec), StoreJson.write(rec), owner) == 1;
    }

    @Override
    public void putMandate(String account, Map<String, Object> record) {
        sql().update("INSERT INTO mandates (owner, account, record) VALUES (?, ?, ?::jsonb) "
                        + "ON CONFLICT (owner, account) DO UPDATE SET record = EXCLUDED.record",
                owner, account, StoreJson.write(record));
    }

    @Override
    public Map<String, Map<String, Object>> mandates() {
        Map<String, Map<String, Object>> records = new LinkedHashMap<>();
        sql().list("SELECT account, record::text FROM mandates WHERE owner = ? ORDER BY account",
                rs -> Map.entry(rs.getString(1), StoreJson.readMap(rs.getString(2))), owner)
                .forEach(entry -> records.put(entry.getKey(), entry.getValue()));
        return records;
    }

    @Override
    public boolean markMandateMoved(String account, Map<String, Object> expected, List<String> changes) {
        String json = StoreJson.write(changes);
        return sql().update("UPDATE mandates SET record = record || jsonb_build_object('moved', ?::jsonb) "
                        + "WHERE owner = ? AND account = ? AND record = ?::jsonb "
                        + "AND record->'moved' IS DISTINCT FROM ?::jsonb",
                json, owner, account, StoreJson.write(expected), json) == 1;
    }

    @Override
    public boolean clearMandate(String account) {
        return sql().update("DELETE FROM mandates WHERE owner = ? AND account = ?", owner, account) == 1;
    }

    @Override
    public void closeNegotiation(String family) {
        if (family == null || family.isEmpty()) {
            return;
        }
        // Tickets cascade.
        sql().update("DELETE FROM negotiations WHERE family = ? AND owner = ?", family, owner);
    }

    @Override
    public int reapExpired() {
        int reaped = sql().update("DELETE FROM negotiations WHERE expires < ? AND owner = ?",
                now(), owner);
        // The event feed is bounded by the same sweep rather than a timer of its own.
        sql().update("DELETE FROM owner_events "
                        + "WHERE ts < now() - make_interval(secs => ?) AND owner = ?",
                (double) JdbcStore.EVENT_RETENTION_SECONDS, owner);
        return reaped;
    }

    @Override
    public List<Map<String, Object>> pendingNegotiations() {
        return sql().list("SELECT rec::text FROM negotiations "
                        + "WHERE state = 'awaiting-owner' AND decision IS NULL AND owner = ?",
                rs -> StoreJson.readMap(rs.getString(1)), owner);
    }

    /** The WHERE clause is the guard; who decided is written by the same statement. */
    @Override
    public boolean decide(String family, String decision, Map<String, Object> decidedBy) {
        String row = sql().one(
                "UPDATE negotiations SET decision = ?, "
                        + "  rec = rec || jsonb_build_object('decision', ?::text, "
                        + "                                  'decided_by', ?::jsonb) "
                        + "WHERE family = ? AND owner = ? AND state = 'awaiting-owner' "
                        + "  AND decision IS NULL RETURNING family",
                rs -> rs.getString(1), decision, decision, StoreJson.write(decidedBy),
                family, owner);
        return row != null;
    }

    // --- RPTs ---------------------------------------------------------------

    @Override
    public void recordRpt(String jti, String family, String handle,
                          Map<String, Object> operation, String tier) {
        sql().update("INSERT INTO rpts (owner, jti, family, handle, operation, consumed, tier) "
                        + "VALUES (?, ?, ?, ?, ?::jsonb, false, ?)",
                owner, jti, family, handle,
                operation == null ? null : StoreJson.write(operation), tier);
    }

    @Override
    public Map<String, Object> rpt(String jti) {
        return sql().one("SELECT jti, family, handle, operation::text, consumed, tier "
                        + "FROM rpts WHERE jti = ? AND owner = ?",
                rs -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("jti", rs.getString(1));
                    out.put("family", rs.getString(2));
                    out.put("handle", rs.getString(3));
                    out.put("consumed", rs.getBoolean(5));
                    String op = rs.getString(4);
                    out.put("operation", op == null || "null".equals(op) ? null
                            : StoreJson.readMap(op));
                    out.put("tier", rs.getString(6));
                    return out;
                }, nonNull(jti), owner);
    }

    /** The statement this store exists for: zero rows means another caller won. */
    @Override
    public String consumeRpt(String jti) {
        return sql().one("UPDATE rpts SET consumed = true "
                        + "WHERE jti = ? AND owner = ? AND consumed = false RETURNING family",
                rs -> rs.getString(1), nonNull(jti), owner);
    }

    // --- standing relationships ---------------------------------------------

    @Override
    public Map<String, Object> connection(String handle) {
        return sql().one("SELECT conn::text FROM connections WHERE handle = ? AND owner = ?",
                rs -> StoreJson.readMap(rs.getString(1)), nonNull(handle), owner);
    }

    @Override
    public void putConnection(Map<String, Object> conn) {
        sql().update("INSERT INTO connections (owner, handle, first_seen, conn) "
                        + "VALUES (?, ?, ?, ?::jsonb) "
                        + "ON CONFLICT (owner, handle) DO UPDATE SET conn = EXCLUDED.conn",
                owner, String.valueOf(conn.get("handle")), String.valueOf(conn.get("first_seen")),
                StoreJson.write(conn));
    }

    @Override
    public List<Map<String, Object>> connections() {
        return sql().list("SELECT conn::text FROM connections WHERE owner = ? "
                        + "ORDER BY first_seen DESC",
                rs -> StoreJson.readMap(rs.getString(1)), owner);
    }

    /** The connection's status and revocation count, its row locked as revoke locks it. */
    private Map.Entry<String, Integer> lockConnection(java.sql.Connection conn, String handle)
            throws java.sql.SQLException {
        return Sql.one(conn, "SELECT conn->>'status', "
                        + "COALESCE((conn->>'revocations')::int, 0) FROM connections "
                        + "WHERE handle = ? AND owner = ? FOR UPDATE",
                rs -> Map.entry(String.valueOf(rs.getString(1)), rs.getInt(2)),
                nonNull(handle), owner);
    }

    @Override
    public boolean admitConnection(Map<String, Object> record, int expectedRevocations) {
        String handle = String.valueOf(record.get("handle"));
        return sql().inTransaction(conn -> {
            Map.Entry<String, Integer> current = lockConnection(conn, handle);
            if (current == null) {
                if (expectedRevocations != 0) {
                    // No record has no revocations; nothing is written for a mismatch.
                    return false;
                }
                String inserted = Sql.one(conn,
                        "INSERT INTO connections (owner, handle, first_seen, conn) "
                                + "VALUES (?, ?, ?, ?::jsonb) "
                                + "ON CONFLICT (owner, handle) DO NOTHING RETURNING handle",
                        rs -> rs.getString(1), owner, handle,
                        String.valueOf(record.get("first_seen")), StoreJson.write(record));
                if (inserted != null) {
                    return true;
                }
                // Another writer created it first: decide against what it wrote.
                current = lockConnection(conn, handle);
            }
            if (current.getValue() != expectedRevocations) {
                return false;
            }
            Sql.update(conn, "UPDATE connections SET conn = ?::jsonb "
                    + "WHERE handle = ? AND owner = ?", StoreJson.write(record), handle, owner);
            return true;
        });
    }

    @Override
    public boolean recordRptIfConnected(String jti, String family, String handle,
                                        Map<String, Object> operation, String tier,
                                        int expectedRevocations) {
        return sql().inTransaction(conn -> {
            Map.Entry<String, Integer> current = lockConnection(conn, handle);
            if (current == null || !"active".equals(current.getKey())
                    || current.getValue() != expectedRevocations) {
                return false;
            }
            Sql.update(conn, "INSERT INTO rpts (owner, jti, family, handle, operation, "
                            + "consumed, tier) VALUES (?, ?, ?, ?, ?::jsonb, false, ?)",
                    owner, jti, family, handle,
                    operation == null ? null : StoreJson.write(operation), tier);
            return true;
        });
    }

    @Override
    public void touchConnection(String handle, String when) {
        sql().update("UPDATE connections "
                        + "SET conn = jsonb_set(conn, '{last_access}', to_jsonb(?::text)) "
                        + "WHERE handle = ? AND owner = ?", when, nonNull(handle), owner);
    }

    /** One transaction: flipping the connection and burning its tokens are one decision. */
    @Override
    public Integer revokeConnection(String handle) {
        return sql().inTransaction(conn -> {
            String row = Sql.one(conn, "UPDATE connections SET conn = jsonb_set("
                            + "  jsonb_set(conn, '{status}', '\"revoked\"'), '{revocations}', "
                            + "  to_jsonb(COALESCE((conn->>'revocations')::int, 0) + 1)) "
                            + "WHERE handle = ? AND owner = ? RETURNING handle",
                    rs -> rs.getString(1), nonNull(handle), owner);
            if (row == null) {
                return null;
            }
            return Sql.update(conn, "UPDATE rpts SET consumed = true "
                    + "WHERE handle = ? AND owner = ? AND consumed = false", handle, owner);
        });
    }

    /** Append-if-absent in one statement, so concurrent grants cannot lose each other's. */
    @Override
    public void noteTierGrant(String handle, String tierId) {
        appendIfAbsent("tiers_granted", handle, tierId);
    }

    @Override
    public void noteTierApproval(String handle, String tierId) {
        appendIfAbsent("tiers_approved", handle, tierId);
    }

    private void appendIfAbsent(String field, String handle, String value) {
        sql().update("UPDATE connections SET conn = jsonb_set("
                        + "  conn, '{" + field + "}',"
                        + "  COALESCE(conn->'" + field + "', '[]'::jsonb) || to_jsonb(?::text)) "
                        + "WHERE handle = ? AND owner = ? "
                        + "  AND NOT COALESCE(conn->'" + field + "', '[]'::jsonb) "
                        + "          @> to_jsonb(?::text)",
                nonNull(value), nonNull(handle), owner, value);
    }

    /** The root and its live children in one statement; the union happens in the database. */
    @Override
    public List<String> lineageApprovals(String root) {
        return sql().list("SELECT DISTINCT t.tier FROM connections c, "
                        + "     jsonb_array_elements_text(c.conn -> 'tiers_approved') AS t(tier) "
                        + "WHERE c.owner = ? AND c.conn ->> 'status' = 'active' "
                        + "  AND (c.handle = ? OR c.conn ->> 'parent_handle' = ?)",
                rs -> rs.getString(1), owner, nonNull(root), root);
    }

    @Override
    public int countChildren(String handle) {
        Integer n = sql().one("SELECT count(*) FROM connections "
                        + "WHERE owner = ? AND conn ->> 'parent_handle' = ? "
                        + "  AND conn ->> 'status' = 'active'",
                rs -> rs.getInt(1), owner, nonNull(handle));
        return n == null ? 0 : n;
    }

    // --- operators ----------------------------------------------------------

    @Override
    public Map<String, Map<String, Object>> blockedOperators() {
        return originTable("SELECT origin, blocked::text FROM blocked_operators WHERE owner = ?");
    }

    @Override
    public void blockOperator(String origin, String when) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("origin", origin);
        rec.put("blocked_at", when);
        sql().update("INSERT INTO blocked_operators (owner, origin, blocked) "
                + "VALUES (?, ?, ?::jsonb) ON CONFLICT (owner, origin) DO NOTHING",
                owner, nonNull(origin), StoreJson.write(rec));
    }

    @Override
    public boolean unblockOperator(String origin) {
        return sql().one("DELETE FROM blocked_operators WHERE origin = ? AND owner = ? "
                + "RETURNING origin", rs -> rs.getString(1), nonNull(origin), owner) != null;
    }

    @Override
    public Map<String, Map<String, Object>> ownedOperators() {
        return originTable("SELECT origin, owned::text FROM owned_operators WHERE owner = ?");
    }

    @Override
    public void claimOperator(String origin, String when) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("origin", origin);
        rec.put("claimed_at", when);
        sql().update("INSERT INTO owned_operators (owner, origin, owned) "
                + "VALUES (?, ?, ?::jsonb) ON CONFLICT (owner, origin) DO NOTHING",
                owner, nonNull(origin), StoreJson.write(rec));
    }

    @Override
    public boolean disclaimOperator(String origin) {
        return sql().one("DELETE FROM owned_operators WHERE origin = ? AND owner = ? "
                + "RETURNING origin", rs -> rs.getString(1), nonNull(origin), owner) != null;
    }

    private Map<String, Map<String, Object>> originTable(String select) {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        sql().list(select, rs -> Map.entry(rs.getString(1), StoreJson.readMap(rs.getString(2))),
                owner).forEach(e -> out.put(e.getKey(), e.getValue()));
        return out;
    }

    // --- resource servers ---------------------------------------------------

    @Override
    public Map<String, Map<String, Object>> resourceServers() {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        sql().list("SELECT client_id, rs::text FROM resource_servers WHERE owner = ? "
                        + "ORDER BY client_id",
                rs -> Map.entry(rs.getString(1), StoreJson.readMap(rs.getString(2))), owner)
                .forEach(e -> out.put(e.getKey(), e.getValue()));
        return out;
    }

    @Override
    public Map<String, Object> resourceServer(String clientId) {
        return sql().one("SELECT rs::text FROM resource_servers "
                        + "WHERE client_id = ? AND owner = ?",
                rs -> StoreJson.readMap(rs.getString(1)), nonNull(clientId), owner);
    }

    @Override
    public void putResourceServer(String clientId, Map<String, Object> rs) {
        sql().update("INSERT INTO resource_servers (owner, client_id, rs) "
                        + "VALUES (?, ?, ?::jsonb) "
                        + "ON CONFLICT (owner, client_id) DO UPDATE SET rs = EXCLUDED.rs",
                owner, clientId, StoreJson.write(rs));
    }

    @Override
    public boolean pendResourceServer(String clientId, Map<String, Object> registration) {
        return sql().one("INSERT INTO resource_servers (owner, client_id, rs) "
                        + "VALUES (?, ?, ?::jsonb) "
                        + "ON CONFLICT (owner, client_id) DO UPDATE SET rs = EXCLUDED.rs "
                        + "|| jsonb_build_object('last_pat_issued', resource_servers.rs->'last_pat_issued') "
                        + "WHERE resource_servers.rs->>'status' = 'revoked' RETURNING client_id",
                row -> row.getString(1), owner, clientId, StoreJson.write(registration)) != null;
    }

    @Override
    public boolean approveResourceServer(String clientId, String consented) {
        return sql().one("UPDATE resource_servers SET rs = rs || "
                        + "jsonb_build_object('status', 'active', 'consented', ?::text) "
                        + "WHERE client_id = ? AND owner = ? AND rs->>'status' = 'pending' "
                        + "RETURNING client_id",
                row -> row.getString(1), consented, clientId, owner) != null;
    }

    /** One statement: the secret changes and nothing else does. */
    @Override
    public Map<String, Object> updateResourceServerSecret(String clientId, String secret) {
        return sql().one("UPDATE resource_servers "
                        + "SET rs = jsonb_set(rs, '{secret}', to_jsonb(?::text)) "
                        + "WHERE client_id = ? AND owner = ? RETURNING rs::text",
                rs -> StoreJson.readMap(rs.getString(1)), secret, nonNull(clientId), owner);
    }

    @Override
    public void touchPat(String clientId, String when) {
        sql().update("UPDATE resource_servers "
                        + "SET rs = jsonb_set(rs, '{last_pat_issued}', to_jsonb(?::text)) "
                        + "WHERE client_id = ? AND owner = ?", when, clientId, owner);
    }

    @Override
    public boolean revokeResourceServer(String clientId) {
        return sql().one("UPDATE resource_servers "
                        + "SET rs = jsonb_set(rs, '{status}', '\"revoked\"') "
                        + "WHERE client_id = ? AND owner = ? RETURNING client_id",
                rs -> rs.getString(1), nonNull(clientId), owner) != null;
    }

    @Override
    public Map<String, Object> organization() {
        return sql().one("SELECT record::text FROM organizations WHERE owner = ?",
                row -> StoreJson.readMap(row.getString(1)), owner);
    }

    @Override
    public void putOrganization(Map<String, Object> membership) {
        sql().update("INSERT INTO organizations (owner, record) VALUES (?, ?::jsonb) "
                        + "ON CONFLICT (owner) DO UPDATE SET record = EXCLUDED.record",
                owner, StoreJson.write(membership));
    }

    @Override
    public boolean updateOrganization(String token, Map<String, Object> fields) {
        return sql().one("UPDATE organizations SET record = record || ?::jsonb "
                        + "WHERE owner = ? AND record->>'token' = ? RETURNING owner",
                row -> row.getString(1), StoreJson.write(fields), owner, token) != null;
    }

    @Override
    public boolean clearOrganization(String token) {
        return sql().one("DELETE FROM organizations WHERE owner = ? AND record->>'token' = ? "
                        + "RETURNING owner",
                row -> row.getString(1), owner, token) != null;
    }

    @Override
    public boolean setOrganizationBlock(String token, String group, String key, String timestamp) {
        String current = "COALESCE(record->'blocked'->?::text, '{}'::jsonb)";
        String change = timestamp == null ? current + " - ?::text"
                : current + " || jsonb_build_object(?::text, ?::text)";
        String update = "UPDATE organizations SET record = record || "
                + "jsonb_build_object('blocked', COALESCE(record->'blocked', '{}'::jsonb) "
                + "|| jsonb_build_object(?::text, " + change + ")) "
                + "WHERE owner = ? AND record->>'token' = ? RETURNING owner";
        Object[] bind = timestamp == null ? new Object[] {group, group, key, owner, token}
                : new Object[] {group, group, key, timestamp, owner, token};
        return sql().one(update, row -> row.getString(1), bind) != null;
    }

    // --- owner-visible documents --------------------------------------------

    @Override
    public void ledgerAdd(String kind, String family, String ts, Map<String, Object> entry,
                          String handle) {
        sql().update("INSERT INTO ledger (owner, kind, family, ts, entry, handle) "
                        + "VALUES (?, ?, ?, ?, ?::jsonb, ?)",
                owner, kind, family, ts, StoreJson.write(entry), handle);
    }

    @Override
    public List<Map<String, Object>> ledger(String handle) {
        String select = "SELECT kind, family, ts, entry::text, handle FROM ledger ";
        Sql.Row<Map<String, Object>> row = rs -> {
            Map<String, Object> out = new LinkedHashMap<>(StoreJson.readMap(rs.getString(4)));
            // Columns last, so an entry key can never shadow one of them.
            for (String column : List.of("kind", "family", "ts", "handle")) {
                out.remove(column);
            }
            out.put("kind", rs.getString(1));
            out.put("family", rs.getString(2));
            out.put("ts", rs.getString(3));
            out.put("handle", rs.getString(5));
            return out;
        };
        return handle == null
                ? sql().list(select + "WHERE owner = ? ORDER BY seq", row, owner)
                : sql().list(select + "WHERE handle = ? AND owner = ? ORDER BY seq", row,
                        handle, owner);
    }

    @Override
    public Map<String, Object> grantForFamily(String family) {
        return sql().one("SELECT handle, tier FROM rpts WHERE family = ? AND owner = ? "
                        + "AND handle IS NOT NULL ORDER BY jti LIMIT 1",
                rs -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("handle", rs.getString(1));
                    out.put("tier", rs.getString(2));
                    return out;
                }, nonNull(family), owner);
    }

    /**
     * One pass over her ledger. {@code ts} is fixed-width UTC, so the text comparison is a
     * time comparison. A tier recorded as null or empty is not a tier reached.
     */
    @Override
    public Map<String, Object> trajectory(String handle, String since) {
        return sql().one("SELECT count(*) FILTER (WHERE kind = 'denied'), "
                        + "       count(*) FILTER (WHERE kind = 'touched'), "
                        + "       coalesce(array_agg(DISTINCT entry->>'tier') "
                        + "                FILTER (WHERE COALESCE(entry->>'tier', '') <> ''), "
                        + "                '{}') "
                        + "  FROM ledger WHERE handle = ? AND ts >= ? AND owner = ?",
                rs -> {
                    java.sql.Array tiers = rs.getArray(3);
                    java.util.TreeSet<String> sorted = new java.util.TreeSet<>();
                    for (Object tier : (Object[]) tiers.getArray()) {
                        sorted.add(String.valueOf(tier));
                    }
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("denials", rs.getInt(1));
                    out.put("tiers", new java.util.ArrayList<>(sorted));
                    out.put("calls", rs.getInt(2));
                    return out;
                }, nonNull(handle), nonNull(since), owner);
    }

    /** DO NOTHING, not DO UPDATE: a published version's content never changes. */
    @Override
    public void publishTerms(Map<String, Object> doc) {
        sql().update("INSERT INTO terms_docs (owner, template_id, doc) VALUES (?, ?, ?::jsonb) "
                        + "ON CONFLICT (owner, template_id) DO NOTHING",
                owner, String.valueOf(doc.get("template_id")), StoreJson.write(doc));
    }

    @Override
    public Map<String, Object> termsDoc(String templateId) {
        return sql().one("SELECT doc::text FROM terms_docs WHERE template_id = ? AND owner = ?",
                rs -> StoreJson.readMap(rs.getString(1)), nonNull(templateId), owner);
    }

    @Override
    public List<Map<String, Object>> termsDocs() {
        return sql().list("SELECT doc::text FROM terms_docs WHERE owner = ? "
                        + "ORDER BY template_id",
                rs -> StoreJson.readMap(rs.getString(1)), owner);
    }

    // --- her policy ---------------------------------------------------------

    @Override
    public Map<String, Map<String, Object>> tiers() {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        sql().list("SELECT tier_id, tier::text FROM tiers WHERE owner = ? ORDER BY tier_id",
                rs -> Map.entry(rs.getString(1), StoreJson.readMap(rs.getString(2))), owner)
                .forEach(e -> out.put(e.getKey(), e.getValue()));
        return out;
    }

    /** FOR UPDATE, so two edits at once produce two version bumps in order. */
    @Override
    public Map<String, Object> updateTier(String tierId, UnaryOperator<Map<String, Object>> edit) {
        return sql().inTransaction(conn -> {
            Map<String, Object> tier = Sql.one(conn,
                    "SELECT tier::text FROM tiers WHERE tier_id = ? AND owner = ? FOR UPDATE",
                    rs -> StoreJson.readMap(rs.getString(1)), tierId, owner);
            if (tier == null) {
                throw new NoSuchElementException(tierId);
            }
            Map<String, Object> updated = edit.apply(tier);
            Sql.update(conn, "UPDATE tiers SET tier = ?::jsonb WHERE tier_id = ? AND owner = ?",
                    StoreJson.write(updated), tierId, owner);
            return updated;
        });
    }

    /** The uniqueness test and the write are one statement. */
    @Override
    public Map<String, Object> createTier(String tierId, Map<String, Object> tier) {
        String created = sql().one("INSERT INTO tiers (owner, tier_id, tier) "
                        + "VALUES (?, ?, ?::jsonb) "
                        + "ON CONFLICT (owner, tier_id) DO NOTHING RETURNING tier_id",
                rs -> rs.getString(1), owner, nonNull(tierId), StoreJson.write(tier));
        if (created == null) {
            throw new IllegalStateException(tierId);
        }
        return StoreJson.copy(tier);
    }

    @Override
    public boolean deleteTier(String tierId) {
        return sql().one("DELETE FROM tiers WHERE tier_id = ? AND owner = ? RETURNING tier_id",
                rs -> rs.getString(1), nonNull(tierId), owner) != null;
    }

    // --- single-use values ---------------------------------------------------

    /** One INSERT decides it: two replicas receiving the same value cannot both act. */
    @Override
    public boolean spendOnce(String key, double expiresEpochSeconds) {
        sql().update("DELETE FROM spent WHERE owner = ? AND expires < now()", owner);
        return sql().one("INSERT INTO spent (owner, key, expires) "
                        + "VALUES (?, ?, to_timestamp(?)) ON CONFLICT DO NOTHING RETURNING key",
                rs -> rs.getString(1), owner, key, expiresEpochSeconds) != null;
    }

    // --- fan-out ------------------------------------------------------------

    /**
     * The row carries the payload; NOTIFY carries its id, because NOTIFY payloads are capped
     * at 8000 bytes. Every replica's listener receives it and re-reads the row.
     */
    @Override
    public void notify(Map<String, Object> payload) {
        sql().inTransaction(conn -> {
            Long id = Sql.one(conn, "INSERT INTO owner_events (owner, payload) "
                            + "VALUES (?, ?::jsonb) RETURNING id",
                    rs -> rs.getLong(1), owner, StoreJson.write(payload));
            Sql.one(conn, "SELECT pg_notify('owner_events', ?)", rs -> null, String.valueOf(id));
            return null;
        });
    }

    @Override
    public Subscription subscribe() {
        return parent.subscribe(owner);
    }

    private static String decisionOf(Map<String, Object> rec) {
        return rec.get("decision") instanceof String d ? d : null;
    }

    private static String nonNull(String value) {
        return value == null ? "" : value;
    }

    private static String randomToken() {
        byte[] buf = new byte[24];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
