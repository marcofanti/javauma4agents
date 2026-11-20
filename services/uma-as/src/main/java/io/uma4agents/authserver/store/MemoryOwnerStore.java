package io.uma4agents.authserver.store;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;

/**
 * One owner's state in one process. Every method holds this object's monitor for its
 * whole check and write, which is the atomic step the interface promises; every read
 * hands back a copy.
 */
final class MemoryOwnerStore implements OwnerStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String owner;
    private final Seeds seeds;
    private final Map<String, Map<String, Object>> negotiations = new LinkedHashMap<>();
    private final Map<String, String> tickets = new LinkedHashMap<>();
    private final Map<String, Map<String, Object>> rpts = new LinkedHashMap<>();
    private final List<Map<String, Object>> ledger = new ArrayList<>();
    private final Map<String, Map<String, Object>> connections = new LinkedHashMap<>();
    private final Map<String, Map<String, Object>> terms = new TreeMap<>();
    private final Map<String, Map<String, Object>> tiers = new TreeMap<>();
    private final Map<String, Map<String, Object>> resourceServers = new LinkedHashMap<>();
    private Map<String, Object> organization;
    private final Map<String, Map<String, Object>> mandates = new TreeMap<>();
    private final Map<String, Double> spent = new LinkedHashMap<>();
    private final Map<String, Map<String, Object>> blockedOperators = new LinkedHashMap<>();
    private final Map<String, Map<String, Object>> ownedOperators = new LinkedHashMap<>();
    private final List<Subscription> subscribers = new CopyOnWriteArrayList<>();
    private boolean seeded;

    MemoryOwnerStore(String owner, Seeds seeds) {
        this.owner = owner;
        this.seeds = seeds;
    }

    synchronized boolean seeded() {
        return seeded;
    }

    @Override
    public synchronized void seed() {
        if (seeded) {
            return;
        }
        seeded = true;
        if (tiers.isEmpty()) {
            seeds.tiers().apply(owner).forEach((id, tier) -> tiers.put(id, StoreJson.copy(tier)));
        }
        if (resourceServers.isEmpty()) {
            seeds.resourceServers().apply(owner)
                    .forEach((id, rs) -> resourceServers.put(id, StoreJson.copy(rs)));
        }
    }

    // --- negotiations and tickets -------------------------------------------

    private void keepDecision(Map<String, Object> rec) {
        Map<String, Object> stored = negotiations.get(String.valueOf(rec.get("family")));
        if (stored == null || stored.get("decision") == null) {
            return;
        }
        rec.put("decision", stored.get("decision"));
        if (stored.containsKey("decided_by")) {
            rec.put("decided_by", StoreJson.copy(stored.get("decided_by")));
        }
    }

    @Override
    public synchronized String mintTicket(Map<String, Object> rec, double ttlSeconds) {
        String ticket = "tkt_" + randomToken();
        rec.put("expires", MemoryStore.now() + ttlSeconds);
        Map<String, Object> stored = StoreJson.copy(rec);
        keepDecision(stored);
        String family = String.valueOf(rec.get("family"));
        negotiations.put(family, stored);
        tickets.put(ticket, family);
        return ticket;
    }

    @Override
    public synchronized Map<String, Object> peekTicket(String ticket) {
        String family = tickets.get(ticket == null ? "" : ticket);
        Map<String, Object> rec = family == null ? null : negotiations.get(family);
        if (rec == null || MemoryStore.expiresOf(rec) < MemoryStore.now()) {
            return null;
        }
        return StoreJson.copy(rec);
    }

    @Override
    public synchronized Map<String, Object> consumeTicket(String ticket) {
        String family = tickets.remove(ticket == null ? "" : ticket);
        if (family == null) {
            return null;
        }
        Map<String, Object> rec = negotiations.get(family);
        if (rec == null || MemoryStore.expiresOf(rec) < MemoryStore.now()) {
            return null;
        }
        return StoreJson.copy(rec);
    }

    @Override
    public synchronized Map<String, Object> negotiation(String family) {
        return StoreJson.copy(negotiations.get(family));
    }

    @Override
    public synchronized void saveNegotiation(Map<String, Object> rec) {
        Map<String, Object> stored = StoreJson.copy(rec);
        if (!(stored.get("expires") instanceof Number)) {
            stored.put("expires", MemoryStore.now() + 3600);
        }
        keepDecision(stored);
        negotiations.put(String.valueOf(rec.get("family")), stored);
    }

    @Override
    public synchronized boolean beginJointNegotiation(Map<String, Object> rec) {
        return negotiations.putIfAbsent(String.valueOf(rec.get("family")), StoreJson.copy(rec)) == null;
    }

    @Override
    public synchronized void putMandate(String account, Map<String, Object> record) {
        mandates.put(account, StoreJson.copy(record));
    }

    @Override
    public synchronized Map<String, Map<String, Object>> mandates() {
        return StoreJson.copy(mandates);
    }

    @Override
    public synchronized boolean markMandateMoved(String account, Map<String, Object> expected,
                                                   List<String> changes) {
        var current = mandates.get(account);
        if (!expected.equals(current) || changes.equals(current.get("moved"))) {
            return false;
        }
        current.put("moved", new ArrayList<>(changes));
        return true;
    }

    @Override
    public synchronized boolean clearMandate(String account) {
        return mandates.remove(account) != null;
    }

    @Override
    public synchronized void closeNegotiation(String family) {
        if (family == null || family.isEmpty()) {
            return;
        }
        negotiations.remove(family);
        tickets.values().removeIf(family::equals);
    }

    @Override
    public synchronized int reapExpired() {
        double cutoff = MemoryStore.now();
        List<String> stale = new ArrayList<>();
        negotiations.forEach((family, rec) -> {
            if (MemoryStore.expiresOf(rec) < cutoff) {
                stale.add(family);
            }
        });
        stale.forEach(this::closeNegotiation);
        return stale.size();
    }

    @Override
    public synchronized List<Map<String, Object>> pendingNegotiations() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> rec : negotiations.values()) {
            if ("awaiting-owner".equals(rec.get("state")) && rec.get("decision") == null) {
                out.add(StoreJson.copy(rec));
            }
        }
        return out;
    }

    @Override
    public synchronized boolean decide(String family, String decision,
                                       Map<String, Object> decidedBy) {
        Map<String, Object> rec = negotiations.get(family);
        if (rec == null || !"awaiting-owner".equals(rec.get("state"))
                || rec.get("decision") != null) {
            return false;
        }
        rec.put("decision", decision);
        rec.put("decided_by", StoreJson.copy(decidedBy));
        return true;
    }

    // --- RPTs ---------------------------------------------------------------

    @Override
    public synchronized void recordRpt(String jti, String family, String handle,
                                       Map<String, Object> operation, String tier) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("jti", jti);
        rec.put("consumed", false);
        rec.put("family", family);
        rec.put("operation", StoreJson.copy(operation));
        rec.put("handle", handle);
        rec.put("tier", tier);
        rpts.put(jti, rec);
    }

    @Override
    public synchronized Map<String, Object> rpt(String jti) {
        return StoreJson.copy(rpts.get(jti));
    }

    @Override
    public synchronized String consumeRpt(String jti) {
        Map<String, Object> rec = rpts.get(jti);
        if (rec == null || Boolean.TRUE.equals(rec.get("consumed"))) {
            return null;
        }
        rec.put("consumed", true);
        return String.valueOf(rec.get("family"));
    }

    // --- standing relationships ---------------------------------------------

    @Override
    public synchronized Map<String, Object> connection(String handle) {
        return StoreJson.copy(connections.get(handle));
    }

    @Override
    public synchronized void putConnection(Map<String, Object> conn) {
        connections.put(String.valueOf(conn.get("handle")), StoreJson.copy(conn));
    }

    @Override
    public synchronized List<Map<String, Object>> connections() {
        List<Map<String, Object>> out = new ArrayList<>();
        connections.values().forEach(c -> out.add(StoreJson.copy(c)));
        out.sort(MemoryStore.BY_FIRST_SEEN_DESC);
        return out;
    }

    private static int revocationsOf(Map<String, Object> conn) {
        return conn != null && conn.get("revocations") instanceof Number n ? n.intValue() : 0;
    }

    @Override
    public synchronized boolean admitConnection(Map<String, Object> conn,
                                                int expectedRevocations) {
        String handle = String.valueOf(conn.get("handle"));
        if (revocationsOf(connections.get(handle)) != expectedRevocations) {
            return false;
        }
        connections.put(handle, StoreJson.copy(conn));
        return true;
    }

    @Override
    public synchronized boolean recordRptIfConnected(String jti, String family, String handle,
                                                     Map<String, Object> operation,
                                                     String tier, int expectedRevocations) {
        Map<String, Object> conn = connections.get(handle);
        if (conn == null || !"active".equals(conn.get("status"))
                || revocationsOf(conn) != expectedRevocations) {
            return false;
        }
        recordRpt(jti, family, handle, operation, tier);
        return true;
    }

    @Override
    public synchronized void touchConnection(String handle, String when) {
        Map<String, Object> conn = connections.get(handle);
        if (conn != null) {
            conn.put("last_access", when);
        }
    }

    @Override
    public synchronized Integer revokeConnection(String handle) {
        Map<String, Object> conn = connections.get(handle);
        if (conn == null) {
            return null;
        }
        conn.put("status", "revoked");
        int prior = conn.get("revocations") instanceof Number n ? n.intValue() : 0;
        conn.put("revocations", prior + 1);
        int killed = 0;
        for (Map<String, Object> rec : rpts.values()) {
            if (handle.equals(rec.get("handle")) && !Boolean.TRUE.equals(rec.get("consumed"))) {
                rec.put("consumed", true);
                killed++;
            }
        }
        return killed;
    }

    @Override
    public synchronized void noteTierGrant(String handle, String tierId) {
        appendIfAbsent(connections.get(handle), "tiers_granted", tierId);
    }

    @Override
    public synchronized void noteTierApproval(String handle, String tierId) {
        appendIfAbsent(connections.get(handle), "tiers_approved", tierId);
    }

    @SuppressWarnings("unchecked")
    private static void appendIfAbsent(Map<String, Object> conn, String field, String value) {
        if (conn == null) {
            return;
        }
        List<Object> values = conn.get(field) instanceof List<?> l
                ? new ArrayList<>((List<Object>) l) : new ArrayList<>();
        if (!values.contains(value)) {
            values.add(value);
        }
        conn.put(field, values);
    }

    @Override
    public synchronized List<String> lineageApprovals(String root) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> conn : connections.values()) {
            boolean member = root.equals(conn.get("handle"))
                    || root.equals(conn.get("parent_handle"));
            if (!member || !"active".equals(conn.get("status"))) {
                continue;
            }
            if (conn.get("tiers_approved") instanceof List<?> approved) {
                for (Object tier : approved) {
                    if (!out.contains(String.valueOf(tier))) {
                        out.add(String.valueOf(tier));
                    }
                }
            }
        }
        return out;
    }

    @Override
    public synchronized int countChildren(String handle) {
        int n = 0;
        for (Map<String, Object> conn : connections.values()) {
            if (handle.equals(conn.get("parent_handle")) && "active".equals(conn.get("status"))) {
                n++;
            }
        }
        return n;
    }

    // --- operators ----------------------------------------------------------

    @Override
    public synchronized Map<String, Map<String, Object>> blockedOperators() {
        return StoreJson.copy(blockedOperators);
    }

    @Override
    public synchronized void blockOperator(String origin, String when) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("origin", origin);
        rec.put("blocked_at", when);
        blockedOperators.putIfAbsent(origin, rec);
    }

    @Override
    public synchronized boolean unblockOperator(String origin) {
        return blockedOperators.remove(origin) != null;
    }

    @Override
    public synchronized Map<String, Map<String, Object>> ownedOperators() {
        return StoreJson.copy(ownedOperators);
    }

    @Override
    public synchronized void claimOperator(String origin, String when) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("origin", origin);
        rec.put("claimed_at", when);
        ownedOperators.putIfAbsent(origin, rec);
    }

    @Override
    public synchronized boolean disclaimOperator(String origin) {
        return ownedOperators.remove(origin) != null;
    }

    // --- resource servers ---------------------------------------------------

    @Override
    public synchronized Map<String, Map<String, Object>> resourceServers() {
        return StoreJson.copy(resourceServers);
    }

    @Override
    public synchronized Map<String, Object> resourceServer(String clientId) {
        return StoreJson.copy(resourceServers.get(clientId));
    }

    @Override
    public synchronized void putResourceServer(String clientId, Map<String, Object> rs) {
        resourceServers.put(clientId, StoreJson.copy(rs));
    }

    @Override
    public synchronized boolean pendResourceServer(String clientId,
                                                   Map<String, Object> registration) {
        Map<String, Object> existing = resourceServers.get(clientId);
        if (existing != null && !"revoked".equals(existing.get("status"))) {
            return false;
        }
        Map<String, Object> pending = StoreJson.copy(registration);
        pending.put("last_pat_issued", existing == null ? null : existing.get("last_pat_issued"));
        resourceServers.put(clientId, pending);
        return true;
    }

    @Override
    public synchronized boolean approveResourceServer(String clientId, String consented) {
        Map<String, Object> existing = resourceServers.get(clientId);
        if (existing == null || !"pending".equals(existing.get("status"))) {
            return false;
        }
        existing.put("status", "active");
        existing.put("consented", consented);
        return true;
    }

    @Override
    public synchronized Map<String, Object> updateResourceServerSecret(String clientId,
                                                                    String secret) {
        Map<String, Object> rs = resourceServers.get(clientId);
        if (rs == null) {
            return null;
        }
        rs.put("secret", secret);
        return StoreJson.copy(rs);
    }

    @Override
    public synchronized void touchPat(String clientId, String when) {
        Map<String, Object> rs = resourceServers.get(clientId);
        if (rs != null) {
            rs.put("last_pat_issued", when);
        }
    }

    @Override
    public synchronized boolean revokeResourceServer(String clientId) {
        Map<String, Object> rs = resourceServers.get(clientId);
        if (rs == null) {
            return false;
        }
        rs.put("status", "revoked");
        return true;
    }

    @Override
    public synchronized Map<String, Object> organization() {
        return StoreJson.copy(organization);
    }

    @Override
    public synchronized void putOrganization(Map<String, Object> membership) {
        organization = StoreJson.copy(membership);
    }

    @Override
    public synchronized boolean updateOrganization(String token, Map<String, Object> fields) {
        if (organization == null || !token.equals(organization.get("token"))) {
            return false;
        }
        organization.putAll(StoreJson.copy(fields));
        return true;
    }

    @Override
    public synchronized boolean clearOrganization(String token) {
        if (organization == null || !token.equals(organization.get("token"))) {
            return false;
        }
        organization = null;
        return true;
    }

    @Override
    @SuppressWarnings("unchecked")
    public synchronized boolean setOrganizationBlock(String token, String group, String key,
                                                      String timestamp) {
        if (organization == null || !token.equals(organization.get("token"))) {
            return false;
        }
        Map<String, Object> blocked = (Map<String, Object>) organization.computeIfAbsent(
                "blocked", ignored -> new LinkedHashMap<>());
        Map<String, Object> entries = (Map<String, Object>) blocked.computeIfAbsent(group,
                ignored -> new LinkedHashMap<>());
        if (timestamp == null) {
            entries.remove(key);
        } else {
            entries.put(key, timestamp);
        }
        return true;
    }

    // --- owner-visible documents --------------------------------------------

    @Override
    public synchronized void ledgerAdd(String kind, String family, String ts,
                                       Map<String, Object> entry, String handle) {
        Map<String, Object> row = new LinkedHashMap<>(StoreJson.copy(entry));
        // Columns last, so an entry key can never shadow one of them.
        row.remove("kind");
        row.remove("family");
        row.remove("ts");
        row.remove("handle");
        row.put("kind", kind);
        row.put("family", family);
        row.put("ts", ts);
        row.put("handle", handle);
        ledger.add(row);
    }

    @Override
    public synchronized List<Map<String, Object>> ledger(String handle) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> row : ledger) {
            if (handle == null || handle.equals(row.get("handle"))) {
                out.add(StoreJson.copy(row));
            }
        }
        return out;
    }

    @Override
    public synchronized Map<String, Object> grantForFamily(String family) {
        for (Map<String, Object> rec : rpts.values()) {
            if (family.equals(rec.get("family")) && rec.get("handle") != null) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("handle", rec.get("handle"));
                out.put("tier", rec.get("tier"));
                return out;
            }
        }
        return null;
    }

    @Override
    public synchronized Map<String, Object> trajectory(String handle, String since) {
        int denials = 0;
        int calls = 0;
        java.util.TreeSet<String> tiersSeen = new java.util.TreeSet<>();
        for (Map<String, Object> row : ledger) {
            if (!handle.equals(row.get("handle"))
                    || String.valueOf(row.get("ts")).compareTo(since) < 0) {
                continue;
            }
            if ("denied".equals(row.get("kind"))) {
                denials++;
            }
            if ("touched".equals(row.get("kind"))) {
                calls++;
            }
            if (row.get("tier") instanceof String tier && !tier.isEmpty()) {
                tiersSeen.add(tier);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("denials", denials);
        out.put("tiers", new ArrayList<>(tiersSeen));
        out.put("calls", calls);
        return out;
    }

    @Override
    public synchronized void publishTerms(Map<String, Object> doc) {
        terms.putIfAbsent(String.valueOf(doc.get("template_id")), StoreJson.copy(doc));
    }

    @Override
    public synchronized Map<String, Object> termsDoc(String templateId) {
        return StoreJson.copy(terms.get(templateId));
    }

    @Override
    public synchronized List<Map<String, Object>> termsDocs() {
        return StoreJson.copy(new ArrayList<>(terms.values()));
    }

    // --- her policy ---------------------------------------------------------

    @Override
    public synchronized Map<String, Map<String, Object>> tiers() {
        return StoreJson.copy(new LinkedHashMap<>(tiers));
    }

    @Override
    public synchronized Map<String, Object> updateTier(String tierId,
                                                       UnaryOperator<Map<String, Object>> edit) {
        Map<String, Object> tier = tiers.get(tierId);
        if (tier == null) {
            throw new NoSuchElementException(tierId);
        }
        Map<String, Object> updated = edit.apply(StoreJson.copy(tier));
        tiers.put(tierId, StoreJson.copy(updated));
        return StoreJson.copy(updated);
    }

    @Override
    public synchronized Map<String, Object> createTier(String tierId, Map<String, Object> tier) {
        if (tiers.containsKey(tierId)) {
            throw new IllegalStateException(tierId);
        }
        tiers.put(tierId, StoreJson.copy(tier));
        return StoreJson.copy(tier);
    }

    @Override
    public synchronized boolean deleteTier(String tierId) {
        return tiers.remove(tierId) != null;
    }

    // --- single-use values ---------------------------------------------------

    @Override
    public synchronized boolean spendOnce(String key, double expiresEpochSeconds) {
        double now = MemoryStore.now();
        spent.values().removeIf(expires -> expires < now);
        return spent.putIfAbsent(key, expiresEpochSeconds) == null;
    }

    // --- fan-out ------------------------------------------------------------

    @Override
    public void notify(Map<String, Object> payload) {
        for (Iterator<Subscription> it = subscribers.iterator(); it.hasNext(); ) {
            it.next().deliver(payload);
        }
    }

    @Override
    public Subscription subscribe() {
        Subscription subscription = new Subscription(subscribers::remove);
        subscribers.add(subscription);
        return subscription;
    }

    private static String randomToken() {
        byte[] buf = new byte[24];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
