package io.uma4agents.authserver;

import io.uma4agents.common.EventLog;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * The in-memory world, mirroring the Python module-level dicts. Negotiation
 * records, contracts, and templates are kept as JSON-shaped
 * {@code Map<String,Object>} because their shape leaks directly into wire
 * responses; each record is a single mutable object shared by every rotated
 * ticket that points at it (the UMA single-use ticket rule).
 */
@Component
public class AsState {

    private static final SecureRandom RANDOM = new SecureRandom();

    public final EventLog log = new EventLog("uma-as");
    public final KeyPair signingKey;
    public final Map<String, Object> publicJwk;

    /** resource id → FedAuthz description. */
    public final Map<String, Map<String, Object>> resources = new ConcurrentHashMap<>();
    /**
     * family → negotiation record, alive for the whole negotiation. Keying the
     * record by the ticket instead — the obvious first design — makes it
     * invisible between the pop and the re-insert, so a concurrent
     * /owner/pending misses it and the decision endpoint 404s on a negotiation
     * that plainly exists. The family is the stable identity; the ticket is a
     * credential for it.
     */
    public final Map<String, Map<String, Object>> negotiations = new ConcurrentHashMap<>();
    /** rotating ticket → family (each presentation consumes the index entry). */
    public final Map<String, String> tickets = new ConcurrentHashMap<>();
    /** RPT jti → {consumed, operation, family, handle}. */
    public final Map<String, Map<String, Object>> rpts = new ConcurrentHashMap<>();
    /** promised / touched / approved / refused / connected / revoked entries. */
    public final List<Map<String, Object>> ledger = Collections.synchronizedList(new ArrayList<>());
    /** connection handle → standing-relationship record. */
    public final Map<String, Map<String, Object>> connections = new ConcurrentHashMap<>();
    /** template id → published terms document (append-only version archive). */
    public final Map<String, Map<String, Object>> termsDocs = new ConcurrentHashMap<>();
    /** RS client id → registration (secret, name, status, consented, last_pat_issued). */
    public final Map<String, Map<String, Object>> rsClients = new ConcurrentHashMap<>();

    public AsState(AsConfig config) {
        this.signingKey = EdDsa.loadOrCreate(Path.of(config.keyPath));
        Map<String, Object> jwk = Jwks.okpPublicJwk(signingKey.getPublic());
        jwk.put("kid", AsConfig.KID);
        jwk.put("use", "sig");
        this.publicJwk = jwk;

        Map<String, Object> rs = new LinkedHashMap<>();
        rs.put("secret", config.rsClientSecret);
        rs.put("name", "Meridian Wealth API gateway");
        rs.put("status", "active");
        rs.put("consented", "seeded at provisioning (Alice linked her brokerage)");
        rs.put("last_pat_issued", null);
        rsClients.put(config.rsClientId, rs);
    }

    public static long now() {
        return java.time.Instant.now().getEpochSecond();
    }

    public static String urlsafeToken(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /**
     * Mints a ticket and indexes it to the record's family. The record itself
     * stays in {@code negotiations} throughout.
     */
    public String newTicket(Map<String, Object> record) {
        String ticket = "tkt_" + urlsafeToken(24);
        long ttl = "awaiting-owner".equals(record.get("state"))
                ? AsConfig.PENDING_TTL : AsConfig.TICKET_TTL;
        record.put("expires", now() + ttl);
        String family = (String) record.get("family");
        negotiations.put(family, record);
        tickets.put(ticket, family);
        return ticket;
    }

    /**
     * Burns the presented ticket (UMA single-use) and returns its negotiation.
     * Only the index entry is removed — the negotiation remains addressable by
     * family, so the owner's portal can see and decide a pending request even
     * in the window between one ticket being consumed and its rotation being
     * issued. Null when unknown or expired.
     */
    public Map<String, Object> consumeTicket(String ticket) {
        String family = tickets.remove(ticket == null ? "" : ticket);
        if (family == null) {
            return null;
        }
        Map<String, Object> record = negotiations.get(family);
        if (record == null) {
            return null;
        }
        Object expires = record.get("expires");
        if (expires instanceof Number n && n.longValue() < now()) {
            return null;
        }
        return record;
    }

    /**
     * Drops a finished negotiation and any ticket still indexed to it. Every
     * path out of the grant loop is terminal except need_info and
     * awaiting-owner, so without this the record set grows for the life of the
     * process. The ledger, not this map, is the audit trail.
     */
    public void closeNegotiation(Map<String, Object> record) {
        if (record == null) {
            return;
        }
        String family = (String) record.get("family");
        negotiations.remove(family);
        tickets.values().removeIf(f -> f.equals(family));
    }

    /** Sweeps negotiations whose ticket window has closed with nobody returning. */
    public void reapExpired() {
        long cutoff = now();
        for (Map<String, Object> record : negotiations.values()) {
            if (record.get("expires") instanceof Number n && n.longValue() < cutoff) {
                closeNegotiation(record);
            }
        }
    }

    public void ledgerAdd(String kind, String family, Map<String, Object> entry) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("kind", kind);
        row.put("family", family);
        row.put("ts", EventLog.utcNow());
        row.putAll(entry);
        ledger.add(row);
    }
}
