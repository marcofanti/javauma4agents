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
    /** current ticket string → shared negotiation record (popped on presentation). */
    public final Map<String, Map<String, Object>> tickets = new ConcurrentHashMap<>();
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

    /** Mints a rotated ticket for the (shared) negotiation record. */
    public String newTicket(Map<String, Object> record) {
        String ticket = "tkt_" + urlsafeToken(24);
        long ttl = "awaiting-owner".equals(record.get("state"))
                ? AsConfig.PENDING_TTL : AsConfig.TICKET_TTL;
        record.put("expires", now() + ttl);
        tickets.put(ticket, record);
        return ticket;
    }

    /** Pops the ticket (UMA single-use); null when unknown or expired. */
    public Map<String, Object> consumeTicket(String ticket) {
        Map<String, Object> record = tickets.remove(ticket == null ? "" : ticket);
        if (record == null) {
            return null;
        }
        Object expires = record.get("expires");
        if (expires instanceof Number n && n.longValue() < now()) {
            return null;
        }
        return record;
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
