package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.EventLog;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The Protection API (resource-server side): perm, introspect, consume, audit. Registration
 * is declarative: the AS pulls what the resource server publishes.
 */
@RestController
public class ProtectionController {

    private final AsConfig config;
    private final AsState state;
    private final OwnerStore store;
    private final SigningKeys keys;
    private final GrantService grants;
    private final RegistrationPuller puller;
    private final Organization organization;

    public ProtectionController(AsConfig config, AsState state, OwnerStore store,
                                SigningKeys keys, GrantService grants,
                                RegistrationPuller puller, Organization organization) {
        this.config = config;
        this.state = state;
        this.store = store;
        this.keys = keys;
        this.grants = grants;
        this.puller = puller;
        this.organization = organization;
    }

    /**
     * A ticket against her registry, for a resource server that serves the resource and no
     * other. An unknown id, or one not yet known to be served by the asker, may mean the
     * pulled copy is stale, so every approved resource server is read again first.
     */
    @PostMapping("/perm")
    public ResponseEntity<Object> registerPermission(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> body) {
        GrantService.Pat pat = grants.requirePat(authorization);
        String rid = body.get("resource_id") instanceof String id ? id : null;
        Map<String, Object> registered = rid == null ? null : state.resource(rid);
        if (!servedBy(registered, pat.clientId())) {
            puller.pullAll();
            registered = rid == null ? null : state.resource(rid);
        }
        if (!servedBy(registered, pat.clientId())) {
            state.log.event("permission.rejected", null, "resource_id", rid,
                    "reason", "invalid_resource_id");
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_resource_id",
                    "error_description",
                    "resource is not registered at this AS by this resource server"));
        }
        List<?> scopes = body.get("resource_scopes") instanceof List<?> list ? list : List.of();
        List<?> registeredScopes = registered.get("resource_scopes") instanceof List<?> l
                ? l : List.of();
        if (scopes.isEmpty() || !new HashSet<>(registeredScopes).containsAll(scopes)) {
            state.log.event("permission.rejected", null, "resource_id", rid,
                    "reason", "invalid_scope", "requested", scopes);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_scope",
                    "error_description", "requested scopes exceed the registered resource"));
        }
        String family = "fam_" + AsState.urlsafeToken(8);
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("family", family);
        record.put("state", "issued");
        record.put("resource_id", rid);
        record.put("resource_scopes", new ArrayList<>(scopes));
        String ticket = PermissionTickets.mint(store, config.ownerUsername, record);
        state.log.event("permission.registered", family, "resource_id", rid, "scopes", scopes);
        return ResponseEntity.status(201).body(Map.of("ticket", ticket));
    }

    private static boolean servedBy(Map<String, Object> registered, String clientId) {
        return registered != null && registered.get("sources") instanceof List<?> sources
                && sources.contains(clientId);
    }

    /** A decoded-and-looked-up RPT: claims, live record, or a reason it is dead. */
    private record DecodedRpt(Map<String, Object> claims, Map<String, Object> rec, String err) {}

    private DecodedRpt decodeRpt(String token) {
        Map<String, Object> claims;
        try {
            claims = keys.verifyOwn(token).claims();
            if (!config.issuer.equals(claims.get("iss"))) {
                throw new SecurityException("unexpected issuer");
            }
        } catch (Exception e) {
            return new DecodedRpt(null, null, "invalid_signature");
        }
        try {
            TokenVerifiers.checkExpiry(claims);
        } catch (Exception e) {
            return new DecodedRpt(null, null, "expired");
        }
        Map<String, Object> rec = store.rpt(String.valueOf(claims.getOrDefault("jti", "")));
        if (rec == null) {
            return new DecodedRpt(claims, null, "unknown_token");
        }
        Map<String, Object> conn = store.connection(String.valueOf(rec.get("handle")));
        if (conn != null && !"active".equals(conn.get("status"))) {
            return new DecodedRpt(claims, rec, "connection_revoked");
        }
        if (Boolean.TRUE.equals(rec.get("consumed"))) {
            // A reusable grant is marked spent only by revoking the connection it was
            // issued under; checking the connection's current status alone would revive
            // it the moment the same agent is admitted again.
            return new DecodedRpt(claims, rec,
                    Boolean.TRUE.equals(claims.get("single_use")) ? "already_consumed"
                            : "revoked");
        }
        return new DecodedRpt(claims, rec, "");
    }

    /**
     * Whose grant this is. A resource server holding one owner's PAT learns nothing about
     * another owner's grants — not whether they are live, spent or revoked — so a mismatch
     * is answered as an unknown token, before any other reason.
     */
    private boolean otherOwners(DecodedRpt decoded, GrantService.Pat pat) {
        if (decoded.claims() == null) {
            return false;
        }
        Object owner = decoded.claims().get("owner");
        String grantOwner = owner instanceof String o && !o.isEmpty() ? o : config.ownerUsername;
        return !grantOwner.equals(pat.owner());
    }

    @PostMapping(value = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> introspect(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestParam("token") String token,
            @RequestParam(value = "consume", required = false) String consume) {
        GrantService.Pat pat = grants.requirePat(authorization);
        DecodedRpt decoded = decodeRpt(token);
        if (otherOwners(decoded, pat)) {
            state.log.event("rpt.introspected", null, "result", "owner_mismatch");
            return Map.of("active", false, "error", "unknown_token");
        }
        if (!decoded.err().isEmpty()) {
            // Without a reason the PEP cannot tell "come back after re-negotiating" from
            // "the owner revoked you", and sends revoked agents round a loop.
            String family = decoded.rec() == null ? null
                    : String.valueOf(decoded.rec().get("family"));
            state.log.event("rpt.introspected", family, "result", decoded.err());
            return Map.of("active", false, "error", decoded.err());
        }
        Map<String, Object> claims = decoded.claims();
        Map<String, Object> rec = decoded.rec();
        if (organizationRevoked(claims, rec)) {
            return Map.of("active", false, "error", "organization_revoked");
        }
        String family = String.valueOf(rec.get("family"));
        if (rec.get("handle") instanceof String handle) {
            store.touchConnection(handle, EventLog.utcNow());
        }
        // Consumption is not done here by default: the PEP has not yet verified
        // proof-of-possession, so burning now would let an unsigned replay destroy a grant
        // the owner just approved. The PEP calls /consume once every check has passed.
        if (Boolean.TRUE.equals(claims.get("single_use")) && "true".equals(consume)) {
            if (store.consumeRpt(String.valueOf(claims.getOrDefault("jti", ""))) == null) {
                state.log.event("rpt.introspected", family, "result", "already_consumed");
                return Map.of("active", false, "error", "already_consumed");
            }
            state.log.event("rpt.consumed", family, "jti", claims.getOrDefault("jti", ""));
        }
        state.log.event("rpt.introspected", family, "result", "active");
        return activeResponse(claims, rec);
    }

    /**
     * The active introspection answer, member for member as at the pin. The RPT's
     * {@code client_id} and {@code owner} stay in the token and are not echoed;
     * {@code consequence} is always present, null until Phase D issues classes;
     * {@code clearance} joins with organization support in E2.
     */
    static Map<String, Object> activeResponse(Map<String, Object> claims,
                                              Map<String, Object> rec) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("active", true);
        out.put("family", rec.get("family"));
        out.put("iss", claims.get("iss"));
        out.put("sub", claims.get("sub"));
        out.put("exp", claims.get("exp"));
        out.put("permissions", claims.get("permissions"));
        out.put("cnf", claims.get("cnf"));
        out.put("contract", claims.get("contract"));
        out.put("single_use", claims.getOrDefault("single_use", false));
        out.put("operation", claims.get("operation"));
        out.put("consequence", claims.get("consequence"));
        if (claims.containsKey("clearance")) {
            out.put("clearance", claims.get("clearance"));
        }
        return out;
    }

    /**
     * Burns a single-use RPT — the last step of enforcement, not the first. The burn is one
     * store statement that decides and writes, so whoever loses the race, on this replica
     * or another, is told so and must deny.
     */
    @PostMapping(value = "/consume", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> consumeRpt(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestParam("token") String token) {
        GrantService.Pat pat = grants.requirePat(authorization);
        DecodedRpt decoded = decodeRpt(token);
        if (otherOwners(decoded, pat)) {
            state.log.event("rpt.consume_refused", null, "reason", "owner_mismatch");
            return Map.of("consumed", false, "error", "unknown_token");
        }
        if (!decoded.err().isEmpty()) {
            return Map.of("consumed", false, "error", decoded.err());
        }
        if (organizationRevoked(decoded.claims(), decoded.rec())) {
            return Map.of("consumed", false, "error", "organization_revoked");
        }
        if (!Boolean.TRUE.equals(decoded.claims().get("single_use"))) {
            return Map.of("consumed", false, "error", "not_single_use");
        }
        String family = store.consumeRpt(
                String.valueOf(decoded.claims().getOrDefault("jti", "")));
        if (family == null) {
            return Map.of("consumed", false, "error", "already_consumed");
        }
        state.log.event("rpt.consumed", family, "jti", decoded.claims().getOrDefault("jti", ""));
        return Map.of("consumed", true, "family", family);
    }

    private boolean organizationRevoked(Map<String, Object> claims, Map<String, Object> rec) {
        Object handle = rec.get("handle");
        if (handle == null || store.organization() == null) {
            return false;
        }
        Map<String, Object> connection = Organization.object(store.connection((String) handle));
        Map<String, Object> identity = Organization.object(connection.get("identity"));
        return Organization.list(claims.get("permissions")).stream().anyMatch(permission ->
                organization.blockedAgent(Organization.text(
                        Organization.object(permission).get("resource_id")), (String) handle, identity));
    }

    /**
     * The enforcement point reports what it allowed; the authority decides whose it was,
     * from the grant it was issued under. The enforcement point is never told the handle.
     */
    @PostMapping("/audit/access")
    public Map<String, Object> auditAccess(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> body) {
        grants.requirePat(authorization);
        String family = body.get("family") instanceof String f ? f : "?";
        Map<String, Object> grant = store.grantForFamily(family);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("tool", body.get("tool"));
        entry.put("summary", body.get("summary"));
        entry.put("tier", grant == null ? null : grant.get("tier"));
        store.ledgerAdd("touched", family, EventLog.utcNow(), entry,
                grant == null ? null : (String) grant.get("handle"));
        state.log.event("access.allowed", family, "tool", body.get("tool"));
        return Map.of("recorded", true);
    }
}
