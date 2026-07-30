package io.uma4agents.authserver;

import io.uma4agents.common.EventLog;

import io.uma4agents.common.CompactJws;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** The Protection API (gateway-side, FedAuthz shape): rreg, perm, introspect, audit. */
@RestController
public class ProtectionController {

    private final AsConfig config;
    private final AsState state;
    private final GrantService grants;

    public ProtectionController(AsConfig config, AsState state, GrantService grants) {
        this.config = config;
        this.state = state;
        this.grants = grants;
    }

    /** Validates and normalizes a FedAuthz §3 resource description, or 400s. */
    private static ResponseEntity<Object> invalidDescription() {
        return ResponseEntity.badRequest().body(Map.of("detail", Map.of(
                "error", "invalid_request",
                "error_description", "resource_scopes (non-empty list) is required")));
    }

    private static Map<String, Object> resourceDescription(Map<String, Object> body) {
        Object scopes = body.get("resource_scopes");
        if (!(scopes instanceof List<?> list) || list.isEmpty()
                || !list.stream().allMatch(s -> s instanceof String str && !str.isEmpty())) {
            return null;
        }
        Map<String, Object> desc = new LinkedHashMap<>();
        desc.put("resource_scopes", new ArrayList<>(list));
        desc.put("name", body.get("name"));
        desc.put("type", body.get("type"));
        desc.put("icon_uri", body.get("icon_uri"));
        desc.put("description", body.get("description"));
        return desc;
    }

    @PostMapping("/rreg")
    public ResponseEntity<Object> registerResource(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> body) {
        grants.requirePat(authorization);
        Map<String, Object> desc = resourceDescription(body);
        if (desc == null) {
            return invalidDescription();
        }
        String rid = body.get("_id") instanceof String id && !id.isEmpty()
                ? id : "res_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        boolean created = !state.resources.containsKey(rid);
        state.resources.put(rid, desc);
        state.log.event("resource.registered", null, "resource_id", rid,
                "scopes", desc.get("resource_scopes"), "created", created);
        ResponseEntity.BodyBuilder response = ResponseEntity.status(created ? 201 : 200);
        if (created) {
            response.header("Location", config.issuer + "/rreg/" + rid);
        }
        return response.body(Map.of(
                "_id", rid,
                "user_access_policy_uri", config.issuer + "/owner/policies"));
    }

    @GetMapping("/rreg")
    public List<String> listResources(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        grants.requirePat(authorization);
        return new ArrayList<>(state.resources.keySet());
    }

    @GetMapping("/rreg/**")
    public ResponseEntity<Object> readResource(
            @RequestHeader(value = "authorization", required = false) String authorization,
            HttpServletRequest request) {
        grants.requirePat(authorization);
        String rid = ridFrom(request);
        Map<String, Object> desc = state.resources.get(rid);
        if (desc == null) {
            return notFound();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("_id", rid);
        desc.forEach((k, v) -> {
            if (v != null) {
                out.put(k, v);
            }
        });
        return ResponseEntity.ok(out);
    }

    @PutMapping("/rreg/**")
    public ResponseEntity<Object> updateResource(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> body, HttpServletRequest request) {
        grants.requirePat(authorization);
        String rid = ridFrom(request);
        if (!state.resources.containsKey(rid)) {
            return notFound();
        }
        Map<String, Object> desc = resourceDescription(body);
        if (desc == null) {
            return invalidDescription();
        }
        state.resources.put(rid, desc);
        state.log.event("resource.updated", null, "resource_id", rid,
                "scopes", desc.get("resource_scopes"));
        return ResponseEntity.ok(Map.of("_id", rid));
    }

    @DeleteMapping("/rreg/**")
    public ResponseEntity<Object> deleteResource(
            @RequestHeader(value = "authorization", required = false) String authorization,
            HttpServletRequest request) {
        grants.requirePat(authorization);
        String rid = ridFrom(request);
        if (state.resources.remove(rid) == null) {
            return notFound();
        }
        state.log.event("resource.deleted", null, "resource_id", rid);
        return ResponseEntity.status(204).build();
    }

    private static String ridFrom(HttpServletRequest request) {
        return request.getRequestURI().substring("/rreg/".length());
    }

    private static ResponseEntity<Object> notFound() {
        return ResponseEntity.status(404).body(Map.of("detail", Map.of("error", "not_found")));
    }

    @PostMapping("/perm")
    public ResponseEntity<Object> registerPermission(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> body) {
        grants.requirePat(authorization);
        String rid = body.get("resource_id") instanceof String id ? id : null;
        Map<String, Object> registered = rid == null ? null : state.resources.get(rid);
        if (registered == null) {
            state.log.event("permission.rejected", null, "resource_id", rid,
                    "reason", "invalid_resource_id");
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_resource_id",
                    "error_description", "resource is not registered at this AS"));
        }
        List<?> scopes = body.get("resource_scopes") instanceof List<?> list ? list : List.of();
        @SuppressWarnings("unchecked")
        List<Object> registeredScopes = (List<Object>) registered.get("resource_scopes");
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
        String ticket = state.newTicket(record);
        state.log.event("permission.registered", family, "resource_id", rid, "scopes", scopes);
        return ResponseEntity.status(201).body(Map.of("ticket", ticket));
    }

    /** A decoded-and-looked-up RPT: claims, live record, or a reason it is dead. */
    private record DecodedRpt(Map<String, Object> claims, Map<String, Object> rec, String err) {}

    private DecodedRpt decodeRpt(String token) {
        Map<String, Object> claims;
        try {
            CompactJws.Parsed parsed = CompactJws.verify(token, state.signingKey.getPublic());
            claims = parsed.claims();
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
        Map<String, Object> rec = state.rpts.get(String.valueOf(claims.getOrDefault("jti", "")));
        if (rec == null) {
            return new DecodedRpt(claims, null, "unknown_token");
        }
        Map<String, Object> conn = state.connections.get(String.valueOf(rec.get("handle")));
        if (conn != null && !"active".equals(conn.get("status"))) {
            return new DecodedRpt(claims, rec, "connection_revoked");
        }
        if (Boolean.TRUE.equals(claims.get("single_use"))
                && Boolean.TRUE.equals(rec.get("consumed"))) {
            return new DecodedRpt(claims, rec, "already_consumed");
        }
        return new DecodedRpt(claims, rec, "");
    }

    @PostMapping(value = "/introspect",
            consumes = org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> introspect(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestParam("token") String token,
            @RequestParam(value = "consume", required = false) String consume) {
        grants.requirePat(authorization);
        DecodedRpt decoded = decodeRpt(token);
        if (!decoded.err().isEmpty()) {
            // RFC 7662 permits additional members. Without a reason the PEP
            // cannot tell "come back after re-negotiating" from "the owner
            // revoked you and re-negotiating is pointless" — and sends revoked
            // agents round a loop.
            String family = decoded.rec() == null ? null
                    : String.valueOf(decoded.rec().get("family"));
            state.log.event("rpt.introspected", family, "result", decoded.err());
            return Map.of("active", false, "error", decoded.err());
        }
        Map<String, Object> claims = decoded.claims();
        Map<String, Object> rec = decoded.rec();
        String family = String.valueOf(rec.get("family"));

        Map<String, Object> conn = state.connections.get(String.valueOf(rec.get("handle")));
        if (conn != null) {
            conn.put("last_access", EventLog.utcNow());
        }
        // Consumption is no longer done here by default: the PEP has not yet
        // verified proof-of-possession at this point, so burning the token now
        // lets an unsigned replay destroy a grant the owner just approved. The
        // PEP calls /consume once every check has passed. The parameter is kept
        // for the single-shot case where a caller has already verified.
        if (Boolean.TRUE.equals(claims.get("single_use")) && "true".equals(consume)) {
            synchronized (rec) {
                rec.put("consumed", true);
            }
            state.log.event("rpt.consumed", family, "jti", claims.getOrDefault("jti", ""));
        }

        state.log.event("rpt.introspected", family, "result", "active");
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
        return out;
    }

    /**
     * Burns a single-use RPT — the last step of enforcement, not the first.
     * Split out of introspection so the PEP can verify proof-of-possession and
     * the operation binding <em>before</em> anything is spent. Check-then-act,
     * so the burn itself has to be the atomic step: a caller that loses the
     * race is told so and must deny.
     */
    @PostMapping(value = "/consume",
            consumes = org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> consumeRpt(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestParam("token") String token) {
        grants.requirePat(authorization);
        DecodedRpt decoded = decodeRpt(token);
        if (!decoded.err().isEmpty()) {
            return Map.of("consumed", false, "error", decoded.err());
        }
        if (!Boolean.TRUE.equals(decoded.claims().get("single_use"))) {
            return Map.of("consumed", false, "error", "not_single_use");
        }
        Map<String, Object> rec = decoded.rec();
        synchronized (rec) {
            if (Boolean.TRUE.equals(rec.get("consumed"))) {
                return Map.of("consumed", false, "error", "already_consumed");
            }
            rec.put("consumed", true);
        }
        String family = String.valueOf(rec.get("family"));
        state.log.event("rpt.consumed", family, "jti", decoded.claims().getOrDefault("jti", ""));
        return Map.of("consumed", true, "family", family);
    }

    @PostMapping("/audit/access")
    public Map<String, Object> auditAccess(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> body) {
        grants.requirePat(authorization);
        String family = body.get("family") instanceof String f ? f : "?";
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("tool", body.get("tool"));
        entry.put("summary", body.get("summary"));
        state.ledgerAdd("touched", family, entry);
        state.log.event("access.allowed", family, "tool", body.get("tool"));
        return Map.of("recorded", true);
    }
}
