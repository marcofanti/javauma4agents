package io.uma4agents.authserver;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/** The owner API — the portal's backend, authenticated by Alice's OIDC token. */
@RestController
public class OwnerController {

    private final AsState state;
    private final PolicyService policy;
    private final GrantService grants;
    private final TokenVerifiers verifiers;
    private final SseHub sse;

    public OwnerController(AsState state, PolicyService policy, GrantService grants,
                           TokenVerifiers verifiers, SseHub sse) {
        this.state = state;
        this.policy = policy;
        this.grants = grants;
        this.verifiers = verifiers;
        this.sse = sse;
    }

    @GetMapping("/owner/pending")
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> pending(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> rec : state.negotiations.values()) {
            if ("awaiting-owner".equals(rec.get("state")) && rec.get("decision") == null) {
                Map<String, Object> contract = (Map<String, Object>) rec.get("contract");
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("family", rec.get("family"));
                item.put("kind", rec.getOrDefault("pending_kind", "operation"));
                item.put("tier", rec.get("tier"));
                item.put("purpose", contract.get("purpose"));
                item.put("operation", contract.get("operation"));
                item.put("prohibited", contract.get("prohibited"));
                item.put("identity", contract.get("_identity"));
                item.put("handle", rec.get("handle"));
                out.add(item);
            }
        }
        return out;
    }

    @PostMapping("/owner/pending/{family}/decision")
    public Map<String, Object> decision(
            @PathVariable String family,
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> body) {
        verifiers.requireOwner(authorization);
        Object decision = body.get("decision");
        if (!"approved".equals(decision) && !"denied".equals(decision)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "decision must be approved|denied");
        }
        Map<String, Object> rec = state.negotiations.get(family);
        if (rec == null || !"awaiting-owner".equals(rec.get("state"))) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "no pending negotiation for that family");
        }
        rec.put("decision", decision);
        state.log.event("owner.decision", family, "decision", decision);
        state.ledgerAdd("approved".equals(decision) ? "approved" : "denied", family,
                Map.of("decision", decision));
        Map<String, Object> notification = new LinkedHashMap<>();
        notification.put("type", "decided");
        notification.put("family", family);
        notification.put("decision", decision);
        sse.publish(notification);
        return Map.of("family", family, "decision", decision);
    }

    @GetMapping("/owner/resource-servers")
    public List<Map<String, Object>> resourceServers(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        List<Map<String, Object>> out = new ArrayList<>();
        state.rsClients.forEach((cid, rs) -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("client_id", cid);
            rs.forEach((k, v) -> {
                if (!"secret".equals(k)) {
                    item.put(k, v);
                }
            });
            out.add(item);
        });
        return out;
    }

    @PostMapping("/owner/resource-servers/{clientId}/revoke")
    public Map<String, Object> revokeResourceServer(
            @PathVariable String clientId,
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        Map<String, Object> rs = state.rsClients.get(clientId);
        if (rs == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown resource server");
        }
        rs.put("status", "revoked");
        state.log.event("resource_server.revoked", null, "client_id", clientId);
        state.ledgerAdd("revoked", "-", Map.of("resource_server", clientId));
        return Map.of("client_id", clientId, "status", "revoked");
    }

    @GetMapping("/owner/resources")
    public List<Map<String, Object>> resources(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        List<Map<String, Object>> out = new ArrayList<>();
        state.resources.forEach((rid, desc) -> {
            Map.Entry<String, Map<String, Object>> tierEntry = policy.tierForResource(rid);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("_id", rid);
            item.put("name", desc.get("name") != null ? desc.get("name") : rid);
            item.put("type", desc.get("type"));
            item.put("resource_scopes", desc.get("resource_scopes"));
            item.put("tier", tierEntry == null ? null : tierEntry.getKey());
            item.put("tier_name", tierEntry == null ? null : tierEntry.getValue().get("name"));
            item.put("ask_me", tierEntry == null ? null : tierEntry.getValue().get("ask_me"));
            item.put("registered_via", desc.getOrDefault("registered_via", "push"));
            out.add(item);
        });
        out.sort(Comparator.comparing(r -> String.valueOf(r.get("_id"))));
        return out;
    }

    @GetMapping("/owner/policies")
    public Map<String, Map<String, Object>> policies(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        return policy.tiers();
    }

    @PutMapping("/owner/policies/{tierId}")
    public Map<String, Object> updatePolicy(
            @PathVariable String tierId,
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody Map<String, Object> patch) {
        verifiers.requireOwner(authorization);
        Map<String, Object> updated;
        try {
            updated = policy.updateTier(tierId, patch);
        } catch (java.util.NoSuchElementException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown tier");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> terms = (Map<String, Object>) updated.get("terms");
        state.log.event("policy.updated", null, "tier", tierId,
                "template_id", terms.get("template_id"));
        // Publish the new version immediately so its terms URI dereferences from
        // the moment it exists; earlier versions remain served.
        grants.publishTerms(tierId, updated);
        return updated;
    }

    @GetMapping("/owner/connections")
    public List<Map<String, Object>> connections(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        List<Map<String, Object>> out = new ArrayList<>(state.connections.values());
        out.sort(Comparator.comparing((Map<String, Object> c) ->
                String.valueOf(c.get("first_seen"))).reversed());
        return out;
    }

    @PostMapping("/owner/connections/{handle}/revoke")
    public Map<String, Object> revokeConnection(
            @PathVariable String handle,
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        Map<String, Object> conn = state.connections.get(handle);
        if (conn == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown connection");
        }
        conn.put("status", "revoked");
        int killed = 0;
        for (Map<String, Object> rec : state.rpts.values()) {
            if (handle.equals(rec.get("handle")) && !Boolean.TRUE.equals(rec.get("consumed"))) {
                rec.put("consumed", true);
                killed++;
            }
        }
        state.log.event("connection.revoked", null, "handle", handle,
                "rpts_deactivated", killed);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("handle", handle);
        entry.put("rpts_deactivated", killed);
        state.ledgerAdd("revoked", "-", entry);
        Map<String, Object> notification = new LinkedHashMap<>();
        notification.put("type", "decided");
        notification.put("family", "-");
        notification.put("decision", "revoked");
        sse.publish(notification);
        return Map.of("handle", handle, "status", "revoked", "rpts_deactivated", killed);
    }

    @GetMapping("/owner/ledger")
    public List<Map<String, Object>> ledger(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        synchronized (state.ledger) {
            return new ArrayList<>(state.ledger);
        }
    }

    /** SSE stream for the portal: pending approvals arriving, decisions landing. */
    @GetMapping("/owner/events")
    public SseEmitter events(
            @RequestHeader(value = "authorization", required = false) String authorization) {
        verifiers.requireOwner(authorization);
        return sse.subscribe();
    }
}
