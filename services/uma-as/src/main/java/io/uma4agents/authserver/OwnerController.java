package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.authserver.store.Subscription;
import io.uma4agents.common.EventLog;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import tools.jackson.databind.ObjectMapper;

/**
 * The owner API — the portal's backend. Alice authenticates with her OIDC token or a
 * request signed by her own key, whichever the deployment accepts ({@link OwnerAuth}).
 * Everything she reads or changes is her store's, so any replica answers the same.
 */
@RestController
public class OwnerController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AsState state;
    private final OwnerStore store;
    private final PolicyService policy;
    private final GrantService grants;
    private final OwnerAuth ownerAuth;
    private final RegistrationPuller puller;
    private final Organization organization;

    public OwnerController(AsState state, OwnerStore store, PolicyService policy,
                           GrantService grants, OwnerAuth ownerAuth,
                           RegistrationPuller puller, Organization organization) {
        this.state = state;
        this.store = store;
        this.policy = policy;
        this.grants = grants;
        this.ownerAuth = ownerAuth;
        this.puller = puller;
        this.organization = organization;
    }

    /**
     * Everything waiting on her decision, with what was checked and why she is asked:
     * persisted on the negotiation, so a reload shows what a live dialog showed.
     */
    @GetMapping("/owner/pending")
    public List<Map<String, Object>> pending(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        return pendingView();
    }

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> pendingView() {
        java.util.Set<Object> connected = new java.util.HashSet<>();
        for (Map<String, Object> c : store.connections()) {
            if ("active".equals(c.get("status"))) {
                connected.add(c.get("handle"));
            }
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> rec : store.pendingNegotiations()) {
            Map<String, Object> contract = rec.get("contract") instanceof Map<?, ?> c
                    ? (Map<String, Object>) c : Map.of();
            Map<String, Object> template = rec.get("template") instanceof Map<?, ?> t
                    ? (Map<String, Object>) t : Map.of();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("family", rec.get("family"));
            item.put("kind", rec.getOrDefault("pending_kind", "operation"));
            item.put("first_contact", "connection".equals(rec.get("pending_kind"))
                    || !connected.contains(rec.get("handle")));
            item.put("tier", rec.get("tier"));
            item.put("purpose", contract.get("purpose"));
            item.put("operation", contract.get("operation"));
            item.put("reason", contract.get("reason"));
            item.put("mission", contract.get("mission"));
            item.put("prohibited", contract.get("prohibited"));
            item.put("enforced", Py.truthy(template.get("enforced")) ? template.get("enforced")
                    : Map.of());
            item.put("identity", contract.get("_identity"));
            item.put("handle", rec.get("handle"));
            item.put("assurance", rec.getOrDefault("assurance", Map.of()));
            item.put("assurance_notes", rec.getOrDefault("assurance_notes", List.of()));
            item.put("because", rec.getOrDefault("because", List.of()));
            item.put("organization", rec.get("org"));
            item.put("resource_id", rec.get("resource_id"));
            if (rec.containsKey("joint")) {
                item.put("joint", rec.get("joint"));
            }
            out.add(item);
        }
        return out;
    }

    /**
     * One pending request, answered. The store's guard decides it, with who decided, in
     * one step: a double tap or two portals produce one decision, and the second gets 404.
     */
    @PostMapping("/owner/pending/{family}/decision")
    public Map<String, Object> decision(@PathVariable String family, HttpServletRequest request,
                                        @RequestBody Map<String, Object> body) {
        String owner = ownerAuth.requireOwner(request);
        return decidePending(family, body, Map.of("kind", "owner", "owner", owner), null);
    }

    Map<String, Object> decidePending(String family, Map<String, Object> body,
                                     Map<String, Object> decidedBy,
                                     Map<String, Object> externalActor) {
        Object decision = body.get("decision");
        if (!"approved".equals(decision) && !"denied".equals(decision)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "decision must be approved|denied");
        }
        if (!store.decide(family, (String) decision, decidedBy)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "no pending negotiation for that family");
        }
        state.log.event("owner.decision", family, "decision", decision, "by", decidedBy);
        // Read after the decision: the negotiation survives it until the grant is issued.
        Map<String, Object> pended = store.negotiation(family);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("decision", decision);
        entry.put("tier", pended == null ? null : pended.get("tier"));
        if (externalActor != null) {
            entry.put("by", externalActor);
        }
        store.ledgerAdd("approved".equals(decision) ? "approved" : "denied", family,
                EventLog.utcNow(), entry, pended == null ? null : (String) pended.get("handle"));
        Map<String, Object> notification = new LinkedHashMap<>();
        notification.put("type", "decided");
        notification.put("family", family);
        notification.put("decision", decision);
        notification.put("by", externalActor);
        store.notify(notification);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("family", family);
        out.put("decision", decision);
        out.put("by", externalActor);
        return out;
    }

    @GetMapping("/owner/resource-servers")
    public List<Map<String, Object>> resourceServers(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        List<Map<String, Object>> out = new ArrayList<>();
        store.resourceServers().forEach((cid, rs) -> {
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
    public Map<String, Object> revokeResourceServer(@PathVariable String clientId,
                                                    HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        if (!store.revokeResourceServer(clientId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown resource server");
        }
        state.log.event("resource_server.revoked", null, "client_id", clientId);
        store.ledgerAdd("revoked", "-", EventLog.utcNow(), Map.of("resource_server", clientId),
                null);
        return Map.of("client_id", clientId, "status", "revoked");
    }

    @PostMapping("/owner/resource-servers/decision")
    public Map<String, Object> decideResourceServer(@RequestBody Map<String, Object> body,
                                                    HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        String clientId = body.get("client_id") instanceof String s ? s.strip() : "";
        String decision = body.get("decision") instanceof String s ? s : "";
        String status = switch (decision) {
            case "approved" -> {
                if (!store.approveResourceServer(clientId, EventLog.utcNow())) {
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                            "no pending registration for that resource server");
                }
                yield "active";
            }
            case "revoked" -> {
                if (!store.revokeResourceServer(clientId)) {
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown resource server");
                }
                yield "revoked";
            }
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "decision must be approved or revoked");
        };
        state.log.event("resource_server." + decision, null, "client_id", clientId);
        store.ledgerAdd(decision, "-", EventLog.utcNow(), Map.of("resource_server", clientId), null);
        store.notify(Map.of("type", "resource_server_decided", "client_id", clientId,
                "status", status));
        return Map.of("client_id", clientId, "status", status);
    }

    /**
     * What her authority protects, joined with the governing tier. The registry is a
     * per-process cache of what resource servers publish, so this listing re-pulls it when
     * it is older than {@code UMA_AS_RESOURCE_REFRESH_S}.
     */
    @GetMapping("/owner/resources")
    public List<Map<String, Object>> resources(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        Map<String, Object> envelope = organization.envelope();
        List<?> granted = Organization.list(envelope.get("grants"));
        var registered = state.resources().keySet();
        boolean missing = granted.stream().anyMatch(pattern -> registered.stream().noneMatch(rid ->
                io.uma4agents.common.OrganizationPatterns.matches(rid, List.of(pattern))));
        if (missing) {
            puller.pullAll();
        } else {
            puller.pullIfStale();
        }
        Map<String, Map<String, Object>> tiers = policy.tiers();
        List<Map<String, Object>> out = new ArrayList<>();
        state.resources().forEach((rid, desc) -> {
            Map.Entry<String, Map<String, Object>> tierEntry =
                    PolicyService.tierForResource(tiers, rid);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("_id", rid);
            item.put("name", desc.get("name") != null ? desc.get("name") : rid);
            item.put("type", desc.get("type"));
            item.put("resource_scopes", desc.get("resource_scopes"));
            item.put("consequence", desc.get("consequence"));
            item.put("tier", tierEntry == null ? null : tierEntry.getKey());
            item.put("tier_name", tierEntry == null ? null : tierEntry.getValue().get("name"));
            item.put("ask_me", tierEntry == null ? null : tierEntry.getValue().get("ask_me"));
            item.put("registered_via", desc.getOrDefault("registered_via", "push"));
            if (io.uma4agents.common.OrganizationEnvelope.reaches(rid, envelope)) {
                item.put("shared_by", envelope.get("name"));
                item.put("granted", io.uma4agents.common.OrganizationPatterns.matches(rid, granted));
                item.put("delegation", envelope.get("delegation"));
            }
            out.add(item);
        });
        out.sort(Comparator.comparing(r -> String.valueOf(r.get("_id"))));
        return out;
    }

    @GetMapping("/owner/policies")
    public Map<String, Map<String, Object>> policies(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        return policy.tiers();
    }

    /** The conditions her rules may use, and which may relax: one source of truth. */
    @GetMapping("/owner/policy-vocabulary")
    public List<Map<String, Object>> policyVocabulary(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        return Rules.vocabulary();
    }

    /**
     * Her new tier: her terms, over resources her authority already protects. A miss
     * re-reads the listings before refusing, as /perm does. A tier deleted and written
     * again continues its numbering, so no id ever names two documents.
     */
    @PostMapping("/owner/policies")
    @SuppressWarnings("unchecked")
    public Map<String, Object> createPolicy(HttpServletRequest request,
                                            @RequestBody Map<String, Object> spec) {
        String owner = ownerAuth.requireOwner(request);
        String tierId = spec.get("id") instanceof String id
                ? io.uma4agents.common.PyStr.strip(id) : "";
        if (spec.get("resources") instanceof List<?> wanted
                && !state.resources().keySet().containsAll(wanted)) {
            puller.pullAll();
        }
        Map<String, Object> tier;
        try {
            List<String> jointPatterns = Organization.jointPatterns(store);
            var jointlyHeld = state.resources().keySet().stream()
                    .filter(resource -> io.uma4agents.common.OrganizationPatterns.matches(resource, jointPatterns))
                    .collect(java.util.stream.Collectors.toSet());
            tier = PolicyService.newTier(tierId, spec, policy.tiers(),
                    state.resources().keySet(), jointlyHeld, owner);
            Map<String, Object> envelope = organization.envelope();
            List<String> excess = io.uma4agents.common.OrganizationEnvelope.wouldExceed(tier,
                    (List<String>) tier.get("resources"), envelope);
            if (!excess.isEmpty()) {
                throw new IllegalArgumentException(String.join("; ", excess));
            }
            PolicyService.clamp(tier, envelope);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
        String prefix = owner + "/" + tierId + "/v";
        int latest = 0;
        for (Map<String, Object> doc : store.termsDocs()) {
            String id = String.valueOf(doc.get("template_id"));
            String rest = id.startsWith(prefix) ? id.substring(prefix.length()) : "";
            if (!rest.isEmpty() && rest.chars().allMatch(Character::isDigit)) {
                latest = Math.max(latest, Integer.parseInt(rest));
            }
        }
        if (latest > 0) {
            ((Map<String, Object>) tier.get("terms")).put("template_id", prefix + (latest + 1));
        }
        Map<String, Object> created;
        try {
            created = store.createTier(tierId, tier);
        } catch (IllegalStateException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "there is already a tier called " + io.uma4agents.common.PyRepr.of(tierId));
        }
        Map<String, Object> terms = (Map<String, Object>) created.get("terms");
        state.log.event("policy.created", null, "tier", tierId,
                "template_id", terms.get("template_id"), "resources", created.get("resources"));
        grants.publishTerms(tierId, created);
        return created;
    }

    /**
     * Removes a tier. Its resources become ungoverned, and an ungoverned resource is
     * denied: a destructive edit withdraws access rather than widening it. Published terms
     * stay, so an agreement signed against them stays checkable.
     */
    @DeleteMapping("/owner/policies/{tierId}")
    public Map<String, Object> deletePolicy(@PathVariable String tierId,
                                            HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        Map<String, Object> held = policy.tiers().get(tierId);
        List<Object> orphaned = held != null && held.get("resources") instanceof List<?> l
                ? new ArrayList<>(l) : new ArrayList<>();
        if (!store.deleteTier(tierId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown tier");
        }
        state.log.event("policy.deleted", null, "tier", tierId, "ungoverned", orphaned);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("deleted", tierId);
        out.put("ungoverned", orphaned);
        return out;
    }

    @PutMapping("/owner/policies/{tierId}")
    public Map<String, Object> updatePolicy(@PathVariable String tierId,
                                            HttpServletRequest request,
                                            @RequestBody Map<String, Object> patch) {
        ownerAuth.requireOwner(request);
        Map<String, Object> updated;
        try {
            updated = policy.updateTier(tierId, patch, organization.envelope());
        } catch (NoSuchElementException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown tier");
        } catch (IllegalArgumentException e) {
            // Her editor shows this text, so it says what is wrong.
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> terms = (Map<String, Object>) updated.get("terms");
        state.log.event("policy.updated", null, "tier", tierId,
                "template_id", terms.get("template_id"));
        // Published at once so its terms URI dereferences from the moment it exists.
        grants.publishTerms(tierId, updated);
        return updated;
    }

    @GetMapping("/owner/connections")
    public List<Map<String, Object>> connections(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        return store.connections();
    }

    /**
     * Deactivating the connection and burning every live grant issued under it is one
     * store step. The agents it introduced go with it, after it, so a negotiation arriving
     * mid-cascade cannot find the parent still active. A lineage is one level deep.
     */
    @PostMapping("/owner/connections/revoke")
    public Map<String, Object> revokeConnection(HttpServletRequest request,
                                                @RequestBody(required = false)
                                                Map<String, Object> body) {
        String owner = ownerAuth.requireOwner(request);
        if (body == null || !(body.get("handle") instanceof String handle) || handle.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "name the connection as {\"handle\": …}");
        }
        Integer killed = store.revokeConnection(handle);
        if (killed == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown connection");
        }
        int[] children = revokeChildren(handle, new java.util.HashSet<>(List.of(handle)));
        int tokens = killed + children[1];
        state.log.event("connection.revoked", null, "handle", handle,
                "rpts_deactivated", tokens, "connections_revoked", children[0], "by", owner);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("rpts_deactivated", tokens);
        if (children[0] > 0) {
            entry.put("connections_revoked", children[0]);
        }
        store.ledgerAdd("revoked", "-", EventLog.utcNow(), entry, handle);
        notifyDecided("revoked");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("handle", handle);
        out.put("status", "revoked");
        out.put("rpts_deactivated", tokens);
        out.put("connections_revoked", children[0]);
        return out;
    }

    /**
     * Revokes the live agents {@code handle} introduced: {connections, tokens}. Handles in
     * {@code done} are skipped and each one revoked is added, because a revocation bumps
     * her count every time it runs and a stale snapshot must not revoke anything twice.
     */
    private int[] revokeChildren(String handle, java.util.Set<String> done) {
        int connections = 0;
        int tokens = 0;
        for (Map<String, Object> conn : store.connections()) {
            String child = String.valueOf(conn.get("handle"));
            if (!handle.equals(conn.get("parent_handle")) || !"active".equals(conn.get("status"))
                    || !done.add(child)) {
                continue;
            }
            Integer killed = store.revokeConnection(child);
            if (killed != null) {
                connections++;
                tokens += killed;
            }
        }
        return new int[] {connections, tokens};
    }

    private void notifyDecided(String decision) {
        Map<String, Object> notification = new LinkedHashMap<>();
        notification.put("type", "decided");
        notification.put("family", "-");
        notification.put("decision", decision);
        notification.put("by", null);
        store.notify(notification);
    }

    // --- operators --------------------------------------------------------

    /**
     * Operators she has met, assembled from her connections, with whether she has shut
     * any out or claimed any as hers, annotated on read.
     */
    @GetMapping("/owner/operators")
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> operators(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        Map<String, Map<String, Object>> blocked = store.blockedOperators();
        Map<String, Map<String, Object>> owned = store.ownedOperators();
        Map<String, Map<String, Object>> seen = new java.util.TreeMap<>();
        for (Map<String, Object> conn : store.connections()) {
            Map<String, Object> identity = conn.get("identity") instanceof Map<?, ?> i
                    ? (Map<String, Object>) i : Map.of();
            String origin = Standing.operatorOrigin(identity);
            if (origin == null) {
                continue;
            }
            Map<String, Object> meta = identity.get("client_metadata") instanceof Map<?, ?> m
                    ? (Map<String, Object>) m : Map.of();
            Map<String, Object> row = seen.computeIfAbsent(origin, o -> operatorRow(o,
                    Py.truthy(meta.get("client_name")) ? meta.get("client_name") : o,
                    blocked, owned));
            row.put("agents", (int) row.get("agents") + 1);
            if ("active".equals(conn.get("status"))) {
                row.put("active", (int) row.get("active") + 1);
            }
        }
        blocked.keySet().forEach(o -> seen.computeIfAbsent(o,
                x -> operatorRow(x, x, blocked, owned)));
        owned.forEach((o, rec) -> {
            Map<String, Object> row = seen.computeIfAbsent(o,
                    x -> operatorRow(x, x, blocked, owned));
            row.put("mine", true);
            row.put("claimed_at", rec.get("claimed_at"));
        });
        return new ArrayList<>(seen.values());
    }

    private static Map<String, Object> operatorRow(String origin, Object name,
                                                   Map<String, Map<String, Object>> blocked,
                                                   Map<String, Map<String, Object>> owned) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("origin", origin);
        row.put("name", name);
        row.put("agents", 0);
        row.put("active", 0);
        row.put("blocked", blocked.containsKey(origin));
        row.put("blocked_at", blocked.containsKey(origin)
                ? blocked.get(origin).get("blocked_at") : null);
        row.put("mine", owned.containsKey(origin));
        row.put("claimed_at", owned.containsKey(origin)
                ? owned.get(origin).get("claimed_at") : null);
        return row;
    }

    private static String originIn(Map<String, Object> body) {
        Object raw = body == null ? null : body.get("origin");
        String origin = Py.truthy(raw) ? io.uma4agents.common.PyStr.strip(String.valueOf(raw))
                : "";
        while (origin.endsWith("/")) {
            origin = origin.substring(0, origin.length() - 1);
        }
        return origin;
    }

    private static void requireHttpsOrigin(String origin) {
        if (!origin.startsWith("https://")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "an operator is named by its https origin");
        }
    }

    /**
     * Says an origin is hers. Never enough alone: an agent is first-party only when this
     * origin is claimed and her authority found its key in that operator's own directory.
     */
    @PostMapping("/owner/operators/claim")
    public Map<String, Object> claimOperator(HttpServletRequest request,
                                             @RequestBody(required = false)
                                             Map<String, Object> body) {
        ownerAuth.requireOwner(request);
        String origin = originIn(body);
        requireHttpsOrigin(origin);
        store.claimOperator(origin, EventLog.utcNow());
        state.log.event("operator.claimed", null, "operator", origin);
        store.ledgerAdd("claimed", "-", EventLog.utcNow(), Map.of("operator", origin), null);
        Map<String, Object> notification = new LinkedHashMap<>();
        notification.put("type", "decided");
        notification.put("family", "-");
        notification.put("decision", "claimed");
        store.notify(notification);
        return Map.of("origin", origin, "status", "mine");
    }

    /** Stops treating an origin as hers, from the next request; revokes nothing. */
    @PostMapping("/owner/operators/disclaim")
    public Map<String, Object> disclaimOperator(HttpServletRequest request,
                                                @RequestBody(required = false)
                                                Map<String, Object> body) {
        ownerAuth.requireOwner(request);
        String origin = originIn(body);
        boolean dropped = store.disclaimOperator(origin);
        state.log.event("operator.disclaimed", null, "operator", origin, "was_claimed", dropped);
        if (dropped) {
            store.ledgerAdd("disclaimed", "-", EventLog.utcNow(), Map.of("operator", origin),
                    null);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("origin", origin);
        out.put("status", "not-mine");
        out.put("was_claimed", dropped);
        return out;
    }

    /**
     * Shuts out every agent of one operator in one action, revoking what is connected and
     * the sub-agents those introduced: a block that left live grants would be a door she
     * believes shut that is still open.
     */
    @PostMapping("/owner/operators/block")
    @SuppressWarnings("unchecked")
    public Map<String, Object> blockOperator(HttpServletRequest request,
                                             @RequestBody(required = false)
                                             Map<String, Object> body) {
        String owner = ownerAuth.requireOwner(request);
        String origin = originIn(body);
        requireHttpsOrigin(origin);
        store.blockOperator(origin, EventLog.utcNow());
        int revoked = 0;
        int tokens = 0;
        java.util.Set<String> done = new java.util.HashSet<>();
        for (Map<String, Object> conn : store.connections()) {
            Map<String, Object> identity = conn.get("identity") instanceof Map<?, ?> i
                    ? (Map<String, Object>) i : Map.of();
            String handle = String.valueOf(conn.get("handle"));
            if (!"active".equals(conn.get("status"))
                    || !origin.equals(Standing.operatorOrigin(identity)) || !done.add(handle)) {
                continue;
            }
            Integer killed = store.revokeConnection(handle);
            if (killed != null) {
                revoked++;
                tokens += killed;
            }
            int[] children = revokeChildren(handle, done);
            revoked += children[0];
            tokens += children[1];
        }
        state.log.event("operator.blocked", null, "operator", origin,
                "connections_revoked", revoked, "rpts_deactivated", tokens, "by", owner);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("operator", origin);
        entry.put("connections_revoked", revoked);
        entry.put("rpts_deactivated", tokens);
        store.ledgerAdd("revoked", "-", EventLog.utcNow(), entry, null);
        notifyDecided("revoked");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("origin", origin);
        out.put("connections_revoked", revoked);
        out.put("rpts_deactivated", tokens);
        return out;
    }

    /** Lets them ask again; what the block revoked stays revoked. */
    @PostMapping("/owner/operators/unblock")
    public Map<String, Object> unblockOperator(HttpServletRequest request,
                                               @RequestBody(required = false)
                                               Map<String, Object> body) {
        String owner = ownerAuth.requireOwner(request);
        String origin = originIn(body);
        if (!store.unblockOperator(origin)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "that operator is not blocked");
        }
        state.log.event("operator.unblocked", null, "operator", origin, "by", owner);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("origin", origin);
        out.put("blocked", false);
        return out;
    }

    @GetMapping("/owner/ledger")
    public List<Map<String, Object>> ledger(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        String handle = request.getParameter("handle");
        return store.ledger(handle == null || handle.isEmpty() ? null : handle);
    }

    /**
     * Her live feed: pending approvals arriving, decisions landing. Fed by her store's
     * subscription, so an event published on any replica reaches the stream this one
     * holds, and no other owner's does.
     */
    @GetMapping("/owner/events")
    public SseEmitter events(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        SseEmitter emitter = new SseEmitter(0L);
        Subscription subscription = store.subscribe();
        Runnable cleanup = subscription::close;
        emitter.onCompletion(cleanup);
        emitter.onTimeout(cleanup);
        emitter.onError(e -> cleanup.run());
        Thread.startVirtualThread(() -> drain(subscription, emitter));
        return emitter;
    }

    private static void drain(Subscription subscription, SseEmitter emitter) {
        try {
            while (true) {
                Map<String, Object> item = subscription.poll(15, TimeUnit.SECONDS);
                if (item == null) {
                    // A comment line: finds a subscriber that has gone away.
                    emitter.send(SseEmitter.event().comment("keepalive"));
                    continue;
                }
                emitter.send(SseEmitter.event()
                        .name(String.valueOf(item.get("type")))
                        .data(MAPPER.writeValueAsString(item)));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException | IllegalStateException e) {
            // The subscriber went away.
        } finally {
            subscription.close();
        }
    }
}
