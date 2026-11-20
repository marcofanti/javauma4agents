package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.S256;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * Beat 3 and her answer: a committed agreement is verified, recorded as promised, and put
 * through her rules with what her authority can establish (assurance) and what she has
 * seen (standing). It is granted, refused, or put to her, inside her attention budget;
 * once she answers, the poll re-checks what she withdrew since and issues. Ported from the
 * pinned {@code app.py} {@code /token} beat 3, {@code pending_poll} and
 * {@code withdrawn_since_asked}, with organization, clearance and joint branches left to E.
 */
@Component
public class Commitment {

    private final AsConfig config;
    private final AsState state;
    private final OwnerStore store;
    private final PolicyService policy;
    private final GrantService grants;
    private final Standing standing;
    private final Organization organization;

    public Commitment(AsConfig config, AsState state, OwnerStore store, PolicyService policy,
                      GrantService grants, Standing standing, Organization organization) {
        this.config = config;
        this.state = state;
        this.store = store;
        this.policy = policy;
        this.grants = grants;
        this.standing = standing;
        this.organization = organization;
    }

    /** What beat 3 decided about the agent, carried between its steps. */
    private record Asked(Map<String, Object> rec, Map<String, Object> contract,
                         Map<String, Object> identity, Map<String, Object> signerJwk,
                         String contractHash, String handle, String tierId,
                         Map<String, Object> tier) {
        String family() {
            return (String) rec.get("family");
        }
    }

    /** Beat 3: the agreement is committed. */
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> commit(Map<String, Object> rec, String claimToken,
                                         String tierId, Map<String, Object> tier) {
        String family = (String) rec.get("family");
        GrantService.VerifiedContract verified;
        try {
            verified = grants.verifyContract(claimToken, rec);
        } catch (RuntimeException e) {
            state.log.event("contract.rejected", family, "reason", e.getMessage());
            store.closeNegotiation(family);
            return refusal(403, "request_denied", String.valueOf(e.getMessage()));
        }
        byte[] raw = GrantService.base64UrlDecodePadded(claimToken);
        String contractHash = S256.of(raw);
        Map<String, Object> contract = verified.claims();
        rec.put("contract", contract);
        rec.put("contract_hash", contractHash);
        rec.put("agreement_jws", new String(raw, StandardCharsets.UTF_8));
        rec.put("signer_jwk", verified.signerJwk());
        state.log.event("contract.committed", family, "tier", rec.get("tier"),
                "contract", contractHash, "identity", verified.identity().get("level"));
        String handle = grants.connectionHandle(verified.identity(), verified.signerJwk());
        Asked a = new Asked(rec, contract, verified.identity(), verified.signerJwk(),
                contractHash, handle, tierId, tier);
        ledger("promised", family, promised(a), handle);
        return decide(a);
    }

    private Map<String, Object> promised(Asked a) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("tier", a.rec().get("tier"));
        entry.put("purpose", a.contract().get("purpose"));
        entry.put("prohibited", a.contract().get("prohibited"));
        entry.put("expires_in", a.contract().get("expires_in"));
        entry.put("contract", a.contractHash());
        entry.put("terms_uri", a.contract().get("terms_uri"));
        entry.put("operation", a.contract().get("operation"));
        entry.put("reason", a.contract().get("reason"));
        entry.put("mission", a.contract().get("mission"));
        entry.put("consequence", grants.consequenceOf((String) a.rec().get("resource_id")));
        if (Py.truthy(a.rec().get("clearance"))) {
            entry.put("clearance", a.rec().get("clearance"));
        }
        return entry;
    }

    /** Everything between the promise and the grant or the pend, in the pinned order. */
    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> decide(Asked a) {
        Map<String, Object> conn = store.connection(a.handle());
        boolean needsConnection = conn == null || !"active".equals(conn.get("status"));
        // An agent put forward by one she already deals with. Decided here, written only
        // once the request is certain to reach her or a grant.
        Map<String, Object> introducedConn = null;
        String introducedBy = null;
        int parentRevocations = 0;
        Map<String, Object> offered = a.contract().get("introduction") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : null;
        if (needsConnection && (offered != null
                || Py.truthy(a.identity().get("parent_agent")))) {
            Standing.Lineage lineage = standing.introduction(offered, a.identity(), conn);
            if (lineage.parentHandle() != null) {
                introducedBy = lineage.parentHandle();
                parentRevocations = lineage.parentRevocations();
                introducedConn = Standing.introducedConnection(a.handle(), a.identity(),
                        introducedBy, conn);
                conn = introducedConn;
                needsConnection = false;
                state.log.event("connection.introduced", a.family(), "handle", a.handle(),
                        "by", introducedBy);
            } else {
                a.rec().put("introduction_refused", lineage.whyNot());
                state.log.event("connection.introduction_refused", a.family(),
                        "handle", a.handle(), "because", lineage.whyNot());
            }
        }
        String origin = Standing.operatorOrigin(a.identity());
        if (organization.blockedAgent((String) a.rec().get("resource_id"), a.handle(), a.identity())) {
            ledger("org_refused", a.family(), Map.of("tier", a.tierId(), "because",
                    List.of("your organization has shut this agent out of its resources")),
                    a.handle());
            store.closeNegotiation(a.family());
            return refusal(403, "request_denied", "the resource owner's organization has "
                    + "withdrawn this agent's access to its resources");
        }
        if (origin != null && store.blockedOperators().containsKey(origin)) {
            state.log.event("policy.evaluated", a.family(), "result", "operator-blocked",
                    "operator", origin);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("tier", a.rec().get("tier"));
            entry.put("operator", origin);
            entry.put("because", List.of("operator is blocked"));
            return refuse(a, entry, 403,
                    "the owner does not accept agents from " + origin);
        }
        Map<String, Object> axes = Assurance.assess(a.identity());
        Map<String, Object> facts = facts(a, conn, axes);
        Rules.Outcome outcome = Rules.evaluate(a.tier(), facts);
        state.log.event("assurance.assessed", a.family(), "binding", axes.get("binding"),
                "provenance", axes.get("provenance"),
                "accountability", axes.get("accountability"));
        Map<String, Object> verdict = organization.decision(a.rec(), a.contract(), facts);
        if (!verdict.isEmpty()) {
            a.rec().put("org", verdict);
        }
        if (Rules.REFUSE.equals(verdict.get("effect"))) {
            List<?> reasons = Organization.list(verdict.get("because"));
            ledger("org_refused", a.family(), Organization.row("tier", a.tierId(),
                    "organization", verdict.get("organization"), "because", reasons,
                    "charter_version", verdict.get("charter_version")), a.handle());
            store.closeNegotiation(a.family());
            return refusal(403, "request_denied", reasons.isEmpty()
                    ? "the resource owner's organization refused this request"
                    : String.join("; ", reasons.stream().map(String::valueOf).toList()));
        }
        if (Rules.ASK.equals(verdict.get("effect")) && Rules.AUTO.equals(outcome.requirement())) {
            outcome = new Rules.Outcome(Rules.ASK, outcome.because());
        }
        if (Rules.REFUSE.equals(outcome.requirement())) {
            state.log.event("policy.evaluated", a.family(), "result", "refused",
                    "tier", a.rec().get("tier"), "because", outcome.because());
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("tier", a.rec().get("tier"));
            entry.put("because", outcome.because());
            return refuse(a, entry, 403, String.join("; ", outcome.because()));
        }
        boolean needsOperationApproval = Rules.ASK.equals(outcome.requirement());
        ResponseEntity<Object> full = attentionBudget(a, conn, introducedConn, axes,
                needsConnection, needsOperationApproval);
        if (full != null) {
            return full;
        }
        if (introducedConn != null) {
            ResponseEntity<Object> withdrawn = writeIntroduced(a, introducedConn, introducedBy,
                    parentRevocations);
            if (withdrawn != null) {
                return withdrawn;
            }
        }
        if (needsConnection || needsOperationApproval) {
            return pend(a, needsConnection ? "connection" : "operation", axes, outcome.because());
        }
        return autoGrant(a, conn, outcome);
    }

    private Map<String, Object> facts(Asked a, Map<String, Object> conn,
                                      Map<String, Object> axes) {
        @SuppressWarnings("unchecked")
        Map<String, Object> terms = (Map<String, Object>) a.tier().get("terms");
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("expires_in", a.contract().getOrDefault("expires_in", 0));
        request.put("max_expires_in", terms.get("expires_in"));
        request.put("reason", a.contract().get("reason"));
        request.put("mission", a.contract().get("mission"));
        request.put("consequence", grants.consequenceOf((String) a.rec().get("resource_id")));
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("assurance", axes);
        facts.put("standing", Standing.facts(conn, (String) a.rec().get("tier"),
                standing.trajectory(a.handle()), standing.firstParty(a.identity(), axes),
                standing.lineage(conn), AsState.now()));
        facts.put("request", request);
        facts.put("tier", a.rec().get("tier"));
        return facts;
    }

    /**
     * Her attention has a depth limit and only strangers spend it, counted per lane so a
     * flood of anonymous agents cannot crowd out one that can be named. An introduced
     * agent is counted too, with its operation pends. This counts the queue and then
     * admits: two strangers arriving together may both see one free slot, so under
     * concurrent admission a lane can briefly hold more than its budget (the pinned
     * semantics; see PHASE-D-GATES.md).
     */
    private ResponseEntity<Object> attentionBudget(Asked a, Map<String, Object> conn,
                                                   Map<String, Object> introducedConn,
                                                   Map<String, Object> axes,
                                                   boolean needsConnection,
                                                   boolean needsOperationApproval) {
        boolean introduced = introducedConn != null
                || (conn != null && Py.truthy(conn.get("parent_handle")));
        if (!(needsConnection || introducedConn != null
                || (introduced && needsOperationApproval))) {
            return null;
        }
        List<String> counted = introduced ? List.of("connection", "operation")
                : List.of("connection");
        String lane = PolicyService.pendLane(axes);
        int budget = policy.pendBudget(lane);
        int waiting = 0;
        for (Map<String, Object> p : store.pendingNegotiations()) {
            if (a.family().equals(p.get("family"))
                    || !counted.contains(String.valueOf(p.get("pending_kind")))) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> theirs = p.get("assurance") instanceof Map<?, ?> m
                    ? (Map<String, Object>) m : Map.of();
            if (!PolicyService.pendLane(theirs).equals(lane)) {
                continue;
            }
            if ("operation".equals(p.get("pending_kind"))) {
                Map<String, Object> pconn = store.connection(String.valueOf(
                        p.get("handle") == null ? "" : p.get("handle")));
                if (pconn == null || !Py.truthy(pconn.get("parent_handle"))) {
                    continue;
                }
            }
            waiting++;
        }
        if (waiting < budget) {
            return null;
        }
        state.log.event("policy.evaluated", a.family(), "result", "attention-budget",
                "lane", lane, "waiting", waiting, "budget", budget);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("reason", "her queue of agent requests is full");
        entry.put("lane", lane);
        entry.put("waiting", waiting);
        entry.put("budget", budget);
        return refuse(a, entry, 429,
                "the owner is not accepting new agent requests at the moment; try later");
    }

    /**
     * Writes the introduced connection only while the parent is the relationship the
     * introduction was honoured against: active, with the revocation count observed then.
     * Checked before the write and again after it, undoing the write if a revocation (or a
     * revocation and readmission) of the parent landed in between. The write itself is
     * conditional on the child's revocation count, as any admission here is.
     */
    private ResponseEntity<Object> writeIntroduced(Asked a, Map<String, Object> child,
                                                   String parentHandle, int parentRevocations) {
        String noLonger = "the agent that introduced this one is no longer connected";
        if (!parentUnchanged(parentHandle, parentRevocations)) {
            state.log.event("connection.introduction_refused", a.family(), "handle", a.handle(),
                    "because", "the introducing connection is no longer active");
            store.closeNegotiation(a.family());
            return refusal(403, "request_denied", noLonger);
        }
        if (!store.admitConnection(child, TokenController.revocations(child))) {
            return withdrawn(a.rec(), "this agent was revoked after it asked");
        }
        if (!parentUnchanged(parentHandle, parentRevocations)) {
            store.revokeConnection(a.handle());
            state.log.event("connection.introduction_refused", a.family(), "handle", a.handle(),
                    "because", "the introducing connection was revoked as it was admitted");
            store.closeNegotiation(a.family());
            return refusal(403, "request_denied", noLonger);
        }
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("identity", a.identity());
        entry.put("introduced_by", parentHandle);
        ledger("connected", a.family(), entry, a.handle());
        return null;
    }

    private boolean parentUnchanged(String parentHandle, int revocations) {
        Map<String, Object> parent = store.connection(parentHandle);
        return parent != null && "active".equals(parent.get("status"))
                && TokenController.revocations(parent) == revocations;
    }

    private ResponseEntity<Object> pend(Asked a, String kind, Map<String, Object> axes,
                                        List<String> because) {
        Map<String, Object> rec = a.rec();
        rec.put("state", "awaiting-owner");
        rec.put("decision", null);
        rec.put("pending_kind", kind);
        rec.put("handle", a.handle());
        // How many times she had revoked this agent when it asked. A revocation after this
        // point is one her answer did not know about.
        rec.put("revocations_seen", TokenController.revocations(store.connection(a.handle())));
        List<String> notes = Assurance.describe(axes, a.identity());
        rec.put("assurance", axes);
        rec.put("assurance_notes", notes);
        rec.put("because", because);
        String rotated = newTicket(rec);
        state.log.event("ticket.awaiting_owner", a.family(), "tier", rec.get("tier"),
                "kind", kind);
        @SuppressWarnings("unchecked")
        Map<String, Object> template = rec.get("template") instanceof Map<?, ?> t
                ? (Map<String, Object>) t : Map.of();
        Map<String, Object> n = new LinkedHashMap<>();
        n.put("type", "pending");
        n.put("kind", kind);
        n.put("family", a.family());
        n.put("tier", rec.get("tier"));
        n.put("tier_name", a.tier().get("name"));
        n.put("purpose", a.contract().get("purpose"));
        n.put("operation", a.contract().get("operation"));
        n.put("reason", a.contract().get("reason"));
        n.put("mission", a.contract().get("mission"));
        n.put("prohibited", a.contract().get("prohibited"));
        n.put("enforced", Py.truthy(template.get("enforced")) ? template.get("enforced")
                : Map.of());
        n.put("identity", a.identity());
        n.put("handle", a.handle());
        n.put("assurance", axes);
        n.put("assurance_notes", notes);
        n.put("because", because);
        n.put("organization", rec.get("org"));
        store.notify(n);
        state.log.event("owner.notified", a.family(), "kind", kind);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "request_submitted");
        body.put("ticket", rotated);
        body.put("interval", AsConfig.POLL_INTERVAL);
        return ResponseEntity.status(403).body(body);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> autoGrant(Asked a, Map<String, Object> conn,
                                             Rules.Outcome outcome) {
        Map<String, Object> rec = a.rec();
        rec.put("revocations_seen", TokenController.revocations(conn));
        store.touchConnection(a.handle(), EventLog.utcNow());
        store.noteTierGrant(a.handle(), (String) rec.get("tier"));
        state.log.event("policy.evaluated", a.family(), "result", "auto-grant",
                "tier", rec.get("tier"), "connection", a.handle(),
                "because", outcome.because().isEmpty() ? null : outcome.because());
        if (!outcome.because().isEmpty() && Rules.AUTO.equals(outcome.requirement())
                && Py.truthy(a.tier().get("ask_me"))) {
            // A rule she wrote lowered an ask-me tier: the one direction worth auditing.
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("tier", rec.get("tier"));
            entry.put("because", outcome.because());
            ledger("relaxed", a.family(), entry, a.handle());
        }
        return issued(rec, () -> grants.issueRpt(rec, a.contractHash(), a.signerJwk(),
                (Map<String, Object>) a.contract().get("operation")));
    }

    // --- her answer ---------------------------------------------------------

    /** A pending request re-presented after she decided. */
    @SuppressWarnings("unchecked")
    public ResponseEntity<Object> pendingPoll(Map<String, Object> rec) {
        String family = (String) rec.get("family");
        if ("approved".equals(rec.get("decision"))) {
            String why = withdrawnSinceAsked(rec);
            if (why != null) {
                return withdrawn(rec, why);
            }
            Map<String, Object> contract = (Map<String, Object>) rec.get("contract");
            if ("connection".equals(rec.get("pending_kind"))
                    && !admit(rec, (Map<String, Object>) contract.get("_identity"))) {
                return withdrawn(rec, "this agent was revoked after it asked");
            }
            state.log.event("policy.evaluated", family, "result", "owner-approved",
                    "tier", rec.get("tier"));
            noteHerAnswer(rec);
            return issued(rec, () -> grants.issueRpt(rec, (String) rec.get("contract_hash"),
                    (Map<String, Object>) rec.get("signer_jwk"),
                    (Map<String, Object>) contract.get("operation")));
        }
        if ("denied".equals(rec.get("decision"))) {
            state.log.event("policy.evaluated", family, "result", "owner-denied",
                    "tier", rec.get("tier"));
            store.closeNegotiation(family);
            return refusal(403, "request_denied", null);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "request_submitted");
        body.put("ticket", newTicket(rec));
        body.put("interval", AsConfig.POLL_INTERVAL);
        return ResponseEntity.status(403).body(body);
    }

    /**
     * Granted at this tier, and approved here by her in person only when the decision
     * names her: an approval somebody else gave never becomes a fact that relaxes her rules.
     */
    @SuppressWarnings("unchecked")
    private void noteHerAnswer(Map<String, Object> rec) {
        if (!(rec.get("handle") instanceof String handle) || handle.isEmpty()) {
            return;
        }
        String tier = (String) rec.get("tier");
        store.noteTierGrant(handle, tier);
        Map<String, Object> by = rec.get("decided_by") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Map.of();
        Object owner = rec.get("owner") != null ? rec.get("owner") : config.ownerUsername;
        if ("owner".equals(by.get("kind")) && owner.equals(by.get("owner"))) {
            store.noteTierApproval(handle, tier);
        } else {
            state.log.event("policy.evaluated", (String) rec.get("family"),
                    "result", "decided-by-org", "tier", tier, "by", by.get("admin"));
        }
    }

    /**
     * What she withdrew since this request was put to her: an operator she blocked, a
     * revocation, an operation agent no longer connected. Organization and clearance
     * re-checks arrive with those features.
     */
    @SuppressWarnings("unchecked")
    String withdrawnSinceAsked(Map<String, Object> rec) {
        Map<String, Object> contract = rec.get("contract") instanceof Map<?, ?> c
                ? (Map<String, Object>) c : Map.of();
        Map<String, Object> identity = contract.get("_identity") instanceof Map<?, ?> i
                ? (Map<String, Object>) i : Map.of();
        String origin = Standing.operatorOrigin(identity);
        if (origin != null && store.blockedOperators().containsKey(origin)) {
            return "the operator behind this agent has been blocked";
        }
        if (!(rec.get("handle") instanceof String handle) || handle.isEmpty()) {
            return null;
        }
        Map<String, Object> conn = store.connection(handle);
        int seen = rec.get("revocations_seen") instanceof Number n ? n.intValue() : 0;
        if (TokenController.revocations(conn) > seen) {
            return "this agent was revoked after it asked";
        }
        if ("operation".equals(rec.get("pending_kind"))
                && (conn == null || !"active".equals(conn.get("status")))) {
            return "this agent is no longer connected";
        }
        String resource = (String) rec.get("resource_id");
        if (resource != null) {
            if (organization.blockedAgent(resource, handle, identity)) {
                return "the organization has shut this agent out of its resources";
            }
            String blocked = organization.block(resource);
            if (blocked != null) {
                return blocked;
            }
            Map<String, Object> tier = policy.tiers().get(rec.get("tier"));
            if (tier != null) {
                Organization.Attestation clearance = organization.attest(tier, resource);
                if (!clearance.problems().isEmpty()) {
                    return String.join("; ", clearance.problems());
                }
                rec.put("clearance", clearance.facts());
            }
        }
        return null;
    }

    /**
     * Admits the agent she approved, unless she revoked it after it asked: conditional on
     * the revocation count she was asked under, in the store step a revocation takes. A
     * previously revoked agent starts a new relationship but not a clean record.
     */
    private boolean admit(Map<String, Object> rec, Map<String, Object> identity) {
        String family = (String) rec.get("family");
        String handle = (String) rec.get("handle");
        int seen = rec.get("revocations_seen") instanceof Number n ? n.intValue() : 0;
        Map<String, Object> connection = new LinkedHashMap<>();
        connection.put("handle", handle);
        connection.put("identity", identity);
        Object sub = identity.get("sub");
        connection.put("label", Py.truthy(sub) ? sub
                : "Agent " + handle.substring(Math.min(4, handle.length()),
                        Math.min(12, handle.length())));
        connection.put("status", "active");
        connection.put("first_seen", EventLog.utcNow());
        connection.put("last_access", null);
        connection.put("tiers_granted", new java.util.ArrayList<>());
        connection.put("tiers_approved", new java.util.ArrayList<>());
        connection.put("revocations", seen);
        if (!store.admitConnection(connection, seen)) {
            return false;
        }
        state.log.event("connection.approved", family, "handle", handle);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("identity", identity);
        ledger("connected", family, entry, handle);
        return true;
    }

    // --- shared steps -------------------------------------------------------

    private ResponseEntity<Object> refuse(Asked a, Map<String, Object> entry, int status,
                                          String description) {
        ledger("refused", a.family(), entry, a.handle());
        store.closeNegotiation(a.family());
        return refusal(status, "request_denied", description);
    }

    /** An approval that what she withdrew since overtook: refused, recorded, closed. */
    ResponseEntity<Object> withdrawn(Map<String, Object> rec, String why) {
        String family = (String) rec.get("family");
        state.log.event("access.denied", family, "reason", "withdrawn-after-approval",
                "detail", why);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("tier", rec.get("tier"));
        entry.put("because", List.of(why));
        entry.put("resource_id", rec.get("resource_id"));
        ledger("refused", family, entry, (String) rec.get("handle"));
        store.closeNegotiation(family);
        return refusal(403, "request_denied", why);
    }

    /** Issues the grant and closes the negotiation; an unissuable grant is a refusal. */
    private ResponseEntity<Object> issued(Map<String, Object> rec,
                                          Supplier<Map<String, Object>> rpt) {
        String family = (String) rec.get("family");
        try {
            return ResponseEntity.ok(rpt.get());
        } catch (GrantService.GrantWithdrawn e) {
            return withdrawn(rec, e.getMessage());
        } catch (IllegalArgumentException e) {
            state.log.event("policy.evaluated", family, "result", "no-covered-scope");
            return refusal(403, "request_denied", String.valueOf(e.getMessage()));
        } finally {
            store.closeNegotiation(family);
        }
    }

    static ResponseEntity<Object> refusal(int status, String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null) {
            body.put("error_description", description);
        }
        return ResponseEntity.status(status).body(body);
    }

    String newTicket(Map<String, Object> rec) {
        return PermissionTickets.mint(store, config.ownerUsername, rec);
    }

    void ledger(String kind, String family, Map<String, Object> entry, String handle) {
        store.ledgerAdd(kind, family, EventLog.utcNow(), entry, handle);
    }
}
