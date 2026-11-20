package io.uma4agents.authserver;

import static io.uma4agents.authserver.Organization.list;
import static io.uma4agents.authserver.Organization.number;
import static io.uma4agents.authserver.Organization.object;
import static io.uma4agents.authserver.Organization.row;
import static io.uma4agents.authserver.Organization.text;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.JointMandate;
import io.uma4agents.common.JointPeer;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.OrganizationPatterns;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.PyJwtClaims;
import io.uma4agents.common.S256;
import jakarta.servlet.http.HttpServletRequest;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
final class JointOwnership {
    private final AsConfig config;
    private final OwnerStore store;
    private final PolicyService policy;
    private final GrantService grants;
    private final Standing standing;
    private final Commitment commitment;
    private final SigningKeys signing;
    private final OwnerAuth auth;
    private final RegistrationPuller puller;
    private final Organization organization;
    private final JointPeer peer;

    JointOwnership(AsConfig config, OwnerStore store, PolicyService policy, GrantService grants,
                   Standing standing, Commitment commitment, SigningKeys signing, OwnerAuth auth,
                   RegistrationPuller puller, Organization organization, HttpClient http) {
        this.config = config;
        this.store = store;
        this.policy = policy;
        this.grants = grants;
        this.standing = standing;
        this.commitment = commitment;
        this.signing = signing;
        this.auth = auth;
        this.puller = puller;
        this.organization = organization;
        this.peer = new JointPeer(http);
    }

    @PostMapping("/owner/joint/preview")
    Map<String, Object> preview(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        auth.requireOwner(request);
        String tally = tallyOf(body);
        String account = text(body.get("account"));
        JointMandate mandate = read(tally, account);
        var mine = policy.tiers().values().stream()
                .filter(tier -> list(tier.get("resources")).stream()
                        .anyMatch(resource -> mandate.governs(text(resource))))
                .map(tier -> row("name", tier.get("name"), "expires_in",
                        object(tier.get("terms")).get("expires_in"),
                        "ask_me", Boolean.TRUE.equals(tier.get("ask_me")))).toList();
        return Map.of("mandate", wire(mandate, tally, account), "summary", mandate.describe(),
                "my_terms", mine, "writes_terms", !mine.isEmpty());
    }

    @PostMapping("/owner/joint")
    Map<String, Object> join(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        String owner = auth.requireOwner(request);
        if (!Boolean.TRUE.equals(body.get("agreed"))) {
            throw status(HttpStatus.BAD_REQUEST, "joining a jointly held account gives its "
                    + "other holders a say over what your agents may do with it. Say so explicitly.");
        }
        String tally = tallyOf(body);
        String account = text(body.get("account"));
        JointMandate mandate = read(tally, account);
        var holder = mandate.holder(owner);
        if (holder == null || !config.issuer.equals(holder.issuer())) {
            throw status(HttpStatus.FORBIDDEN, "that mandate does not name you as a holder");
        }
        var claims = list(organization.envelope().get("claims"));
        var overlap = mandate.resources().stream()
                .filter(resource -> OrganizationPatterns.matches(resource, claims)).toList();
        if (!overlap.isEmpty()) {
            throw status(HttpStatus.CONFLICT, "your organization claims "
                    + String.join(", ", overlap) + "; a resource it owns cannot be held jointly through you");
        }
        for (var entry : policy.tiers().entrySet()) {
            var resources = list(entry.getValue().get("resources"));
            long jointlyHeld = resources.stream().filter(r -> mandate.governs(text(r))).count();
            if (jointlyHeld > 0 && jointlyHeld < resources.size()) {
                throw status(HttpStatus.CONFLICT, "your tier '" + entry.getKey()
                        + "' covers some of this account's resources and others as well; split it before joining");
            }
        }
        var doc = wire(mandate, tally, account);
        store.putMandate(account, Map.of("account", account, "tally", tally, "mandate", doc,
                "enrolment", java.util.UUID.randomUUID().toString()));
        puller.pullAll();
        ledger("joint_joined", "-", Map.of("account", account, "tally", tally,
                "holders", mandate.holders().stream().map(JointMandate.Holder::owner).toList()), null);
        store.notify(Map.of("type", "joint", "state", "joined", "account", account));
        return Map.of("joined", account, "mandate", doc, "summary", mandate.describe());
    }

    @GetMapping("/owner/joint")
    List<Map<String, Object>> listing(HttpServletRequest request) {
        auth.requireOwner(request);
        return store.mandates().values().stream().map(record -> {
            var mandate = JointMandate.parse(record.get("mandate"), 0);
            return row("account", record.get("account"), "tally", record.get("tally"),
                    "resources", mandate.resources(), "holders", mandate.holders().stream()
                            .map(h -> Map.of("owner", h.owner(), "weight", h.weight())).toList(),
                    "rule", mandate.rule(), "summary", mandate.describe(),
                    "moved", list(record.get("moved")));
        }).toList();
    }

    @DeleteMapping("/owner/joint/{account}")
    Map<String, Object> leave(HttpServletRequest request, @PathVariable String account) {
        auth.requireOwner(request);
        if (!store.clearMandate(account)) {
            throw status(HttpStatus.NOT_FOUND, "not a party to that mandate");
        }
        ledger("joint_left", "-", Map.of("account", account), null);
        store.notify(Map.of("type", "joint", "state", "left", "account", account));
        return Map.of("left", account);
    }

    @PostMapping("/joint/quote")
    Map<String, Object> quote(@RequestBody Map<String, Object> body) {
        Question question = authenticate(body);
        String resource = text(question.claims().get("resource_id"));
        var tier = policy.tierForResource(resource);
        if (tier == null || !question.mandate().governs(resource)) {
            return row("owner", config.ownerUsername, "tier", null,
                    "because", "this holder has written no terms over this resource");
        }
        var definition = tier.getValue();
        var terms = object(definition.get("terms"));
        return Map.of("owner", config.ownerUsername, "tier_id", tier.getKey(), "tier",
                row("name", definition.get("name"), "resources", question.mandate().resources(),
                        "ask_me", Boolean.TRUE.equals(definition.get("ask_me")), "terms",
                        row("expires_in", terms.get("expires_in"), "scope", list(terms.get("scope")),
                                "prohibited", list(terms.get("prohibited")))));
    }

    @PostMapping("/joint/verdict")
    Map<String, Object> verdict(@RequestBody Map<String, Object> body) {
        Question q = authenticate(body);
        String account = text(q.claims().get("account"));
        String family = text(q.claims().get("negotiation"));
        String resource = text(q.claims().get("resource_id"));
        if (!family.matches("[A-Za-z0-9_-]{1,128}")) {
            throw status(HttpStatus.BAD_REQUEST, "that request names no usable negotiation");
        }
        if (!q.mandate().governs(resource)) {
            return refuse(q, List.of("that resource is not part of this mandate"));
        }
        JointMandate published;
        try {
            published = read(q.tally(), account);
        } catch (RuntimeException unavailable) {
            return refuse(q, List.of("the tally's published mandate could not be read"));
        }
        if (!q.mandate().digest().equals(published.digest())) {
            var changes = q.mandate().changesTo(published);
            if (store.markMandateMoved(account, q.enrolment(), changes)) {
                ledger("joint_moved", "-", Map.of("account", account, "changes", changes), null);
                store.notify(Map.of("type", "joint", "state", "moved", "account", account));
            }
            var reasons = new ArrayList<String>();
            reasons.add("the mandate changed after this holder agreed to it");
            reasons.addAll(changes);
            return refuse(q, reasons);
        }

        store.reapExpired();
        var pending = store.negotiation(family);
        if (pending != null) {
            if (!"joint".equals(pending.get("pending_kind"))
                    || !account.equals(object(pending.get("joint")).get("account"))
                    || !q.tally().equals(object(pending.get("joint")).get("tally"))
                    || !java.util.Objects.equals(q.claims().get("contract"), pending.get("contract_hash"))
                    || !q.mandate().digest().equals(pending.get("mandate_digest"))
                    || !java.util.Objects.equals(q.enrolment().get("enrolment"), pending.get("joint_enrolment"))
                    || !resource.equals(pending.get("resource_id"))) {
                return refuse(q, List.of("this holder approved a different agreement"));
            }
            if ("denied".equals(pending.get("decision"))) {
                return refuse(q, List.of("this holder declined"));
            }
            if ("approved".equals(pending.get("decision"))) {
                String withdrawn = commitment.withdrawnSinceAsked(pending);
                if (withdrawn != null) {
                    ledger("joint_refused", family, Map.of("account", account,
                            "because", List.of(withdrawn)), text(pending.get("handle")));
                    return refuse(q, List.of(withdrawn));
                }
                return allow(q, object(pending.get("contract")), object(pending.get("signer_jwk")),
                        text(pending.get("handle")));
            }
            return waiting(family);
        }

        var tier = policy.tierForResource(resource);
        if (tier == null) {
            return refuse(q, List.of("this holder has written no terms over this resource"));
        }
        String agreement = text(q.claims().get("agreement"));
        GrantService.VerifiedContract verified;
        try {
            verified = grants.verifyAgreementSigner(agreement, q.tally());
            if (!S256.of(GrantService.base64UrlDecodePadded(agreement)).equals(q.claims().get("contract"))) {
                return refuse(q, List.of("the agreement does not match the digest it was sent under"));
            }
            GrantService.requesterClaims(verified.claims(), config.maxReason);
        } catch (RuntimeException invalid) {
            return refuse(q, List.of("the agreement did not verify: " + invalid.getMessage()));
        }
        Map<String, Object> contract = verified.claims();
        var ownTerms = object(tier.getValue().get("terms"));
        List<String> problems = compareTerms(contract, ownTerms);
        String handle = grants.connectionHandle(verified.identity(), verified.signerJwk());
        if (!problems.isEmpty()) {
            ledger("joint_refused", family, Map.of("account", account, "because", problems), handle);
            return refuse(q, problems);
        }
        String operator = Standing.operatorOrigin(verified.identity());
        if (operator != null && store.blockedOperators().containsKey(operator)) {
            return refuse(q, List.of("this holder does not accept agents from that operator"));
        }
        var connection = store.connection(handle);
        var axes = Assurance.assess(verified.identity());
        var facts = row("assurance", axes, "standing",
                Standing.facts(connection, tier.getKey(), standing.trajectory(handle),
                        standing.firstParty(verified.identity(), axes), standing.lineage(connection), AsState.now()),
                "request", row("expires_in", contract.get("expires_in"), "max_expires_in",
                        ownTerms.get("expires_in"), "reason", contract.get("reason"), "mission",
                        contract.get("mission"), "consequence", grants.consequenceOf(resource)), "tier", tier.getKey());
        Rules.Outcome outcome = Rules.evaluate(tier.getValue(), facts);
        if (Rules.REFUSE.equals(outcome.requirement())) {
            return refuse(q, outcome.because());
        }
        boolean stranger = connection == null || !"active".equals(connection.get("status"));
        if (stranger) {
            String lane = PolicyService.pendLane(axes);
            long waiting = store.pendingNegotiations().stream()
                    .filter(rec -> !family.equals(rec.get("family")))
                    .filter(rec -> "connection".equals(rec.get("pending_kind"))
                            || "joint".equals(rec.get("pending_kind")) && !"active".equals(
                            object(store.connection(text(rec.get("handle")))).get("status")))
                    .filter(rec -> lane.equals(PolicyService.pendLane(object(rec.get("assurance")))))
                    .count();
            if (waiting >= policy.pendBudget(lane)) {
                return refuse(q, List.of("this holder is not accepting new agent requests at the moment"));
            }
        }
        if (stranger || Rules.ASK.equals(outcome.requirement())) {
            var joint = Map.of("account", account, "tally", q.tally(), "holders",
                    q.mandate().holders().stream().map(JointMandate.Holder::owner).toList(),
                    "rule", q.mandate().kind());
            List<String> explained = Assurance.describe(axes, verified.identity());
            var saved = row("family", family, "owner", config.ownerUsername, "state", "awaiting-owner",
                    "decision", null, "expires", AsState.now() + AsConfig.PENDING_TTL, "pending_kind",
                    "joint", "tier", tier.getKey(), "resource_id", resource, "resource_scopes",
                    list(contract.get("scope")), "handle", handle, "contract", contract, "contract_hash",
                    q.claims().get("contract"), "signer_jwk", verified.signerJwk(), "template",
                    Map.of("enforced", Map.of()), "assurance", axes, "assurance_notes", explained,
                    "because", outcome.because(), "joint", joint, "mandate_digest", q.mandate().digest(),
                    "joint_enrolment", q.enrolment().get("enrolment"), "revocations_seen",
                    TokenController.revocations(connection));
            if (store.beginJointNegotiation(saved)) {
                store.notify(row("type", "pending", "kind", "joint", "family", family,
                        "tier", tier.getKey(), "tier_name", tier.getValue().get("name"), "purpose",
                        contract.get("purpose"), "operation", contract.get("operation"), "reason",
                        contract.get("reason"), "mission", contract.get("mission"), "prohibited",
                        contract.get("prohibited"), "enforced", Map.of(), "identity", verified.identity(),
                        "handle", handle, "assurance", axes, "assurance_notes", explained, "because",
                        outcome.because(), "joint", joint));
            }
            return waiting(family);
        }
        store.touchConnection(handle, EventLog.utcNow());
        return allow(q, contract, verified.signerJwk(), handle);
    }

    private record Question(String tally, JointMandate mandate, Map<String, Object> claims,
                            Map<String, Object> enrolment) {}

    private Question authenticate(Map<String, Object> body) {
        String token = text(body.get("request"));
        CompactJws.Parsed parsed;
        try {
            parsed = CompactJws.parse(token);
        } catch (RuntimeException invalid) {
            throw status(HttpStatus.BAD_REQUEST, "that is not a tally request");
        }
        if (!"u4a-tally-req+jwt".equals(parsed.header().get("typ"))) {
            throw status(HttpStatus.UNAUTHORIZED, "that is not a tally request");
        }
        if (!config.ownerUsername.equals(parsed.claims().get("owner"))) {
            throw status(HttpStatus.NOT_FOUND, "not an owner here");
        }
        String account = text(parsed.claims().get("account"));
        Map<String, Object> record = store.mandates().get(account);
        if (record == null) {
            throw status(HttpStatus.FORBIDDEN, "this owner is not a party to that mandate");
        }
        String tally = text(record.get("tally"));
        if (tally.equals(parsed.claims().get("iss"))) {
            for (boolean fresh : List.of(false, true)) {
                for (var published : peer.keys(tally, fresh)) {
                    var kid = parsed.header().get("kid");
                    if (kid != null && !kid.equals(published.get("kid"))) {
                        continue;
                    }
                    try {
                        var claims = CompactJws.verify(token, Jwks.toPublicKey(published)).claims();
                        PyJwtClaims.validateWithIat(claims, AsState.now(), "iss", "exp");
                        return new Question(tally, JointMandate.parse(record.get("mandate"), 0), claims, record);
                    } catch (RuntimeException invalid) {
                        // Continue with the next published key.
                    }
                }
            }
        }
        throw status(HttpStatus.UNAUTHORIZED, "not signed by the tally named in this mandate");
    }

    private Map<String, Object> allow(Question q, Map<String, Object> contract,
                                     Map<String, Object> key, String handle) {
        String family = text(q.claims().get("negotiation"));
        String resource = text(q.claims().get("resource_id"));
        String account = text(q.claims().get("account"));
        var current = store.mandates().get(account);
        if (current == null || !java.util.Objects.equals(q.enrolment().get("enrolment"), current.get("enrolment"))
                || !q.enrolment().get("mandate").equals(current.get("mandate"))) {
            return refuse(q, List.of("the holder's mandate changed while this request was being answered"));
        }
        long lifetime = number(contract.get("expires_in"), 0);
        if (lifetime <= 0) {
            return refuse(q, List.of("the agreement names no valid lifetime"));
        }
        if (store.spendOnce("verdict:" + q.tally() + ":" + family, AsState.now() + AsConfig.PENDING_TTL)) {
            ledger("joint_allowed", family, Map.of("account", account, "resource_id", resource), handle);
        }
        var facts = row("cnf_jkt", Jwks.thumbprint(key), "scope", list(contract.get("scope")).stream()
                .map(String::valueOf).sorted().toList(), "expires_in", lifetime,
                "mandate_s256", q.mandate().digest());
        String consequence = grants.consequenceOf(resource);
        if (consequence != null) {
            facts.put("consequence", consequence);
        }
        var operation = object(contract.get("operation"));
        if (!operation.isEmpty()) {
            facts.put("operation", Map.of("tool", text(operation.get("tool")), "params_s256",
                    S256.of(PyJson.compactSortedUnicode(operation.getOrDefault("params", Map.of())))));
        }
        return signed(q, "allow", AsState.now() + lifetime, facts);
    }

    private Map<String, Object> refuse(Question q, List<String> why) {
        return signed(q, "refuse", AsState.now() + 300, Map.of("because", why));
    }

    private Map<String, Object> signed(Question q, String effect, long expiry, Map<String, Object> facts) {
        var claims = row("iss", config.issuer, "iat", AsState.now(), "exp", expiry, "holder",
                config.ownerUsername, "account", q.claims().get("account"), "negotiation",
                q.claims().get("negotiation"), "resource_id", q.claims().get("resource_id"),
                "contract", q.claims().get("contract"), "effect", effect);
        claims.putAll(facts);
        return Map.of("verdict", CompactJws.sign(signing.header("u4a-verdict+jwt"), claims,
                signing.current().getPrivate()));
    }

    private static List<String> compareTerms(Map<String, Object> signed, Map<String, Object> own) {
        List<String> found = new ArrayList<>();
        long expiry = number(signed.get("expires_in"), 0);
        long cap = number(own.get("expires_in"), 0);
        if (expiry <= 0) {
            found.add("the agreement names no valid lifetime");
        } else if (cap > 0 && expiry > cap) {
            found.add("the agreed access lasts " + expiry + "s, longer than the " + cap
                    + "s this holder's own terms allow");
        }
        var offered = list(own.get("scope"));
        var extra = list(signed.get("scope")).stream().filter(scope -> !offered.contains(scope))
                .map(String::valueOf).toList();
        if (!extra.isEmpty()) {
            found.add("the agreed terms carry " + String.join(", ", extra)
                    + ", which this holder does not offer over this resource");
        }
        var missing = new TreeSet<String>();
        for (Object required : list(own.get("prohibited"))) {
            if (!list(signed.get("prohibited")).contains(required)) {
                missing.add(String.valueOf(required));
            }
        }
        if (!missing.isEmpty()) {
            found.add("the agreed terms drop " + String.join(", ", missing)
                    + ", which this holder forbids over this resource");
        }
        return found;
    }

    private JointMandate read(String tally, String account) {
        try {
            JointMandate mandate = peer.mandate(tally, account);
            if (mandate != null) {
                return mandate;
            }
        } catch (RuntimeException unreachable) {
            throw status(HttpStatus.BAD_GATEWAY, "could not read that mandate");
        }
        throw status(HttpStatus.BAD_GATEWAY, "could not read that mandate");
    }

    private static Map<String, Object> wire(JointMandate mandate, String tally, String account) {
        Map<String, Object> result = new LinkedHashMap<>(mandate.wire());
        result.putAll(Map.of("account", account, "tally", tally, "summary", mandate.describe()));
        return result;
    }

    private static String tallyOf(Map<String, Object> body) {
        return text(body.get("tally")).replaceFirst("/+$", "");
    }

    private void ledger(String kind, String family, Map<String, Object> item, String handle) {
        store.ledgerAdd(kind, family, EventLog.utcNow(), item, handle);
    }

    private static Map<String, Object> waiting(String family) {
        return Map.of("pending", true, "family", family);
    }

    private static ResponseStatusException status(HttpStatus status, String detail) {
        return new ResponseStatusException(status, detail);
    }
}
