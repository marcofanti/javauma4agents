package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.EventLog;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The grant API (agent-facing, UMA 2.0 Grant shape): PAT issuance via
 * client_credentials and the four-beat uma-ticket loop with need_info,
 * request_submitted (pending owner), ticket rotation, and decline handling.
 *
 * <p>Every negotiation is read from and written back to the owner's store; nothing here
 * relies on an object another request might hold. The store's single-use steps decide who
 * may proceed: a ticket is spent by {@link OwnerStore#consumeTicket}, and only its winner
 * continues.
 */
@RestController
public class TokenController {

    private final AsConfig config;
    private final AsState state;
    private final OwnerStore store;
    private final PolicyService policy;
    private final GrantService grants;
    private final Commitment commitment;
    private final ResourceServerSignatures resourceSignatures;
    private final Organization organization;
    private final EnterpriseFederation federation;

    public TokenController(AsConfig config, AsState state, OwnerStore store,
                           PolicyService policy, GrantService grants, Commitment commitment,
                           ResourceServerSignatures resourceSignatures, Organization organization,
                           EnterpriseFederation federation) {
        this.commitment = commitment;
        this.config = config;
        this.state = state;
        this.store = store;
        this.policy = policy;
        this.grants = grants;
        this.resourceSignatures = resourceSignatures;
        this.organization = organization;
        this.federation = federation;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Object> tokenRequest(HttpServletRequest request) throws IOException {
        byte[] body = SignedRequestBody.read(request);
        if (body == null) {
            return ResponseEntity.status(413).body(Map.of("error", "invalid_request"));
        }
        Map<String, String> form = new LinkedHashMap<>();
        try {
            for (String field : new String(body, StandardCharsets.UTF_8).split("&")) {
                String[] fields = field.split("=", 2);
                String value = fields.length == 2 ? fields[1] : "";
                form.put(URLDecoder.decode(fields[0], StandardCharsets.UTF_8),
                        URLDecoder.decode(value, StandardCharsets.UTF_8));
            }
        } catch (IllegalArgumentException invalidForm) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request"));
        }
        if ("client_credentials".equals(form.get("grant_type"))) {
            String owner = form.get("owner");
            if (owner != null && !owner.isEmpty() && !config.ownerUsername.equals(owner)) {
                return invalidClient();
            }
            return patGrant(form.get("client_id"), form.get("client_secret"), form.get("scope"),
                    request, body);
        }
        return token(form.get("grant_type"), form.get("ticket"), form.get("claim_token"),
                form.get("claim_token_format"), form.get("decline"), null, null, null);
    }

    ResponseEntity<Object> token(String grantType, String ticket, String claimToken,
                                 String claimTokenFormat, String decline,
                                 String clientId, String clientSecret, String scope) {
        if ("client_credentials".equals(grantType)) {
            return patGrant(clientId, clientSecret, scope, null, null);
        }
        if (!"urn:ietf:params:oauth:grant-type:uma-ticket".equals(grantType)) {
            return ResponseEntity.status(400).body(Map.of("error", "unsupported_grant_type"));
        }

        String rawTicket = PermissionTickets.forOwner(ticket, config.ownerUsername);
        if (rawTicket == null) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid_grant"));
        }
        store.reapExpired();
        // A request still waiting on her is polled, not spent: a lost poll response must
        // not cost the agent its only handle on her decision.
        Map<String, Object> waiting = store.peekTicket(rawTicket);
        if (waiting != null && "awaiting-owner".equals(waiting.get("state"))
                && waiting.get("decision") == null) {
            state.log.event("ticket.presented", (String) waiting.get("family"),
                    "state", "awaiting-owner");
            return ResponseEntity.status(403).body(Map.of(
                    "error", "request_submitted", "ticket", ticket,
                    "interval", AsConfig.POLL_INTERVAL));
        }
        Map<String, Object> rec = store.consumeTicket(rawTicket);
        if (rec == null) {
            state.log.event("ticket.presented", null, "result", "invalid_grant");
            return ResponseEntity.status(400).body(Map.of("error", "invalid_grant"));
        }
        return umaTicketGrant(rec, claimToken, claimTokenFormat, decline);
    }

    /**
     * PAT issuance: an authorized resource server exchanges client credentials for a
     * {@code uma_protection} token. A registration with no secret is never opened by
     * sending none. Only an authenticated client seeds the owner.
     */
    private ResponseEntity<Object> patGrant(String clientId, String clientSecret, String scope,
                                            HttpServletRequest request, byte[] body) {
        Map<String, Object> rs = store.resourceServer(clientId == null ? "" : clientId);
        if (rs == null) {
            return invalidClient();
        }
        if (rs.get("secret") instanceof String stored && !stored.isEmpty()) {
            rs = provisionedSecret(clientId, rs);
            if (rs == null || !constantTimeEquals(clientSecret, (String) rs.get("secret"))) {
                return invalidClient();
            }
        } else {
            if (request == null || !"origin_signature".equals(rs.get("auth"))
                    || !(rs.get("resource_uri") instanceof String resource)
                    || !clientId.equals(ResourceServerSignatures.origin(resource))
                    || resourceSignatures.verify(request, body, resource) != null) {
                return invalidClient();
            }
            rs = store.resourceServer(clientId);
            if (rs == null || !resource.equals(rs.get("resource_uri"))
                    || !"origin_signature".equals(rs.get("auth"))) {
                return invalidClient();
            }
        }
        if ("pending".equals(rs.get("status"))) {
            return ResponseEntity.status(403).body(Map.of("error", "authorization_pending",
                    "error_description", "the owner has not yet authorized this resource server"));
        }
        if (!"active".equals(rs.get("status"))) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "access_denied",
                    "error_description", "the owner has revoked this resource server"));
        }
        if (!"uma_protection".equals(scope)) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid_scope"));
        }
        store.seed();
        return ResponseEntity.ok(grants.issuePat(clientId));
    }

    private static ResponseEntity<Object> invalidClient() {
        return ResponseEntity.status(401).body(Map.of("error", "invalid_client"));
    }

    /**
     * The registration seeded from the provisioned secret is written once; a rotated
     * secret must not lock the resource server out. Only the configured client's secret
     * follows the configuration, and only the secret. The pinned code writes the whole
     * record it read, which can put back a status she changed in between; here the store
     * sets the secret alone and the status is read from the record it returns, so a
     * revocation landing at the same moment is still a revocation.
     *
     * @return the live record, or null when it is gone
     */
    private Map<String, Object> provisionedSecret(String clientId, Map<String, Object> rs) {
        if (!config.rsClientId.equals(clientId)
                || constantTimeEquals(config.rsClientSecret, (String) rs.get("secret"))) {
            return rs;
        }
        Map<String, Object> live = store.updateResourceServerSecret(clientId,
                config.rsClientSecret);
        state.log.event("rs.secret_reprovisioned", null, "client_id", clientId);
        return live;
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> umaTicketGrant(Map<String, Object> rec, String claimToken,
                                                  String claimTokenFormat, String decline) {
        String family = (String) rec.get("family");
        state.log.event("ticket.presented", family, "state", rec.get("state"));

        // The requesting side declines the proffered terms. Refusals are records too; this
        // one has no agent to name, because nothing has been signed yet.
        if ("true".equals(decline) && "need_info".equals(rec.get("state"))) {
            Map<String, Object> template = rec.get("template") instanceof Map<?, ?> t
                    ? (Map<String, Object>) t : Map.of();
            state.log.event("terms.declined", family, "tier", rec.get("tier"),
                    "template_id", template.get("template_id"));
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("tier", rec.get("tier"));
            entry.put("terms_uri", template.get("terms_uri"));
            ledger("refused", family, entry, null);
            store.closeNegotiation(family);
            return ResponseEntity.status(403).body(Map.of("error", "request_denied"));
        }

        if ("awaiting-owner".equals(rec.get("state"))) {
            return commitment.pendingPoll(rec);
        }

        String resource = (String) rec.get("resource_id");
        String orgBlocked = organization.block(resource);
        if (orgBlocked != null) {
            ledger("org_refused", family, Map.of("because", List.of(orgBlocked)), null);
            store.closeNegotiation(family);
            return Commitment.refusal(403, "request_denied", orgBlocked);
        }

        Map.Entry<String, Map<String, Object>> tierEntry =
                policy.tierForResource((String) rec.get("resource_id"));
        if (tierEntry == null) {
            state.log.event("policy.evaluated", family, "result", "no-tier");
            // A refusal is a record too; she should see what was turned away and why.
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("reason", "no tier of hers covers this resource");
            entry.put("resource_id", rec.get("resource_id"));
            ledger("refused", family, entry, (String) rec.get("handle"));
            store.closeNegotiation(family);
            return ResponseEntity.status(403).body(Map.of("error", "request_denied"));
        }
        String tierId = tierEntry.getKey();
        Map<String, Object> tier = tierEntry.getValue();
        Organization.Attestation clearance = organization.attest(tier, resource);
        if (!clearance.problems().isEmpty()) {
            ledger("refused", family, Map.of("tier", tierId, "because", clearance.problems(),
                    "resource_id", resource), (String) rec.get("handle"));
            store.closeNegotiation(family);
            return Commitment.refusal(403, "request_denied", String.join("; ", clearance.problems()));
        }
        rec.put("clearance", clearance.facts());

        Map<String, Object> provider = EnterpriseFederation.provider(organization.envelope(), resource);
        var asserted = Organization.object(rec.get("asserted"));
        if (!provider.isEmpty() && !provider.get("issuer").equals(asserted.get("issuer"))) {
            if (io.uma4agents.common.IdentityTokens.ID_JAG.equals(claimTokenFormat)
                    && claimToken != null && !claimToken.isEmpty()) {
                Map<String, Object> verified;
                try {
                    verified = federation.verify(claimToken, provider, resource);
                    if (!store.spendOnce("id-jag:" + verified.get("jti"),
                            Organization.number(verified.get("exp"), AsState.now()))) {
                        throw new IllegalArgumentException("that assertion has already been used");
                    }
                } catch (IllegalArgumentException refused) {
                    String why = refused.getMessage();
                    state.log.event("identity.rejected", family, "reason", why);
                    ledger("identity_refused", family, Map.of("because", List.of(why)), null);
                    store.closeNegotiation(family);
                    return Commitment.refusal(403, "request_denied", why);
                }
                rec.put("asserted", EnterpriseFederation.recorded(verified));
                state.log.event("identity.asserted", family, "provider", verified.get("iss"),
                        "member", verified.get("preferred_username"), "application", verified.get("client_id"));
                return needInfoResponse(rec, tierId, tier);
            }
            rec.put("state", "need_identity");
            String rotated = PermissionTickets.mint(store, config.ownerUsername, rec);
            state.log.event("need_info.identity_required", family, "provider", provider.get("issuer"),
                    "resource_id", resource);
            return ResponseEntity.status(403).body(Map.of("error", "need_info", "ticket", rotated,
                    "required_claims", List.of(federation.challenge(provider, resource))));
        }

        // Beat 2: no contract yet -> dictate her terms.
        if (claimToken == null || claimToken.isEmpty()) {
            return needInfoResponse(rec, tierId, tier);
        }

        // Beat 3: contract committed.
        if (!AsConfig.AGREEMENT_FORMAT.equals(claimTokenFormat)) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid_claim_token_format"));
        }
        if (!"need_info".equals(rec.get("state"))) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid_grant"));
        }
        // An agreement is to the terms as dictated. If the governing tier or its terms
        // changed since, what was signed is an offer she no longer makes: dictate again.
        Map<String, Object> dictated = rec.get("template") instanceof Map<?, ?> t
                ? (Map<String, Object>) t : Map.of();
        Map<String, Object> current = (Map<String, Object>) tier.get("terms");
        if (!tierId.equals(rec.get("tier"))
                || !String.valueOf(current.get("template_id"))
                        .equals(String.valueOf(dictated.get("template_id")))) {
            state.log.event("need_info.terms_changed", family, "was", rec.get("tier"),
                    "now", tierId);
            return needInfoResponse(rec, tierId, tier);
        }
        return commitment.commit(rec, claimToken, tierId, tier);
    }

    private ResponseEntity<Object> needInfoResponse(Map<String, Object> rec, String tierId,
                                                    Map<String, Object> tier) {
        String family = (String) rec.get("family");
        rec.put("state", "need_info");
        rec.put("nonce", AsState.urlsafeToken(12));
        rec.put("tier", tierId);
        @SuppressWarnings("unchecked")
        Map<String, Object> terms = (Map<String, Object>) tier.get("terms");
        Map<String, Object> template = new LinkedHashMap<>(terms);
        template.put("proffered_by", config.issuer);
        template.put("terms_uri", grants.publishTerms(tierId, tier));
        template.put("nonce", rec.get("nonce"));
        template.put("family", family);
        template.put("resource_id", rec.get("resource_id"));
        rec.put("template", template);
        String rotated = PermissionTickets.mint(store, config.ownerUsername, rec);
        state.log.event("need_info.terms_dictated", family, "tier", tierId,
                "template_id", template.get("template_id"), "resource_id", rec.get("resource_id"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "need_info");
        body.put("ticket", rotated);
        body.put("required_claims", List.of(Map.of(
                "claim_type", AsConfig.AGREEMENT_CLAIM,
                "claim_token_format", List.of(AsConfig.AGREEMENT_FORMAT),
                "friendly_name", "Alice's terms: " + tier.get("name"),
                "terms_template", template)));
        return ResponseEntity.status(403).body(body);
    }

    private void ledger(String kind, String family, Map<String, Object> entry, String handle) {
        store.ledgerAdd(kind, family, EventLog.utcNow(), entry, handle);
    }

    static int revocations(Map<String, Object> conn) {
        return conn != null && conn.get("revocations") instanceof Number n ? n.intValue() : 0;
    }

    private static boolean constantTimeEquals(String a, String b) {
        byte[] left = (a == null ? "" : a).getBytes(StandardCharsets.UTF_8);
        byte[] right = (b == null ? "" : b).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(left, right);
    }
}
