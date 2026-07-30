package io.uma4agents.authserver;

import io.uma4agents.common.EventLog;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The grant API (agent-facing, UMA 2.0 Grant shape): PAT issuance via
 * client_credentials and the four-beat uma-ticket loop with need_info,
 * request_submitted (pending owner), ticket rotation, and decline handling.
 */
@RestController
public class TokenController {

    private final AsConfig config;
    private final AsState state;
    private final PolicyService policy;
    private final GrantService grants;
    private final SseHub sse;

    public TokenController(AsConfig config, AsState state, PolicyService policy,
                           GrantService grants, SseHub sse) {
        this.config = config;
        this.state = state;
        this.policy = policy;
        this.grants = grants;
        this.sse = sse;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Object> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "ticket", required = false) String ticket,
            @RequestParam(value = "claim_token", required = false) String claimToken,
            @RequestParam(value = "claim_token_format", required = false) String claimTokenFormat,
            @RequestParam(value = "decline", required = false) String decline,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam(value = "scope", required = false) String scope) {

        // PAT issuance: an authorized resource server exchanges client
        // credentials for a uma_protection-scoped token (FedAuthz's PAT).
        if ("client_credentials".equals(grantType)) {
            Map<String, Object> rs = state.rsClients.get(clientId == null ? "" : clientId);
            if (rs == null || !constantTimeEquals(clientSecret, (String) rs.get("secret"))) {
                return ResponseEntity.status(401).body(Map.of("error", "invalid_client"));
            }
            if (!"active".equals(rs.get("status"))) {
                return ResponseEntity.status(403).body(Map.of(
                        "error", "access_denied",
                        "error_description", "the owner has revoked this resource server"));
            }
            if (!"uma_protection".equals(scope)) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_scope"));
            }
            return ResponseEntity.ok(grants.issuePat(clientId));
        }

        if (!"urn:ietf:params:oauth:grant-type:uma-ticket".equals(grantType)) {
            return ResponseEntity.status(400).body(Map.of("error", "unsupported_grant_type"));
        }

        state.reapExpired();
        Map<String, Object> rec = state.consumeTicket(ticket);
        if (rec == null) {
            state.log.event("ticket.presented", null, "result", "invalid_grant");
            return ResponseEntity.status(400).body(Map.of("error", "invalid_grant"));
        }
        synchronized (rec) {
            return umaTicketGrant(rec, claimToken, claimTokenFormat, decline);
        }
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> umaTicketGrant(Map<String, Object> rec, String claimToken,
                                                  String claimTokenFormat, String decline) {
        String family = (String) rec.get("family");
        state.log.event("ticket.presented", family, "state", rec.get("state"));

        // The requesting side declines the proffered terms. Refusals are records
        // too: the owner's ledger notes who walked away from which terms.
        if ("true".equals(decline) && "need_info".equals(rec.get("state"))) {
            Map<String, Object> template = rec.get("template") instanceof Map<?, ?> t
                    ? (Map<String, Object>) t : Map.of();
            state.log.event("terms.declined", family, "tier", rec.get("tier"),
                    "template_id", template.get("template_id"));
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("tier", rec.get("tier"));
            entry.put("terms_uri", template.get("terms_uri"));
            state.ledgerAdd("refused", family, entry);
            state.closeNegotiation(rec);
            return ResponseEntity.status(403).body(Map.of("error", "request_denied"));
        }

        // Pending ask-me ticket being re-presented (beat 3, taking longer).
        if ("awaiting-owner".equals(rec.get("state"))) {
            return pendingPoll(rec);
        }

        Map.Entry<String, Map<String, Object>> tierEntry =
                policy.tierForResource((String) rec.get("resource_id"));
        if (tierEntry == null) {
            state.log.event("policy.evaluated", family, "result", "no-tier");
            state.closeNegotiation(rec);
            return ResponseEntity.status(403).body(Map.of("error", "request_denied"));
        }
        String tierId = tierEntry.getKey();
        Map<String, Object> tier = tierEntry.getValue();

        // Beat 2: no contract yet -> dictate Alice's terms.
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
        GrantService.VerifiedContract verified;
        try {
            verified = grants.verifyContract(claimToken, rec);
        } catch (Exception e) {
            state.log.event("contract.rejected", family, "reason", e.getMessage());
            state.closeNegotiation(rec);
            return ResponseEntity.status(403).body(Map.of(
                    "error", "request_denied", "error_description", e.getMessage()));
        }
        Map<String, Object> contract = verified.claims();
        Map<String, Object> signerJwk = verified.signerJwk();

        byte[] raw = GrantService.base64UrlDecodePadded(claimToken);
        String contractHash = io.uma4agents.common.S256.of(raw);
        rec.put("contract", contract);
        rec.put("contract_hash", contractHash);
        rec.put("agreement_jws", new String(raw, StandardCharsets.UTF_8));
        rec.put("signer_jwk", signerJwk);
        if (verified.identity().get("sub") != null) {
            rec.put("agent_sub", verified.identity().get("sub"));
        }
        state.log.event("contract.committed", family, "tier", rec.get("tier"),
                "contract", contractHash, "identity", verified.identity().get("level"));
        Map<String, Object> promised = new LinkedHashMap<>();
        promised.put("tier", rec.get("tier"));
        promised.put("purpose", contract.get("purpose"));
        promised.put("prohibited", contract.get("prohibited"));
        promised.put("expires_in", contract.get("expires_in"));
        promised.put("contract", contractHash);
        promised.put("terms_uri", contract.get("terms_uri"));
        promised.put("operation", contract.get("operation"));
        state.ledgerAdd("promised", family, promised);

        // Day-1 handshake: an agent without a standing connection pends — the
        // same request_submitted machinery, asking "do you want a relationship
        // with this agent?". Approval creates the connection AND releases this
        // negotiation in one tap.
        String handle = grants.connectionHandle(verified.identity(), signerJwk);
        Map<String, Object> conn = state.connections.get(handle);
        boolean needsConnection = conn == null || !"active".equals(conn.get("status"));
        boolean needsOperationApproval = Boolean.TRUE.equals(tier.get("ask_me"));

        if (needsConnection || needsOperationApproval) {
            String kind = needsConnection ? "connection" : "operation";
            rec.put("state", "awaiting-owner");
            rec.put("decision", null);
            rec.put("pending_kind", kind);
            rec.put("handle", handle);
            String rotated = state.newTicket(rec);
            state.log.event("ticket.awaiting_owner", family, "tier", rec.get("tier"),
                    "kind", kind);
            Map<String, Object> notification = new LinkedHashMap<>();
            notification.put("type", "pending");
            notification.put("kind", kind);
            notification.put("family", family);
            notification.put("tier", rec.get("tier"));
            notification.put("tier_name", tier.get("name"));
            notification.put("purpose", contract.get("purpose"));
            notification.put("operation", contract.get("operation"));
            notification.put("prohibited", contract.get("prohibited"));
            notification.put("identity", verified.identity());
            notification.put("handle", handle);
            sse.publish(notification);
            state.log.event("owner.notified", family, "kind", kind);
            return ResponseEntity.status(403).body(Map.of(
                    "error", "request_submitted", "ticket", rotated,
                    "interval", AsConfig.POLL_INTERVAL));
        }

        conn.put("last_access", EventLog.utcNow());
        state.log.event("policy.evaluated", family, "result", "auto-grant",
                "tier", rec.get("tier"), "connection", handle);
        Map<String, Object> granted = grants.issueRpt(rec, contractHash, signerJwk, null);
        state.closeNegotiation(rec);
        return ResponseEntity.ok(granted);
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
        String rotated = state.newTicket(rec);
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

    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> pendingPoll(Map<String, Object> rec) {
        String family = (String) rec.get("family");
        if ("approved".equals(rec.get("decision"))) {
            Map<String, Object> contract = (Map<String, Object>) rec.get("contract");
            if ("connection".equals(rec.get("pending_kind"))) {
                String handle = (String) rec.get("handle");
                Map<String, Object> identity = (Map<String, Object>) contract.get("_identity");
                Map<String, Object> connection = new LinkedHashMap<>();
                connection.put("handle", handle);
                connection.put("identity", identity);
                Object sub = identity.get("sub");
                connection.put("label", sub != null ? sub
                        : "Agent " + handle.substring(4, Math.min(12, handle.length())));
                connection.put("status", "active");
                connection.put("first_seen", EventLog.utcNow());
                connection.put("last_access", null);
                connection.put("tiers", List.of("tier1", "tier2", "tier3"));
                state.connections.put(handle, connection);
                state.log.event("connection.approved", family, "handle", handle);
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("handle", handle);
                entry.put("identity", identity);
                state.ledgerAdd("connected", family, entry);
            }
            state.log.event("policy.evaluated", family, "result", "owner-approved",
                    "tier", rec.get("tier"));
            // Tier policy still applies after connection: an ask-me tier's
            // per-operation approval was covered by Alice's tap only because
            // this negotiation's contract binds the operation.
            Map<String, Object> granted = grants.issueRpt(rec,
                    (String) rec.get("contract_hash"),
                    (Map<String, Object>) rec.get("signer_jwk"),
                    (Map<String, Object>) contract.get("operation"));
            state.closeNegotiation(rec);
            return ResponseEntity.ok(granted);
        }
        if ("denied".equals(rec.get("decision"))) {
            state.log.event("policy.evaluated", family, "result", "owner-denied",
                    "tier", rec.get("tier"));
            state.closeNegotiation(rec);
            return ResponseEntity.status(403).body(Map.of("error", "request_denied"));
        }
        String rotated = state.newTicket(rec);
        return ResponseEntity.status(403).body(Map.of(
                "error", "request_submitted", "ticket", rotated,
                "interval", AsConfig.POLL_INTERVAL));
    }

    private static boolean constantTimeEquals(String a, String b) {
        byte[] left = (a == null ? "" : a).getBytes(StandardCharsets.UTF_8);
        byte[] right = (b == null ? "" : b).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(left, right);
    }
}
