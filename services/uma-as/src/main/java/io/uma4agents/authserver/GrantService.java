package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.Jose;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.S256;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * The grant mechanics of the four-beat loop: PAT issuance/verification, terms
 * publication, intent-contract verification (template echo checks), connection
 * handles, and RPT + MyTerms-receipt issuance. Direct port of the corresponding
 * functions in the Python app.py.
 */
@Component
public class GrantService {

    private final AsConfig config;
    private final AsState state;
    private final OwnerStore store;
    private final SigningKeys keys;
    private final PolicyService policy;
    private final TokenVerifiers verifiers;
    private final RequesterMetadata requesterMetadata;

    public GrantService(AsConfig config, AsState state, OwnerStore store, SigningKeys keys,
                        PolicyService policy, TokenVerifiers verifiers,
                        RequesterMetadata requesterMetadata) {
        this.config = config;
        this.state = state;
        this.store = store;
        this.keys = keys;
        this.policy = policy;
        this.verifiers = verifiers;
        this.requesterMetadata = requesterMetadata;
    }

    /**
     * Who a Protection API call is from: the owner its PAT was issued for, and the
     * resource server holding it.
     *
     * @param owner the PAT's subject
     * @param clientId the resource server's client id ({@code azp})
     */
    public record Pat(String owner, String clientId) {}

    // --- PAT ----------------------------------------------------------------

    public Map<String, Object> issuePat(String clientId) {
        long exp = AsState.now() + AsConfig.PAT_TTL;
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", config.issuer);
        claims.put("sub", config.ownerUsername);
        claims.put("azp", clientId);
        claims.put("scope", "uma_protection");
        claims.put("jti", "pat_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
        claims.put("exp", exp);
        String token = CompactJws.sign(keys.header("pat+jwt"), claims, keys.current().getPrivate());
        store.touchPat(clientId, EventLog.utcNow());
        state.log.event("pat.issued", null, "client_id", clientId, "expires_in", AsConfig.PAT_TTL);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", token);
        response.put("token_type", "Bearer");
        response.put("expires_in", AsConfig.PAT_TTL);
        response.put("scope", "uma_protection");
        return response;
    }

    /**
     * Verifies a PAT for the Protection API: one this server signed (under any key it
     * still publishes), scoped {@code uma_protection}, for the owner it serves, held by a
     * resource server whose registration is still active.
     *
     * @throws org.springframework.web.server.ResponseStatusException 401 or 403, pinned details
     */
    public Pat requirePat(String authorization) {
        String token = TokenVerifiers.bearer(authorization);
        Map<String, Object> claims;
        try {
            claims = keys.verifyOwn(token).claims();
            if (!config.issuer.equals(claims.get("iss"))) {
                throw new SecurityException("unexpected issuer");
            }
            TokenVerifiers.checkExpiry(claims);
        } catch (Exception e) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.UNAUTHORIZED,
                    "protection API requires a valid PAT: " + e.getMessage());
        }
        String scope = String.valueOf(claims.getOrDefault("scope", ""));
        if (!List.of(scope.split(" ")).contains("uma_protection")) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.FORBIDDEN,
                    "PAT lacks uma_protection scope");
        }
        String owner = claims.get("sub") instanceof String sub && !sub.isEmpty()
                ? sub : config.ownerUsername;
        if (!config.ownerUsername.equals(owner)) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.FORBIDDEN,
                    "this authorization server serves a different owner");
        }
        String clientId = String.valueOf(claims.getOrDefault("azp", ""));
        Map<String, Object> rs = store.resourceServer(clientId);
        if (rs == null || !"active".equals(rs.get("status"))) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.UNAUTHORIZED,
                    "the owner has revoked this resource server");
        }
        return new Pat(owner, clientId);
    }

    // --- Terms roster -------------------------------------------------------

    public String termsUri(String templateId) {
        return config.issuer + "/terms/" + templateId;
    }

    /** Archives the current version of a tier's terms; idempotent per template_id. */
    public String publishTerms(String tierId, Map<String, Object> tier) {
        @SuppressWarnings("unchecked")
        Map<String, Object> terms = (Map<String, Object>) tier.get("terms");
        String templateId = (String) terms.get("template_id");
        if (store.termsDoc(templateId) == null) {
            Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("template_id", templateId);
            doc.put("terms_uri", termsUri(templateId));
            doc.put("proffered_by", config.issuer);
            doc.put("name", tier.get("name"));
            doc.put("tier", tierId);
            terms.forEach((k, v) -> {
                if (!"template_id".equals(k)) {
                    doc.put(k, v);
                }
            });
            Map<String, Object> envelope = Organization.effectiveEnvelope(store, store.organization());
            if (Organization.list(tier.get("resources")).stream().anyMatch(resource ->
                    io.uma4agents.common.OrganizationEnvelope.reaches((String) resource, envelope))) {
                doc.put("organization", Organization.row("name", envelope.get("name"),
                        "id", envelope.get("org"), "issuer", envelope.get("issuer"),
                        "charter_version", envelope.get("charter_version"),
                        "requires", envelope.get("summary")));
            }
            doc.put("published_at", EventLog.utcNow());
            store.publishTerms(doc);
            state.log.event("terms.published", null, "template_id", templateId, "tier", tierId);
        }
        return termsUri(templateId);
    }

    // --- Contract verification (beat 3) -------------------------------------

    public record VerifiedContract(Map<String, Object> claims, Map<String, Object> signerJwk,
                                   Map<String, Object> identity) {}

    /**
     * Verifies the intent contract JWS and its echo of the dictated template.
     * The signer key comes from the JWS protected header: {@code jwk}
     * (pseudonymous bare key) or the {@code cnf.jwk} of an embedded verified
     * {@code agent_token}, and the signature is verified with the algorithm that key
     * names. Throws IllegalArgumentException on any failure.
     */
    @SuppressWarnings("unchecked")
    public VerifiedContract verifyContract(String claimTokenB64, Map<String, Object> rec) {
        VerifiedContract verified = verifyAgreementSigner(claimTokenB64, config.issuer);
        Map<String, Object> contract = verified.claims();
        Map<String, Object> template = (Map<String, Object>) rec.get("template");
        requireEqual(contract.get("nonce"), template.get("nonce"), "nonce mismatch");
        requireEqual(contract.get("family"), rec.get("family"), "negotiation family mismatch");
        requireEqual(contract.get("template_id"), template.get("template_id"),
                "template version mismatch");
        requireEqual(contract.get("terms_uri"), template.get("terms_uri"),
                "agreement must name the proffered terms document");
        requireEqual(contract.get("purpose"), template.get("purpose"), "purpose was altered");
        checkAgreedTerms(contract, template);
        requesterClaims(contract, config.maxReason);
        // A sibling's introduction, verified as far as the document goes. Whether the
        // introducing key means anything to this owner needs her store, later. A malformed
        // or misdirected one is a bad request, not a silent downgrade.
        if (contract.get("introduction") != null) {
            try {
                contract.put("introduction", Introduction.verifyClaim(
                        contract.get("introduction"), Jwks.thumbprint(verified.signerJwk()),
                        config.issuer, AsState.now()));
            } catch (Introduction.Refused e) {
                throw new IllegalArgumentException(e.getMessage());
            }
        }
        return verified;
    }

    @SuppressWarnings("unchecked")
    VerifiedContract verifyAgreementSigner(String claimTokenB64, String audience) {
        byte[] raw = base64UrlDecodePadded(claimTokenB64);
        String token = new String(raw, StandardCharsets.UTF_8);
        CompactJws.Parsed unverified = CompactJws.parse(token);
        Map<String, Object> header = unverified.header();

        Map<String, Object> signerJwk;
        Map<String, Object> identity = new LinkedHashMap<>();
        if (header.get("jwk") instanceof Map) {
            signerJwk = (Map<String, Object>) header.get("jwk");
            identity.put("level", "pseudonymous");
        } else if (header.get("agent_token") instanceof String agentToken) {
            Map<String, Object> agentClaims = verifiers.verifyAgentToken(agentToken);
            signerJwk = (Map<String, Object>) ((Map<String, Object>) agentClaims.get("cnf")).get("jwk");
            identity.put("level", "identified");
            identity.put("iss", agentClaims.get("iss"));
            identity.put("sub", agentClaims.get("sub"));
            if (agentClaims.get("parent_agent") instanceof String parent && !parent.isEmpty()) {
                identity.put("parent_agent", parent);
            }
        } else {
            throw new IllegalArgumentException(
                    "contract JWS must carry jwk or agent_token in its header");
        }
        describeOperator(header, signerJwk, identity);

        Map<String, Object> contract;
        try {
            contract = CompactJws.verifyWith(token, Jwks.toPublicKey(signerJwk),
                    Jose.algOf(signerJwk)).claims();
        } catch (SecurityException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
        identity.put("key_bound", true);
        if (!audience.equals(contract.get("aud"))) {
            throw new IllegalArgumentException("Audience doesn't match");
        }

        contract.put("_identity", identity);
        return new VerifiedContract(contract, signerJwk, identity);
    }

    /**
     * Bounds and normalises, in place, what the requesting side wrote about itself. A
     * reason is bounded and nothing else: never compared, parsed or scored. A mission is a
     * citation checked for shape, normalised to its two fields.
     */
    static void requesterClaims(Map<String, Object> contract, int maxReason) {
        Object reason = contract.get("reason");
        if (reason != null) {
            if (!(reason instanceof String text)) {
                throw new IllegalArgumentException("reason must be a string");
            }
            if (text.getBytes(StandardCharsets.UTF_8).length > maxReason) {
                throw new IllegalArgumentException(
                        "reason exceeds the permitted length (" + maxReason + " bytes)");
            }
        }
        Object mission = contract.get("mission");
        if (mission != null) {
            if (!(mission instanceof Map<?, ?> m)) {
                throw new IllegalArgumentException("mission must be an object");
            }
            Object approver = m.get("approver");
            Object digest = m.get("s256");
            if (!(approver instanceof String a) || !a.startsWith("https://")) {
                throw new IllegalArgumentException("mission.approver must be an https URL");
            }
            int length = digest instanceof String d ? d.codePointCount(0, d.length()) : -1;
            if (length < 16 || length > 128) {
                throw new IllegalArgumentException("mission.s256 must be a content hash");
            }
            Map<String, Object> citation = new LinkedHashMap<>();
            citation.put("approver", approver);
            citation.put("s256", digest);
            contract.put("mission", citation);
        }
    }

    /**
     * What the agent agreed to, against what was dictated, checked in full before she is
     * asked, because issuance relies on it after she has answered. It may agree to less
     * than was offered and never to more, and never to nothing.
     */
    @SuppressWarnings("unchecked")
    static void checkAgreedTerms(Map<String, Object> contract, Map<String, Object> template) {
        for (String member : List.of("scope", "prohibited")) {
            if (!(contract.get(member) instanceof List<?> values)
                    || !values.stream().allMatch(String.class::isInstance)) {
                throw new IllegalArgumentException(member + " must be an array of strings");
            }
        }
        List<Object> agreedScope = (List<Object>) contract.get("scope");
        List<Object> templateProhibited = template.get("prohibited") instanceof List<?> l
                ? (List<Object>) l : List.of();
        if (!new HashSet<>((List<Object>) contract.get("prohibited"))
                .containsAll(templateProhibited)) {
            throw new IllegalArgumentException("prohibited-actions list was weakened");
        }
        Object agreedFor = contract.get("expires_in");
        boolean wholeSeconds = agreedFor instanceof Integer || agreedFor instanceof Long
                || agreedFor instanceof java.math.BigInteger;
        // Compared whole: narrowing first would let 2^64 + 60 read as 60.
        java.math.BigInteger agreed = wholeSeconds
                ? new java.math.BigInteger(agreedFor.toString()) : null;
        if (agreed == null || agreed.signum() <= 0) {
            throw new IllegalArgumentException("expires_in must be a positive number of seconds");
        }
        java.math.BigInteger dictated = template.get("expires_in") instanceof Number n
                ? new java.math.BigDecimal(n.toString()).toBigInteger() : java.math.BigInteger.ZERO;
        if (agreed.compareTo(dictated) > 0) {
            throw new IllegalArgumentException("expiry was extended beyond dictated terms");
        }
        List<Object> offered = template.get("scope") instanceof List<?> l
                ? (List<Object>) l : List.of();
        if (!new HashSet<>(offered).containsAll(agreedScope)) {
            throw new IllegalArgumentException("scope was widened beyond the proffered terms");
        }
        if (!offered.isEmpty() && agreedScope.isEmpty()) {
            throw new IllegalArgumentException("the agreement names no scope of those offered");
        }
        if (Boolean.TRUE.equals(template.get("per_operation"))) {
            boolean named = contract.get("operation") instanceof Map<?, ?> op
                    && op.get("tool") instanceof String tool && !tool.isEmpty()
                    && op.get("params") instanceof Map;
            if (!named) {
                throw new IllegalArgumentException("per-operation tier requires an operation "
                        + "naming a tool and an object of params");
            }
        }
    }

    /**
     * A CIMD URL tells Alice who operates this agent, and a Web Bot Auth directory on the
     * same origin can confirm that operator published this key. Both are resolved and
     * shown, never trusted: neither reaches the handle or the grant's key binding.
     */
    private void describeOperator(Map<String, Object> header, Map<String, Object> signerJwk,
                                  Map<String, Object> identity) {
        if (!(header.get("client_id") instanceof String clientId) || clientId.isEmpty()) {
            return;
        }
        identity.put("client_metadata", requesterMetadata.resolveClientId(clientId));
        if (header.get("signature_agent") instanceof String directory && !directory.isEmpty()) {
            identity.put("operator_attested",
                    requesterMetadata.operatorPublishedKey(clientId, directory, signerJwk));
            identity.put("operator_directory", directory);
            identity.put("operator_client_id", clientId);
        }
    }

    private static void requireEqual(Object actual, Object expected, String message) {
        if (actual == null ? expected != null : !actual.equals(expected)) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * The stable name for a standing relationship. A pseudonymous, CIMD-described or
     * Web Bot Auth-published agent is its key (the {@code jkt:} RFC 7638 thumbprint). An
     * identified agent's continuity lives in its issuer-qualified subject: qualified by
     * the whole issuer, path included, unless the subject already ends with it, so two
     * issuers (or two tenants of one host) never share a connection.
     */
    public String connectionHandle(Map<String, Object> identity, Map<String, Object> signerJwk) {
        if ("identified".equals(identity.get("level"))) {
            URI issuer = URI.create(String.valueOf(identity.get("iss")));
            String path = issuer.getRawPath() == null ? "" : issuer.getRawPath();
            String where = issuer.getRawAuthority() + path.replaceAll("/+$", "");
            String sub = String.valueOf(identity.get("sub"));
            return sub.endsWith("@" + where) ? sub : sub + "@" + where;
        }
        return Jwks.thumbprint(signerJwk);
    }

    // --- RPT + receipt (beat 4) ---------------------------------------------

    /**
     * The connection a grant was decided on was revoked before the grant could be recorded.
     * The signed token is never returned, and no record exists for it.
     */
    public static final class GrantWithdrawn extends RuntimeException {
        private static final long serialVersionUID = 1L;

        GrantWithdrawn(String message) {
            super(message);
        }
    }

    /**
     * Signs and records a grant. Recorded only while the connection it was decided on is
     * active with the revocation count in {@code rec.revocations_seen}, in the same store
     * step a revocation serializes with.
     *
     * @throws GrantWithdrawn when a revocation landed first
     * @throws IllegalArgumentException when the agreement covers none of the needed scopes
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> issueRpt(Map<String, Object> rec, String contractHash,
                                        Map<String, Object> signerJwk,
                                        Map<String, Object> operation) {
        String family = (String) rec.get("family");
        Map<String, Object> tier = policy.tiers().get((String) rec.get("tier"));
        Map<String, Object> terms = (Map<String, Object>) tier.get("terms");
        Map<String, Object> contract = (Map<String, Object>) rec.get("contract");
        long lifetime = ((Number) terms.get("expires_in")).longValue();
        if (contract.get("expires_in") instanceof Number agreed && agreed.longValue() > 0) {
            lifetime = Math.min(lifetime, agreed.longValue());
        }
        List<String> scopes = grantedScopes(rec, terms, contract);
        long now = AsState.now();
        String jti = "rpt_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String handle = connectionHandle((Map<String, Object>) contract.get("_identity"),
                signerJwk);

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", config.issuer);
        claims.put("sub", handle);
        claims.put("client_id", handle);
        claims.put("owner", config.ownerUsername);
        claims.put("aud", config.rptAudience);
        claims.put("jti", jti);
        claims.put("iat", now);
        claims.put("exp", now + lifetime);
        claims.put("cnf", Map.of("jwk", signerJwk));
        Map<String, Object> permission = new LinkedHashMap<>();
        permission.put("resource_id", rec.get("resource_id"));
        permission.put("resource_scopes", scopes);
        permission.put("exp", now + lifetime);
        claims.put("permissions", List.of(permission));
        claims.put("contract", contractHash);
        // What the resource said the act leaves behind when she answered, so the
        // enforcement point can tell the question it performs is still the one she was asked.
        String declared = consequenceOf((String) rec.get("resource_id"));
        if (declared != null) {
            claims.put("consequence", declared);
        }
        Map<String, Object> attested = Organization.object(rec.get("clearance"));
        if (!attested.isEmpty()) {
            claims.put("clearance", io.uma4agents.common.Clearance.digest(attested));
        }
        if (operation != null) {
            claims.put("single_use", true);
            Map<String, Object> boundOperation = new LinkedHashMap<>();
            boundOperation.put("tool", operation.get("tool"));
            Object params = operation.getOrDefault("params", Map.of());
            boundOperation.put("params_s256", S256.of(PyJson.compactSortedUnicode(params)
                    .getBytes(StandardCharsets.UTF_8)));
            claims.put("operation", boundOperation);
        }
        String token = CompactJws.sign(keys.header("at+jwt"), claims, keys.current().getPrivate());

        int seen = rec.get("revocations_seen") instanceof Number n ? n.intValue() : 0;
        if (!store.recordRptIfConnected(jti, family, handle,
                (Map<String, Object>) claims.get("operation"), (String) rec.get("tier"), seen)) {
            throw new GrantWithdrawn("this agent was revoked after it asked");
        }
        state.log.event("rpt.issued", family, "jti", jti,
                "single_use", claims.getOrDefault("single_use", false), "tier", rec.get("tier"));

        // MyTerms pattern: identical, dually-signed copies on both sides. The
        // receipt embeds the complete agent-signed agreement JWS, counter-signed
        // by the AS.
        Map<String, Object> template = (Map<String, Object>) rec.get("template");
        Map<String, Object> receiptClaims = new LinkedHashMap<>();
        receiptClaims.put("iss", config.issuer);
        receiptClaims.put("sub", handle);
        receiptClaims.put("iat", AsState.now());
        receiptClaims.put("family", family);
        receiptClaims.put("terms_uri", template.get("terms_uri"));
        receiptClaims.put("template_id", template.get("template_id"));
        receiptClaims.put("agreement", contractHash);
        receiptClaims.put("agreement_jws", rec.get("agreement_jws"));
        String receipt = CompactJws.sign(keys.header("myterms-receipt+jws"), receiptClaims,
                keys.current().getPrivate());
        rec.put("receipt", receipt);
        state.log.event("receipt.issued", family, "agreement", contractHash);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", token);
        response.put("token_type", "PoP");
        response.put("expires_in", lifetime);
        response.put("receipt", receipt);
        return response;
    }

    /**
     * The scopes a grant carries: what the request needs, limited to what the tier offered
     * and the agreement accepted. Refused when that leaves nothing.
     */
    @SuppressWarnings("unchecked")
    private static List<String> grantedScopes(Map<String, Object> rec, Map<String, Object> terms,
                                              Map<String, Object> contract) {
        List<Object> offered = terms.get("scope") instanceof List<?> l ? (List<Object>) l
                : List.of();
        List<Object> agreed = contract.get("scope") instanceof List<?> l ? (List<Object>) l
                : List.of();
        List<String> scopes = new java.util.ArrayList<>();
        for (Object scope : (List<Object>) rec.get("resource_scopes")) {
            if (offered.isEmpty() || (offered.contains(scope) && agreed.contains(scope))) {
                scopes.add(String.valueOf(scope));
            }
        }
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException(
                    "the agreement covers none of the scopes this request needs");
        }
        return scopes;
    }

    /** The declared class of a registered resource, or null when nothing was declared. */
    public String consequenceOf(String resourceId) {
        Map<String, Object> desc = resourceId == null ? null : state.resource(resourceId);
        return desc == null ? null : io.uma4agents.common.Consequence.normalise(
                desc.get("consequence"));
    }

    public static byte[] base64UrlDecodePadded(String value) {
        int pad = (4 - value.length() % 4) % 4;
        return Base64.getUrlDecoder().decode(value + "=".repeat(pad));
    }
}
