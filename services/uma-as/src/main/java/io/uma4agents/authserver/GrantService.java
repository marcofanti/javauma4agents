package io.uma4agents.authserver;

import io.uma4agents.common.EventLog;

import io.uma4agents.common.CompactJws;
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
    private final PolicyService policy;
    private final TokenVerifiers verifiers;

    public GrantService(AsConfig config, AsState state, PolicyService policy,
                        TokenVerifiers verifiers) {
        this.config = config;
        this.state = state;
        this.policy = policy;
        this.verifiers = verifiers;
    }

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
        String token = CompactJws.sign(
                Map.of("typ", "pat+jwt", "kid", AsConfig.KID), claims, state.signingKey.getPrivate());
        state.rsClients.get(clientId).put("last_pat_issued", EventLog.utcNow());
        state.log.event("pat.issued", null, "client_id", clientId, "expires_in", AsConfig.PAT_TTL);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", token);
        response.put("token_type", "Bearer");
        response.put("expires_in", AsConfig.PAT_TTL);
        response.put("scope", "uma_protection");
        return response;
    }

    /** Verifies a PAT for the Protection API; throws with a FastAPI-shaped detail. */
    public void requirePat(String authorization) {
        String token = TokenVerifiers.bearer(authorization);
        Map<String, Object> claims;
        try {
            CompactJws.Parsed parsed =
                    CompactJws.verify(token, state.signingKey.getPublic());
            claims = parsed.claims();
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
        Map<String, Object> rs = state.rsClients.get(String.valueOf(claims.get("azp")));
        if (rs == null || !"active".equals(rs.get("status"))) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.UNAUTHORIZED,
                    "the owner has revoked this resource server");
        }
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
        if (!state.termsDocs.containsKey(templateId)) {
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
            doc.put("published_at", EventLog.utcNow());
            state.termsDocs.put(templateId, doc);
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
     * {@code agent_token}. Throws IllegalArgumentException on any failure.
     */
    @SuppressWarnings("unchecked")
    public VerifiedContract verifyContract(String claimTokenB64, Map<String, Object> rec) {
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
        } else {
            throw new IllegalArgumentException(
                    "contract JWS must carry jwk or agent_token in its header");
        }

        Map<String, Object> contract;
        try {
            contract = CompactJws.verify(token, Jwks.toPublicKey(signerJwk)).claims();
        } catch (SecurityException e) {
            throw new IllegalArgumentException("Signature verification failed");
        }
        if (!config.issuer.equals(contract.get("aud"))) {
            throw new IllegalArgumentException("Audience doesn't match");
        }

        Map<String, Object> template = (Map<String, Object>) rec.get("template");
        requireEqual(contract.get("nonce"), template.get("nonce"), "nonce mismatch");
        requireEqual(contract.get("family"), rec.get("family"), "negotiation family mismatch");
        requireEqual(contract.get("template_id"), template.get("template_id"),
                "template version mismatch");
        requireEqual(contract.get("terms_uri"), template.get("terms_uri"),
                "agreement must name the proffered terms document");
        requireEqual(contract.get("purpose"), template.get("purpose"), "purpose was altered");
        List<Object> templateProhibited = (List<Object>) template.get("prohibited");
        List<Object> contractProhibited = contract.get("prohibited") instanceof List<?> list
                ? (List<Object>) list : List.of();
        if (!new HashSet<>(contractProhibited).containsAll(templateProhibited)) {
            throw new IllegalArgumentException("prohibited-actions list was weakened");
        }
        long contractExpires = contract.get("expires_in") instanceof Number n ? n.longValue() : 0;
        long templateExpires = template.get("expires_in") instanceof Number n ? n.longValue() : 0;
        if (contractExpires > templateExpires) {
            throw new IllegalArgumentException("expiry was extended beyond dictated terms");
        }
        if (Boolean.TRUE.equals(template.get("per_operation")) && contract.get("operation") == null) {
            throw new IllegalArgumentException(
                    "per-operation tier requires a proposed operation in the contract");
        }

        contract.put("_identity", identity);
        return new VerifiedContract(contract, signerJwk, identity);
    }

    private static void requireEqual(Object actual, Object expected, String message) {
        if (actual == null ? expected != null : !actual.equals(expected)) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * The stable name for a standing relationship: a pseudonymous agent is its
     * key (RFC 7638 thumbprint); an identified agent's continuity lives in its
     * issuer-qualified subject.
     */
    public String connectionHandle(Map<String, Object> identity, Map<String, Object> signerJwk) {
        if ("identified".equals(identity.get("level"))) {
            String sub = String.valueOf(identity.get("sub"));
            String host = URI.create(String.valueOf(identity.get("iss"))).getAuthority();
            return sub.endsWith("@" + host) ? sub : sub + "@" + host;
        }
        return Jwks.thumbprint(signerJwk);
    }

    // --- RPT + receipt (beat 4) ---------------------------------------------

    @SuppressWarnings("unchecked")
    public Map<String, Object> issueRpt(Map<String, Object> rec, String contractHash,
                                        Map<String, Object> signerJwk,
                                        Map<String, Object> operation) {
        String family = (String) rec.get("family");
        Map<String, Object> tier = policy.tiers().get((String) rec.get("tier"));
        Map<String, Object> terms = (Map<String, Object>) tier.get("terms");
        long expiresIn = ((Number) terms.get("expires_in")).longValue();
        long exp = AsState.now() + Math.min(3600, expiresIn);
        String jti = "rpt_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", config.issuer);
        claims.put("sub", rec.getOrDefault("agent_sub", "aauth:pseudonymous-agent"));
        claims.put("aud", config.rptAudience);
        claims.put("jti", jti);
        claims.put("exp", exp);
        claims.put("cnf", Map.of("jwk", signerJwk));
        Map<String, Object> permission = new LinkedHashMap<>();
        permission.put("resource_id", rec.get("resource_id"));
        permission.put("resource_scopes", rec.get("resource_scopes"));
        permission.put("exp", AsState.now() + expiresIn);
        claims.put("permissions", List.of(permission));
        claims.put("contract", contractHash);
        if (operation != null) {
            claims.put("single_use", true);
            Map<String, Object> boundOperation = new LinkedHashMap<>();
            boundOperation.put("tool", operation.get("tool"));
            Object params = operation.getOrDefault("params", Map.of());
            boundOperation.put("params_s256", S256.of(PyJson.dumpsSorted(params)));
            claims.put("operation", boundOperation);
        }
        String token = CompactJws.sign(Map.of("typ", "aa-auth+jwt", "kid", AsConfig.KID),
                claims, state.signingKey.getPrivate());

        Map<String, Object> contract = (Map<String, Object>) rec.get("contract");
        String handle = connectionHandle((Map<String, Object>) contract.get("_identity"), signerJwk);
        Map<String, Object> rptRecord = new LinkedHashMap<>();
        rptRecord.put("consumed", false);
        rptRecord.put("family", family);
        rptRecord.put("operation", claims.get("operation"));
        rptRecord.put("handle", handle);
        state.rpts.put(jti, rptRecord);
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
        String receipt = CompactJws.sign(Map.of("typ", "myterms-receipt+jws", "kid", AsConfig.KID),
                receiptClaims, state.signingKey.getPrivate());
        rec.put("receipt", receipt);
        state.log.event("receipt.issued", family, "agreement", contractHash);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", token);
        response.put("token_type", "PoP");
        response.put("expires_in", exp - AsState.now());
        response.put("receipt", receipt);
        return response;
    }

    public static byte[] base64UrlDecodePadded(String value) {
        int pad = (4 - value.length() % 4) % 4;
        return Base64.getUrlDecoder().decode(value + "=".repeat(pad));
    }
}
