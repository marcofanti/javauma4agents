package io.uma4agents.pep.core;

import io.uma4agents.common.EventLog;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.S256;
import io.uma4agents.pep.core.EnforcerSettings.ToolSurface;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One owner's enforcement obligations against one authorization server: the verdict
 * pipeline shared by the ext_authz gateway host and the embedded vault host. Ported from
 * the pinned {@code lib/uma4a_pep.py}; the organization and joint branches land in Phase E.
 */
public class Enforcer {

    /** Inactive-grant reasons answered with a fresh challenge rather than a refusal. */
    static final Set<String> RENEGOTIABLE = Set.of("expired", "invalid_signature",
            "unknown_token", "already_consumed", "revoked");
    private static final String MIN_ROUTED_VERSION = "2026-07-28";

    private final EnforcerSettings settings;
    private final ProtectionClient protection;
    private final EventLog log;

    public Enforcer(EnforcerSettings settings, ProtectionClient protection, EventLog log) {
        this.settings = settings;
        this.protection = protection;
        this.log = log;
    }

    public EnforcerSettings settings() {
        return settings;
    }

    /** The Origin rule, applied by hosts to every request to the MCP endpoint. */
    public Decision originRefused(String origin) {
        if (origin != null && !origin.isEmpty() && !settings.allowedOrigins().contains(origin)) {
            log.event("access.denied", null, "reason", "bad-origin", "origin", origin);
            return Decision.deny(403, "invalid_origin", "");
        }
        return null;
    }

    /** Decides one request; the ordering is normative. */
    public Decision authorize(AuthzFacts f) {
        return authorize(f, (info, surface) -> null, false);
    }

    @FunctionalInterface
    public interface GrantGuard {
        Decision check(Map<String, Object> grant, ToolSurface surface);
    }

    /** Checks a host-scoped grant after proof of possession and before it can be spent. */
    public Decision authorize(AuthzFacts f, GrantGuard guard, boolean override) {
        Decision early = requestShape(f);
        if (early != null) {
            return early;
        }
        ToolSurface surface = settings.tools().get(f.tool());
        if (f.authorization() == null || f.authorization().isEmpty()) {
            return challenge(f.tool(), surface);
        }
        if (!f.authorization().startsWith("PoP ")) {
            return Decision.deny(401, "invalid_token", "RPTs are PoP tokens here, not Bearer");
        }
        String rpt = f.authorization().substring(4);
        Map<String, Object> info = protection.introspect(rpt);
        if (!Boolean.TRUE.equals(info.get("active"))) {
            String reason = String.valueOf(info.getOrDefault("error", ""));
            log.event("access.denied", null, "reason", "inactive-rpt: " + reason,
                    "tool", f.tool());
            return override ? Decision.deny(403, reason.isEmpty() ? "invalid_token" : reason,
                    "the organization did not confirm an active override")
                    : notLive(reason, f.tool(), surface);
        }
        if (!permits(info, surface)) {
            log.event("access.denied", null, "reason", "permission-scope", "tool", f.tool(),
                    "needed", surface.scopes());
            return override ? Decision.deny(403, "insufficient_authorization",
                    "the override does not cover this resource and scope")
                    : challenge(f.tool(), surface);
        }
        Decision proof = proofOfPossession(f, info);
        if (proof != null) {
            return proof;
        }
        Decision limited = guard.check(info, surface);
        if (limited != null) {
            return limited;
        }
        Decision raised = consequenceRaised(f.tool(), surface, info);
        if (raised != null) {
            return raised;
        }
        if (settings.singleUseTools().contains(f.tool())
                || Boolean.TRUE.equals(info.get("single_use"))) {
            Decision spent = spendOnce(f, info, rpt, surface);
            if (spent != null) {
                return spent;
            }
        }
        String family = info.get("family") == null ? "?" : String.valueOf(info.get("family"));
        String contract = info.get("contract") == null ? null
                : String.valueOf(info.get("contract"));
        log.event("access.allowed", family, "tool", f.tool(), "contract", contract,
                "single_use", Boolean.TRUE.equals(info.get("single_use")),
                "break_glass", info.get("break_glass") instanceof Map<?, ?>,
                "traceparent", f.traceparent());
        protection.reportAccess(family, f.tool(),
                PyJson.dumpsSorted(f.args() == null ? Map.of() : f.args()));
        return Decision.allowed(family, contract);
    }

    /** Origin, header/body reconciliation, method and tool admission, in pinned order. */
    private Decision requestShape(AuthzFacts f) {
        Decision refused = originRefused(f.origin());
        if (refused != null) {
            return refused;
        }
        if (f.headerMcpMethod() != null && f.mcpMethod() != null
                && !f.headerMcpMethod().equals(f.mcpMethod())) {
            log.event("access.denied", null, "reason", "header-body-mismatch",
                    "header_method", f.headerMcpMethod(), "body_method", f.mcpMethod());
            return Decision.deny(400, "header_body_mismatch",
                    "Mcp-Method disagrees with the JSON-RPC body");
        }
        if (f.headerMcpName() != null && f.tool() != null
                && !f.headerMcpName().equals(f.tool())) {
            log.event("access.denied", null, "reason", "header-body-mismatch",
                    "header_name", f.headerMcpName(), "body_name", f.tool());
            return Decision.deny(400, "header_body_mismatch",
                    "Mcp-Name disagrees with the JSON-RPC body");
        }
        // A body with no readable method is neither open nor protected. Checked before the
        // set lookups, which do not admit null.
        String method = f.mcpMethod();
        if (method != null && settings.openMethods().contains(method)) {
            return Decision.ALLOW;
        }
        if (method == null || !settings.protectedMethods().contains(method)) {
            log.event("access.denied", null, "reason", "unknown-method", "mcp_method", method);
            return Decision.deny(403, "unknown_method",
                    (method == null ? "None" : method) + " is not enforceable by this PEP");
        }
        if (f.protocolVersion() != null && f.protocolVersion().compareTo(MIN_ROUTED_VERSION) >= 0
                && (f.headerMcpMethod() == null || f.headerMcpName() == null)) {
            log.event("access.denied", null, "reason", "missing-routing-headers",
                    "tool", f.tool());
            return Decision.deny(400, "missing_routing_headers",
                    "Mcp-Method and Mcp-Name are required on tools/call");
        }
        if (f.tool() == null || !settings.tools().containsKey(f.tool())) {
            log.event("access.denied", null, "reason", "unknown-tool", "tool", f.tool());
            return Decision.deny(403, "unknown_tool", "");
        }
        return null;
    }

    private static boolean permits(Map<String, Object> info, ToolSurface surface) {
        double now = Instant.now().getEpochSecond();
        for (Object p : listOf(info.get("permissions"))) {
            if (!(p instanceof Map<?, ?> perm)
                    || !surface.resourceId().equals(perm.get("resource_id"))) {
                continue;
            }
            Set<Object> granted = new HashSet<>(listOf(perm.get("resource_scopes")));
            boolean scoped = granted.containsAll(surface.scopes());
            boolean notExpired = !(perm.get("exp") instanceof Number exp)
                    || exp.doubleValue() > now;
            boolean started = !(perm.get("nbf") instanceof Number nbf)
                    || nbf.doubleValue() <= now;
            if (scoped && notExpired && started) {
                return true;
            }
        }
        return false;
    }

    private Decision proofOfPossession(AuthzFacts f, Map<String, Object> info) {
        try {
            if (!(info.get("cnf") instanceof Map<?, ?> cnf) || !(cnf.get("jwk") instanceof Map<?, ?> jwk)) {
                throw new HttpSignature.VerifyException("the grant names no confirmation key");
            }
            @SuppressWarnings("unchecked")
            PublicKey key = Jwks.toPublicKey((Map<String, Object>) jwk);
            HttpSignature.verify(new HttpSignature.VerifyRequest(f.httpMethod(),
                    settings.expectedAuthority(), f.path(), f.authorization(),
                    f.signatureInput(), f.signature(), key, 60, f.signatureAgent(), f.body(),
                    settings.requireContentDigest(), f.contentDigest()));
            return null;
        } catch (HttpSignature.VerifyException | IllegalArgumentException e) {
            log.event("access.denied", null, "reason", "pop: " + e.getMessage(),
                    "tool", f.tool(), "path", f.path(), "signature_input", f.signatureInput());
            return Decision.deny(401, "invalid_token",
                    "proof-of-possession failed: " + e.getMessage());
        }
    }

    /**
     * The grant was issued against what this resource said the act costs. If it now says
     * something worse, her authority answered a different question. Both sides must be
     * declared: refusing grants issued before anything was declared would revoke every
     * standing grant the day a deployment first described its tools.
     */
    private Decision consequenceRaised(String tool, ToolSurface surface,
                                       Map<String, Object> info) {
        Integer declared = io.uma4agents.common.Consequence.rank(surface.consequence());
        Integer granted = io.uma4agents.common.Consequence.rank(info.get("consequence"));
        if (declared == null || granted == null || declared <= granted) {
            return null;
        }
        log.event("access.denied", null, "reason", "consequence-raised", "tool", tool,
                "granted", info.get("consequence"), "declared", surface.consequence());
        return Decision.deny(403, "consequence_changed",
                "this operation now declares a consequence the grant was not issued against");
    }

    private Decision spendOnce(AuthzFacts f, Map<String, Object> info, String rpt,
                               ToolSurface surface) {
        Map<?, ?> op = info.get("operation") instanceof Map<?, ?> m ? m : Map.of();
        if (op.isEmpty()) {
            log.event("access.denied", null, "reason", "operation-binding-missing",
                    "tool", f.tool());
            return Decision.deny(403, "operation_required",
                    "this tool takes a grant bound to one operation");
        }
        String actual = S256.of(PyJson.compactSortedUnicode(f.args() == null ? Map.of() : f.args())
                .getBytes(StandardCharsets.UTF_8));
        if (!f.tool().equals(op.get("tool")) || !actual.equals(op.get("params_s256"))) {
            log.event("access.denied", null, "reason", "operation-binding", "tool", f.tool(),
                    "expected", op.get("params_s256"), "actual", actual);
            return Decision.deny(403, "operation_mismatch",
                    "RPT authorizes a different operation");
        }
        Map<String, Object> spent = protection.consume(rpt);
        if (spent == null) {
            log.event("access.denied", null, "reason", "consume-unavailable", "tool", f.tool());
            return Decision.deny(503, "temporarily_unavailable", "the grant could not be spent "
                    + "because the authorization server could not be reached");
        }
        if (Boolean.TRUE.equals(spent.get("consumed"))) {
            return null;
        }
        String reason = String.valueOf(spent.getOrDefault("error", ""));
        if ("already_consumed".equals(reason)) {
            log.event("access.denied", null, "reason", "consume-lost-race", "tool", f.tool());
            return Decision.deny(403, "already_consumed",
                    "this single-use grant was already spent");
        }
        log.event("access.denied", null, "reason", "consume-refused: " + reason,
                "tool", f.tool());
        return notLive(reason, f.tool(), surface);
    }

    /** What to tell the agent when its grant is not live, by reason. */
    Decision notLive(String reason, String tool, ToolSurface surface) {
        if (ProtectionClient.UNAVAILABLE.equals(reason)) {
            return Decision.deny(503, "temporarily_unavailable",
                    "the authorization server could not be asked about this grant");
        }
        if (RENEGOTIABLE.contains(reason) || ProtectionClient.PENDING.equals(reason)) {
            return challenge(tool, surface);
        }
        if ("organization_revoked".equals(reason)) {
            return Decision.deny(403, "access_revoked",
                    "the owner's organization revoked this agent");
        }
        return Decision.deny(403, "access_revoked", "the resource owner revoked this agent");
    }

    /** Beat 1: a real ticket from the AS, and where to take it. */
    public Decision challenge(String tool, ToolSurface surface) {
        String ticket;
        try {
            ticket = protection.mintTicket(surface.resourceId(), surface.scopes());
        } catch (ProtectionClient.PendingException e) {
            log.event("challenge.awaiting_owner", null, "tool", tool,
                    "resource_id", surface.resourceId(), "error", e.getMessage());
            return Decision.awaitingOwner(settings.asPublic(), settings.resourceMetadataUrl());
        }
        if (ticket == null) {
            return Decision.deny(503, "temporarily_unavailable",
                    "the owner's authorization server could not issue a ticket for this "
                            + "resource");
        }
        List<Map<String, Object>> details = authorizationDetails(surface, tool);
        log.event("challenge.issued", null, "tool", tool, "resource_id", surface.resourceId(),
                "scopes", surface.scopes());
        String reference = S256.of(PyJson.compactSortedUnicode(details)
                .getBytes(StandardCharsets.UTF_8));
        return Decision.challenge(ticket, settings.asPublic(), settings.resourceMetadataUrl(),
                surface.scopes(), details, reference);
    }

    /** The RFC 9396 description of the missing authority. */
    List<Map<String, Object>> authorizationDetails(ToolSurface surface, String tool) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "https://u4a.ai/spec/core/1.0#tool-call");
        String url = settings.resourceMetadataUrl();
        int wellKnown = url.lastIndexOf("/.well-known/");
        detail.put("locations", List.of(wellKnown < 0 ? url : url.substring(0, wellKnown)));
        detail.put("identifier", surface.resourceId());
        detail.put("actions", List.of(tool));
        detail.put("datatypes", surface.scopes());
        // What the act leaves behind, before the agent negotiates for it.
        if (surface.consequence() != null) {
            detail.put("consequence", surface.consequence());
        }
        return List.of(detail);
    }

    /** The {@code authorization_remediation} object, the same in both envelopes. */
    public static Map<String, Object> remediation(Decision d) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("authorization_details",
                d.authorizationDetails() == null ? List.of() : d.authorizationDetails());
        out.put("authorization_reference", d.authorizationReference());
        out.put("authorization_server", d.asUri());
        out.put("ticket", d.ticket());
        return out;
    }

    /** The UMA challenge header, for hosts that have a status line. */
    public String wwwAuthenticate(Decision d) {
        String blob = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                PyJson.compactOrdered(remediation(d)).getBytes(StandardCharsets.UTF_8));
        List<String> parts = new ArrayList<>();
        parts.add("realm=\"" + settings.realm() + "\"");
        parts.add("error=\"insufficient_authorization\"");
        parts.add("as_uri=\"" + d.asUri() + "\"");
        parts.add("ticket=\"" + d.ticket() + "\"");
        parts.add("resource_metadata=\"" + d.resourceMetadata() + "\"");
        if (d.scopes() != null && !d.scopes().isEmpty()) {
            parts.add("scope=\"" + String.join(" ", d.scopes()) + "\"");
        }
        parts.add("authorization_remediation=\"" + blob + "\"");
        return "UMA " + String.join(", ", parts);
    }

    /**
     * The in-band envelope for hosts without a status line: a JSON-RPC error object. A
     * challenge is code -32001 with the ticket and remediation; anything else is -32002.
     */
    public Map<String, Object> jsonRpcError(Decision d) {
        Map<String, Object> error = new LinkedHashMap<>();
        Map<String, Object> data = new LinkedHashMap<>();
        if (d.outcome() == Decision.Outcome.CHALLENGE) {
            error.put("code", UMA_CHALLENGE);
            error.put("message",
                    "authorization required: present this ticket to the resource owner's AS");
            data.put("error", "insufficient_authorization");
            data.put("as_uri", d.asUri());
            data.put("ticket", d.ticket());
            data.put("resource_metadata", d.resourceMetadata());
            data.put("realm", settings.realm());
            data.put("scope", String.join(" ", d.scopes() == null ? List.of() : d.scopes()));
            data.put("authorization_remediation", remediation(d));
        } else {
            error.put("code", UMA_DENIED);
            error.put("message", d.description() == null || d.description().isEmpty()
                    ? d.error() : d.description());
            data.put("error", d.error());
            data.put("status", d.status());
        }
        error.put("data", data);
        return error;
    }

    /** JSON-RPC error code for an in-band UMA challenge. */
    public static final int UMA_CHALLENGE = -32001;
    /** JSON-RPC error code for an in-band refusal. */
    public static final int UMA_DENIED = -32002;

    private static List<?> listOf(Object value) {
        return value instanceof List<?> list ? list : List.of();
    }
}
