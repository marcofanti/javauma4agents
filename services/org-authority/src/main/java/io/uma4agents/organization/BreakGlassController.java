package io.uma4agents.organization;

import static io.uma4agents.organization.OrganizationAdministration.random;
import static io.uma4agents.organization.OrganizationAdministration.row;
import static io.uma4agents.organization.OrganizationCharter.object;
import static io.uma4agents.organization.OrganizationCharter.strings;
import static io.uma4agents.organization.OrganizationCharter.text;
import static io.uma4agents.organization.OrganizationMembership.bad;
import static io.uma4agents.organization.OrganizationMembership.number;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.OrganizationPatterns;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.PyRepr;
import io.uma4agents.common.S256;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
final class BreakGlassController {
    private static final String GLASS = "break_glass";

    private final OrganizationState state;
    private final OrganizationMembership membership;
    private final OrganizationAdminAuth auth;
    private final OrgHttp http;
    private final Object lock = new Object();
    private final Map<String, Voucher> vouchers = new LinkedHashMap<>();
    private final Map<String, Grant> grants = new LinkedHashMap<>();
    private final Map<String, Long> signatures = new LinkedHashMap<>();

    private record Voucher(OrganizationState.Member member, String admin, String reason,
                           String opened, long expires) {}

    private static final class Grant {
        final OrganizationState.Member member;
        final Map<String, Object> claims;
        final String resource;
        final String reason;
        final String authorizedBy;
        final String issued = EventLog.utcNow();
        boolean spent;
        boolean released;

        Grant(OrganizationState.Member member, Map<String, Object> claims, String resource,
              String reason, String authorizedBy) {
            this.member = member;
            this.claims = claims;
            this.resource = resource;
            this.reason = reason;
            this.authorizedBy = authorizedBy;
        }
    }

    private record Lookup(Grant grant, String refusal) {}

    BreakGlassController(OrganizationState state, OrganizationMembership membership,
                         OrganizationAdminAuth auth, OrgHttp http) {
        this.state = state;
        this.membership = membership;
        this.auth = auth;
        this.http = http;
    }

    @GetMapping("/admin/break-glass")
    Map<String, Object> log(HttpServletRequest request) {
        auth.requireAdmin(request);
        synchronized (lock) {
            List<Map<String, Object>> open = new ArrayList<>();
            long now = now();
            vouchers.forEach((code, voucher) -> {
                if (voucher.expires > now) {
                    open.add(Map.of("code", code, "owner", voucher.member.owner, "admin", voucher.admin,
                            "reason", voucher.reason, "opened", voucher.opened, "expires", voucher.expires,
                            "membership", voucher.member.tokenJti, "expires_in", voucher.expires - now));
                }
            });
            List<Map<String, Object>> issued = new ArrayList<>();
            grants.forEach((jti, g) -> issued.addFirst(Map.of("jti", jti, "member", g.member.owner,
                    "resource_id", g.resource, "reason", g.reason, "authorised_by", g.authorizedBy,
                    "issued", g.issued, "spent", g.spent)));
            return Map.of("clause", clause(), "open_vouchers", open, "grants", issued);
        }
    }

    @PostMapping("/admin/break-glass")
    Map<String, Object> open(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        String admin = auth.requireAdmin(request);
        Map<String, Object> clause = clause();
        requireEnabled(clause);
        var member = membership.findMember(text(body.get("owner")).strip());
        String reason = reason(body, clause);
        long ttl = positiveRange(body.get("window_s"), 300, 3600);
        List<String> resources = strings(clause.get("resources"), "break_glass.resources");
        if (!membership.notify(member, Map.of("kind", "break_glass_opened", "by", admin,
                "reason", reason, "window_s", ttl, "resources", resources))) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "her authority could not be told, so no window was opened; try again");
        }
        String code = "bgv_" + random(9);
        synchronized (lock) {
            long now = now();
            vouchers.values().removeIf(v -> v.expires <= now);
            vouchers.put(code, new Voucher(member, admin, reason, EventLog.utcNow(), now + ttl));
        }
        state.note("break_glass.opened", Map.of("member", member.owner, "by", admin, "window_s", ttl));
        return Map.of("voucher", code, "expires_in", ttl, "owner", member.owner,
                "resources", resources, "max_expires_in", clause.get("max_expires_in"));
    }

    @PostMapping("/break-glass")
    Map<String, Object> redeem(HttpServletRequest request, @RequestBody byte[] bytes) {
        var version = state.current();
        Map<String, Object> clause = object(version.charter().get(GLASS));
        requireEnabled(clause);
        Map<String, Object> body = http.decode(new String(bytes, java.nio.charset.StandardCharsets.UTF_8));
        if (body == null) {
            throw bad("a break-glass request must be an object");
        }
        Map<String, Object> jwk = object(body.get("agent_jwk"));
        verify(request, bytes, jwk);
        var member = membership.findMember(text(body.get("owner")).strip());
        String resource = text(body.get("resource_id")).strip();
        if (!OrganizationPatterns.matches(resource, strings(clause.get("resources"), "resources"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "the charter does not name "
                    + PyRepr.of(resource) + " for break-glass");
        }
        String reason = reason(body, clause);
        Map<String, Object> op = object(body.get("operation"));
        String tool = text(op.get("tool"));
        Object params = op.getOrDefault("params", Map.of());
        if (!tool.equals(resource.substring(resource.lastIndexOf('/') + 1))
                || !(params instanceof Map<?, ?>)) {
            throw bad("break-glass is for one act: name the operation as {tool, params}, "
                    + "for the tool the resource is");
        }
        String sig = request.getHeader("signature").strip();
        synchronized (lock) {
            rejectReplay(sig, now());
        }
        String code = text(body.get("voucher"));
        Voucher voucher;
        synchronized (lock) {
            Voucher candidate = vouchers.get(code);
            voucher = candidate != null && candidate.member == member && candidate.expires > now()
                    ? candidate : null;
        }
        String thumb = Jwks.thumbprint(jwk);
        String approvedBy = voucher == null ? listedOperator(clause, thumb)
                : "voucher from " + voucher.admin;
        if (approvedBy == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "break-glass needs either a voucher opened by an administrator or a key "
                            + "published by an operator this charter lists");
        }
        long ceiling = number(clause.get("max_expires_in"), 900);
        long ttl = positiveRange(body.get("expires_in"), ceiling, ceiling);
        List<String> asked = strings(body.get("scopes"), "scopes");
        Object allowed = object(version.charter().get("envelope")).get("allowed_scopes");
        List<String> scopes = allowed instanceof List<?> allow
                ? asked.stream().filter(allow::contains).toList() : asked;
        if (!asked.isEmpty() && scopes.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "this charter does not allow "
                    + String.join(", ", asked) + " over its resources, under break-glass or otherwise");
        }

        String jti = "bg_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        long now = now();
        long exp = now + ttl;
        Map<String, Object> glass = Map.of("org", state.config.id, "reason", reason,
                "authorised_by", approvedBy, "charter_version", version.number());
        Map<String, Object> claims = row("iss", state.config.issuer, "sub", thumb, "client_id", thumb,
                "owner", member.owner, "aud", state.config.glassAudience, "jti", jti, "iat", now,
                "exp", exp, "cnf", Map.of("jwk", jwk), "permissions",
                List.of(Map.of("resource_id", resource, "resource_scopes", scopes, "exp", exp)),
                GLASS, glass, "single_use", true, "operation", Map.of("tool", tool, "params_s256",
                        S256.of(PyJson.compactSortedUnicode(params))));
        var grant = new Grant(member, claims, resource, reason, approvedBy);
        synchronized (lock) {
            rejectReplay(sig, now);
            if (state.members.get(member.owner) != member || state.current() != version) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "the membership or charter changed while this request was being checked");
            }
            if (voucher != null && !vouchers.remove(code, voucher)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "that voucher has been used");
            }
            signatures.put(sig, now);
            grants.put(jti, grant);
        }
        Map<String, Object> notice = row("kind", GLASS, "resource_id", resource, "scopes", scopes,
                "reason", reason, "authorised_by", approvedBy, "expires_in", ttl, "family", jti,
                "charter_version", version.number());
        if (!membership.notify(member, notice)) {
            synchronized (lock) {
                grant.spent = true;
            }
            state.note("break_glass.voided", Map.of("member", member.owner, "jti", jti,
                    "reason", "the member's authority could not be told"));
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "the member's authorization server could not be told of this override");
        }
        synchronized (lock) {
            grant.released = true;
        }
        state.note("break_glass.granted", Map.of("member", member.owner, "resource", resource,
                "jti", jti, "authorised_by", approvedBy, "expires_in", ttl));
        return Map.of("access_token", state.sign("at+jwt", claims), "token_type", "PoP",
                "expires_in", ttl, GLASS, glass);
    }

    private void verify(HttpServletRequest request, byte[] body, Map<String, Object> jwk) {
        try {
            HttpSignature.verify(new HttpSignature.VerifyRequest("POST", state.config.authority,
                    "/break-glass", "", request.getHeader("signature-input"),
                    request.getHeader("signature"), Jwks.toPublicKey(jwk), 60, null, body, true,
                    request.getHeader("content-digest")));
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "break-glass must be signed by the key it will bind to: " + invalid.getMessage());
        }
    }

    private String listedOperator(Map<String, Object> clause, String thumb) {
        for (String origin : strings(clause.get("invokers"), "break_glass.invokers")) {
            try {
                Map<String, Object> keys = http.get(origin.replaceFirst("/+$", "")
                        + "/.well-known/http-message-signatures-directory");
                if (keys.get("keys") instanceof List<?> published) {
                    for (Object key : published) {
                        var jwk = object(key);
                        if ("OKP".equals(jwk.get("kty")) && "Ed25519".equals(jwk.get("crv"))
                                && thumb.equals(Jwks.thumbprint(jwk))) {
                            return "operator " + origin;
                        }
                    }
                }
            } catch (RuntimeException unavailable) {
                state.note("invoker_directory.unresolved", Map.of("origin", origin));
            }
        }
        return null;
    }

    private void rejectReplay(String signature, long now) {
        signatures.values().removeIf(t -> t < now - 120);
        if (signatures.containsKey(signature)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "that request has already been redeemed. Sign a new one");
        }
    }

    @PostMapping(value = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    Map<String, Object> introspect(HttpServletRequest request, @RequestParam String token) {
        auth.requireResourceServer(request);
        synchronized (lock) {
            Lookup lookup = lookup(token);
            if (lookup.refusal != null) {
                return Map.of("active", false, "error", lookup.refusal);
            }
            Map<String, Object> c = lookup.grant.claims;
            return row("active", true, "family", c.get("jti"), "iss", c.get("iss"), "sub", c.get("sub"),
                    "owner", c.get("owner"), "exp", c.get("exp"), "permissions", c.get("permissions"),
                    "cnf", c.get("cnf"), "contract", null, "single_use", true,
                    "operation", c.get("operation"), GLASS, c.get(GLASS));
        }
    }

    @PostMapping(value = "/consume", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    Map<String, Object> consume(HttpServletRequest request, @RequestParam String token) {
        auth.requireResourceServer(request);
        synchronized (lock) {
            Lookup lookup = lookup(token);
            if (lookup.refusal != null) {
                return Map.of("consumed", false, "error", lookup.refusal);
            }
            Grant grant = lookup.grant;
            grant.spent = true;
            Object family = grant.claims.get("jti");
            state.note("break_glass.spent", Map.of("member", grant.member.owner, "jti", family,
                    "resource", grant.resource));
            return Map.of("consumed", true, "family", family);
        }
    }

    @PostMapping("/audit/access")
    Map<String, Object> audit(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        auth.requireResourceServer(request);
        String family = text(body.get("family"));
        Grant grant;
        synchronized (lock) {
            grant = grants.get(family);
        }
        if (grant != null) {
            state.note("break_glass.used", row("member", grant.member.owner, "tool", body.get("tool"),
                    "jti", family));
            membership.notify(grant.member, row("kind", "break_glass_used", "family", family,
                    "tool", body.get("tool"), "summary", body.get("summary"),
                    "resource_id", grant.resource, "reason", grant.reason));
        }
        return Map.of("recorded", true);
    }

    private Lookup lookup(String token) {
        Map<String, Object> claims;
        try {
            var decoded = CompactJws.verify(token, state.config.signing.getPublic());
            claims = decoded.claims();
            if (!state.config.issuer.equals(claims.get("iss"))
                    || !"at+jwt".equals(decoded.header().get("typ"))) {
                return new Lookup(null, "invalid_signature");
            }
        } catch (RuntimeException refused) {
            return new Lookup(null, "invalid_signature");
        }
        if (number(claims.get("exp"), 0) <= now()) {
            return new Lookup(null, "expired");
        }
        Grant grant = grants.get(text(claims.get("jti")));
        if (grant == null || !grant.released) {
            return new Lookup(null, "unknown_token");
        }
        if (grant.spent) {
            return new Lookup(null, "already_consumed");
        }
        if (state.members.get(grant.member.owner) != grant.member) {
            return new Lookup(null, "revoked");
        }
        return new Lookup(grant, null);
    }

    private Map<String, Object> clause() {
        return object(state.current().charter().get(GLASS));
    }

    private static void requireEnabled(Map<String, Object> clause) {
        if (!Boolean.TRUE.equals(clause.get("enabled"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "this organization's charter does not permit break-glass access");
        }
    }

    private static String reason(Map<String, Object> body, Map<String, Object> clause) {
        String value = text(body.get("reason")).strip();
        if (Boolean.TRUE.equals(clause.get("require_reason")) && value.isEmpty()) {
            throw bad("the charter requires a stated reason");
        }
        return value;
    }

    private static long positiveRange(Object value, long fallback, long max) {
        long requested = number(value, fallback);
        if (requested <= 0) {
            throw bad("the duration must be positive");
        }
        return Math.min(requested, max);
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }
}
