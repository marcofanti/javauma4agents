package io.uma4agents.organization;

import static io.uma4agents.organization.OrganizationAdminAuth.bearer;
import static io.uma4agents.organization.OrganizationAdminAuth.constantTime;
import static io.uma4agents.organization.OrganizationCharter.object;
import static io.uma4agents.organization.OrganizationCharter.strings;
import static io.uma4agents.organization.OrganizationCharter.text;

import io.uma4agents.common.Clearance;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.OrganizationPatterns;
import io.uma4agents.common.PyJwtClaims;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
final class OrganizationMembership {
    private static final String MEMBERSHIP = "u4a-membership+jwt";

    private final OrganizationState state;
    private final OrgConfig config;
    private final OrganizationAdminAuth auth;
    private final OrgHttp http;
    private final EmployeeEnrollment employees;

    OrganizationMembership(OrganizationState state, OrganizationAdminAuth auth, OrgHttp http,
                           EmployeeEnrollment employees) {
        this.state = state;
        this.config = state.config;
        this.auth = auth;
        this.http = http;
        this.employees = employees;
    }

    @GetMapping("/health")
    Map<String, Object> health() {
        return Map.of("status", "ok", "org", config.id,
                "charter_version", state.current().number());
    }

    @GetMapping("/jwks")
    Map<String, Object> jwks() {
        Map<String, Object> key = Jwks.okpPublicJwk(config.signing.getPublic());
        key.put("kid", config.kid);
        key.put("use", "sig");
        key.put("alg", "EdDSA");
        return Map.of("keys", List.of(key));
    }

    @GetMapping("/.well-known/u4a-organization")
    Map<String, Object> discovery() {
        OrganizationState.Version version = state.current();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("issuer", config.issuer);
        out.put("organization", Map.of("id", config.id, "name", config.name));
        out.put("jwks_uri", config.issuer + "/jwks");
        out.put("envelope_endpoint", config.issuer + "/member/envelope");
        out.put("decision_endpoint", config.issuer + "/decision");
        out.put("enrolment_endpoint", config.issuer + "/member/join");
        out.put("enrolment_preview_endpoint", config.issuer + "/member/preview");
        out.put("invitation_endpoint", config.issuer + "/member/invitation");
        out.put("leave_endpoint", config.issuer + "/member/leave");
        out.put("clearance_endpoint", config.issuer + "/member/clearance");
        out.put("compliance_endpoint", config.issuer + "/member/compliance");
        out.put("membership_endpoint", config.issuer + "/membership");
        out.put("introspection_endpoint", config.issuer + "/introspect");
        out.put("consumption_endpoint", config.issuer + "/consume");
        out.put("audit_endpoint", config.issuer + "/audit/access");
        out.put("charter_version", version.number());
        out.put("break_glass", object(version.charter().get("break_glass")).get("enabled"));
        out.put("claims", version.charter().get("claims"));
        Map<String, Object> identity = object(version.charter().get("identity_provider"));
        out.put("identity_provider", Boolean.TRUE.equals(identity.get("enabled"))
                ? Map.of("issuer", identity.get("issuer"), "assertion", identity.get("assertion"),
                        "enrol", identity.get("enrol")) : null);
        return out;
    }

    @PostMapping("/member/preview")
    Map<String, Object> preview(@RequestBody Map<String, Object> body) {
        String code = text(body.get("code")).strip();
        if (code.isEmpty() || !(sharedCode(code) || state.invites.values().stream()
                .anyMatch(i -> open(i) && constantTime(text(i.get("code")), code)))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "that is not this organization's enrolment code");
        }
        return envelope(null);
    }

    @PostMapping("/member/join")
    synchronized Map<String, Object> join(@RequestBody Map<String, Object> body) {
        String owner = requireOwnerName(body.get("owner"));
        if (state.members.containsKey(owner)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "that name is already a member of this organization");
        }
        Object agreedTo = body.get("charter_version");
        if (agreedTo == null) {
            throw bad("name the charter version you agreed to; joining binds you to that version");
        }
        var charter = state.current();
        int version = charter.number();
        if (!Integer.toString(version).equals(agreedTo.toString())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "the charter changed from v"
                    + agreedTo + " to v" + version + " after you previewed it; look again before joining");
        }
        String code = text(body.get("code")).strip();
        Map<String, Object> invited = state.invites.get(owner);
        boolean invitation = open(invited) && constantTime(text(invited.get("code")), code);
        var federation = object(charter.charter().get("identity_provider"));
        String assertion = text(body.get("assertion"));
        String via;
        if (!assertion.isEmpty() && Boolean.TRUE.equals(federation.get("enabled"))
                && Boolean.TRUE.equals(federation.get("enrol"))) {
            employees.verify(federation, owner, assertion);
            via = "identity-provider";
        } else if (invitation) {
            via = "invitation";
        } else if (sharedCode(code)) {
            via = "code";
        } else {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "enrolment requires a valid code or an invitation for this member");
        }
        String asUri = authority(text(body.get("as_uri")).strip());
        synchronized (state.policyLock) {
            if (state.current() != charter) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "the charter changed after you previewed it; look again before joining");
            }
            Map<String, Object> claims = state.claims(owner);
            OrganizationState.Member member = new OrganizationState.Member(owner, asUri,
                    state.defaultRole(), (String) claims.get("jti"), version);
            state.members.put(owner, member);
            if ("invitation".equals(via)) {
                state.invites.remove(owner, invited);
            }
            Map<String, Object> result = envelope(member);
            result.put("membership_token", state.sign(MEMBERSHIP, claims));
            state.note("member.joined", Map.of("member", owner, "as_uri", asUri,
                    "via", via, "charter_version", version));
            return result;
        }
    }

    private boolean sharedCode(String code) {
        return !state.joinCode.isEmpty() && constantTime(
                state.joinCode.toUpperCase(java.util.Locale.ROOT),
                code.toUpperCase(java.util.Locale.ROOT));
    }

    @GetMapping("/member/invitation")
    Map<String, Object> invitation(@RequestParam(defaultValue = "") String owner) {
        Map<String, Object> invite = state.invites.get(owner.strip());
        if (!open(invite)) {
            return Map.of("invited", false);
        }
        return Map.of("invited", true, "org", config.id, "name", config.name,
                "issuer", config.issuer, "charter_version", state.current().number(),
                "by", invite.get("by"), "note", invite.get("note"), "created", invite.get("created"),
                "summary", envelope(null).get("summary"));
    }

    @PostMapping("/member/invitation/decline")
    synchronized Map<String, Object> decline(@RequestBody Map<String, Object> body) {
        String owner = requireOwnerName(body.get("owner"));
        Map<String, Object> invite = state.invites.get(owner);
        if (!open(invite)) {
            throw notFound("no open invitation");
        }
        if (!constantTime(text(invite.get("code")), text(body.get("code")))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "that is not her invitation");
        }
        Map<String, Object> declined = new LinkedHashMap<>(invite);
        declined.put("state", "declined");
        declined.put("decided", EventLog.utcNow());
        state.invites.replace(owner, invite, declined);
        state.note("invitation.declined", Map.of("member", owner));
        return Map.of("declined", true);
    }

    @PostMapping("/member/leave")
    Map<String, Object> leave(HttpServletRequest request) {
        OrganizationState.Member member = requireMember(request);
        state.members.remove(member.owner, member);
        state.note("member.left", Map.of("member", member.owner));
        return Map.of("left", config.id, "member", member.owner);
    }

    @GetMapping("/member/envelope")
    Map<String, Object> readEnvelope(HttpServletRequest request) {
        OrganizationState.Member member = requireMember(request);
        member.lastSeen = EventLog.utcNow();
        return envelope(member);
    }

    @GetMapping("/member/clearance")
    Map<String, Object> clearance(HttpServletRequest request) {
        OrganizationState.Member member = requireMember(request);
        Map<String, Object> facts = member.clearance;
        if (facts.isEmpty()) {
            throw notFound("this organization holds no clearance for that member");
        }
        Map<String, Object> claims = state.claims(member.owner);
        claims.put("aud", member.asUri);
        claims.put("exp", ((Number) claims.get("iat")).longValue() + config.clearanceTtl);
        claims.put(Clearance.CLAIM, facts);
        return Map.of("clearance", state.sign(Clearance.TYPE, claims),
                "expires_in", config.clearanceTtl);
    }

    @PostMapping("/member/compliance")
    Map<String, Object> recordCompliance(HttpServletRequest request,
                                         @RequestBody Map<String, Object> body) {
        OrganizationState.Member member = requireMember(request);
        int version = (int) number(body.get("charter_version"), 0);
        var clamped = new TreeSet<>(strings(body.get("clamped_fields"), "clamped_fields"));
        member.compliance = Map.of("charter_version", version,
                "resources_governed", number(body.get("resources_governed"), 0),
                "tiers_governed", number(body.get("tiers_governed"), 0),
                "clamped_fields", clamped, "within", !Boolean.FALSE.equals(body.get("within")),
                "reported", EventLog.utcNow());
        if (version != 0) {
            member.charterVersion = version;
        }
        state.note("member.compliance", Map.of("member", member.owner,
                "charter_version", version, "clamped", clamped));
        return Map.of("recorded", true);
    }

    @PostMapping("/decision")
    Map<String, Object> decision(HttpServletRequest request,
                                 @RequestBody Map<String, Object> facts) {
        OrganizationState.Member member = requireMember(request);
        String resource = text(facts.get("resource_id"));
        OrganizationState.Version version = state.current();
        if (!OrganizationPatterns.matches(resource, strings(version.charter().get("claims"), "claims"))) {
            return Map.of("effect", "allow", "because", List.of(), "governed", false,
                    "charter_version", version.number());
        }
        Map<String, Object> role = state.role(member);
        if (!OrganizationPatterns.matches(resource, strings(role.get("grants"), "grants"))) {
            String reason = config.name + " has not shared " + resource + " with this member"
                    + (role.get("id") == null ? ", who holds no role here"
                            : " — their role is " + role.get("name"));
            return Map.of("effect", "refuse", "because", List.of(reason), "governed", true,
                    "charter_version", version.number());
        }
        Map<String, Object> result = new LinkedHashMap<>(state.evaluate(member, facts));
        result.put("governed", true);
        result.put("charter_version", version.number());
        state.note("decision", Map.of("member", member.owner, "resource", resource,
                "effect", result.get("effect"), "because",
                result.getOrDefault("because", List.of())));
        return result;
    }

    @GetMapping("/membership/{owner}")
    Map<String, Object> membership(@PathVariable String owner, HttpServletRequest request) {
        auth.requireResourceServer(request);
        OrganizationState.Member member = state.members.get(owner);
        if (member == null) {
            return Map.of("member", false);
        }
        Map<String, Object> result = envelope(member);
        result.put("member", true);
        result.put("since", member.joined);
        return result;
    }

    OrganizationState.Member requireMember(HttpServletRequest request) {
        Map<String, Object> claims;
        try {
            var verified = CompactJws.verify(bearer(request), config.signing.getPublic());
            claims = verified.claims();
            if (!MEMBERSHIP.equals(verified.header().get("typ"))
                    || !config.issuer.equals(claims.get("iss"))) {
                throw new IllegalArgumentException("invalid membership token type or issuer");
            }
            PyJwtClaims.validateWithIat(claims, Instant.now().getEpochSecond(), "sub", "jti");
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "membership token did not verify");
        }
        OrganizationState.Member member = state.members.get(text(claims.get("sub")));
        if (member == null || !member.tokenJti.equals(claims.get("jti"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "that membership is no longer current");
        }
        return member;
    }

    OrganizationState.Member findMember(String owner) {
        OrganizationState.Member member = state.members.get(owner);
        if (member == null) {
            throw notFound("not a member");
        }
        return member;
    }

    boolean notify(OrganizationState.Member member, Map<String, Object> payload) {
        if (member.asUri.isEmpty()) {
            return false;
        }
        Map<String, Object> notice = new LinkedHashMap<>(payload);
        notice.putAll(state.claims(member.owner));
        notice.put("exp", ((Number) notice.get("iat")).longValue() + 300);
        try {
            OrgHttp.Reply response = http.send("POST", member.asUri + "/org/notice",
                    http.encode(Map.of("notice", state.sign("u4a-org-notice+jwt", notice))),
                    Map.of("Content-Type", "application/json"));
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                return true;
            }
            state.note("notice.failed", Map.of("member", member.owner,
                    "notice", payload.get("kind"), "error", "her authority answered " + response.statusCode()));
        } catch (RuntimeException unavailable) {
            state.note("notice.failed", Map.of("member", member.owner,
                    "notice", payload.get("kind"), "error", String.valueOf(unavailable.getMessage())));
        }
        return false;
    }

    Map<String, Object> envelope(OrganizationState.Member member) {
        OrganizationState.Version current = state.current();
        Map<String, Object> charter = current.charter();
        Map<String, Object> role = state.role(member);
        Map<String, Object> ceiling = object(charter.get("envelope"));
        Map<String, Object> glass = object(charter.get("break_glass"));
        Map<String, Object> result = new LinkedHashMap<>(ceiling);
        result.put("org", config.id);
        result.put("name", config.name);
        result.put("issuer", config.issuer);
        result.put("charter_version", current.number());
        result.put("published_at", current.publishedAt());
        result.put("charter_name", charter.get("name"));
        result.put("claims", charter.get("claims"));
        Map<String, Object> provider = object(charter.get("identity_provider"));
        result.put("identity_provider", Boolean.TRUE.equals(provider.get("enabled")) ? provider : null);
        Map<String, Object> override = new LinkedHashMap<>();
        override.put("enabled", glass.get("enabled"));
        override.put("resources", strings(glass.get("resources"), "break_glass.resources"));
        override.put("max_expires_in", glass.get("max_expires_in"));
        result.put("break_glass", override);
        result.put("role", role.get("id"));
        result.put("role_name", role.get("name"));
        result.put("grants", role.get("grants"));
        result.put("delegation", role.get("delegation"));
        Map<String, Object> disclosed = role.get("id") == null ? state.role(null) : role;
        result.put("summary", CharterDisclosure.summary(charter, disclosed));
        result.put("powers", CharterDisclosure.powers(charter, disclosed));
        return result;
    }

    static boolean open(Map<String, Object> invite) {
        return invite != null && "open".equals(invite.get("state"));
    }

    static String requireOwnerName(Object raw) {
        String owner = text(raw).strip();
        if (!owner.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
            throw bad("which member is joining?");
        }
        return owner;
    }

    private static String authority(String address) {
        try {
            URI uri = URI.create(address);
            if ("https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null
                    && uri.getQuery() == null && uri.getFragment() == null) {
                return address.replaceFirst("/+$", "");
            }
        } catch (IllegalArgumentException invalid) {
            throw bad("member authority must be an HTTPS URL");
        }
        throw bad("member authority must be an HTTPS URL");
    }

    static long number(Object value, long fallback) {
        return value instanceof Number n ? n.longValue() : fallback;
    }

    static ResponseStatusException bad(String reason) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, reason);
    }

    static ResponseStatusException notFound(String reason) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, reason);
    }
}
