package io.uma4agents.organization;

import static io.uma4agents.organization.OrganizationCharter.object;
import static io.uma4agents.organization.OrganizationCharter.text;
import static io.uma4agents.organization.OrganizationMembership.bad;
import static io.uma4agents.organization.OrganizationMembership.notFound;

import io.uma4agents.common.EventLog;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyRepr;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
final class OrganizationAdministration {
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    private final OrganizationState state;
    private final OrganizationMembership membership;
    private final OrganizationAdminAuth auth;
    private final OrgHttp http;

    OrganizationAdministration(OrganizationState state, OrganizationMembership membership,
                               OrganizationAdminAuth auth, OrgHttp http) {
        this.state = state;
        this.membership = membership;
        this.auth = auth;
        this.http = http;
    }

    @GetMapping("/admin/org")
    Map<String, Object> organization(HttpServletRequest request) {
        String admin = auth.requireAdmin(request);
        OrganizationState.Version version = state.current();
        return Map.ofEntries(Map.entry("id", state.config.id), Map.entry("name", state.config.name),
                Map.entry("issuer", state.config.issuer), Map.entry("admin", admin),
                Map.entry("join_code", state.joinCode), Map.entry("charter_version", version.number()),
                Map.entry("published_at", version.publishedAt()), Map.entry("published_by", version.by()),
                Map.entry("versions", state.versions().size()), Map.entry("members", state.members.size()),
                Map.entry("break_glass", object(version.charter().get("break_glass")).get("enabled")),
                Map.entry("claims", version.charter().get("claims")),
                Map.entry("summary", membership.envelope(null).get("summary")));
    }

    @GetMapping("/admin/charter")
    Map<String, Object> charter(HttpServletRequest request) {
        auth.requireAdmin(request);
        var version = state.current();
        return Map.of("version", version.number(), "charter", version.charter(),
                "published_at", version.publishedAt(), "published_by", version.by(),
                "summary", membership.envelope(null).get("summary"));
    }

    @PutMapping("/admin/charter")
    Map<String, Object> publish(HttpServletRequest request, @RequestBody Map<String, Object> draft) {
        String admin = auth.requireAdmin(request);
        Map<String, Object> charter = new LinkedHashMap<>(draft);
        Object raw = charter.remove("base_version");
        Integer baseVersion = raw == null ? null : Integer.valueOf(raw.toString());
        var version = publish(charter, admin, baseVersion);
        return Map.of("version", version.number(), "charter", version.charter(),
                "summary", CharterDisclosure.summary(version.charter(), state.role(null)));
    }

    @GetMapping("/admin/charter/versions")
    List<Map<String, Object>> versions(HttpServletRequest request) {
        auth.requireAdmin(request);
        return state.versions().stream().map(v -> Map.<String, Object>of(
                "version", v.number(), "published_at", v.publishedAt(), "by", v.by())).toList();
    }

    @GetMapping("/admin/charter/versions/{version}")
    Map<String, Object> version(@PathVariable int version, HttpServletRequest request) {
        auth.requireAdmin(request);
        return state.versions().stream().filter(v -> v.number() == version).findFirst()
                .orElseThrow(() -> notFound("no such charter version")).wire();
    }

    @GetMapping("/admin/members")
    List<Map<String, Object>> members(HttpServletRequest request) {
        auth.requireAdmin(request);
        return new TreeMap<>(state.members).values().stream().map(this::memberRow).toList();
    }

    private Map<String, Object> memberRow(OrganizationState.Member member) {
        var role = state.role(member);
        var compliance = member.compliance;
        int current = state.current().number();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("owner", member.owner);
        row.put("as_uri", member.asUri);
        row.put("joined", member.joined);
        row.put("role", role.get("id"));
        row.put("role_name", role.get("name"));
        row.put("grants", role.get("grants"));
        row.put("delegation", role.get("delegation"));
        row.put("last_seen", member.lastSeen);
        row.put("charter_version", member.charterVersion);
        row.put("current_version", current);
        row.put("compliance", compliance);
        row.put("state", compliance == null ? "unreported"
                : !Integer.valueOf(current).equals(compliance.get("charter_version")) ? "stale"
                : Boolean.TRUE.equals(compliance.get("within")) ? "within" : "outside");
        return row;
    }

    @PostMapping("/admin/members/{owner}/role")
    Map<String, Object> assignRole(@PathVariable String owner, HttpServletRequest request,
                                   @RequestBody Map<String, Object> body) {
        String admin = auth.requireAdmin(request);
        OrganizationState.Member member = membership.findMember(owner);
        String role = text(body.get("role")).strip();
        if (!role.isEmpty() && !object(state.current().charter().get("roles")).containsKey(role)) {
            throw bad(PyRepr.of(role) + " is not a role in this charter");
        }
        member.role = role.isEmpty() ? null : role;
        Map<String, Object> notice = row("kind", "role_changed", "role", member.role, "by", admin);
        membership.notify(member, notice);
        state.note("member.role_set", row("member", owner, "role", member.role, "by", admin));
        return row("owner", owner, "role", member.role);
    }

    @PutMapping("/admin/members/{owner}/clearance")
    Map<String, Object> setClearance(@PathVariable String owner, HttpServletRequest request,
                                     @RequestBody Map<String, Object> body) {
        String admin = auth.requireAdmin(request);
        OrganizationState.Member member = membership.findMember(owner);
        if (!(body.get("clearance") instanceof Map<?, ?> raw)) {
            throw bad("send {\"clearance\": {...}} — an object of facts this organization "
                    + "will attest, or {} to withdraw it");
        }
        Map<String, Object> facts = object(raw);
        facts.forEach((key, value) -> {
            if (!(value instanceof Number || value instanceof Boolean || value instanceof String)) {
                throw bad(PyRepr.of(key) + " must be a simple fact — a string, number or boolean "
                        + "this organization can stand behind");
            }
        });
        member.clearance = Map.copyOf(facts);
        state.note("member.clearance_set", Map.of("member", owner, "by", admin,
                "claims", facts.keySet().stream().sorted().toList(), "withdrawn", facts.isEmpty()));
        return Map.of("owner", owner, "clearance", member.clearance);
    }

    @DeleteMapping("/admin/members/{owner}")
    Map<String, Object> remove(@PathVariable String owner, HttpServletRequest request) {
        String admin = auth.requireAdmin(request);
        var member = membership.findMember(owner);
        // Remove the active credential before the signed notice is observed.
        state.members.remove(owner, member);
        membership.notify(member, Map.of("kind", "membership_ended", "by", admin));
        state.note("member.removed", Map.of("member", owner, "by", admin));
        return Map.of("removed", owner);
    }

    @GetMapping("/admin/roles")
    Map<String, Object> roles(HttpServletRequest request) {
        auth.requireAdmin(request);
        Map<String, Object> roles = object(state.current().charter().get("roles"));
        var holders = new TreeMap<String, List<String>>();
        var unassigned = new ArrayList<String>();
        roles.keySet().forEach(id -> holders.put(id, new ArrayList<>()));
        new TreeMap<>(state.members).values().forEach(member -> {
            List<String> users = member.role == null ? null : holders.get(member.role);
            (users == null ? unassigned : users).add(member.owner);
        });
        return row("roles", roles, "default_role", state.defaultRole(), "members", holders,
                "unassigned", unassigned);
    }

    @PutMapping("/admin/roles/{id}")
    Map<String, Object> saveRole(@PathVariable String id, HttpServletRequest request,
                                 @RequestBody Map<String, Object> body) {
        String admin = auth.requireAdmin(request);
        String roleId = id.strip();
        if (roleId.isEmpty()) {
            throw bad("a group needs an id");
        }
        var current = state.current();
        Map<String, Object> draft = new LinkedHashMap<>(current.charter());
        Map<String, Object> roles = new LinkedHashMap<>(object(draft.get("roles")));
        String name = text(body.get("name")).strip();
        String delegation = text(body.get("delegation"));
        boolean created = roles.put(roleId, Map.of("name", name.isEmpty() ? roleId : name,
                "grants", body.getOrDefault("grants", List.of()), "delegation",
                delegation.isEmpty() ? "none" : delegation)) == null;
        draft.put("roles", roles);
        if (Boolean.TRUE.equals(body.get("default"))) {
            draft.put("default_role", roleId);
        }
        var published = publish(draft, admin, current.number());
        state.note("role.saved", Map.of("role", roleId, "by", admin,
                "version", published.number(), "created", created));
        return row("version", published.number(), "role", roleId, "roles",
                published.charter().get("roles"), "default_role", published.charter().get("default_role"));
    }

    @DeleteMapping("/admin/roles/{id}")
    Map<String, Object> removeRole(@PathVariable String id, HttpServletRequest request) {
        String admin = auth.requireAdmin(request);
        var current = state.current();
        Map<String, Object> draft = new LinkedHashMap<>(current.charter());
        Map<String, Object> roles = new LinkedHashMap<>(object(draft.get("roles")));
        if (roles.remove(id) == null) {
            throw notFound("no such group");
        }
        List<String> holders = state.members.values().stream().filter(m -> id.equals(m.role))
                .map(m -> m.owner).sorted().toList();
        if (!holders.isEmpty()) {
            throw conflict(holders.size() + " member(s) are in this group — "
                    + String.join(", ", holders) + ". Move them to another group first.");
        }
        draft.put("roles", roles);
        if (id.equals(draft.get("default_role"))) {
            draft.put("default_role", null);
        }
        var published = publish(draft, admin, current.number());
        state.note("role.removed", Map.of("role", id, "by", admin, "version", published.number()));
        return row("version", published.number(), "removed", id, "roles", roles,
                "default_role", published.charter().get("default_role"));
    }

    @PostMapping("/admin/roles/default")
    Map<String, Object> defaultRole(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        String admin = auth.requireAdmin(request);
        var current = state.current();
        Map<String, Object> draft = new LinkedHashMap<>(current.charter());
        String roleId = text(body.get("role")).strip();
        draft.put("default_role", roleId.isEmpty() ? null : roleId);
        var published = publish(draft, admin, current.number());
        state.note("role.default_set", row("role", published.charter().get("default_role"),
                "by", admin, "version", published.number()));
        return row("version", published.number(), "default_role", published.charter().get("default_role"));
    }

    @GetMapping("/admin/invites")
    List<Map<String, Object>> invitations(HttpServletRequest request) {
        auth.requireAdmin(request);
        return new TreeMap<>(state.invites).entrySet().stream().<Map<String, Object>>map(entry -> {
            var value = new LinkedHashMap<>(entry.getValue());
            value.remove("code");
            value.put("owner", entry.getKey());
            return value;
        }).toList();
    }

    @PostMapping("/admin/invites")
    Map<String, Object> invite(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        String admin = auth.requireAdmin(request);
        String owner = OrganizationMembership.requireOwnerName(body.get("owner"));
        if (state.members.containsKey(owner)) {
            throw conflict(owner + " is already a member");
        }
        String code = "inv_" + random(12);
        state.invites.compute(owner, (name, old) -> {
            if (OrganizationMembership.open(old)) {
                throw conflict(owner + " already has an open invitation");
            }
            return Map.of("by", admin, "note", text(body.get("note")).strip(),
                    "created", EventLog.utcNow(), "code", code, "state", "open");
        });
        state.note("invitation.sent", Map.of("member", owner, "by", admin));
        return Map.of("invited", owner, "state", "open", "code", code);
    }

    @DeleteMapping("/admin/invites/{owner}")
    Map<String, Object> withdraw(@PathVariable String owner, HttpServletRequest request) {
        String admin = auth.requireAdmin(request);
        if (state.invites.remove(owner) == null) {
            throw notFound("no such invitation");
        }
        state.note("invitation.withdrawn", Map.of("member", owner, "by", admin));
        return Map.of("withdrawn", owner);
    }

    @GetMapping("/admin/activity")
    List<Map<String, Object>> activity(HttpServletRequest request) {
        auth.requireAdmin(request);
        return state.activity();
    }

    @PostMapping("/admin/join-code/rotate")
    Map<String, Object> rotate(HttpServletRequest request) {
        String admin = auth.requireAdmin(request);
        state.joinCode = "join_" + random(12);
        state.note("join_code.rotated", Map.of("by", admin));
        return Map.of("join_code", state.joinCode);
    }

    @RequestMapping(value = "/admin/members/{owner}/{*action}",
            method = {RequestMethod.GET, RequestMethod.POST})
    ResponseEntity<String> proxy(@PathVariable String owner, @PathVariable String action,
                                 HttpServletRequest request,
                                 @RequestBody(required = false) byte[] body) {
        String admin = auth.requireAdmin(request);
        var member = membership.findMember(owner);
        if (!action.matches("/(?:pending|connections|operators|ledger)"
                + "(?:/[A-Za-z0-9._:-]+)*") || List.of(action.split("/")).contains("..")
                || List.of(action.split("/")).contains(".")) {
            throw notFound("unknown administration action");
        }
        long now = Instant.now().getEpochSecond();
        String jwt = state.sign("u4a-org-admin+jwt", Map.of("iss", state.config.issuer,
                "sub", owner, "org", state.config.id, "org_name", state.config.name, "admin", admin,
                "iat", now, "exp", now + 120));
        OrgHttp.Reply result;
        try {
            result = http.send(request.getMethod(), member.asUri + "/org/admin/" + owner + action,
                    body, Map.of("Authorization", "Bearer " + jwt, "Content-Type", "application/json"));
        } catch (RuntimeException unavailable) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "her authorization server could not be reached");
        }
        if ("POST".equals(request.getMethod())) {
            state.note("member.administered", Map.of("member", owner, "by", admin,
                    "action", action.substring(1), "result", result.statusCode()));
        }
        return ResponseEntity.status(result.statusCode()).contentType(MediaType.APPLICATION_JSON)
                .body(result.body());
    }

    private OrganizationState.Version publish(Map<String, Object> draft, String admin, Integer base) {
        var version = state.publish(draft, admin, base);
        for (var member : List.copyOf(state.members.values())) {
            Thread.startVirtualThread(() -> membership.notify(member,
                    Map.of("kind", "charter_changed", "charter_version", version.number())));
        }
        return version;
    }

    static Map<String, Object> row(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], pairs[i + 1]);
        }
        return map;
    }

    static String random(int length) {
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return Jwks.b64url(value);
    }

    private static ResponseStatusException conflict(String reason) {
        return new ResponseStatusException(HttpStatus.CONFLICT, reason);
    }
}
