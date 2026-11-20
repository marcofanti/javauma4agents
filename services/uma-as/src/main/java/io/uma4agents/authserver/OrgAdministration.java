package io.uma4agents.authserver;

import static io.uma4agents.authserver.Organization.list;
import static io.uma4agents.authserver.Organization.object;
import static io.uma4agents.authserver.Organization.row;
import static io.uma4agents.authserver.Organization.text;

import io.uma4agents.common.EventLog;
import io.uma4agents.common.OrganizationEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
final class OrgAdministration {
    private static final Set<String> MEMBERSHIP_EVENTS = Set.of("org_joined", "org_left",
            "org_clamped", "org_refused", "org_role", "org_acted", "break_glass");

    private final Organization org;
    private final OwnerController owner;

    OrgAdministration(Organization org, OwnerController owner) {
        this.org = org;
        this.owner = owner;
    }

    @GetMapping("/org/admin/{ownerName}/pending")
    List<Map<String, Object>> pending(@PathVariable String ownerName, HttpServletRequest request) {
        Scope scope = authorize(ownerName, request);
        return owner.pendingView().stream()
                .filter(row -> scope.reaches(text(row.get("resource_id"))))
                .<Map<String, Object>>map(row -> {
                    Map<String, Object> exposed = new LinkedHashMap<>(row);
                    exposed.remove("because");
                    return exposed;
                }).toList();
    }

    @PostMapping("/org/admin/{ownerName}/pending/{family}/decision")
    Map<String, Object> decision(@PathVariable String ownerName, @PathVariable String family,
                                 HttpServletRequest request, @RequestBody Map<String, Object> body) {
        Scope scope = authorize(ownerName, request);
        Map<String, Object> pending = org.store.negotiation(family);
        if (!scope.reaches(text(object(pending).get("resource_id")))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "that request is about a resource your organization does not share with this "
                            + "member, and is none of its business");
        }
        if ("connection".equals(pending.get("pending_kind")) && "approved".equals(body.get("decision"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "this is an agent asking to be admitted for the first time; only the member "
                            + "admits an agent, and she has been asked");
        }
        return owner.decidePending(family, body, scope.actor(), scope.actor());
    }

    @GetMapping("/org/admin/{ownerName}/connections")
    List<Map<String, Object>> connections(@PathVariable String ownerName, HttpServletRequest request) {
        return connections(authorize(ownerName, request));
    }

    @PostMapping("/org/admin/{ownerName}/connections/{action}")
    Map<String, Object> connectionAction(@PathVariable String ownerName, @PathVariable String action,
                                         HttpServletRequest request, @RequestBody Map<String, Object> body) {
        Scope scope = authorize(ownerName, request);
        String handle = text(body.get("handle")).strip();
        if ("revoke".equals(action)) {
            if (connections(scope).stream().noneMatch(conn -> handle.equals(conn.get("handle")))) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "that agent has no dealings with your organization's resources");
            }
            changeBlock(scope, "handles", handle, true);
            org.ledger("org_acted", "-", row("what",
                    "shut an agent out of the organization's resources",
                    "note", "its access to your own accounts is unchanged", "by", scope.actor()), handle);
            org.store.notify(row("type", "decided", "family", "-", "decision", "org-revoked",
                    "by", scope.actor()));
            return Map.of("handle", handle, "status", "blocked-for-organization");
        }
        if ("restore".equals(action)) {
            changeBlock(scope, "handles", handle, false);
            org.ledger("org_acted", "-", row("what",
                    "let an agent reach the organization's resources again", "by", scope.actor()), handle);
            return Map.of("handle", handle, "status", "allowed");
        }
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown action");
    }

    @GetMapping("/org/admin/{ownerName}/operators")
    List<Map<String, Object>> operators(@PathVariable String ownerName, HttpServletRequest request) {
        Scope scope = authorize(ownerName, request);
        Map<String, List<Map<String, Object>>> groups = new LinkedHashMap<>();
        for (Map<String, Object> connection : connections(scope)) {
            String origin = Standing.operatorOrigin(object(connection.get("identity")));
            if (origin != null) {
                groups.computeIfAbsent(origin, ignored -> new ArrayList<>()).add(connection);
            }
        }
        Map<String, Object> blocked = object(object(scope.record().get("blocked")).get("operators"));
        blocked.keySet().forEach(origin -> groups.computeIfAbsent(origin, ignored -> List.of()));
        return groups.entrySet().stream().map(entry -> {
            List<Map<String, Object>> agents = entry.getValue();
            Map<String, Object> metadata = agents.isEmpty() ? Map.of()
                    : object(object(agents.getFirst().get("identity")).get("client_metadata"));
            return row("origin", entry.getKey(), "name", metadata.getOrDefault("client_name", entry.getKey()),
                    "agents", agents.size(), "active",
                    agents.stream().filter(agent -> "active".equals(agent.get("status"))).count(),
                    "blocked_for_organization", blocked.containsKey(entry.getKey()));
        }).toList();
    }

    @PostMapping("/org/admin/{ownerName}/operators/{action}")
    Map<String, Object> operatorAction(@PathVariable String ownerName, @PathVariable String action,
                                       HttpServletRequest request, @RequestBody Map<String, Object> body) {
        Scope scope = authorize(ownerName, request);
        String origin = text(body.get("origin")).strip().replaceFirst("/+$", "");
        if (!Set.of("block", "unblock").contains(action) || origin.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown action");
        }
        boolean block = "block".equals(action);
        changeBlock(scope, "operators", origin, block);
        org.ledger("org_acted", "-", row("what", block
                ? "shut out every agent of an operator, for the organization's resources"
                : "let an operator's agents reach the organization's resources again",
                "operator", origin, "by", scope.actor()), null);
        org.store.notify(row("type", "decided", "family", "-", "decision", "org-" + action,
                "by", scope.actor()));
        return Map.of("origin", origin, "blocked_for_organization", block);
    }

    @GetMapping("/org/admin/{ownerName}/ledger")
    List<Map<String, Object>> ledger(@PathVariable String ownerName, HttpServletRequest request,
                                     @RequestParam(required = false) String handle) {
        Scope scope = authorize(ownerName, request);
        Set<String> wholly = new LinkedHashSet<>();
        org.store.tiers().forEach((id, tier) -> {
            List<?> resources = list(tier.get("resources"));
            if (!resources.isEmpty() && resources.stream().allMatch(r -> scope.reaches(text(r)))) {
                wholly.add(id);
            }
        });
        return org.store.ledger(handle).stream().filter(entry -> {
            String kind = text(entry.get("kind"));
            if (MEMBERSHIP_EVENTS.contains(kind)) {
                return true;
            }
            String resource = text(entry.get("resource_id"));
            return resource.isEmpty() ? wholly.contains(text(entry.get("tier"))) : scope.reaches(resource);
        }).toList();
    }

    private List<Map<String, Object>> connections(Scope scope) {
        Set<String> governed = new LinkedHashSet<>();
        org.store.tiers().forEach((id, tier) -> {
            if (list(tier.get("resources")).stream().anyMatch(r -> scope.reaches(text(r)))) {
                governed.add(id);
            }
        });
        Set<Object> pending = new LinkedHashSet<>();
        org.store.pendingNegotiations().forEach(rec -> {
            if (scope.reaches(text(rec.get("resource_id")))) {
                pending.add(rec.get("handle"));
            }
        });
        Map<String, Object> blocked = object(scope.record().get("blocked"));
        List<Map<String, Object>> visible = new ArrayList<>();
        for (Map<String, Object> connection : org.store.connections()) {
            var touched = new TreeSet<String>();
            for (String field : List.of("tiers_granted", "tiers_approved")) {
                list(connection.get(field)).stream().map(Organization::text)
                        .filter(governed::contains).forEach(touched::add);
            }
            String handle = text(connection.get("handle"));
            if (touched.isEmpty() && !pending.contains(handle)) {
                continue;
            }
            Map<String, Object> result = new LinkedHashMap<>();
            for (String field : List.of("handle", "label", "identity", "status", "first_seen", "last_access")) {
                result.put(field, connection.get(field));
            }
            String operator = Standing.operatorOrigin(object(connection.get("identity")));
            result.put("org_tiers", touched);
            result.put("blocked_for_organization", object(blocked.get("handles")).containsKey(handle)
                    || operator != null && object(blocked.get("operators")).containsKey(operator));
            visible.add(result);
        }
        return visible;
    }

    private void changeBlock(Scope scope, String group, String key, boolean block) {
        if (!org.store.setOrganizationBlock(text(scope.record().get("token")), group, key,
                block ? EventLog.utcNow() : null)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "this membership changed");
        }
    }

    private Scope authorize(String ownerName, HttpServletRequest request) {
        if (!org.config.ownerUsername.equals(ownerName)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "not an owner here");
        }
        String header = request.getHeader("authorization");
        Map<String, Object> record = org.store.organization();
        if (record == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "this owner does not administer these resources for anyone");
        }
        Map<String, Object> claims = null;
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            try {
                claims = org.verify(header.substring(7), Organization.ADMIN_TYPE, record, false);
            } catch (RuntimeException invalid) {
                // A member's own credentials cannot be used here.
            }
        }
        if (claims == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "that token is not signed by this owner's organization for this owner");
        }
        return new Scope(record, Organization.effectiveEnvelope(org.store, record), row("org", claims.get("org"), "name", claims.get("org_name"),
                "admin", claims.get("admin")));
    }

    private record Scope(Map<String, Object> record, Map<String, Object> envelope, Map<String, Object> actor) {
        boolean reaches(String resource) {
            return OrganizationEnvelope.reaches(resource, envelope);
        }
    }
}
