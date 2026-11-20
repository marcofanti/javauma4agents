package io.uma4agents.authserver;

import static io.uma4agents.authserver.Organization.list;
import static io.uma4agents.authserver.Organization.row;
import static io.uma4agents.authserver.Organization.text;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.OrganizationEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
final class OwnerOrganizationController {
    private final Organization org;
    private final OwnerAuth ownerAuth;
    private final PolicyService policy;

    OwnerOrganizationController(Organization org, OwnerAuth ownerAuth, PolicyService policy) {
        this.org = org;
        this.ownerAuth = ownerAuth;
        this.policy = policy;
    }

    @GetMapping("/owner/organization")
    Map<String, Object> view(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        Map<String, Object> record = org.current(false);
        if (record == null) {
            return row("enrolled", false, "enrolment_available", !org.config.orgIssuer.isEmpty(),
                    "issuer", org.config.orgIssuer, "invitation", invited());
        }
        Map<String, Object> envelope = Organization.effectiveEnvelope(org.store, record);
        Map<String, Object> tiers = new LinkedHashMap<>();
        policy.tiers().forEach((id, tier) -> {
            if (list(tier.get("resources")).stream()
                    .anyMatch(resource -> OrganizationEnvelope.reaches((String) resource, envelope))) {
                List<?> alwaysAsk = list(envelope.get("always_ask"));
                tiers.put(id, row("org", envelope.get("org"), "name", envelope.get("name"),
                        "charter_version", envelope.get("charter_version"),
                        "max_expires_in", envelope.get("max_expires_in"),
                        "require_prohibited", list(envelope.get("require_prohibited")),
                        "allowed_scopes", envelope.get("allowed_scopes"),
                        "always_ask", list(tier.get("resources")).stream().anyMatch(r ->
                                io.uma4agents.common.OrganizationPatterns.matches((String) r, alwaysAsk)),
                        "pending", OrganizationEnvelope.clamp(tier, envelope).changes().stream()
                                .map(change -> change.get("text")).toList()));
            }
        });
        return row("enrolled", true, "issuer", record.get("issuer"), "joined", record.get("joined"),
                "org", envelope.get("org"), "name", envelope.get("name"),
                "charter_version", envelope.get("charter_version"), "summary", envelope.get("summary"),
                "envelope", envelope, "stale", org.stale(), "unreadable", org.unreadable(),
                "last_read_error", org.lastError(), "tiers", tiers,
                "governed_resources", governed(envelope));
    }

    @PostMapping("/owner/organization/preview")
    Map<String, Object> preview(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        ownerAuth.requireOwner(request);
        String issuer = configuredIssuer();
        Map<String, Object> envelope = Organization.withJointExclusions(org.store,
                requirePeer(org.send(issuer, "POST", "/member/preview",
                        null, Map.of("code", text(body.get("code"))))));
        List<Map<String, Object>> changes = new ArrayList<>();
        policy.tiers().forEach((id, tier) -> OrganizationEnvelope.clamp(tier, envelope).changes()
                .forEach(change -> {
                    Map<String, Object> found = new LinkedHashMap<>(change);
                    found.put("tier", id);
                    found.put("tier_name", tier.get("name"));
                    changes.add(found);
                }));
        return row("envelope", envelope, "summary", envelope.get("summary"),
                "powers", envelope.get("powers"), "changes", changes,
                "governed_resources", governed(envelope));
    }

    @PostMapping("/owner/organization")
    Map<String, Object> join(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        String owner = ownerAuth.requireOwner(request);
        String issuer = configuredIssuer();
        if (!Boolean.TRUE.equals(body.get("agreed"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "joining an organization gives it standing authority over your agents. "
                            + "Read what it would be entitled to do, and agree to it explicitly");
        }
        if (body.get("charter_version") == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "name the version of the charter you read; agreeing is to that version");
        }
        Map<String, Object> joined = new LinkedHashMap<>(requirePeer(org.send(issuer, "POST",
                "/member/join", null, row("owner", owner, "as_uri", org.config.orgCallback,
                        "code", text(body.get("code")), "assertion", text(body.get("assertion")),
                        "charter_version", body.get("charter_version")))));
        String token = text(joined.remove("membership_token"));
        if (token.isEmpty() || !issuer.equals(joined.get("issuer"))) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "the organization's answer contained no usable membership");
        }
        List<Map<String, Object>> changes = org.joined(issuer, token, joined);
        return row("joined", joined.get("org"), "name", joined.get("name"),
                "charter_version", joined.get("charter_version"), "role", joined.get("role"),
                "role_name", joined.get("role_name"), "grants", joined.get("grants"),
                "delegation", joined.get("delegation"), "summary", joined.get("summary"),
                "changes", changes);
    }

    @DeleteMapping("/owner/organization")
    Map<String, Object> leave(HttpServletRequest request) {
        ownerAuth.requireOwner(request);
        Map<String, Object> record = org.current(false);
        if (record == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "you are not enrolled");
        }
        try {
            org.send(text(record.get("issuer")), "POST", "/member/leave",
                    text(record.get("token")), null);
        } catch (RuntimeException unavailable) {
            org.state.log.event("org.leave_unavailable", null);
        }
        org.end(record, "you left this organization");
        return Map.of("left", true, "note", "your terms keep the narrowing this organization "
                + "required. Nothing was widened by leaving; anything you want back, "
                + "you widen yourself.");
    }

    @PostMapping("/owner/organization/decline")
    Map<String, Object> decline(HttpServletRequest request, @RequestBody Map<String, Object> body) {
        String owner = ownerAuth.requireOwner(request);
        Map<String, Object> invite = invited();
        if (invite == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "nothing is waiting on you");
        }
        if (invite.containsKey("unknown")) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, text(invite.get("unknown")));
        }
        Organization.Reply response = org.send(configuredIssuer(), "POST", "/member/invitation/decline",
                null, Map.of("owner", owner, "code", text(body.get("code"))));
        if (!response.ok()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "that is not the code the invitation came with");
        }
        org.ledger("org_declined", "-", row("organization", invite.get("name"), "by", invite.get("by")),
                null);
        return row("declined", invite.get("name"));
    }

    @PostMapping("/org/notice")
    Map<String, Object> notice(@RequestBody Map<String, Object> body) {
        String jwt = text(body.get("notice"));
        CompactJws.Parsed parsed;
        try {
            parsed = CompactJws.parse(jwt);
        } catch (RuntimeException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "that is not a notice");
        }
        if (!org.config.ownerUsername.equals(parsed.claims().get("sub"))) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "not an owner here");
        }
        Map<String, Object> record = org.store.organization();
        if (record == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "not enrolled");
        }
        Map<String, Object> claims;
        try {
            claims = org.verify(jwt, Organization.NOTICE_TYPE, record, true);
        } catch (RuntimeException invalid) {
            claims = null;
        }
        if (claims == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "that notice is not signed by this owner's organization");
        }
        String jti = text(claims.get("jti"));
        if (!org.store.spendOnce("notice:" + jti, Organization.number(claims.get("exp"), 0))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "that notice was already received");
        }
        String kind = text(claims.get("kind"));
        var envelope = Organization.effectiveEnvelope(org.store, record);
        org.state.log.event("org.notice", null, "kind", kind, "owner", org.config.ownerUsername);
        return switch (kind) {
            case "membership_ended" -> {
                org.end(record, "your organization ended this membership");
                yield Map.of("received", kind);
            }
            case "role_changed" -> {
                org.current(true);
                org.ledger("org_role", "-", row("organization", envelope.get("name"),
                        "role", claims.get("role"), "by", claims.get("by")), null);
                org.store.notify(row("type", "organization", "state", "role",
                        "role", claims.get("role"), "by", claims.get("by")));
                yield row("received", kind, "role", claims.get("role"));
            }
            case "charter_changed" -> row("received", kind, "charter_version",
                    Organization.envelopeOf(org.current(true)).get("charter_version"));
            case "break_glass_opened", "break_glass", "break_glass_used" -> {
                String family = text(claims.get("family"));
                Object by = claims.getOrDefault("authorised_by", claims.get("by"));
                org.ledger("break_glass", family.isEmpty() ? jti : family, row(
                        "stage", kind, "organization", envelope.get("name"),
                        "resource_id", claims.get("resource_id"), "resources", claims.get("resources"),
                        "reason", claims.get("reason"), "authorised_by", by,
                        "tool", claims.get("tool"), "summary", claims.get("summary"),
                        "expires_in", claims.getOrDefault("expires_in", claims.get("window_s")),
                        "charter_version", claims.get("charter_version")), null);
                org.store.notify(row("type", "break_glass", "stage", kind,
                        "resource_id", claims.get("resource_id"), "reason", claims.get("reason"), "by", by));
                yield Map.of("received", kind);
            }
            default -> Map.of("received", kind.isEmpty() ? "unknown" : kind);
        };
    }

    private Map<String, Object> invited() {
        String issuer = org.config.orgIssuer;
        if (issuer.isEmpty()) {
            return null;
        }
        try {
            var response = org.send(issuer, "GET", "/member/invitation?owner="
                    + java.net.URLEncoder.encode(org.config.ownerUsername,
                            java.nio.charset.StandardCharsets.UTF_8), null, null);
            if (!response.ok()) {
                throw new IllegalStateException("invitation endpoint returned " + response.status());
            }
            return Boolean.TRUE.equals(response.body().get("invited")) ? response.body() : null;
        } catch (RuntimeException unavailable) {
            return Map.of("unknown", "the organization could not be reached to check");
        }
    }

    private List<String> governed(Map<String, Object> envelope) {
        return org.state.resources().keySet().stream()
                .filter(resource -> OrganizationEnvelope.reaches(resource, envelope)).sorted().toList();
    }

    private String configuredIssuer() {
        if (org.config.orgIssuer.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "this authority is not configured with an organization to enrol with");
        }
        return org.config.orgIssuer;
    }

    private static Map<String, Object> requirePeer(Organization.Reply response) {
        if (!response.ok()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    String.valueOf(response.body().getOrDefault("detail",
                            "organization returned HTTP " + response.status())));
        }
        return response.body();
    }
}
