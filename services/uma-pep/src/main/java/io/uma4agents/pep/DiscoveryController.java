package io.uma4agents.pep;

import io.uma4agents.pep.core.Publication;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * The gateway's publication: the signed RFC 9728 documents for the alias and the owner's
 * own path, the resource JWKS, and the owner-resources listing served only to the owner's
 * authorization server. The documents come from the shared {@link Publication} builders.
 */
@RestController
public class DiscoveryController {

    private final PepConfig config;
    private final OrganizationRoutes organizations;
    private final JointRoutes joints;

    public DiscoveryController(PepConfig config, OrganizationRoutes organizations, JointRoutes joints) {
        this.config = config;
        this.organizations = organizations;
        this.joints = joints;
    }

    private Map<String, Object> prm(String leaf, PepConfig.OwnerRoute route) {
        var settings = route.settings();
        Map<String, Object> doc = Publication.prmDocument(config.publicBase, settings.asPublic(),
                settings.tools(), leaf, "/owner-resources/" + settings.owner());
        return Publication.signMetadata(doc, config.signingKey, PepConfig.PEP_KID);
    }

    /** The alias, for a client configured against the bare /mcp path; names /mcp. */
    @GetMapping({"/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp"})
    public Map<String, Object> protectedResourceMetadata() {
        return prm("mcp", config.ownerRoute(config.owner));
    }

    /** One owner's resource at her own path; 404 for an owner not served here. */
    @GetMapping("/.well-known/oauth-protected-resource/mcp/{owner}")
    public ResponseEntity<Object> protectedResourceMetadataFor(@PathVariable String owner) {
        PepConfig.OwnerRoute route = config.ownerRoute(owner);
        return route == null ? notFound() : ResponseEntity.ok(prm("mcp/" + owner, route));
    }

    @GetMapping("/.well-known/oauth-protected-resource/mcp/shared/{owner}")
    public ResponseEntity<Object> sharedResource(@PathVariable String owner) {
        try {
            OrganizationRoutes.Shared shared = organizations.shared(owner, true);
            if (shared == null) {
                return notFound();
            }
            var settings = shared.normal().settings();
            Map<String, Object> doc = Publication.prmDocument(config.publicBase,
                    settings.asPublic(), shared.tools(), organizations.leaf(owner),
                    "/owner-resources/" + owner);
            return ResponseEntity.ok(Publication.signMetadata(doc, config.signingKey,
                    PepConfig.PEP_KID));
        } catch (OrganizationRoutes.Unavailable unavailable) {
            return unreadable(unavailable);
        }
    }

    @GetMapping("/.well-known/oauth-protected-resource/mcp/joint/{account}")
    public ResponseEntity<Object> jointResource(@PathVariable String account) {
        try {
            JointRoutes.Joint joint = joints.route(account);
            if (joint == null) {
                return ResponseEntity.status(404).body(Map.of("error", "no_mandate"));
            }
            var settings = joint.enforcer().settings();
            var doc = Publication.prmDocument(config.publicBase, settings.asPublic(),
                    settings.tools(), joints.leaf(account), "/owner-resources/" + account);
            return ResponseEntity.ok(Publication.signMetadata(doc, config.signingKey,
                    PepConfig.PEP_KID));
        } catch (JointRoutes.Unavailable unavailable) {
            return unreadable(unavailable);
        }
    }

    @GetMapping("/jwks")
    public Map<String, Object> jwks() {
        return Publication.jwks(config.signingKey, PepConfig.PEP_KID);
    }

    @GetMapping("/owner-resources/{owner}")
    public ResponseEntity<Object> ownerResourcesFor(@PathVariable String owner,
                                                    HttpServletRequest request) {
        PepConfig.OwnerRoute route = config.ownerRoute(owner);
        return route == null ? notFound() : ownerResources(request, route);
    }

    /** The protected half of discovery, served only to the owner's AS (RFC 9421). */
    @GetMapping("/owner-resources")
    public ResponseEntity<Object> ownerResources(HttpServletRequest request) {
        return ownerResources(request, config.ownerRoute(config.owner));
    }

    private ResponseEntity<Object> ownerResources(HttpServletRequest request,
                                                  PepConfig.OwnerRoute route) {
        var settings = route.settings();
        String who = settings.owner();
        String reason = Publication.verifyOwnerAsQuery(request.getMethod(),
                config.expectedAuthority, "/owner-resources/" + who,
                request.getHeader("signature-input"), request.getHeader("signature"),
                route.keys());
        if (reason != null) {
            config.log.event("owner_resources.denied", null, "reason", reason, "owner", who);
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("error", "invalid_signature", "error_description",
                            "this listing is served only to the owner's authorization "
                                    + "server: " + reason));
        }
        Map<String, Object> listing = Publication.ownerResourcesDocument(config.publicBase, who,
                settings.tools(), "mcp/" + who);
        try {
            OrganizationRoutes.Shared shared = organizations.shared(who, true);
            List<Object> entries = new ArrayList<>((List<?>) listing.get("resources"));
            int sharedCount = shared == null ? 0 : addResources(entries, who, shared.tools(),
                    organizations.leaf(who), "Shared: ", "shared:");
            int jointCount = 0;
            for (var item : joints.resources(who).entrySet()) {
                String account = item.getKey();
                jointCount += addResources(entries, who, item.getValue(), joints.leaf(account),
                        "Joint: ", "joint:" + account + ":");
            }
            listing.put("resources", entries);
            config.log.event("owner_resources.served", null, "owner", who,
                    "count", entries.size(), "shared", sharedCount, "joint", jointCount);
            return ResponseEntity.ok(listing);
        } catch (OrganizationRoutes.Unavailable | JointRoutes.Unavailable unavailable) {
            return unreadable(unavailable);
        }
    }

    private int addResources(List<Object> entries, String owner,
                             Map<String, io.uma4agents.pep.core.EnforcerSettings.ToolSurface> tools,
                             String leaf, String label, String identifier) {
        List<?> resources = (List<?>) Publication.ownerResourcesDocument(config.publicBase,
                owner, tools, leaf).get("resources");
        for (Object item : resources) {
            if (item instanceof Map<?, ?> resource) {
                Map<Object, Object> row = new LinkedHashMap<>(resource);
                String id = (String) row.get("_id");
                String tool = id.substring(id.lastIndexOf('/') + 1);
                row.put("name", label + tool);
                row.put("tool", identifier + tool);
                entries.add(row);
            }
        }
        return resources.size();
    }

    private static ResponseEntity<Object> unreadable(RuntimeException unavailable) {
        return ResponseEntity.status(503).body(Map.of("error", "temporarily_unavailable",
                "error_description", unavailable.getMessage()));
    }

    private static ResponseEntity<Object> notFound() {
        return ResponseEntity.status(404).contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("error", "no such resource"));
    }
}
