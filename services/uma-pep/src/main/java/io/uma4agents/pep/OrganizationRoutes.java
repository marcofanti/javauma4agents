package io.uma4agents.pep;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.OrganizationEnvelope;
import io.uma4agents.common.OrganizationPatterns;
import io.uma4agents.pep.core.AuthzFacts;
import io.uma4agents.pep.core.Decision;
import io.uma4agents.pep.core.Enforcer;
import io.uma4agents.pep.core.EnforcerSettings;
import io.uma4agents.pep.core.ProtectionClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** Resolves the organization's book to the live role governing its shared owner path. */
@Component
final class OrganizationRoutes {
    private final PepConfig config;
    private final String issuer = PepConfig.env("UMA_PEP_ORG_ISSUER", "");
    private final String internal = PepConfig.env("UMA_PEP_ORG_INTERNAL", issuer);
    private final String token = PepConfig.env("UMA_PEP_ORG_TOKEN", "");
    private final String prefix = PepConfig.env("UMA_PEP_SHARED_PREFIX", "mcp/shared")
            .replaceAll("^/+|/+$", "");
    private final String namespace = PepConfig.env("UMA_PEP_SHARED_NAMESPACE", "northwind-vault");
    private final long ttl = seconds("UMA_PEP_MEMBERSHIP_TTL_S", "10");
    private final long grace = seconds("UMA_PEP_STALE_GRACE_S", "300");
    private final long discoveryTtl = seconds("UMA_PEP_ORG_DISCOVERY_TTL_S", "120");
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Map<String, Membership> cache = new ConcurrentHashMap<>();
    private final Map<String, ProtectionClient> overrideClients = new ConcurrentHashMap<>();
    private volatile Membership discovery;
    private static final ObjectMapper JSON = new ObjectMapper();

    private record Membership(long fetched, Map<String, Object> document) {}
    record Shared(Enforcer normal, Enforcer override, Map<String, Object> member) {
        Map<String, EnforcerSettings.ToolSurface> tools() {
            return normal.settings().tools();
        }
    }

    static final class Unavailable extends RuntimeException {
        Unavailable() { super("the organization could not be reached"); }
    }

    OrganizationRoutes(PepConfig config) {
        this.config = config;
    }

    String ownerAt(String path) {
        String start = "/" + prefix + "/";
        if (!path.startsWith(start)) {
            return null;
        }
        return path.substring(start.length()).split("/", 2)[0];
    }

    String leaf(String owner) {
        return prefix + "/" + owner;
    }

    Shared shared(String owner, boolean forceFresh) {
        PepConfig.OwnerRoute root = config.ownerRoute(owner);
        if (issuer.isEmpty() || root == null) {
            return null;
        }
        Map<String, Object> membership = membership(owner, forceFresh);
        if (!Boolean.TRUE.equals(membership.get("member"))) {
            return null;
        }
        Map<String, EnforcerSettings.ToolSurface> tools = new LinkedHashMap<>();
        List<?> patterns = list(membership.get("grants"));
        root.settings().tools().forEach((tool, surface) -> {
            String id = namespace + "/" + tool;
            if (OrganizationPatterns.matches(id, patterns)) {
                tools.put(tool, new EnforcerSettings.ToolSurface(id, surface.scopes(),
                        surface.consequence()));
            }
        });
        String metadata = config.publicBase + "/.well-known/oauth-protected-resource/" + leaf(owner);
        EnforcerSettings normal = settings(root.settings(), root.settings().asInternal(),
                root.settings().asPublic(), tools, metadata);
        EnforcerSettings emergency = settings(root.settings(), internal, issuer, tools, metadata);
        ProtectionClient override = overrideClients.computeIfAbsent(owner,
                ignored -> ProtectionClient.forOrganization(emergency, config.log, token));
        return new Shared(new Enforcer(normal, root.protection(), config.log),
                new Enforcer(emergency, override, config.log), membership);
    }

    Decision authorize(Shared shared, AuthzFacts f) {
        boolean override = isOverride(f.authorization());
        if (override && !config.publicBase.equals(audience(f.authorization()))) {
            return Decision.deny(401, "invalid_token", "the override was not issued to this resource server");
        }
        return (override ? shared.override() : shared.normal()).authorize(f, (grant, surface) -> {
            if (override && (!shared.normal().settings().owner().equals(grant.get("owner"))
                    || !issuer.equals(grant.get("iss")) || !(grant.get("break_glass") instanceof Map<?, ?>)
                    || !Boolean.TRUE.equals(grant.get("single_use")))) {
                return Decision.deny(403, "invalid_token", "the override does not name this member");
            }
            if (override) {
                return null;
            }
            return checkCeiling(grant, surface, shared.member());
        }, override);
    }

    Decision authorizeOwn(PepConfig.OwnerRoute root, AuthzFacts facts) {
        if ("tools/call".equals(facts.mcpMethod()) && isOverride(facts.authorization())) {
            return Decision.deny(403, "invalid_token", "an organization's own grant is "
                    + "honoured only at the resources it owns, and this is not one");
        }
        if (issuer.isEmpty()) {
            return root.enforcer().authorize(facts);
        }
        String owner = root.settings().owner();
        return root.enforcer().authorize(facts, (grant, surface) -> {
            try {
                Map<String, Object> current = membership(owner, false);
                return OrganizationEnvelope.reaches(surface.resourceId(), current)
                        ? checkCeiling(grant, surface, current) : null;
            } catch (Unavailable unavailable) {
                Membership prior = cache.get(owner);
                if (prior != null && OrganizationEnvelope.reaches(surface.resourceId(),
                        prior.document())) {
                    return Decision.deny(503, "temporarily_unavailable",
                            "the organization could not be reached to establish the ceiling "
                                    + "over this resource");
                }
                return null;
            }
        }, false);
    }

    boolean isOverride(String authorization) {
        return !issuer.isEmpty() && issuer.equals(claims(authorization).get("iss"));
    }

    private static Object audience(String authorization) {
        return claims(authorization).get("aud");
    }

    private static Map<String, Object> claims(String authorization) {
        if (authorization != null && authorization.startsWith("PoP ")) {
            try {
                return CompactJws.parse(authorization.substring(4)).claims();
            } catch (IllegalArgumentException invalid) {
                return Map.of();
            }
        }
        return Map.of();
    }

    private static Decision checkCeiling(Map<String, Object> grant,
                                        EnforcerSettings.ToolSurface surface,
                                        Map<String, Object> envelope) {
        if (!OrganizationEnvelope.reaches(surface.resourceId(), envelope)) {
            return Decision.deny(403, "not_shared", "the organization does not share this resource");
        }
        for (Object item : list(grant.get("permissions"))) {
            Map<String, Object> permitted = object(item);
            if (surface.resourceId().equals(permitted.get("resource_id"))) {
                double now = Instant.now().getEpochSecond();
                double expiry = permitted.get("exp") instanceof Number exp ? exp.doubleValue() : 0;
                String breach = OrganizationEnvelope.breach(permitted, envelope,
                        expiry - now);
                if (breach != null) {
                    return Decision.deny(403, "organization_envelope_exceeded", breach);
                }
            }
        }
        return null;
    }

    private Map<String, Object> membership(String owner, boolean forceFresh) {
        long now = System.currentTimeMillis();
        Membership prior = cache.get(owner);
        if (!forceFresh && prior != null && now - prior.fetched() < ttl) {
            return prior.document();
        }
        try {
            Map<String, Object> doc = get("/membership/" + owner, true);
            if (!(doc.get("member") instanceof Boolean)) {
                throw new Unavailable();
            }
            cache.put(owner, new Membership(now, doc));
            return doc;
        } catch (RuntimeException unavailable) {
            if (!forceFresh && prior != null && now - prior.fetched() < ttl + grace) {
                return prior.document();
            }
            throw new Unavailable();
        }
    }

    Map<String, Object> notShared() {
        Map<String, Object> doc;
        try {
            long now = System.currentTimeMillis();
            Membership cached = discovery;
            if (issuer.isEmpty()) {
                doc = Map.of();
            } else if (cached != null && now - cached.fetched() < discoveryTtl) {
                doc = cached.document();
            } else {
                doc = get("/.well-known/u4a-organization", false);
                discovery = new Membership(now, doc);
            }
        } catch (Unavailable unreachable) {
            doc = Map.of();
        }
        var organization = object(doc.get("organization"));
        var identity = object(doc.get("identity_provider"));
        Object name = organization.get("name");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "not_shared");
        body.put("error_description", name == null ? "this resource is not shared with that member"
                : "this resource belongs to " + name + " and is not shared with that member");
        if (name != null && doc.get("issuer") instanceof String address) {
            body.put("organization", Map.of("name", name, "issuer", address));
        }
        if (Boolean.TRUE.equals(identity.get("enrol"))) {
            body.put("how_to_join", name + " federates identity to " + identity.get("issuer")
                    + ". Whoever this authority belongs to can enrol from their own portal "
                    + "by signing in there — no enrolment code.");
        }
        return body;
    }

    private Map<String, Object> get(String path, boolean authenticated) {
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(internal + path))
                    .timeout(Duration.ofSeconds(5)).GET();
            if (authenticated) {
                request.header("Authorization", "Bearer " + token);
            }
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new Unavailable();
            }
            return JSON.readValue(response.body(), new TypeReference<>() {});
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new Unavailable();
        } catch (IOException | IllegalArgumentException unavailable) {
            throw new Unavailable();
        }
    }

    private static EnforcerSettings settings(EnforcerSettings root, String internal, String issuer,
                                             Map<String, EnforcerSettings.ToolSurface> tools,
                                             String metadata) {
        return new EnforcerSettings(root.owner(), internal, issuer, root.clientId(),
                root.clientSecret(), root.realm(), tools, EnforcerSettings.singleUseTools(tools),
                root.protectedMethods(), root.openMethods(), root.expectedAuthority(),
                root.allowedOrigins(), metadata, root.requireContentDigest());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> list ? list : List.of();
    }

    private static long seconds(String name, String fallback) {
        return (long) (1_000 * Double.parseDouble(PepConfig.env(name, fallback)));
    }
}
