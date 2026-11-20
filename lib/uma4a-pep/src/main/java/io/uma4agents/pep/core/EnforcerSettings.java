package io.uma4agents.pep.core;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Everything one enforcer needs: which authorization server governs which owner's tools,
 * and the request rules for the endpoint it guards.
 *
 * @param owner the owner whose resources this enforcer guards
 * @param asInternal the AS base URL dialled for the protection API
 * @param asPublic the AS issuer agents are sent to
 * @param clientId this resource server's client id at the AS
 * @param clientSecret its client secret
 * @param realm the realm named in challenges
 * @param tools tool name to (resource id, scopes)
 * @param singleUseTools tools whose grant binds one operation
 * @param protectedMethods JSON-RPC methods that need a grant
 * @param openMethods JSON-RPC methods admitted without one
 * @param expectedAuthority the public authority signatures cover
 * @param allowedOrigins Origin values admitted; absent Origin is always admitted
 * @param resourceMetadataUrl the RFC 9728 metadata URL named in challenges
 * @param requireContentDigest whether signatures must cover content-digest
 */
public record EnforcerSettings(String owner, String asInternal, String asPublic,
                               String clientId, String clientSecret, String realm,
                               Map<String, ToolSurface> tools, Set<String> singleUseTools,
                               Set<String> protectedMethods, Set<String> openMethods,
                               String expectedAuthority, Set<String> allowedOrigins,
                               String resourceMetadataUrl, boolean requireContentDigest) {

    /** Methods a gateway admits without a grant, as the pinned uma-pep lists them. */
    public static final Set<String> GATEWAY_OPEN_METHODS = Set.of(
            "server/discover", "initialize", "notifications/initialized", "ping",
            "tools/list", "prompts/list", "resources/list", "resources/templates/list",
            "completion/complete", "logging/setLevel");

    /**
     * One tool's protected resource, the scopes a call needs, and what the call leaves
     * behind as the resource declares it (null when undeclared; an unknown word is no
     * declaration).
     */
    public record ToolSurface(String resourceId, List<String> scopes, String consequence) {
        public ToolSurface {
            consequence = io.uma4agents.common.Consequence.normalise(consequence);
        }

        public ToolSurface(String resourceId, List<String> scopes) {
            this(resourceId, scopes, null);
        }
    }

    /**
     * Tools whose grant binds one operation, derived from the declared class rather than
     * listed a second time: what cannot be undone takes authority over one act.
     */
    public static Set<String> singleUseTools(Map<String, ToolSurface> tools) {
        Set<String> out = new java.util.TreeSet<>();
        tools.forEach((tool, surface) -> {
            if (io.uma4agents.common.Consequence.singleUse(surface.consequence())) {
                out.add(tool);
            }
        });
        return java.util.Collections.unmodifiableSet(out);
    }

    /**
     * The Alice vault surface, keyed by tool, with what each call leaves behind: the two
     * reads nothing to put back, the trade nothing that can be undone.
     */
    public static Map<String, ToolSurface> vaultTools(String owner) {
        Map<String, ToolSurface> tools = new java.util.LinkedHashMap<>();
        tools.put("get_positions",
                new ToolSurface(owner + "-vault/get_positions", List.of("positions:read"),
                        "reversible"));
        tools.put("get_transactions",
                new ToolSurface(owner + "-vault/get_transactions",
                        List.of("transactions:read"), "reversible"));
        tools.put("execute_trade",
                new ToolSurface(owner + "-vault/execute_trade", List.of("trades:execute"),
                        "irreversible"));
        return java.util.Collections.unmodifiableMap(tools);
    }

    /**
     * Allowed Origin values as the pinned hosts parse {@code UMA_ALLOWED_ORIGINS}: unset means
     * the authority and the portal; set (even empty) means exactly its non-empty comma-separated
     * items, unstripped, so an empty value admits no Origin at all.
     */
    public static Set<String> allowedOrigins(String configured, String authority) {
        String raw = configured == null
                ? "https://" + authority + ",https://portal.uma.lab" : configured;
        Set<String> origins = new java.util.LinkedHashSet<>();
        for (String origin : raw.split(",", -1)) {
            if (!origin.isEmpty()) {
                origins.add(origin);
            }
        }
        return java.util.Collections.unmodifiableSet(origins);
    }

    /** A boolean env value as the pin reads one: case-insensitive 1, true or yes. */
    public static boolean flag(String value) {
        return value != null
                && Set.of("1", "true", "yes").contains(value.toLowerCase(java.util.Locale.ROOT));
    }
}
