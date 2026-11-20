package io.uma4agents.pep;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.SslContexts;
import io.uma4agents.pep.core.Enforcer;
import io.uma4agents.pep.core.EnforcerSettings;
import io.uma4agents.pep.core.ProtectionClient;
import io.uma4agents.pep.core.Publication;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Configuration;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * Environment-driven configuration for the ext_authz host, using the pinned uma-pep env
 * names. Registration is declarative: this host only publishes, and the AS pulls.
 */
@Configuration
public class PepConfig {

    public static final String PEP_KID = "uma-pep-1";

    public final String asPublic = env("UMA_AS_PUBLIC", "https://alice-as.uma.lab");
    public final String asInternal = env("UMA_AS_INTERNAL", "http://uma-as:9000");
    public final String rsClientId = env("UMA_AS_RS_CLIENT_ID", "meridian-gateway");
    public final String rsClientSecret = System.getenv().getOrDefault("UMA_AS_RS_CLIENT_SECRET", "gateway-dev-secret");
    public final String realm = env("UMA_REALM", "alice-vault");
    public final String owner = env("UMA_OWNER", "alice");
    /** Signatures are reconstructed against this, never a forwarded Host. */
    public final String expectedAuthority = env("UMA_EXPECTED_AUTHORITY", "gateway.uma.lab");
    public final String publicBase = env("UMA_PEP_SCHEME", "https") + "://" + expectedAuthority;
    public final int maxBodyBytes =
            Integer.parseInt(env("UMA_PEP_MAX_BODY_BYTES", String.valueOf(1024 * 1024)));
    public final boolean requireContentDigest =
            EnforcerSettings.flag(System.getenv("UMA_PEP_REQUIRE_CONTENT_DIGEST"));
    public final Set<String> allowedOrigins = EnforcerSettings.allowedOrigins(
            System.getenv("UMA_ALLOWED_ORIGINS"), expectedAuthority);
    /** The resource's signing key: signs RFC 9728 signed_metadata. */
    public final KeyPair signingKey = EdDsa.loadOrCreate(
            Path.of(env("UMA_PEP_SIGNING_KEY", "/keys/uma-pep-ed25519.pem")));

    public final EventLog log = new EventLog("uma-pep");
    private final String toolsFile = env("UMA_PEP_TOOLS", "");
    private final ToolSurfaceFile configured = toolsFile.isEmpty() ? null : ToolSurfaceFile.read(Path.of(toolsFile));
    private final HttpClient authorityHttp = authorityHttp();
    private final Map<String, OwnerRoute> owners = ownerRoutes();

    private HttpClient authorityHttp() {
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        String ca = env("UMA4A_CA_BUNDLE", "");
        if (!ca.isEmpty()) {
            client.sslContext(SslContexts.fromPem(Path.of(ca)));
        }
        return client.build();
    }

    record OwnerRoute(EnforcerSettings settings, Enforcer enforcer,
                      Publication.AuthorityKeys keys, ProtectionClient protection) {}

    OwnerRoute ownerRoute(String name) {
        return owners.get(name);
    }

    private Map<String, OwnerRoute> ownerRoutes() {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Map<String, String>> authorities = mapper.readValue(
                env("UMA_OWNER_AUTHORITIES", "{}"), new TypeReference<>() {});
        Map<String, String> secrets = mapper.readValue(env("UMA_PEP_RS_SECRETS", "null"),
                new TypeReference<>() {});
        if (secrets == null) {
            secrets = Map.of(owner, rsClientSecret);
        }
        Map<String, OwnerRoute> routes = new LinkedHashMap<>();
        routes.put(owner, ownerRoute(owner, authorities, secrets));
        for (String additional : env("UMA_EXTRA_OWNERS", "").split(",")) {
            if (!additional.isEmpty() && !routes.containsKey(additional)) {
                routes.put(additional, ownerRoute(additional, authorities, secrets));
            }
        }
        return routes;
    }

    private OwnerRoute ownerRoute(String name, Map<String, Map<String, String>> authorities,
                                  Map<String, String> secrets) {
        if (!name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("invalid gateway owner name: " + name);
        }
        Map<String, String> authority = authorities.getOrDefault(name, Map.of());
        String internal = authority.getOrDefault("internal", asInternal);
        String external = authority.getOrDefault("public", asPublic);
        String secret = secrets.getOrDefault(name, "");
        String client = secret.isEmpty() ? publicBase : rsClientId;
        Map<String, EnforcerSettings.ToolSurface> tools = configured == null
                ? EnforcerSettings.vaultTools(name) : configured.tools();
        Set<String> singleUse = configured == null
                ? EnforcerSettings.singleUseTools(tools) : configured.singleUse();
        String metadata = publicBase + "/.well-known/oauth-protected-resource/mcp"
                + (owner.equals(name) ? "" : "/" + name);
        EnforcerSettings settings = new EnforcerSettings(name, internal, external, client,
                secret, realm, tools, singleUse, Set.of("tools/call"),
                EnforcerSettings.GATEWAY_OPEN_METHODS, expectedAuthority, allowedOrigins,
                metadata, requireContentDigest);
        ProtectionClient.OriginIdentity identity = secret.isEmpty()
                ? new ProtectionClient.OriginIdentity(signingKey.getPrivate(), PEP_KID,
                        publicBase + "/mcp/" + name,
                        env("UMA_PEP_RS_NAME", "Meridian Wealth API gateway"))
                : null;
        ProtectionClient protection = new ProtectionClient(settings, log, identity, authorityHttp);
        return new OwnerRoute(settings, new Enforcer(settings, protection, log),
                new Publication.AuthorityKeys(internal + "/jwks", authorityHttp), protection);
    }

    static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
