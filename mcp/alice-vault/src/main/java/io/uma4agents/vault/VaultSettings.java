package io.uma4agents.vault;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.EventLog;
import io.uma4agents.pep.core.Enforcer;
import io.uma4agents.pep.core.EnforcerSettings;
import io.uma4agents.pep.core.ProtectionClient;
import io.uma4agents.pep.core.Publication;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * The vault's environment, using the pinned names. {@code ENFORCEMENT_MODE=embedded} moves
 * enforcement and publication into this process; {@code gateway} (the default) leaves both
 * to the ext_authz host in front of it.
 */
@Component
public class VaultSettings {

    /** The key id the vault signs its own metadata under in embedded mode. */
    public static final String KID = "alice-vault-1";

    public final boolean embedded = "embedded".equals(env("ENFORCEMENT_MODE", "gateway"));
    public final String owner = env("UMA_VAULT_OWNER", env("UMA_OWNER", "alice"));
    public final String authority = env("UMA_EXPECTED_AUTHORITY", "gateway.uma.lab");
    public final String publicBase = env("UMA_PEP_SCHEME", "https") + "://" + authority;
    public final String asPublic = env("UMA_AS_PUBLIC", "https://alice-as.uma.lab");
    public final String asInternal = env("UMA_AS_INTERNAL", "http://uma-as:9000");
    public final EventLog log = new EventLog("alice-vault-uma");

    private Enforcer enforcer;
    private KeyPair signingKey;
    private Publication.AuthorityKeys asKeys;

    /** The vault can prove its own HTTPS origin when the AS was provisioned separately. */
    public synchronized Enforcer enforcer() {
        if (enforcer == null) {
            String secret = env("UMA_AS_RS_CLIENT_SECRET", "gateway-dev-secret");
            String clientId = secret.isEmpty()
                    ? publicBase : env("UMA_AS_RS_CLIENT_ID", "meridian-gateway");
            var tools = EnforcerSettings.vaultTools(owner);
            EnforcerSettings s = new EnforcerSettings(owner, asInternal, asPublic,
                    clientId, secret, env("UMA_REALM", "alice-vault"), tools,
                    EnforcerSettings.singleUseTools(tools),
                    Set.of("tools/call"), Set.of(), authority,
                    EnforcerSettings.allowedOrigins(System.getenv("UMA_ALLOWED_ORIGINS"),
                            authority),
                    "https://" + authority + "/.well-known/oauth-protected-resource/mcp",
                    EnforcerSettings.flag(System.getenv("UMA_PEP_REQUIRE_CONTENT_DIGEST")));
            ProtectionClient.OriginIdentity identity = secret.isEmpty()
                    ? new ProtectionClient.OriginIdentity(signingKey().getPrivate(), KID,
                            publicBase + "/mcp",
                            env("UMA_PEP_RS_NAME", authority + " (embedded)"))
                    : null;
            enforcer = new Enforcer(s, new ProtectionClient(s, log, identity), log);
        }
        return enforcer;
    }

    public synchronized KeyPair signingKey() {
        if (signingKey == null) {
            signingKey = EdDsa.loadOrCreate(
                    Path.of(env("UMA_PEP_SIGNING_KEY", "/keys/vault-ed25519.pem")));
        }
        return signingKey;
    }

    public synchronized Publication.AuthorityKeys asKeys() {
        if (asKeys == null) {
            asKeys = new Publication.AuthorityKeys(asInternal + "/jwks");
        }
        return asKeys;
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null ? fallback : value;
    }
}
