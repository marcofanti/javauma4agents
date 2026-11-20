package io.uma4agents.portal;

import io.uma4agents.common.SslContexts;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Environment-driven configuration, mirroring the Python service's env names. */
@Configuration
public class PortalConfig {

    public final String umaAsInternal = env("UMA_AS_INTERNAL", "http://uma-as:9000");
    public final String vaultMcpUrl = env("VAULT_MCP_URL", "http://alice-vault-mcp:9020/mcp");
    /**
     * {@code oidc}, or {@code none} for a stack with no identity provider. Anything else is
     * a mistake, and a mistake here must not serve her vault to whoever asks.
     */
    public final boolean orgConsole = "org-console".equals(env("UMA_PORTAL_MODE", "owner"));
    public final String authMode = authMode(env(orgConsole ? "CONSOLE_AUTH" : "PORTAL_AUTH",
            "oidc"));
    public final String orgInternal = env("ORG_AUTHORITY_INTERNAL", "http://org-authority:9040");
    public final String consoleAdminToken = env("CONSOLE_ADMIN_TOKEN", "");
    /** Whose portal this is: the only account whose sign-in opens a session. */
    public final String owner = env("UMA_PORTAL_OWNER", orgConsole ? "console" : "alice");
    public final String oidcIssuer = env("OIDC_ISSUER", "https://keycloak.uma.lab/realms/alice");
    public final String oidcClientId = env("OIDC_CLIENT_ID", "meridian-portal");
    public final String sessionSecret = env(orgConsole ? "CONSOLE_SESSION_SECRET"
            : "PORTAL_SESSION_SECRET", "dev-session-secret");
    public final String staticDir =
            env("STATIC_DIR", "conformance/upstream/services/alice-portal/static");

    static String authMode(String value) {
        if (!"oidc".equals(value) && !"none".equals(value)) {
            throw new IllegalStateException(
                    "PORTAL_AUTH must be 'oidc' or 'none', not '" + value + "'");
        }
        return value;
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Outbound HTTP client trusting the lab CA when SSL_CERT_FILE points at it. */
    @Bean
    public HttpClient httpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER);
        String caBundle = System.getenv("SSL_CERT_FILE");
        if (caBundle != null && !caBundle.isBlank()) {
            builder.sslContext(SslContexts.fromPem(Path.of(caBundle)));
        }
        return builder.build();
    }
}
