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
    public final String authMode = env("PORTAL_AUTH", "oidc");
    public final String oidcIssuer = env("OIDC_ISSUER", "https://keycloak.uma.lab/realms/alice");
    public final String oidcClientId = env("OIDC_CLIENT_ID", "alice-portal");
    public final String sessionSecret = env("PORTAL_SESSION_SECRET", "dev-session-secret");
    public final String staticDir = env("STATIC_DIR", "static");

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
