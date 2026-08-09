package io.uma4agents.authserver;

import io.uma4agents.common.SslContexts;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Environment-driven configuration, mirroring the Python service's env names. */
@Configuration
public class AsConfig {

    public static final String AGREEMENT_FORMAT = "urn:uma4agents:format:myterms-agreement-v1+jws";
    public static final String AGREEMENT_CLAIM = "urn:uma4agents:claim:myterms-agreement";
    public static final int PAT_TTL = 3600;
    public static final int TICKET_TTL = 300;
    public static final int PENDING_TTL = 600;
    public static final int POLL_INTERVAL = 3;
    public static final int JWKS_CACHE_TTL = 300;
    public static final String KID = "uma-as-1";

    public final String issuer = env("UMA_AS_ISSUER", "https://alice-as.uma.lab");
    public final String keyPath = env("UMA_AS_SIGNING_KEY", "/keys/uma-as-ed25519.pem");
    public final String ownerIssuer =
            env("UMA_AS_OWNER_ISSUER", "https://keycloak.uma.lab/realms/alice");
    public final String ownerUsername = env("UMA_AS_OWNER", "alice");
    public final Set<String> ownerAudiences = new LinkedHashSet<>(
            Arrays.asList(env("UMA_AS_OWNER_CLIENTS", "alice-portal").split(",")));
    public final String rsClientId = env("UMA_AS_RS_CLIENT_ID", "meridian-gateway");
    public final String rsClientSecret = env("UMA_AS_RS_CLIENT_SECRET", "gateway-dev-secret");
    /**
     * push: the RS registers its resources here (classic FedAuthz /rreg).
     * pull: this AS <em>reads</em> the RS's published metadata — public
     * structure from the RFC 9728 document, owner-bound instances from the
     * protected owner-resources endpoint — and materializes its registry.
     */
    public final String registrationMode = env("REGISTRATION_MODE", "push");
    /**
     * Where the RS publishes itself — the root of declarative registration
     * (RFC 9728 metadata is derived from this identifier).
     */
    public final String rsResourceUri =
            env("UMA_AS_RS_RESOURCE_URI", "https://gateway.uma.lab/mcp");
    public final String caBundle = env("UMA4A_CA_BUNDLE", null);
    /** The RPT audience — hardcoded in the Python reference, configurable here. */
    public final String rptAudience = env("UMA_RPT_AUDIENCE", "https://gateway.uma.lab");

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Outbound client for Keycloak JWKS and AAuth issuer discovery over lab TLS. */
    @Bean
    public HttpClient httpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5));
        if (caBundle != null) {
            builder.sslContext(SslContexts.fromPem(Path.of(caBundle)));
        }
        return builder.build();
    }
}
