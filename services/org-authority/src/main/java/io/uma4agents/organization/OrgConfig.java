package io.uma4agents.organization;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.SslContexts;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class OrgConfig {
    final String issuer = env("ORG_ISSUER", "https://northwind-org.uma.lab");
    final String authority = URI.create(issuer).getRawAuthority();
    final String id = env("ORG_ID", "northwind");
    final String name = env("ORG_NAME", "Northwind Capital");
    final String kid = env("ORG_KID", "org-1");
    final KeyPair signing = EdDsa.loadOrCreate(
            Path.of(env("ORG_SIGNING_KEY", "/keys/org-ed25519.pem")));
    final String adminIssuer =
            env("ORG_ADMIN_ISSUER", "https://keycloak.uma.lab/realms/northwind");
    final String adminMetadata = env("ORG_ADMIN_METADATA_URL",
            adminIssuer + "/.well-known/openid-configuration");
    final Set<String> adminAudiences = Arrays.stream(
            env("ORG_ADMIN_CLIENTS", "meridian-org-console").split(","))
            .filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    final String adminToken = env("ORG_ADMIN_TOKEN", "");
    final String rsToken = env("ORG_RS_TOKEN", "org-rs-dev-token");
    final String joinCode = env("ORG_JOIN_CODE", "");
    final String glassAudience = env("ORG_BREAK_GLASS_AUDIENCE", "https://gateway.uma.lab");
    final int clearanceTtl = Integer.parseInt(env("ORG_CLEARANCE_TTL_S", "300"));

    OrgConfig() {
        if (!adminToken.isEmpty() && !adminIssuer.isEmpty()) {
            throw new IllegalStateException(
                    "ORG_ADMIN_TOKEN is for a stack with no identity provider");
        }
    }

    @Bean
    HttpClient orgHttpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER);
        String ca = env("UMA4A_CA_BUNDLE", "");
        if (!ca.isEmpty()) {
            builder.sslContext(SslContexts.fromPem(Path.of(ca)));
        }
        return builder.build();
    }

    private static String env(String name, String fallback) {
        return System.getenv().getOrDefault(name, fallback);
    }
}
