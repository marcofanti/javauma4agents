package io.uma4agents.organization;

import static io.uma4agents.organization.OrganizationCharter.text;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.IdentityProviders;
import io.uma4agents.common.IdentityTokens;
import io.uma4agents.common.PyJwtClaims;
import io.uma4agents.common.SslContexts;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/** Verifies employment against the charter's workforce directory. */
@Component
final class EmployeeEnrollment {
    private final IdentityProviders providers;

    EmployeeEnrollment() {
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        String ca = System.getenv().getOrDefault("UMA4A_CA_BUNDLE", "");
        if (!ca.isEmpty()) {
            http.sslContext(SslContexts.withAdditionalRoots(Path.of(ca)));
        }
        providers = new IdentityProviders(http.build());
    }

    void verify(Map<String, Object> policy, String owner, String token) {
        String issuer = text(policy.get("issuer"));
        String directory = text(policy.get("directory"));
        if (directory.isEmpty()) {
            directory = text(providers.metadata(issuer).get("id_jag_identity_provider"));
        }
        if (!IdentityProviders.https(directory)) {
            throw unavailable();
        }
        CompactJws.Parsed parsed;
        try {
            parsed = CompactJws.parse(token);
            if (!"RS256".equals(parsed.header().get("alg"))) {
                throw refused();
            }
        } catch (IllegalArgumentException invalid) {
            throw refused();
        }
        java.util.List<Map<String, Object>> keys;
        try {
            keys = providers.keysFor(directory, parsed.header().get("kid"));
        } catch (IllegalArgumentException unreachable) {
            throw unavailable();
        }
        Map<String, Object> claims;
        try {
            claims = IdentityTokens.verify(token, directory, keys);
            PyJwtClaims.validateWithIat(claims, Instant.now().getEpochSecond(), "exp");
            if (!"ID".equals(claims.getOrDefault("typ", "ID"))) {
                throw refused();
            }
        } catch (IllegalArgumentException invalid) {
            throw refused();
        }
        String name = text(claims.get("preferred_username"));
        if (name.isEmpty()) {
            name = text(claims.get("sub"));
        }
        if (!owner.equals(name)) {
            throw refused();
        }
    }

    private static ResponseStatusException unavailable() {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "this organization's identity provider could not be reached to check that");
    }

    private static ResponseStatusException refused() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN,
                "that assertion is not this organization's provider vouching for you");
    }
}
