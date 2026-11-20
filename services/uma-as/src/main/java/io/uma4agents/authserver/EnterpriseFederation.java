package io.uma4agents.authserver;

import static io.uma4agents.authserver.Organization.object;
import static io.uma4agents.authserver.Organization.row;
import static io.uma4agents.authserver.Organization.text;
import static io.uma4agents.common.IdentityTokens.EXCHANGE;
import static io.uma4agents.common.IdentityTokens.ID_JAG;
import static io.uma4agents.common.IdentityTokens.ID_TOKEN;
import static io.uma4agents.common.IdentityTokens.JAG_TYPE;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.IdentityProviders;
import io.uma4agents.common.IdentityTokens;
import io.uma4agents.common.OrganizationEnvelope;
import io.uma4agents.common.PyJwtClaims;
import io.uma4agents.common.PyRepr;
import io.uma4agents.common.SslContexts;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
final class EnterpriseFederation {
    private final AsConfig config;
    private final IdentityProviders providers;
    private final String resourceUri;

    EnterpriseFederation(AsConfig config) {
        this.config = config;
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        if (config.caBundle != null && !config.caBundle.isEmpty()) {
            http.sslContext(SslContexts.withAdditionalRoots(Path.of(config.caBundle)));
        }
        providers = new IdentityProviders(http.build());
        resourceUri = config.rsResourceUri;
    }

    static Map<String, Object> provider(Map<String, Object> envelope, String resource) {
        var provider = object(envelope.get("identity_provider"));
        return !text(provider.get("issuer")).isEmpty() && OrganizationEnvelope.reaches(resource, envelope)
                ? provider : Map.of();
    }

    Map<String, Object> challenge(Map<String, Object> provider, String resource) {
        String issuer = text(provider.get("issuer"));
        var meta = providers.metadata(issuer);
        String endpoint = text(meta.get("token_endpoint"));
        Object supported = meta.get("subject_token_types_supported");
        return Map.of("claim_type", ID_JAG, "claim_token_format", List.of(ID_JAG),
                "friendly_name", "who your organization says you act for", "identity_provider",
                Map.of("issuer", issuer, "token_endpoint", !IdentityProviders.https(endpoint)
                                        ? issuer.replaceFirst("/+$", "") + "/token" : endpoint,
                        "grant_type", EXCHANGE, "requested_token_type", ID_JAG,
                        "subject_token_types_supported", supported instanceof List<?> choices && !choices.isEmpty()
                                ? choices : List.of(ID_TOKEN, "urn:ietf:params:oauth:token-type:refresh_token")),
                "audience", config.issuer, "resource", resourceUri, "scope", List.of(operation(resource)));
    }

    Map<String, Object> verify(String token, Map<String, Object> provider, String resource) {
        String issuer = text(provider.get("issuer"));
        CompactJws.Parsed parsed;
        try {
            parsed = CompactJws.parse(token);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("that is not an assertion: " + invalid.getMessage());
        }
        if (!JAG_TYPE.equals(parsed.header().get("typ"))) {
            throw new IllegalArgumentException("expected an ID-JAG (typ " + JAG_TYPE
                    + "), got typ " + PyRepr.of(parsed.header().get("typ")));
        }
        List<Map<String, Object>> keys;
        try {
            keys = providers.keysFor(issuer, parsed.header().get("kid"));
        } catch (IllegalArgumentException unavailable) {
            throw new IllegalArgumentException(issuer + " could not be reached to check the assertion");
        }
        Map<String, Object> claims;
        try {
            claims = IdentityTokens.verifySignature(token, keys);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("the assertion's signature does not verify against " + issuer);
        }
        validateClaims(claims, provider, resource);
        return claims;
    }

    void validateClaims(Map<String, Object> claims, Map<String, Object> provider, String resource) {
        String issuer = text(provider.get("issuer"));
        PyJwtClaims.validateWithIat(claims, AsState.now(), "exp");
        if (!issuer.equals(claims.get("iss"))) {
            throw new IllegalArgumentException("the assertion is from " + PyRepr.of(claims.get("iss"))
                    + ", and this organization federates to " + PyRepr.of(issuer));
        }
        List<?> audience = claims.get("aud") instanceof String one ? List.of(one)
                : Organization.list(claims.get("aud"));
        if (!audience.contains(config.issuer) || audience.stream().anyMatch(value -> !(value instanceof String))) {
            throw new IllegalArgumentException("the assertion is audienced at "
                    + PyRepr.of(audience.isEmpty() ? List.of("nothing") : audience)
                    + " and this authority is " + PyRepr.of(config.issuer)
                    + " — the resource application's audience at the provider has to be this authority");
        }
        if (text(claims.get("jti")).isEmpty()) {
            throw new IllegalArgumentException("the assertion has no jti and cannot be spent once");
        }
        var named = subjects(claims, text(provider.get("subject_claim")));
        var mapped = object(provider.get("subject_map"));
        if (named.stream().noneMatch(name -> config.ownerUsername.equals(mapped.getOrDefault(name, name)))) {
            String who = PyRepr.of(named.isEmpty() ? List.of("nobody") : named.subList(0, 1));
            throw new IllegalArgumentException("the assertion names " + who + (mapped.isEmpty()
                    ? " and this authority is " + PyRepr.of(config.ownerUsername) + "'s"
                    : " — which this organization does not map to " + PyRepr.of(config.ownerUsername)));
        }
        if (claims.containsKey("resource") && !resourceUri.equals(claims.get("resource"))) {
            throw new IllegalArgumentException("the assertion was issued for a different resource");
        }
        String operation = operation(resource);
        var scopes = scopes(claims);
        if (!scopes.contains(operation)) {
            throw new IllegalArgumentException(issuer + " did not approve this application for "
                    + PyRepr.of(operation) + " — it carries "
                    + PyRepr.of(scopes.isEmpty() ? List.of("nothing") : scopes));
        }
    }

    static Map<String, Object> recorded(Map<String, Object> claims) {
        return row("issuer", claims.get("iss"), "subject", claims.get("sub"), "member",
                claims.get("preferred_username"), "application", claims.get("client_id"),
                "scope", scopes(claims), "jti", claims.get("jti"));
    }

    static List<String> subjects(Map<String, Object> claims, String name) {
        List<String> names = new ArrayList<>();
        if (!name.isEmpty()) {
            names.add(text(claims.get(name)));
        } else {
            names.add(text(claims.get("preferred_username")));
            if (Boolean.TRUE.equals(claims.get("email_verified"))) {
                names.add(text(claims.get("email")));
            }
            names.add(text(claims.get("sub")));
        }
        return names.stream().filter(value -> !value.isEmpty()).toList();
    }

    private static List<String> scopes(Map<String, Object> claims) {
        String value = text(claims.get("scope")).strip();
        return value.isEmpty() ? List.of() : List.of(value.split("(?U)\\s+"));
    }

    private static String operation(String resource) { return resource.substring(resource.indexOf('/') + 1); }
}
