package io.uma4agents.vault;

import io.uma4agents.pep.core.Publication;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A resource that protects itself also publishes for itself: RFC 9728 puts the metadata at
 * the resource's own origin, so with no gateway in the path the vault serves its signed
 * metadata, its JWKS and the owner-resources listing. In gateway mode every route here
 * answers 404 and the filter is not installed, because the ext_authz host serves them.
 */
@RestController
@Configuration
public class EmbeddedPublication {

    private final VaultSettings settings;
    private final VaultTools tools;

    public EmbeddedPublication(VaultSettings settings, VaultTools tools) {
        this.settings = settings;
        this.tools = tools;
    }

    @Bean
    public FilterRegistrationBean<EmbeddedEnforcementFilter> embeddedEnforcement() {
        FilterRegistrationBean<EmbeddedEnforcementFilter> bean =
                new FilterRegistrationBean<>(new EmbeddedEnforcementFilter(settings));
        bean.addUrlPatterns("/mcp", "/mcp/*");
        bean.setEnabled(settings.embedded);
        if (settings.embedded) {
            settings.log.event("publishing.self", null, "base", settings.publicBase,
                    "as", settings.asPublic);
        }
        return bean;
    }

    private Map<String, Object> prm(String leaf) {
        Map<String, Object> doc = Publication.prmDocument(settings.publicBase,
                settings.asPublic, settings.enforcer().settings().tools(), leaf,
                "/owner-resources");
        return Publication.signMetadata(doc, settings.signingKey(), VaultSettings.KID);
    }

    @GetMapping({"/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp"})
    public ResponseEntity<Object> protectedResourceMetadata() {
        return settings.embedded ? ResponseEntity.ok(prm("mcp")) : notFound();
    }

    @GetMapping("/.well-known/oauth-protected-resource/mcp/{owner}")
    public ResponseEntity<Object> protectedResourceMetadataFor(@PathVariable String owner) {
        if (!settings.embedded || !settings.owner.equals(owner)) {
            return notFound();
        }
        return ResponseEntity.ok(prm("mcp/" + owner));
    }

    @GetMapping("/jwks")
    public ResponseEntity<Object> jwks() {
        return settings.embedded
                ? ResponseEntity.ok(Publication.jwks(settings.signingKey(), VaultSettings.KID))
                : notFound();
    }

    /** Served only to the owner's authorization server, proven over RFC 9421. */
    @GetMapping("/owner-resources")
    public ResponseEntity<Object> ownerResources(HttpServletRequest request) {
        if (!settings.embedded) {
            return notFound();
        }
        String reason = Publication.verifyOwnerAsQuery(request.getMethod(), settings.authority,
                "/owner-resources", request.getHeader("signature-input"),
                request.getHeader("signature"), settings.asKeys());
        if (reason != null) {
            settings.log.event("owner_resources.denied", null, "reason", reason);
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("error", "invalid_signature", "error_description",
                            "this listing is served only to the owner's authorization "
                                    + "server: " + reason));
        }
        settings.log.event("owner_resources.served", null, "owner", settings.owner);
        return ResponseEntity.ok(Publication.ownerResourcesDocument(settings.publicBase,
                settings.owner, settings.enforcer().settings().tools(), "mcp"));
    }

    private static ResponseEntity<Object> notFound() {
        return ResponseEntity.status(404).contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("error", "no such resource"));
    }
}
