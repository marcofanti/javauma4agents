package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Health, JWKS, discovery, and the terms roster (JSON / HTML / JSON-LD). */
@RestController
public class DiscoveryController {

    private final AsConfig config;
    private final AsState state;
    private final OwnerStore store;
    private final SigningKeys keys;
    private final PolicyService policy;
    private final GrantService grants;

    public DiscoveryController(AsConfig config, AsState state, OwnerStore store,
                               SigningKeys keys, PolicyService policy, GrantService grants) {
        this.config = config;
        this.state = state;
        this.store = store;
        this.keys = keys;
        this.policy = policy;
        this.grants = grants;
    }

    /**
     * Publishes each tier's current terms at startup (the Python startup hook). Write-once
     * per version, so a restart over a durable store republishes nothing.
     */
    @PostConstruct
    public void publishInitialTerms() {
        policy.tiers().forEach((tierId, tier) -> grants.publishTerms(tierId, tier));
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok", "issuer", config.issuer);
    }

    /** The current signing key and every retired key still listed. */
    @GetMapping("/jwks")
    public Map<String, Object> jwks() {
        return keys.jwks();
    }

    /** Has the declarative pull landed yet? For smoke tests, never for readiness. */
    @GetMapping("/health/registry")
    public ResponseEntity<Object> healthRegistry() {
        int count = state.resources().size();
        boolean ready = count > 0;
        return ResponseEntity.status(ready ? 200 : 503).body(Map.of(
                "status", ready ? "ok" : "pending", "resources", count));
    }

    /**
     * Authorization server metadata at UMA 2.0's well-known path and this lab's original
     * one. Advertises only what the token endpoint accepts and the endpoints that exist in
     * this phase; organization, joint, ID-JAG and resource-server introduction land later.
     */
    @GetMapping({"/.well-known/uma2-configuration", "/.well-known/uma4agents-configuration"})
    public Map<String, Object> discovery() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", config.issuer);
        doc.put("token_endpoint", config.issuer + "/token");
        doc.put("rs_registration_endpoint", config.issuer + "/rs/register");
        doc.put("permission_endpoint", config.issuer + "/perm");
        doc.put("introspection_endpoint", config.issuer + "/introspect");
        doc.put("consume_endpoint", config.issuer + "/consume");
        doc.put("jwks_uri", config.issuer + "/jwks");
        doc.put("terms_endpoint", config.issuer + "/terms");
        doc.put("owner_endpoint", config.issuer + "/owner");
        doc.put("org_notice_endpoint", config.issuer + "/org/notice");
        doc.put("org_admin_endpoint", config.issuer + "/org/admin");
        doc.put("joint_quote_endpoint", config.issuer + "/joint/quote");
        doc.put("joint_verdict_endpoint", config.issuer + "/joint/verdict");
        doc.put("response_types_supported", List.of());
        doc.put("grant_types_supported",
                List.of("urn:ietf:params:oauth:grant-type:uma-ticket", "client_credentials"));
        doc.put("claim_token_formats_supported", List.of(AsConfig.AGREEMENT_FORMAT, io.uma4agents.common.IdentityTokens.ID_JAG));
        doc.put("signing_alg_values_supported", List.of("EdDSA"));
        doc.put("http_message_signature_alg_values_supported", List.of("ed25519"));
        doc.put("uma_profiles_supported", List.of("https://u4a.ai/spec/core/1.0",
                "https://u4a.ai/spec/terms/1.0", "https://u4a.ai/spec/fedauthz/1.0"));
        return doc;
    }

    @GetMapping("/terms")
    public Map<String, Object> termsIndex() {
        return Map.of("proffered_by", config.issuer, "terms", store.termsDocs());
    }

    @GetMapping("/terms/**")
    public ResponseEntity<Object> termsDocument(
            HttpServletRequest request,
            @RequestParam(required = false) String format,
            @RequestHeader(value = "accept", required = false) String accept) {
        String templateId = request.getRequestURI().substring("/terms/".length());
        Map<String, Object> doc = store.termsDoc(templateId);
        if (doc == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown terms document");
        }
        doc = annotateEnforced(doc);
        if ("jsonld".equals(format)) {
            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf("application/ld+json"))
                    .body(termsAsJsonLd(doc));
        }
        String acceptHeader = accept == null ? "" : accept;
        boolean wantsHtml = acceptHeader.contains("text/html")
                && !acceptHeader.split(",")[0].contains("application/json");
        if (wantsHtml) {
            return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(termsAsHtml(doc));
        }
        return ResponseEntity.ok(doc);
    }

    /**
     * The plain-language representation IEEE 7012 (4.4.1) requires. Every interpolation is
     * escaped as Python's {@code html.escape}: she authors most of it, and it is a public
     * URL agents dereference and quote. Prohibitions say which are refused at the door.
     */
    @SuppressWarnings("unchecked")
    static String termsAsHtml(Map<String, Object> doc) {
        Map<String, Object> enforced = doc.get("enforced") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Map.of();
        StringBuilder prohibited = new StringBuilder();
        if (doc.get("prohibited") instanceof List<?> list) {
            for (Object p : list) {
                String name = String.valueOf(p);
                prohibited.append("<li>").append(escape(name)).append(enforced.containsKey(name)
                        ? " — <b>refused at the door</b> (" + escape(String.valueOf(
                                enforced.get(name))) + ")"
                        : " — undertaken, not enforced").append("</li>");
            }
        }
        String scopes = doc.get("scope") instanceof List<?> list
                ? escape(String.join(", ", list.stream().map(String::valueOf).toList())) : "";
        java.math.BigDecimal seconds = doc.get("expires_in") instanceof Number n
                ? new java.math.BigDecimal(n.toString()) : java.math.BigDecimal.ZERO;
        String hours = io.uma4agents.common.PyJson.compactOrdered(new java.math.BigDecimal(
                seconds.doubleValue() / 3600).setScale(1, java.math.RoundingMode.HALF_EVEN)
                .doubleValue());
        return """
                <!doctype html><html><head><meta charset="utf-8">
                <title>%s — %s</title>
                <style>body{background:#0b0e14;color:#e6e9f0;font-family:system-ui;max-width:640px;
                margin:3rem auto;padding:0 1rem;line-height:1.6}h1{font-size:1.3rem}
                code{background:#161b26;padding:2px 7px;border-radius:5px}
                .k{color:#8a93a8}li{margin:.2rem 0}</style></head><body>
                <h1>%s</h1>
                <p class="k">Terms <code>%s</code>, proffered by
                <code>%s</code>, published %s.</p>
                <p>The owner of these accounts offers access on the following terms. By
                signing an agreement that names this document, you accept all of them.</p>
                <ul>
                <li><b>Purpose</b> — access is granted only for: %s.</li>
                <li><b>What you may access</b> — %s.</li>
                <li><b>How long</b> — access expires %s seconds
                    (~%s hours) after grant.</li>
                <li><b>Prohibited</b> — you agree you will not engage in:<ul>%s</ul></li>
                <li><b>Anything not expressly permitted here is not permitted.</b></li>
                </ul>
                <p class="k">Machine-readable: this same URI as <code>application/json</code>,
                or <code>?format=jsonld</code> for a JSON-LD/ODRL representation.</p>
                </body></html>""".formatted(
                escape(doc.get("name")), escape(doc.get("template_id")), escape(doc.get("name")),
                escape(doc.get("template_id")), escape(doc.get("proffered_by")),
                escape(doc.get("published_at")), escape(doc.get("purpose")), scopes,
                seconds.toBigInteger(), hours, prohibited);
    }

    /** Python's {@code html.escape(str(value))}, quotes included. */
    static String escape(Object value) {
        String text = value == null ? "None" : String.valueOf(value);
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    /**
     * Marks which prohibitions the enforcement point refuses, on read and only while this
     * version is in force: stored terms never change, and a superseded version must not be
     * labelled with today's posture.
     */
    @SuppressWarnings("unchecked")
    Map<String, Object> annotateEnforced(Map<String, Object> doc) {
        Map<String, Object> tier = policy.tiers().get(String.valueOf(doc.get("tier")));
        if (tier == null || !(tier.get("terms") instanceof Map<?, ?> terms)
                || !String.valueOf(terms.get("template_id")).equals(doc.get("template_id"))) {
            return doc;
        }
        Map<String, Object> out = new LinkedHashMap<>(doc);
        out.put("enforced", PolicyService.enforcedProhibitions(tier));
        return out;
    }

    /** JSON-LD/ODRL representation (IEEE 7012 4.4.2, Annex A principle (j)). */
    static Map<String, Object> termsAsJsonLd(Map<String, Object> doc) {
        String uri = String.valueOf(doc.get("terms_uri"));
        long expiresIn = doc.get("expires_in") instanceof Number n ? n.longValue() : 0;
        List<Map<String, Object>> permissions = new ArrayList<>();
        if (doc.get("scope") instanceof List<?> scopes) {
            for (Object s : scopes) {
                permissions.add(Map.of(
                        "odrl:action", uri + "#scope/" + s,
                        "odrl:constraint", List.of(Map.of(
                                "odrl:leftOperand", "odrl:elapsedTime",
                                "odrl:operator", "odrl:lteq",
                                "odrl:rightOperand", Map.of(
                                        "@value", "PT" + expiresIn + "S",
                                        "@type", "xsd:duration")))));
            }
        }
        List<Map<String, Object>> prohibitions = new ArrayList<>();
        if (doc.get("prohibited") instanceof List<?> prohibited) {
            for (Object p : prohibited) {
                prohibitions.add(Map.of("odrl:action", uri + "#prohibited/" + p));
            }
        }
        Map<String, Object> jsonld = new LinkedHashMap<>();
        jsonld.put("@context", Map.of(
                "odrl", "http://www.w3.org/ns/odrl/2/",
                "dcterms", "http://purl.org/dc/terms/"));
        jsonld.put("@id", uri);
        jsonld.put("@type", "odrl:Offer");
        jsonld.put("odrl:uid", uri);
        jsonld.put("dcterms:title", doc.get("name"));
        jsonld.put("dcterms:identifier", doc.get("template_id"));
        jsonld.put("dcterms:publisher", doc.get("proffered_by"));
        jsonld.put("dcterms:issued", doc.get("published_at"));
        jsonld.put("dcterms:description", doc.get("purpose"));
        jsonld.put("odrl:permission", permissions);
        jsonld.put("odrl:prohibition", prohibitions);
        return jsonld;
    }
}
