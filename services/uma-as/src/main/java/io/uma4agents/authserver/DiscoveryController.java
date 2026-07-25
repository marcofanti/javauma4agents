package io.uma4agents.authserver;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Comparator;
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
    private final PolicyService policy;
    private final GrantService grants;

    public DiscoveryController(AsConfig config, AsState state, PolicyService policy,
                               GrantService grants) {
        this.config = config;
        this.state = state;
        this.policy = policy;
        this.grants = grants;
    }

    /** Publishes each tier's current terms at startup (the Python startup hook). */
    @PostConstruct
    public void publishInitialTerms() {
        policy.tiers().forEach((tierId, tier) -> grants.publishTerms(tierId, tier));
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok", "issuer", config.issuer);
    }

    @GetMapping("/jwks")
    public Map<String, Object> jwks() {
        return Map.of("keys", List.of(state.publicJwk));
    }

    @GetMapping("/.well-known/uma4agents-configuration")
    public Map<String, Object> discovery() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", config.issuer);
        doc.put("token_endpoint", config.issuer + "/token");
        doc.put("permission_endpoint", config.issuer + "/perm");
        doc.put("introspection_endpoint", config.issuer + "/introspect");
        doc.put("resource_registration_endpoint", config.issuer + "/rreg");
        doc.put("jwks_uri", config.issuer + "/jwks");
        doc.put("terms_endpoint", config.issuer + "/terms");
        doc.put("grant_types_supported", List.of("urn:ietf:params:oauth:grant-type:uma-ticket"));
        doc.put("claim_token_formats_supported", List.of(AsConfig.AGREEMENT_FORMAT));
        return doc;
    }

    @GetMapping("/terms")
    public Map<String, Object> termsIndex() {
        List<Map<String, Object>> docs = new ArrayList<>(state.termsDocs.values());
        docs.sort(Comparator.comparing(d -> String.valueOf(d.get("template_id"))));
        return Map.of("proffered_by", config.issuer, "terms", docs);
    }

    @GetMapping("/terms/**")
    public ResponseEntity<Object> termsDocument(
            HttpServletRequest request,
            @RequestParam(required = false) String format,
            @RequestHeader(value = "accept", required = false) String accept) {
        String templateId = request.getRequestURI().substring("/terms/".length());
        Map<String, Object> doc = state.termsDocs.get(templateId);
        if (doc == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown terms document");
        }
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

    /** The plain-language representation IEEE 7012 (4.4.1) requires. */
    @SuppressWarnings("unchecked")
    static String termsAsHtml(Map<String, Object> doc) {
        List<String> prohibitedList = doc.get("prohibited") instanceof List<?> list
                ? list.stream().map(String::valueOf).toList() : List.of();
        String prohibited = prohibitedList.stream()
                .map(p -> "<li>" + p + "</li>").reduce("", String::concat);
        String scopes = doc.get("scope") instanceof List<?> list
                ? String.join(", ", list.stream().map(String::valueOf).toList()) : "";
        long expiresIn = doc.get("expires_in") instanceof Number n ? n.longValue() : 0;
        double hours = Math.round(expiresIn / 3600.0 * 10) / 10.0;
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
                <li><b>How long</b> — access expires %d seconds
                    (~%s hours) after grant.</li>
                <li><b>Prohibited</b> — you agree you will not engage in:<ul>%s</ul></li>
                <li><b>Anything not expressly permitted here is not permitted.</b></li>
                </ul>
                <p class="k">Machine-readable: this same URI as <code>application/json</code>,
                or <code>?format=jsonld</code> for a JSON-LD/ODRL representation.</p>
                </body></html>""".formatted(
                doc.get("name"), doc.get("template_id"), doc.get("name"),
                doc.get("template_id"), doc.get("proffered_by"), doc.get("published_at"),
                doc.get("purpose"), scopes, expiresIn, hours, prohibited);
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
