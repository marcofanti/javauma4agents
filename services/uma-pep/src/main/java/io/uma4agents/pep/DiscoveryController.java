package io.uma4agents.pep;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.S256;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * The resource's public discovery surface (RFC 9728 PRM and its AAuth-binding
 * encoding, both signed) plus the protected owner-resources listing — the
 * "declare" half of declarative registration.
 */
@RestController
public class DiscoveryController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final PepConfig config;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();
    private final Object asKeysLock = new Object();
    private List<Map<String, Object>> asKeys = List.of();
    private long asKeysExpire;

    public DiscoveryController(PepConfig config) {
        this.config = config;
    }

    /**
     * RFC 9728 Protected Resource Metadata — <em>structural</em> only. It says
     * what shape the resource has (tools, scopes) and where authority lives
     * (authorization_servers, the owner-resources query endpoint); it does not
     * say whose instances sit behind it. Publishing which resources Alice owns
     * at an unauthenticated well-known URI would be a privacy leak the old
     * push registration never had — owner-bound ids live behind
     * /owner-resources ("protected webfinger" for Alice's stuff).
     */
    private Map<String, Object> prmDocument() {
        Set<String> scopes = new TreeSet<>();
        ToolCatalog.TOOLS.values().forEach(s -> scopes.addAll(s.scopes()));
        List<Map<String, Object>> surfaces = new ArrayList<>();
        ToolCatalog.TOOLS.forEach((tool, surface) -> {
            Map<String, Object> ts = new LinkedHashMap<>();
            ts.put("tool", tool);
            ts.put("resource_scopes", surface.scopes());
            surfaces.add(ts);
        });
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", "https://" + config.expectedAuthority + "/mcp");
        doc.put("authorization_servers", List.of(config.asPublic));
        doc.put("jwks_uri", "https://" + config.expectedAuthority + "/jwks");
        doc.put("scopes_supported", List.copyOf(scopes));
        doc.put("bearer_methods_supported", List.of("header"));
        doc.put("resource_signing_alg_values_supported", List.of("EdDSA"));
        doc.put("tool_surfaces", surfaces);
        doc.put("owner_resources_endpoint",
                "https://" + config.expectedAuthority + "/owner-resources");
        return doc;
    }

    @GetMapping({"/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp"})
    public Map<String, Object> protectedResourceMetadata() {
        Map<String, Object> doc = prmDocument();
        // RFC 9728 signed_metadata: the same claims as a JWT under the
        // resource's key (jwks_uri above), so a relayed or cached copy of this
        // document stays attributable to the resource that published it.
        doc.put("signed_metadata", signedMetadata(doc, "oauth-protected-resource+jwt"));
        return doc;
    }

    /**
     * An AAuth Rich Resource Requests (R3) vocabulary describing this
     * resource's operations in a format the agent already speaks (MCP), so a
     * caller that knows only the hostname can learn the API. Content-addressed:
     * the digest is over the canonical operation list, which gives the
     * <em>universal type layer</em> (operations + their scopes) a stable
     * identifier — the same facts, referenceable independent of any one owner.
     */
    private Map<String, Object> r3Vocabulary() {
        List<Map<String, Object>> operations = new ArrayList<>();
        ToolCatalog.TOOLS.forEach((tool, surface) -> {
            Map<String, Object> op = new LinkedHashMap<>();
            op.put("tool", tool);
            op.put("resource_scopes", surface.scopes());
            operations.add(op);
        });
        String digest = S256.of(PyJson.dumpsSorted(operations));
        Map<String, Object> vocabulary = new LinkedHashMap<>();
        vocabulary.put("format", "mcp");
        vocabulary.put("operations", operations);
        vocabulary.put("digest", digest);
        return vocabulary;
    }

    /**
     * The AAuth-binding encoding of the <em>same public structural layer</em>
     * the PRM document carries — AAuth's {@code /.well-known/aauth-resource.json}.
     * Same tool surfaces, expressed as an R3 vocabulary; {@code access_mode}
     * names the four-party (federated) topology this gateway already runs (PS
     * federates with the owner's AS). Crucially it points at the <em>same</em>
     * owner_resources_endpoint: the protected instance layer ("protected
     * webfinger") is binding-independent — only the public encoding changes.
     */
    @GetMapping("/.well-known/aauth-resource.json")
    public Map<String, Object> aauthResourceMetadata() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", "https://" + config.expectedAuthority + "/mcp");
        doc.put("access_mode", "four-party");
        doc.put("access_servers", List.of(config.asPublic));
        doc.put("jwks_uri", "https://" + config.expectedAuthority + "/jwks");
        doc.put("r3_vocabularies", List.of(r3Vocabulary()));
        doc.put("owner_resources_endpoint",
                "https://" + config.expectedAuthority + "/owner-resources");
        doc.put("signed_metadata", signedMetadata(doc, "aauth-resource+jwt"));
        return doc;
    }

    private String signedMetadata(Map<String, Object> doc, String typ) {
        Map<String, Object> claims = new LinkedHashMap<>(doc);
        claims.put("iss", doc.get("resource"));
        claims.put("iat", Instant.now().getEpochSecond());
        return CompactJws.sign(
                Map.of("typ", typ, "kid", PepConfig.PEP_KID),
                claims, config.signingKey.getPrivate());
    }

    @GetMapping("/jwks")
    public Map<String, Object> pepJwks() {
        Map<String, Object> jwk = Jwks.okpPublicJwk(config.signingKey.getPublic());
        jwk.put("kid", PepConfig.PEP_KID);
        jwk.put("use", "sig");
        return Map.of("keys", List.of(jwk));
    }

    /**
     * The protected half of discovery — a "protected webfinger" for the
     * owner's stuff. Serves the owner-bound resource instances only to a
     * querier that proves possession of the owner's AS signing key (RFC 9421
     * over @method/@authority/@path — the same message-signature mechanics the
     * agent uses for proof-of-possession, pointed the other way). The trust
     * was established at onboarding: this gateway holds a PAT from exactly
     * that AS.
     */
    @GetMapping("/owner-resources")
    public ResponseEntity<Object> ownerResources(HttpServletRequest request) {
        boolean verified = false;
        String lastError = "no signature";
        for (Map<String, Object> jwk : asVerificationKeys()) {
            try {
                HttpSignature.verify(
                        request.getMethod(),
                        config.expectedAuthority,
                        "/owner-resources",
                        "",
                        header(request, "signature-input"),
                        header(request, "signature"),
                        Jwks.toPublicKey(jwk));
                verified = true;
                break;
            } catch (HttpSignature.VerifyException | IllegalArgumentException e) {
                lastError = e.getMessage();
            }
        }
        if (!verified) {
            config.log.event("owner_resources.denied", null, "reason", lastError);
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("error", "invalid_signature",
                            "error_description", "this listing is served only to "
                                    + "the owner's authorization server: " + lastError));
        }
        List<Map<String, Object>> resources = new ArrayList<>();
        ToolCatalog.TOOLS.forEach((tool, surface) -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("_id", surface.resourceId());
            item.put("tool", tool);
            item.put("resource_scopes", surface.scopes());
            item.put("name", "Alice's vault: " + tool);
            item.put("type", "mcp-tool");
            resources.add(item);
        });
        config.log.event("owner_resources.served", null, "owner", config.owner,
                "count", resources.size());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("owner", config.owner);
        body.put("resource", "https://" + config.expectedAuthority + "/mcp");
        body.put("resources", resources);
        return ResponseEntity.ok(body);
    }

    private List<Map<String, Object>> asVerificationKeys() {
        synchronized (asKeysLock) {
            long now = Instant.now().getEpochSecond();
            if (asKeysExpire >= now) {
                return asKeys;
            }
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(config.asInternal + "/jwks"))
                        .timeout(Duration.ofSeconds(5)).GET().build();
                HttpResponse<String> response =
                        http.send(request, HttpResponse.BodyHandlers.ofString());
                Map<String, Object> body = MAPPER.readValue(response.body(),
                        new TypeReference<>() {});
                if (body.get("keys") instanceof List<?> keys) {
                    List<Map<String, Object>> parsed = new ArrayList<>();
                    for (Object key : keys) {
                        if (key instanceof Map<?, ?> jwk) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> typed = (Map<String, Object>) jwk;
                            parsed.add(typed);
                        }
                    }
                    asKeys = parsed;
                    asKeysExpire = now + 300;
                }
            } catch (IOException | InterruptedException | RuntimeException e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                config.log.event("owner_resources.keys_unavailable", null,
                        "error", String.valueOf(e.getMessage()));
            }
            return asKeys;
        }
    }

    private static String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value;
    }
}
