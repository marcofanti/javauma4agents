package io.uma4agents.pep;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

/**
 * The PEP's client half against uma-as: PAT lifecycle (client_credentials with
 * refresh), startup resource registration with retry, ticket minting (with the
 * FedAuthz re-push repair path), introspection, and access reporting.
 */
@Component
public class AsClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final PepConfig config;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();
    private final Object patLock = new Object();
    private String patToken;
    private long patExpires;

    public AsClient(PepConfig config) {
        this.config = config;
    }

    /** The current PAT, refreshed via client_credentials before it expires. */
    public String getPat(boolean force) {
        synchronized (patLock) {
            long now = java.time.Instant.now().getEpochSecond();
            if (!force && patToken != null && patExpires >= now + 60) {
                return patToken;
            }
            Map<String, Object> body = postForm(config.asInternal + "/token", Map.of(
                    "grant_type", "client_credentials",
                    "client_id", config.rsClientId,
                    "client_secret", config.rsClientSecret,
                    "scope", "uma_protection"));
            patToken = (String) body.get("access_token");
            long expiresIn = body.get("expires_in") instanceof Number n ? n.longValue() : 300;
            patExpires = now + expiresIn;
            config.log.event("pat.obtained", null, "client_id", config.rsClientId,
                    "expires_in", expiresIn);
            return patToken;
        }
    }

    public void registerToolSurfaces() {
        for (Map.Entry<String, ToolCatalog.Surface> e : ToolCatalog.TOOLS.entrySet()) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("_id", e.getValue().resourceId());
            body.put("name", "Alice's vault: " + e.getKey());
            body.put("type", "mcp-tool");
            body.put("resource_scopes", e.getValue().scopes());
            postJson(config.asInternal + "/rreg", body, getPat(false));
        }
    }

    /** Startup registration with retry — uma-as may still be booting. */
    @Bean
    public ApplicationRunner registerResourcesAtStartup() {
        return args -> {
            for (int attempt = 0; attempt < 30; attempt++) {
                try {
                    registerToolSurfaces();
                    break;
                } catch (RuntimeException e) {
                    Thread.sleep(1000);
                }
            }
            config.log.event("resources.registered_at_startup", null,
                    "tools", List.copyOf(ToolCatalog.TOOLS.keySet()));
        };
    }

    /** Mints a ticket at /perm; null when the AS is unreachable. */
    public String mintTicket(String resourceId, List<String> scopes) {
        Map<String, Object> request = Map.of(
                "resource_id", resourceId, "resource_scopes", scopes);
        try {
            HttpResponse<String> r = postJsonRaw(config.asInternal + "/perm", request,
                    getPat(false));
            if (r.statusCode() == 401) {
                // PAT expired mid-flight or the AS restarted with new keys.
                r = postJsonRaw(config.asInternal + "/perm", request, getPat(true));
            }
            if (r.statusCode() == 400
                    && "invalid_resource_id".equals(parse(r.body()).get("error"))) {
                // The AS restarted and lost the push-registered state; the RS is
                // the party that has to notice and repair it (FedAuthz).
                config.log.event("resources.reregistered", null, "reason", "as_lost_registry");
                registerToolSurfaces();
                r = postJsonRaw(config.asInternal + "/perm", request, getPat(false));
            }
            if (r.statusCode() >= 400) {
                throw new IllegalStateException("HTTP " + r.statusCode());
            }
            return (String) parse(r.body()).get("ticket");
        } catch (Exception e) {
            config.log.event("permission.register_failed", null, "error", e.toString());
            return null;
        }
    }

    public Map<String, Object> introspect(String token, boolean consume) {
        Map<String, Object> body = postForm(config.asInternal + "/introspect", Map.of(
                "token", token, "consume", consume ? "true" : "false"), getPat(false));
        return body;
    }

    /** Reports an allowed call so the ledger's "touched" column is grounded. */
    public void reportAccess(String family, String tool, String summary) {
        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("family", family);
            body.put("tool", tool);
            body.put("summary", summary);
            postJson(config.asInternal + "/audit/access", body, getPat(false));
        } catch (RuntimeException e) {
            // Reporting must never fail the verdict.
        }
    }

    // --- HTTP helpers -------------------------------------------------------

    private Map<String, Object> postForm(String url, Map<String, String> params) {
        return postForm(url, params, null);
    }

    private Map<String, Object> postForm(String url, Map<String, String> params, String pat) {
        String form = params.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .header("content-type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form));
        if (pat != null) {
            builder.header("Authorization", "Bearer " + pat);
        }
        HttpResponse<String> response = send(builder.build());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " from " + url);
        }
        return parse(response.body());
    }

    private void postJson(String url, Map<String, Object> body, String pat) {
        HttpResponse<String> response = postJsonRaw(url, body, pat);
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " from " + url);
        }
    }

    private HttpResponse<String> postJsonRaw(String url, Map<String, Object> body, String pat) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer " + pat)
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(body)))
                    .build();
            return send(request);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("unserializable request body", e);
        }
    }

    private HttpResponse<String> send(HttpRequest request) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("AS unreachable: " + e.getMessage(), e);
        }
    }

    private static Map<String, Object> parse(String json) {
        try {
            return MAPPER.readValue(json, new TypeReference<>() {});
        } catch (IOException e) {
            throw new IllegalStateException("non-JSON response from AS", e);
        }
    }
}
