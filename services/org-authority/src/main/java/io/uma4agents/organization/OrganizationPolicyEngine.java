package io.uma4agents.organization;

import io.uma4agents.common.EventLog;
import io.uma4agents.common.PyJson;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** OPA owns the charter's refusal and ask rules. An incomplete answer fails closed. */
@Component
final class OrganizationPolicyEngine {
    private static final int CACHE_LIMIT = 2048;
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final ObjectMapper json;
    private final URI base;
    private final String shipped;
    private final long graceMillis;
    private final EventLog log = new EventLog("org-authority");
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private final LinkedHashMap<String, Cached> cache = new LinkedHashMap<>(16, 0.75f, true);

    private record Cached(long observed, Map<String, Object> decision) {}

    OrganizationPolicyEngine(ObjectMapper json) {
        this.json = json;
        base = URI.create(System.getenv().getOrDefault("OPA_URL", "http://opa:8181"));
        graceMillis = (long) (1_000 * Double.parseDouble(
                System.getenv().getOrDefault("ORG_OPA_GRACE_S", "60")));
        try (InputStream in = getClass().getResourceAsStream("/org.rego")) {
            if (in == null) {
                throw new IllegalStateException("shipped charter policy is missing");
            }
            shipped = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException read) {
            throw new IllegalStateException("shipped charter policy could not be read", read);
        }
    }

    void loadShipped() {
        HttpResponse<String> result = send("PUT", "/v1/policies/u4a-org", "text/plain", shipped);
        if (result.statusCode() != 200) {
            throw new IllegalStateException("the shipped policy module did not load: " + result.body());
        }
    }

    void loadCustom(String rego) {
        if (rego.isBlank()) {
            HttpResponse<String> response = send("DELETE", "/v1/policies/u4a-custom", null, "");
            if (response.statusCode() != 200 && response.statusCode() != 404) {
                throw new IllegalStateException("the old custom policy could not be removed");
            }
            return;
        }
        HttpResponse<String> response = send("PUT", "/v1/policies/u4a-custom", "text/plain", rego);
        if (response.statusCode() != 200) {
            throw new IllegalArgumentException(compileError(response.body()));
        }
    }

    Map<String, Object> evaluate(String owner, Map<String, Object> charter,
                                 Map<String, Object> role, Map<String, Object> request,
                                 Runnable reloadCurrent) {
        Map<String, Object> payload = Map.of("input", Map.of("member", owner,
                "charter", charter, "role", role, "request", request));
        String key = PyJson.compactSorted(payload);
        boolean wantsCustom = charter.get("rego") instanceof String rego && !rego.isBlank();
        String incomplete = null;
        try {
            Map<String, Object> result = ask(payload);
            incomplete = whyIncomplete(result, wantsCustom);
            if (incomplete != null) {
                reloadCurrent.run();
                result = ask(payload);
                incomplete = whyIncomplete(result, wantsCustom);
            }
            if (incomplete == null) {
                Map<String, Object> decision = object(result.get("decision"));
                synchronized (cache) {
                    cache.put(key, new Cached(System.currentTimeMillis(), decision));
                    while (cache.size() > CACHE_LIMIT) {
                        cache.pollFirstEntry();
                    }
                }
                return decision;
            }
        } catch (RuntimeException failed) {
            log.event("engine.unreachable", null, "error", String.valueOf(failed.getMessage()));
        }
        synchronized (cache) {
            Cached cached = cache.get(key);
            if (cached != null && cached.observed() > System.currentTimeMillis() - graceMillis) {
                return cached.decision();
            }
        }
        String what = incomplete == null ? "could not be reached" : incomplete;
        return Map.of("effect", "refuse", "because", List.of(
                "the organization's policy engine " + what + ", and its policy is not "
                        + "something this request may proceed without"));
    }

    private Map<String, Object> ask(Map<String, Object> input) {
        HttpResponse<String> response = send("POST", "/v1/data/u4a/org", "application/json",
                json.writeValueAsString(input));
        if (response.statusCode() != 200) {
            throw new IllegalStateException("OPA HTTP " + response.statusCode());
        }
        return object(decode(response.body()).get("result"));
    }

    private static String whyIncomplete(Map<String, Object> answer, boolean wantsCustom) {
        if (!(answer.get("decision") instanceof Map<?, ?>)) {
            return "holds none of the organization's policy";
        }
        if (Boolean.TRUE.equals(answer.get("custom_loaded")) != wantsCustom) {
            return wantsCustom ? "does not hold the organization's own rules"
                    : "holds rules the charter in force no longer has";
        }
        return null;
    }

    private String compileError(String body) {
        try {
            Map<String, Object> message = decode(body);
            if (message.get("errors") instanceof List<?> errors && !errors.isEmpty()) {
                return String.join("; ", errors.stream().map(OrganizationPolicyEngine::object)
                        .map(error -> {
                            Object row = object(error.get("location")).get("row");
                            return (row == null ? "" : "line " + row + " ")
                                    + error.getOrDefault("message", "");
                        }).toList());
            }
            return String.valueOf(message.getOrDefault("message", body));
        } catch (JacksonException invalid) {
            return body;
        }
    }

    private Map<String, Object> decode(String body) {
        return json.readValue(body, new TypeReference<>() {});
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    private HttpResponse<String> send(String method, String path, String mediaType, String body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(base.resolve(path)).timeout(TIMEOUT);
        if (mediaType != null) {
            builder.header("Content-Type", mediaType);
        }
        try {
            return http.send(builder.method(method, HttpRequest.BodyPublishers.ofString(body))
                    .build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("OPA call interrupted", interrupted);
        } catch (IOException unavailable) {
            throw new IllegalStateException("OPA could not be reached", unavailable);
        }
    }
}
