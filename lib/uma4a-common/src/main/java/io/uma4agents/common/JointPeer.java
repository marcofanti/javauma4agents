package io.uma4agents.common;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** Bounded HTTPS reads for mandates, holder questions and signing keys. */
public final class JointPeer {
    private static final int LIMIT = 256 * 1024;
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http;
    private final LinkedHashMap<String, CachedKeys> keys = new LinkedHashMap<>();

    private record CachedKeys(long time, List<Map<String, Object>> keys) {}

    public record Reply(int status, Map<String, Object> result) {
        public boolean ok() { return status >= 200 && status < 300; }
    }

    public JointPeer(HttpClient http) {
        this.http = http;
    }

    public Reply request(String method, String address, Object body) {
        URI uri = URI.create(address);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new IllegalArgumentException("peer endpoint must use https");
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(body == null ? 5 : 10));
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(body)));
        try {
            var response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (var stream = response.body()) {
                byte[] bytes = stream.readNBytes(LIMIT + 1);
                if (bytes.length > LIMIT) {
                    throw new IllegalStateException("peer document exceeded its size bound");
                }
                if (response.statusCode() >= 400) {
                    return new Reply(response.statusCode(), Map.of());
                }
                Map<String, Object> result = JSON.readValue(bytes, new TypeReference<>() {});
                return new Reply(response.statusCode(), result == null ? Map.of() : result);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("peer request interrupted", interrupted);
        } catch (IOException unavailable) {
            throw new IllegalStateException("peer could not be reached", unavailable);
        }
    }

    public JointMandate mandate(String issuer, String account) {
        if (!account.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
            return null;
        }
        Reply response = request("GET", issuer + "/mandate/" + account, null);
        if (response.status() == 404) {
            return null;
        }
        if (!response.ok()) {
            throw new IllegalStateException("mandate lookup returned HTTP " + response.status());
        }
        return JointMandate.parse(response.result(), 0);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> keys(String issuer, boolean refresh) {
        long now = System.currentTimeMillis();
        synchronized (keys) {
            CachedKeys cached = keys.get(issuer);
            if (cached != null && now - cached.time() < (refresh ? 60_000 : 300_000)) {
                return cached.keys();
            }
        }
        Reply reply = request("GET", issuer + "/jwks", null);
        if (!reply.ok() || !(reply.result().get("keys") instanceof List<?> jwks)) {
            throw new IllegalStateException("the peer's signing keys could not be read");
        }
        var loaded = jwks.stream().filter(Map.class::isInstance)
                .map(entry -> (Map<String, Object>) entry).toList();
        synchronized (keys) {
            if (keys.size() >= 256) {
                keys.pollFirstEntry();
            }
            keys.put(issuer, new CachedKeys(now, loaded));
        }
        return loaded;
    }
}
