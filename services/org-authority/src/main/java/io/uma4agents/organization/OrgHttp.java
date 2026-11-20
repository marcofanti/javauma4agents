package io.uma4agents.organization;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

@Component
final class OrgHttp {
    private final ObjectMapper json;
    private final HttpClient http;

    OrgHttp(ObjectMapper json, HttpClient http) {
        this.json = json;
        this.http = http;
    }

    Map<String, Object> get(String url) {
        Reply response = send("GET", url, null, Map.of());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " for " + url);
        }
        return decode(response.body());
    }

    Reply send(String method, String url, byte[] body, Map<String, String> headers) {
        URI uri = URI.create(url);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new IllegalArgumentException("peer endpoint must use https");
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach(request::header);
        try {
            HttpResponse<java.io.InputStream> response = http.send(request.build(),
                    HttpResponse.BodyHandlers.ofInputStream());
            String text;
            try (var stream = response.body()) {
                byte[] bytes = stream.readNBytes(262_145);
                if (bytes.length > 262_144) {
                    throw new IllegalStateException("peer document exceeded its size bound");
                }
                text = new String(bytes, StandardCharsets.UTF_8);
            }
            return new Reply(response.statusCode(), text);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("peer request interrupted", interrupted);
        } catch (IOException unavailable) {
            throw new IllegalStateException("peer could not be reached", unavailable);
        }
    }

    byte[] encode(Object body) {
        return json.writeValueAsBytes(body);
    }

    Map<String, Object> decode(String body) {
        return json.readValue(body, new TypeReference<>() {});
    }

    record Reply(int statusCode, String body) {}
}
