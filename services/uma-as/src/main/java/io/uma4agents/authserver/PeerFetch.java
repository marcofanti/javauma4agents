package io.uma4agents.authserver;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * Reads a document a peer, or a stranger, names: an agent token's issuer, a client
 * metadata document, an operator's key directory. The pinned {@code uma4a_fetch.get_json}:
 * https only, no redirects, one five-second deadline, at most 256 KiB, a JSON object.
 */
@Component
public class PeerFetch {

    static final Duration DEADLINE = Duration.ofSeconds(5);
    static final int MAX_BYTES = 256 * 1024;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpClient http;

    public PeerFetch(HttpClient http) {
        this.http = http;
    }

    /**
     * GETs the URL and returns its JSON object.
     *
     * @param url an https URL
     * @return the parsed object
     * @throws IllegalStateException naming what was wrong
     */
    public Map<String, Object> getJson(String url) {
        return getJson(url, MAX_BYTES);
    }

    Map<String, Object> getJson(String url, int maxBytes) {
        if (!url.startsWith("https://")) {
            throw new IllegalStateException(url + " is not https");
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(DEADLINE)
                .GET().build();
        byte[] body;
        try {
            HttpResponse<InputStream> response =
                    http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = response.body()) {
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new IllegalStateException(
                            "HTTP " + response.statusCode() + " for url '" + url + "'");
                }
                body = in.readNBytes(maxBytes + 1);
            }
        } catch (IOException e) {
            throw new IllegalStateException(url + " could not be fetched: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(url + " fetch interrupted", e);
        }
        if (body.length > maxBytes) {
            throw new IllegalStateException(url + " returned more than " + maxBytes + " bytes");
        }
        try {
            Object doc = MAPPER.readValue(body, new TypeReference<Object>() {});
            if (!(doc instanceof Map<?, ?>)) {
                throw new IllegalStateException(url + " did not return a JSON object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) doc;
            return map;
        } catch (JacksonException e) {
            throw new IllegalStateException(url + " did not return JSON", e);
        }
    }
}
