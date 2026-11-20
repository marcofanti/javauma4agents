package io.uma4agents.portal;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/** The organization console owns the browser session and forwards admin requests. */
@RestController
@ConditionalOnProperty(name = "uma.portal.mode", havingValue = "org-console")
final class OrganizationConsole {
    private final PortalConfig config;
    private final Sessions sessions;
    private final OidcService oidc;
    private final HttpClient http;

    OrganizationConsole(PortalConfig config, Sessions sessions, OidcService oidc, HttpClient http) {
        this.config = config;
        this.sessions = sessions;
        this.oidc = oidc;
        this.http = http;
        if ("none".equals(config.authMode) && config.consoleAdminToken.isEmpty()) {
            throw new IllegalStateException("CONSOLE_AUTH=none requires CONSOLE_ADMIN_TOKEN");
        }
    }

    @GetMapping("/health")
    Map<String, String> health() {
        return Map.of("status", "ok", "auth", config.authMode);
    }

    @GetMapping("/api/me")
    ResponseEntity<Map<String, Object>> me(HttpServletRequest request) {
        String user = sessions.currentUser(request);
        return user == null ? ResponseEntity.status(401).body(Map.of("authenticated", false))
                : ResponseEntity.ok(Map.of("authenticated", true, "name", user, "auth", config.authMode));
    }

    @RequestMapping(value = "/api/org/{*path}", method = {RequestMethod.GET, RequestMethod.POST,
            RequestMethod.PUT, RequestMethod.DELETE})
    ResponseEntity<?> forward(@PathVariable String path, HttpServletRequest incoming,
                              @RequestBody(required = false) byte[] body) {
        String token = "oidc".equals(config.authMode) ? oidc.ownerToken(sessions.sid(incoming))
                : config.consoleAdminToken;
        if (token == null || token.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "auth"));
        }
        if (!path.matches("/(?:org|charter|members|invites|roles|activity|break-glass|join-code)"
                + "(?:/[A-Za-z0-9._:-]+)*") || List.of(path.split("/")).contains("..")
                || List.of(path.split("/")).contains(".")) {
            return ResponseEntity.status(404).body(Map.of("error", "unknown endpoint"));
        }
        String url = config.orgInternal + "/admin" + path;
        if (incoming.getQueryString() != null) {
            url += "?" + incoming.getQueryString();
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15)).header("Authorization", "Bearer " + token);
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        request.method(incoming.getMethod(), body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body));
        try {
            HttpResponse<byte[]> response = http.send(request.build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            return ResponseEntity.status(response.statusCode()).contentType(MediaType.APPLICATION_JSON)
                    .body(response.body());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return ResponseEntity.status(502).body(Map.of("error", "organization authority interrupted"));
        } catch (IOException unavailable) {
            return ResponseEntity.status(502).body(Map.of("error", "organization authority unavailable"));
        }
    }
}
