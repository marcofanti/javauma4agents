package io.uma4agents.portal;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Proxies the agent-authorization panel onto uma-as's owner API, attaching
 * Alice's bearer token server-side — the browser never sees the owner token.
 */
@RestController
public class AgentProxyController {

    private final PortalConfig config;
    private final Sessions sessions;
    private final OidcService oidc;
    private final HttpClient http;

    public AgentProxyController(PortalConfig config, Sessions sessions, OidcService oidc,
                                HttpClient http) {
        this.config = config;
        this.sessions = sessions;
        this.oidc = oidc;
        this.http = http;
    }

    @GetMapping("/api/agent/pending")
    public ResponseEntity<String> pending(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/pending", null, "[]");
    }

    @PostMapping("/api/agent/pending/{family}/decision")
    public ResponseEntity<String> decision(@PathVariable String family,
                                           @RequestBody String body,
                                           HttpServletRequest request) {
        return proxy(request, "POST", "/owner/pending/" + family + "/decision", body,
                "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/resources")
    public ResponseEntity<String> resources(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/resources", null, "[]");
    }

    @GetMapping("/api/agent/resource-servers")
    public ResponseEntity<String> resourceServers(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/resource-servers", null, "[]");
    }

    @PostMapping("/api/agent/resource-servers/{clientId}/revoke")
    public ResponseEntity<String> revokeResourceServer(@PathVariable String clientId,
                                                       HttpServletRequest request) {
        return proxy(request, "POST", "/owner/resource-servers/" + clientId + "/revoke", null,
                "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/policies")
    public ResponseEntity<String> policies(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/policies", null, "{}");
    }

    @PutMapping("/api/agent/policies/{tierId}")
    public ResponseEntity<String> updatePolicy(@PathVariable String tierId,
                                               @RequestBody String body,
                                               HttpServletRequest request) {
        return proxy(request, "PUT", "/owner/policies/" + tierId, body,
                "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/connections")
    public ResponseEntity<String> connections(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/connections", null, "[]");
    }

    @PostMapping("/api/agent/connections/{jkt}/revoke")
    public ResponseEntity<String> revokeConnection(@PathVariable String jkt,
                                                   HttpServletRequest request) {
        return proxy(request, "POST", "/owner/connections/" + jkt + "/revoke", null,
                "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/ledger")
    public ResponseEntity<String> ledger(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/ledger", null, "[]");
    }

    /** Raw byte-level SSE pass-through of uma-as's owner event stream. */
    @GetMapping("/api/agent/events")
    public void events(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        if (sessions.currentUser(request) == null) {
            response.setStatus(401);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\": \"auth\"}");
            return;
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(config.umaAsInternal + "/owner/events"))
                .GET();
        String token = oidc.ownerToken(sessions.sid(request));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        response.setStatus(200);
        response.setContentType("text/event-stream");
        response.setHeader("Cache-Control", "no-cache");
        response.flushBuffer();
        try {
            HttpResponse<InputStream> upstream =
                    http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = upstream.body(); OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    if (read > 0) {
                        out.write(buffer, 0, read);
                        out.flush();
                    }
                }
            }
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            // Client or upstream disconnected: the browser will reconnect.
        }
    }

    private ResponseEntity<String> proxy(HttpServletRequest request, String method, String path,
                                         String body, String unauthorizedBody) {
        if (sessions.currentUser(request) == null) {
            return ResponseEntity.status(401)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(unauthorizedBody);
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(config.umaAsInternal + path));
        String token = oidc.ownerToken(sessions.sid(request));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            builder.header("content-type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        try {
            HttpResponse<String> upstream =
                    http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            return ResponseEntity.status(upstream.statusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(upstream.body());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return ResponseEntity.status(502)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"upstream unreachable\"}");
        }
    }
}
