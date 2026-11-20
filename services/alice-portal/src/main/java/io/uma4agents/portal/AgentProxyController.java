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
import org.springframework.web.bind.annotation.DeleteMapping;
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
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
        name = "uma.portal.mode", havingValue = "owner", matchIfMissing = true)
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

    @GetMapping("/api/agent/organization")
    public ResponseEntity<String> organization(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/organization", null, "{}");
    }

    @PostMapping("/api/agent/organization")
    public ResponseEntity<String> joinOrganization(@RequestBody String body,
                                                    HttpServletRequest request) {
        return proxy(request, "POST", "/owner/organization", body, "{\"error\": \"auth\"}");
    }

    @PostMapping("/api/agent/organization/preview")
    public ResponseEntity<String> previewOrganization(@RequestBody String body,
                                                       HttpServletRequest request) {
        return proxy(request, "POST", "/owner/organization/preview", body,
                "{\"error\": \"auth\"}");
    }

    @PostMapping("/api/agent/organization/decline")
    public ResponseEntity<String> declineOrganization(@RequestBody String body,
                                                       HttpServletRequest request) {
        return proxy(request, "POST", "/owner/organization/decline", body,
                "{\"error\": \"auth\"}");
    }

    @DeleteMapping("/api/agent/organization")
    public ResponseEntity<String> leaveOrganization(HttpServletRequest request) {
        return proxy(request, "DELETE", "/owner/organization", null, "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/joint")
    public ResponseEntity<String> joint(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/joint", null, "[]");
    }

    @PostMapping("/api/agent/joint")
    public ResponseEntity<String> joinJoint(@RequestBody String body, HttpServletRequest request) {
        return proxy(request, "POST", "/owner/joint", body, "{\"error\": \"auth\"}");
    }

    @PostMapping("/api/agent/joint/preview")
    public ResponseEntity<String> previewJoint(@RequestBody String body, HttpServletRequest request) {
        return proxy(request, "POST", "/owner/joint/preview", body, "{\"error\": \"auth\"}");
    }

    @DeleteMapping("/api/agent/joint/{account:[a-zA-Z0-9._-]+}")
    public ResponseEntity<String> leaveJoint(@PathVariable String account, HttpServletRequest request) {
        return proxy(request, "DELETE", "/owner/joint/" + account, null, "{\"error\": \"auth\"}");
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

    @PostMapping("/api/agent/resource-servers/decision")
    public ResponseEntity<String> decideResourceServer(@RequestBody String body,
                                                        HttpServletRequest request) {
        return proxy(request, "POST", "/owner/resource-servers/decision", body,
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

    @PostMapping("/api/agent/policies")
    public ResponseEntity<String> createPolicy(@RequestBody String body,
                                               HttpServletRequest request) {
        return proxy(request, "POST", "/owner/policies", body, "{\"error\": \"auth\"}");
    }

    @DeleteMapping("/api/agent/policies/{tierId}")
    public ResponseEntity<String> deletePolicy(@PathVariable String tierId,
                                               HttpServletRequest request) {
        return proxy(request, "DELETE", "/owner/policies/" + tierId, null,
                "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/policy-vocabulary")
    public ResponseEntity<String> policyVocabulary(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/policy-vocabulary", null, "[]");
    }

    @GetMapping("/api/agent/operators")
    public ResponseEntity<String> operators(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/operators", null, "[]");
    }

    /**
     * Blocking and unblocking an operator. Claiming one as hers is not offered here, as at
     * the pin: it stays an owner-API action.
     */
    @PostMapping("/api/agent/operators/{action}")
    public ResponseEntity<String> operatorAction(@PathVariable String action,
                                                 @RequestBody String body,
                                                 HttpServletRequest request) {
        if (!"block".equals(action) && !"unblock".equals(action)) {
            if (sessions.currentUser(request) == null) {
                return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\": \"auth\"}");
            }
            return ResponseEntity.status(404).contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\": \"unknown action\"}");
        }
        return proxy(request, "POST", "/owner/operators/" + action, body,
                "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/connections")
    public ResponseEntity<String> connections(HttpServletRequest request) {
        return proxy(request, "GET", "/owner/connections", null, "[]");
    }

    /** Revokes a connection; the body names it as {"handle": …}, as the pinned portal does. */
    @PostMapping("/api/agent/connections/revoke")
    public ResponseEntity<String> revokeConnection(@RequestBody String body,
                                                   HttpServletRequest request) {
        return proxy(request, "POST", "/owner/connections/revoke", body,
                "{\"error\": \"auth\"}");
    }

    @GetMapping("/api/agent/ledger")
    public ResponseEntity<String> ledger(HttpServletRequest request) {
        // `?handle=` narrows the record to one agent's trajectory, forwarded rather than
        // filtered here: the portal holds no authority and no state.
        String handle = request.getParameter("handle");
        String path = handle == null || handle.isEmpty() ? "/owner/ledger"
                : "/owner/ledger?handle=" + java.net.URLEncoder.encode(handle,
                        java.nio.charset.StandardCharsets.UTF_8);
        return proxy(request, "GET", path, null, "[]");
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
