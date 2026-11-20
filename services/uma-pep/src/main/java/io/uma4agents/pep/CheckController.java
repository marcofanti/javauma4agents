package io.uma4agents.pep;

import io.uma4agents.pep.core.AuthzFacts;
import io.uma4agents.pep.core.Decision;
import io.uma4agents.pep.core.McpRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * agentgateway's ext_authz callback ({@code /check<original path>}): HTTP facts in, HTTP
 * verdict out. Every decision is made by the shared enforcement core; this host reads the
 * request, bounds the body, resolves the route, and renders the Decision as a status line
 * and, on a challenge, the UMA header. It never proxies traffic.
 */
@RestController
public class CheckController {

    private final PepConfig config;
    private final OrganizationRoutes organizations;
    private final JointRoutes joints;

    public CheckController(PepConfig config, OrganizationRoutes organizations, JointRoutes joints) {
        this.config = config;
        this.organizations = organizations;
        this.joints = joints;
    }

    @RequestMapping(value = {"/check", "/check/**"},
            method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.HEAD,
                    RequestMethod.DELETE})
    public ResponseEntity<Object> check(HttpServletRequest request) throws IOException {
        String originalPath = request.getRequestURI().substring("/check".length());
        if (originalPath.isEmpty()) {
            originalPath = "/";
        }
        byte[] body = boundedBody(request);
        if (body == null) {
            return deny(413, Map.of("error", "invalid_request",
                    "error_description", "request body too large"));
        }
        return decide(request, originalPath, body);
    }

    ResponseEntity<Object> decide(HttpServletRequest request, String originalPath,
                                          byte[] body) {
        if ("true".equals(request.getHeader("x-envoy-auth-partial-body"))) {
            config.log.event("access.denied", null, "reason", "truncated-body",
                    "path", originalPath);
            return deny(413, Map.of("error", "request_body_too_large",
                    "error_description", "the call exceeded the gateway's authorization body "
                            + "limit, so the tool being invoked could not be determined"));
        }
        McpRequest mcp = body.length > 0 ? McpRequest.parse(body)
                : new McpRequest(null, null, null, null);
        Decision refused = config.ownerRoute(config.owner).enforcer()
                .originRefused(request.getHeader("origin"));
        if (refused != null) {
            return deny(refused.status(), Map.of("error", refused.error()));
        }
        if (!"POST".equals(request.getMethod())
                || (mcp.method() == null && mcp.tool() == null && body.length == 0)) {
            return ResponseEntity.ok().build();
        }
        String account = joints.accountAt(originalPath);
        if (account != null) {
            try {
                JointRoutes.Joint joint = joints.route(account);
                if (joint == null) {
                    return deny(404, Map.of("error", "no_mandate"));
                }
                return render(joints.authorize(joint, facts(request, originalPath, body, mcp)),
                        originalPath, joint.enforcer());
            } catch (JointRoutes.Unavailable unavailable) {
                return deny(503, Map.of("error", "temporarily_unavailable",
                        "error_description", unavailable.getMessage()));
            }
        }
        String sharedOwner = organizations.ownerAt(originalPath);
        if (sharedOwner != null) {
            try {
                OrganizationRoutes.Shared shared = organizations.shared(sharedOwner, false);
                if (shared == null) {
                    return deny(403, organizations.notShared());
                }
                Decision decision = organizations.authorize(shared,
                        facts(request, originalPath, body, mcp));
                return render(decision, originalPath, shared.normal());
            } catch (OrganizationRoutes.Unavailable unavailable) {
                return deny(503, Map.of("error", "temporarily_unavailable",
                        "error_description", unavailable.getMessage()));
            }
        }
        PepConfig.OwnerRoute route = routeFor(originalPath);
        if (route == null) {
            config.log.event("access.denied", null, "reason", "unknown-route",
                    "path", originalPath);
            return deny(404, Map.of("error", "invalid_resource_id", "error_description",
                    "this gateway serves no owner, shared resource or account at that path"));
        }
        Decision d = organizations.authorizeOwn(route, facts(request, originalPath, body, mcp));
        return render(d, originalPath, route.enforcer());
    }

    private ResponseEntity<Object> render(Decision d, String originalPath,
                                          io.uma4agents.pep.core.Enforcer enforcer) {
        if (d.outcome() == Decision.Outcome.ALLOW) {
            return ResponseEntity.ok()
                    .header("x-uma-contract", d.contract() == null ? "" : d.contract()).build();
        }
        if (d.outcome() == Decision.Outcome.CHALLENGE) {
            Decision routed = d.withResourceMetadata(config.publicBase
                    + "/.well-known/oauth-protected-resource" + originalPath);
            return ResponseEntity.status(routed.status())
                    .header(HttpHeaders.WWW_AUTHENTICATE,
                            enforcer.wwwAuthenticate(routed))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("error", routed.error()));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("error", d.error());
        if (d.description() != null && !d.description().isEmpty()) {
            out.put("error_description", d.description());
        }
        return deny(d.status(), out);
    }

    /** The owner served at a path, read by leading segments as the gateway routes. */
    private PepConfig.OwnerRoute routeFor(String path) {
        List<String> segments = java.util.Arrays.stream(path.split("\\?", 2)[0].split("/"))
                .filter(s -> !s.isEmpty()).toList();
        if (segments.isEmpty() || !"mcp".equals(segments.get(0))) {
            return null;
        }
        return config.ownerRoute(segments.size() == 1 ? config.owner : segments.get(1));
    }

    private AuthzFacts facts(HttpServletRequest request, String path, byte[] body,
                             McpRequest mcp) {
        return AuthzFacts.builder().mcp(mcp).httpMethod(request.getMethod()).path(path)
                .authorization(request.getHeader("authorization"))
                .signature(request.getHeader("signature"))
                .signatureInput(request.getHeader("signature-input"))
                .origin(request.getHeader("origin"))
                .headerMcpMethod(request.getHeader("mcp-method"))
                .headerMcpName(request.getHeader("mcp-name"))
                .protocolVersion(request.getHeader("mcp-protocol-version"))
                .signatureAgent(request.getHeader("signature-agent"))
                .traceparent(request.getHeader("traceparent"))
                .body(body).contentDigest(request.getHeader("content-digest")).build();
    }

    /** The body, read once and bounded before anything parses it; null when too large. */
    byte[] boundedBody(HttpServletRequest request) throws IOException {
        long declared = request.getContentLengthLong();
        if (declared > config.maxBodyBytes) {
            return null;
        }
        try (InputStream in = request.getInputStream()) {
            byte[] body = in.readNBytes(config.maxBodyBytes + 1);
            return body.length > config.maxBodyBytes ? null : body;
        }
    }

    private static ResponseEntity<Object> deny(int status, Map<String, ?> body) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }
}
