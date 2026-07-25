package io.uma4agents.pep;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.S256;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * The ext_authz verdict endpoint ({@code /check<original path>}) plus RFC 9728
 * Protected Resource Metadata and health. Never proxies traffic — returns
 * 200/401/403 verdicts to agentgateway.
 */
@RestController
public class CheckController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final PepConfig config;
    private final AsClient as;

    public CheckController(PepConfig config, AsClient as) {
        this.config = config;
        this.as = as;
    }

    @RequestMapping(value = {"/check", "/check/**"},
            method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.HEAD,
                    RequestMethod.DELETE})
    public ResponseEntity<Object> check(HttpServletRequest request) throws IOException {
        String originalPath = request.getRequestURI().substring("/check".length());
        if (originalPath.isEmpty()) {
            originalPath = "/";
        }
        byte[] body = request.getInputStream().readAllBytes();

        String method = null;
        String tool = null;
        Map<String, Object> args = null;
        if (body.length > 0) {
            Object[] parsed = parseMcp(body);
            method = (String) parsed[0];
            tool = (String) parsed[1];
            @SuppressWarnings("unchecked")
            Map<String, Object> parsedArgs = (Map<String, Object>) parsed[2];
            args = parsedArgs;
        }

        // Session bootstrap and discovery are open; invocation is protected.
        if (!"POST".equals(request.getMethod()) || ToolCatalog.OPEN_METHODS.contains(method)
                || (method == null && tool == null && body.length == 0)) {
            return ResponseEntity.ok().build();
        }
        if (!"tools/call".equals(method)) {
            return ResponseEntity.ok().build();
        }
        if (tool == null || !ToolCatalog.TOOLS.containsKey(tool)) {
            config.log.event("access.denied", null, "reason", "unknown-tool", "tool", tool);
            return deny(403, Map.of("error", "unknown_tool"));
        }

        String authz = request.getHeader("authorization");
        if (authz == null || authz.isEmpty()) {
            return challenge(tool, originalPath);
        }

        if (!authz.startsWith("PoP ")) {
            return deny(401, Map.of("error", "invalid_token",
                    "error_description", "RPTs are PoP tokens here, not Bearer"));
        }
        String rpt = authz.substring(4);

        boolean singleUse = ToolCatalog.SINGLE_USE_TOOLS.contains(tool);
        Map<String, Object> info;
        try {
            info = as.introspect(rpt, singleUse);
        } catch (RuntimeException e) {
            return deny(503, Map.of("error", "as_unreachable"));
        }
        if (!Boolean.TRUE.equals(info.get("active"))) {
            config.log.event("access.denied", null, "reason", "inactive-rpt", "tool", tool);
            return challenge(tool, originalPath);
        }

        ToolCatalog.Surface surface = ToolCatalog.TOOLS.get(tool);
        Set<String> granted = new TreeSet<>();
        if (info.get("permissions") instanceof List<?> permissions) {
            for (Object p : permissions) {
                if (p instanceof Map<?, ?> permission) {
                    granted.add(String.valueOf(permission.get("resource_id")));
                }
            }
        }
        if (!granted.contains(surface.resourceId())) {
            config.log.event("access.denied", null, "reason", "permission-scope",
                    "tool", tool, "granted", List.copyOf(granted));
            return challenge(tool, originalPath);
        }

        // Proof of possession: the request signature must verify against the
        // RPT's cnf key, over components that include the Authorization header.
        try {
            Object cnf = info.get("cnf");
            if (!(cnf instanceof Map<?, ?> cnfMap) || !(cnfMap.get("jwk") instanceof Map)) {
                throw new HttpSignature.VerifyException("no cnf key");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) ((Map<?, ?>) cnf).get("jwk");
            HttpSignature.verify(
                    request.getMethod(),
                    config.expectedAuthority,
                    originalPath,
                    authz,
                    header(request, "signature-input"),
                    header(request, "signature"),
                    Jwks.toPublicKey(jwk));
        } catch (HttpSignature.VerifyException | IllegalArgumentException e) {
            config.log.event("access.denied", null, "reason", "pop: " + e.getMessage(),
                    "tool", tool, "method", request.getMethod(),
                    "authority", header(request, "host"), "path", originalPath,
                    "signature_input", header(request, "signature-input"));
            return deny(401, Map.of("error", "invalid_token",
                    "error_description", "proof-of-possession failed: " + e.getMessage()));
        }

        // Single-use operation binding: this trade, not trading authority.
        if (singleUse) {
            Map<String, Object> op = info.get("operation") instanceof Map<?, ?> operation
                    ? castMap(operation) : Map.of();
            Object expected = op.get("params_s256");
            String actual = S256.of(PyJson.dumpsSorted(args == null ? Map.of() : args));
            if (!tool.equals(op.get("tool")) || !actual.equals(expected)) {
                config.log.event("access.denied", null, "reason", "operation-binding",
                        "tool", tool, "expected", expected, "actual", actual);
                return deny(403, Map.of("error", "operation_mismatch",
                        "error_description", "RPT authorizes a different operation"));
            }
        }

        String family = info.get("family") instanceof String f ? f : "?";
        String contract = info.get("contract") instanceof String c ? c : null;
        config.log.event("access.allowed", family, "tool", tool, "contract", contract,
                "single_use", info.getOrDefault("single_use", false));
        as.reportAccess(family, tool, PyJson.dumpsSorted(args == null ? Map.of() : args));
        return ResponseEntity.ok()
                .header("x-uma-contract", contract == null ? "" : contract)
                .build();
    }

    private ResponseEntity<Object> challenge(String tool, String originalPath) {
        ToolCatalog.Surface surface = ToolCatalog.TOOLS.get(tool);
        String ticket = as.mintTicket(surface.resourceId(), surface.scopes());
        if (ticket == null) {
            return deny(503, Map.of("error", "as_unreachable"));
        }
        config.log.event("challenge.issued", null, "tool", tool,
                "resource_id", surface.resourceId(), "path", originalPath);
        return ResponseEntity.status(401)
                .header("WWW-Authenticate", "UMA realm=\"" + config.realm
                        + "\", as_uri=\"" + config.asPublic + "\", ticket=\"" + ticket + "\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("error", "uma_challenge"));
    }

    private static ResponseEntity<Object> deny(int status, Map<String, Object> body) {
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(body);
    }

    /** Returns (jsonrpc_method, tool_name, tool_args) from an MCP POST body. */
    private static Object[] parseMcp(byte[] body) {
        Map<String, Object> msg;
        try {
            msg = MAPPER.readValue(body, new TypeReference<>() {});
        } catch (IOException | IllegalArgumentException e) {
            return new Object[] {null, null, null};
        }
        Object method = msg.get("method");
        if ("tools/call".equals(method)) {
            Map<String, Object> params = msg.get("params") instanceof Map<?, ?> p
                    ? castMap(p) : Map.of();
            Object args = params.get("arguments");
            return new Object[] {method, params.get("name"),
                    args instanceof Map<?, ?> argsMap ? castMap(argsMap) : new LinkedHashMap<>()};
        }
        return new Object[] {method, null, null};
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }

    private static String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value;
    }

    /** RFC 9728 Protected Resource Metadata (with the tool_surfaces extension). */
    @GetMapping({"/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp"})
    public Map<String, Object> protectedResourceMetadata() {
        Set<String> scopes = new TreeSet<>();
        ToolCatalog.TOOLS.values().forEach(s -> scopes.addAll(s.scopes()));
        List<Map<String, Object>> surfaces = ToolCatalog.TOOLS.entrySet().stream()
                .map(e -> Map.<String, Object>of(
                        "tool", e.getKey(),
                        "resource_id", e.getValue().resourceId(),
                        "resource_scopes", e.getValue().scopes()))
                .toList();
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", "https://" + config.expectedAuthority + "/mcp");
        doc.put("authorization_servers", List.of(config.asPublic));
        doc.put("scopes_supported", List.copyOf(scopes));
        doc.put("bearer_methods_supported", List.of("header"));
        doc.put("resource_signing_alg_values_supported", List.of("EdDSA"));
        doc.put("tool_surfaces", surfaces);
        return doc;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }
}
