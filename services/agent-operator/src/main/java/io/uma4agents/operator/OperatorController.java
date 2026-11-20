package io.uma4agents.operator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * The operator's two identity documents, ported from the pinned
 * {@code clients/agent-operator/server.py}: a Client ID Metadata Document at
 * {@code /agent.json} (display metadata an owner's approval dialog resolves) and a Web Bot
 * Auth key directory. Keys come from {@code AGENT_OPERATOR_KEYS_FILE} when set, which makes
 * the directory read-only; otherwise the lab registers per-run keys through
 * {@code POST /register}, authenticated by {@code AGENT_OPERATOR_REGISTER_TOKEN}.
 */
@RestController
public class OperatorController {

    static final MediaType DIRECTORY_TYPE =
            MediaType.parseMediaType("application/http-message-signatures-directory+json");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String origin = env("AGENT_OPERATOR_ORIGIN", "https://agent.uma.lab");
    private final String name = env("AGENT_OPERATOR_NAME", "Sterling & Vance — Advisory Agent");
    private final String keysFile = env("AGENT_OPERATOR_KEYS_FILE", null);
    private final String registerToken = env("AGENT_OPERATOR_REGISTER_TOKEN", null);
    private final Map<String, Map<String, Object>> keys = new ConcurrentHashMap<>();

    public OperatorController() {
        loadPublishedKeys();
    }

    /** A missing or malformed file degrades discovery; it is never an authorization input. */
    private void loadPublishedKeys() {
        if (keysFile == null) {
            return;
        }
        try {
            Map<String, List<Map<String, Object>>> published = MAPPER.readValue(
                    Files.readString(Path.of(keysFile)), new TypeReference<>() {});
            for (Map<String, Object> jwk : published.getOrDefault("keys", List.of())) {
                if (jwk.get("kid") instanceof String kid) {
                    keys.put(kid, jwk);
                }
            }
            log("agent_keys.published_loaded", Map.of("path", keysFile, "keys", keys.size()));
        } catch (IOException | JacksonException e) {
            log("agent_keys.unreadable", Map.of("path", keysFile,
                    "error", String.valueOf(e.getMessage())));
        }
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok", "keys", keys.size());
    }

    /** The CIMD document; {@code client_id} equals the URL it is served from. */
    @GetMapping("/agent.json")
    public Map<String, Object> clientIdMetadata() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("client_id", origin + "/agent.json");
        doc.put("client_name", name);
        doc.put("client_uri", origin);
        doc.put("policy_uri", origin + "/privacy");
        doc.put("tos_uri", origin + "/terms");
        doc.put("contacts", List.of("advisory-ops@sterling-vance.example"));
        doc.put("software_id", "uma4agents-agent-shim");
        return doc;
    }

    @GetMapping("/.well-known/http-message-signatures-directory")
    public ResponseEntity<Map<String, Object>> signaturesDirectory() {
        return ResponseEntity.ok().contentType(DIRECTORY_TYPE)
                .body(Map.of("keys", new ArrayList<>(keys.values())));
    }

    /** Lab-only key publication; refused once the directory is seeded from a file. */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestHeader(value = "authorization", required = false) String authorization,
            @RequestBody(required = false) Map<String, Object> body) {
        if (keysFile != null) {
            return ResponseEntity.status(409).body(Map.of("registered", false,
                    "error", "this operator publishes keys it already holds",
                    "detail", "AGENT_OPERATOR_KEYS_FILE is set, so the directory is read-only "
                            + "and identical across replicas. Provision the key into that "
                            + "document instead."));
        }
        if (registerToken != null && !constantTimeEquals(authorization,
                "Bearer " + registerToken)) {
            return ResponseEntity.status(401).body(Map.of("registered", false,
                    "error", "this directory publishes keys only for callers holding its "
                            + "registration credential"));
        }
        Map<?, ?> jwk = body != null && body.get("jwk") instanceof Map<?, ?> j ? j : Map.of();
        Object keyid = body != null && body.get("keyid") != null ? body.get("keyid")
                : jwk.get("kid");
        if (!(keyid instanceof String kid) || kid.isEmpty() || jwk.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("registered", false,
                    "error", "keyid and jwk required"));
        }
        Map<String, Object> stored = new LinkedHashMap<>();
        jwk.forEach((k, v) -> stored.put(String.valueOf(k), v));
        stored.put("kid", kid);
        keys.put(kid, stored);
        log("agent_key.published", Map.of("keyid", kid));
        return ResponseEntity.ok(Map.of("registered", true, "keyid", kid, "keys", keys.size()));
    }

    private static boolean constantTimeEquals(String given, String expected) {
        byte[] a = (given == null ? "" : given).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, expected.getBytes(StandardCharsets.UTF_8));
    }

    private static void log(String event, Map<String, Object> details) {
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("event", event);
        line.putAll(details);
        System.out.println(MAPPER.writeValueAsString(line));
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isEmpty() ? fallback : value;
    }
}
