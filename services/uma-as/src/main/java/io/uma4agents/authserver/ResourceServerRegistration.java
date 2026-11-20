package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.EventLog;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

@RestController
final class ResourceServerRegistration {
    private final AsConfig config;
    private final AsState state;
    private final OwnerStore store;
    private final ResourceServerSignatures signatures;
    private final ObjectMapper mapper;

    ResourceServerRegistration(AsConfig config, AsState state, OwnerStore store,
                               ResourceServerSignatures signatures, ObjectMapper mapper) {
        this.config = config;
        this.state = state;
        this.store = store;
        this.signatures = signatures;
        this.mapper = mapper;
    }

    @PostMapping(value = "/rs/register", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<Map<String, Object>> register(HttpServletRequest request) throws IOException {
        byte[] body = SignedRequestBody.read(request);
        if (body == null) {
            return ResponseEntity.status(413).body(Map.of("error", "invalid_request"));
        }
        Map<String, Object> spec;
        try {
            spec = body.length == 0 ? Map.of() : mapper.readValue(body, new TypeReference<>() {});
        } catch (JacksonException invalid) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request"));
        }
        if (spec == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request"));
        }
        String owner = spec.get("owner") instanceof String s && !s.isBlank()
                ? s.strip() : config.ownerUsername;
        if (!owner.equals(config.ownerUsername)) {
            return ResponseEntity.status(403).body(Map.of("error", "invalid_request",
                    "error_description", "this authorization server serves a different owner"));
        }
        String resource = spec.get("resource_uri") instanceof String s ? s.strip() : "";
        String refusal = signatures.verify(request, body, resource);
        if (refusal != null) {
            state.log.event("resource_server.registration_refused", null,
                    "owner", owner, "resource_uri", resource, "reason", refusal);
            return ResponseEntity.status(401).body(Map.of("error", "invalid_client",
                    "error_description", "register by signing with a key published at the origin "
                            + "of the resource you claim to serve: " + refusal));
        }
        String clientId = ResourceServerSignatures.origin(resource);
        String name = spec.get("name") instanceof String s && !s.isEmpty() ? s : clientId;
        int end = name.offsetByCodePoints(0, Math.min(120, name.codePointCount(0, name.length())));

        Map<String, Object> pending = new LinkedHashMap<>();
        pending.put("secret", "");
        pending.put("name", name.substring(0, end));
        pending.put("status", "pending");
        pending.put("consented", null);
        pending.put("last_pat_issued", null);
        pending.put("resource_uri", resource);
        pending.put("registered", EventLog.utcNow());
        pending.put("auth", "origin_signature");
        boolean changed = store.pendResourceServer(clientId, pending);
        if (changed) {
            state.log.event("resource_server.registered", null,
                    "owner", owner, "client_id", clientId, "resource_uri", resource,
                    "status", "pending");
            store.notify(Map.of("type", "resource_server_pending", "client_id", clientId,
                    "resource_uri", resource));
        } else {
            Map<String, Object> existing = store.resourceServer(clientId);
            if (existing != null && "active".equals(existing.get("status"))) {
                return ResponseEntity.ok(Map.of("client_id", clientId, "status", "active"));
            }
        }
        return ResponseEntity.accepted().body(Map.of("client_id", clientId, "status", "pending",
                "error", "authorization_pending", "error_description", "the owner has been asked"));
    }
}
