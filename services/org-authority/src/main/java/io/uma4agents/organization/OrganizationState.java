package io.uma4agents.organization;

import static io.uma4agents.organization.OrganizationCharter.object;
import static io.uma4agents.organization.OrganizationCharter.strings;
import static io.uma4agents.organization.OrganizationCharter.text;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EventLog;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

@Component
final class OrganizationState {
    final OrgConfig config;
    final OrganizationPolicyEngine engine;
    final ConcurrentMap<String, Member> members = new ConcurrentHashMap<>();
    final ConcurrentMap<String, Map<String, Object>> invites = new ConcurrentHashMap<>();
    volatile String joinCode;
    private final ObjectMapper json;
    private final EventLog log = new EventLog("org-authority");
    /** Serializes switching OPA's custom module with changing the current charter. */
    final Object policyLock = new Object();
    private final List<Version> versions = new ArrayList<>();
    private final ArrayDeque<Map<String, Object>> activity = new ArrayDeque<>();
    private volatile Version current;

    OrganizationState(OrgConfig config, OrganizationPolicyEngine engine, ObjectMapper json) {
        this.config = config;
        this.engine = engine;
        this.json = json;
        joinCode = config.joinCode;
    }

    record Version(int number, Map<String, Object> charter, String publishedAt, String by) {
        Map<String, Object> wire() {
            return Map.of("version", number, "charter", charter,
                    "published_at", publishedAt, "by", by);
        }
    }

    static final class Member {
        final String owner;
        final String asUri;
        final String joined;
        final String tokenJti;
        volatile String role;
        volatile int charterVersion;
        volatile String lastSeen;
        volatile Map<String, Object> clearance = Map.of();
        volatile Map<String, Object> compliance;

        Member(String owner, String asUri, String role, String tokenJti, int charterVersion) {
            this.owner = owner;
            this.asUri = asUri;
            this.role = role;
            this.tokenJti = tokenJti;
            this.charterVersion = charterVersion;
            joined = EventLog.utcNow();
        }
    }

    @PostConstruct
    void start() {
        try (InputStream in = getClass().getResourceAsStream("/default-charter.json")) {
            if (in == null) {
                throw new IllegalStateException("default charter is missing");
            }
            engine.loadShipped();
            publish(json.readValue(in, new TypeReference<>() {}), "default", null);
        } catch (IOException invalid) {
            throw new IllegalStateException("default charter could not be read", invalid);
        }
    }

    Version current() {
        return current;
    }

    List<Version> versions() {
        synchronized (policyLock) {
            return List.copyOf(versions);
        }
    }

    Version publish(Map<String, Object> draft, String by, Integer base) {
        synchronized (policyLock) {
            if (base != null && base != current.number()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "the charter is now v"
                        + current.number() + ", not the v" + base
                        + " this change was made against; reload and make it again");
            }
            Map<String, Object> checked = OrganizationCharter.validate(draft);
            var roles = object(checked.get("roles"));
            List<String> orphaned = members.values().stream()
                    .map(m -> m.role).filter(role -> role != null && !roles.containsKey(role))
                    .distinct().sorted().toList();
            if (!orphaned.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        String.join(", ", orphaned) + " still has members; move them to "
                                + "another group before removing it");
            }
            engine.loadCustom(text(checked.get("rego")));
            Version version = new Version(versions.size() + 1, checked, EventLog.utcNow(), by);
            versions.add(version);
            current = version;
            members.values().forEach(member -> member.compliance = null);
            note("charter.published", Map.of("version", version.number(), "by", by,
                    "rego", !text(checked.get("rego")).isEmpty()));
            return version;
        }
    }

    Map<String, Object> evaluate(Member member, Map<String, Object> facts) {
        synchronized (policyLock) {
            return engine.evaluate(member.owner, current.charter(), role(member), facts, () -> {
                engine.loadShipped();
                engine.loadCustom(text(current.charter().get("rego")));
            });
        }
    }

    Map<String, Object> role(Member member) {
        Map<String, Object> roles = object(current.charter().get("roles"));
        String id = member == null ? defaultRole() : member.role;
        Map<String, Object> definition = id == null || id.isEmpty() ? Map.of()
                : object(roles.get(id));
        Map<String, Object> role = new LinkedHashMap<>();
        role.put("id", id);
        role.put("name", definition.get("name"));
        role.put("delegation", definition.getOrDefault("delegation", "none"));
        role.put("grants", strings(definition.get("grants"), "grants"));
        return role;
    }

    String defaultRole() {
        return current.charter().get("default_role") instanceof String name ? name : null;
    }

    String sign(String type, Map<String, Object> claims) {
        return CompactJws.sign(Map.of("typ", type, "kid", config.kid), claims,
                config.signing.getPrivate());
    }

    Map<String, Object> claims(String subject) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", config.issuer);
        claims.put("sub", subject);
        claims.put("org", config.id);
        claims.put("iat", Instant.now().getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString().replace("-", ""));
        return claims;
    }

    synchronized void note(String kind, Map<String, Object> fields) {
        Map<String, Object> entry = new LinkedHashMap<>(fields);
        entry.put("ts", EventLog.utcNow());
        entry.put("kind", kind);
        activity.addLast(entry);
        if (activity.size() > 500) {
            activity.removeFirst();
        }
        Object[] details = fields.entrySet().stream()
                .flatMap(field -> java.util.stream.Stream.of(field.getKey(), field.getValue()))
                .toArray();
        log.event(kind, null, details);
    }

    synchronized List<Map<String, Object>> activity() {
        return new ArrayList<>(activity);
    }
}
