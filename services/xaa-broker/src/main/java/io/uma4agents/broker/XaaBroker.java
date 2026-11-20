package io.uma4agents.broker;

import static io.uma4agents.common.IdentityTokens.EXCHANGE;
import static io.uma4agents.common.IdentityTokens.ID_JAG;
import static io.uma4agents.common.IdentityTokens.ID_TOKEN;
import static io.uma4agents.common.IdentityTokens.JAG_TYPE;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.IdentityProviders;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJwtClaims;
import io.uma4agents.common.SslContexts;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** The enterprise's application-to-resource connection directory and RFC 8693 exchange. */
@RestController
final class XaaBroker {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final String issuer = env("XAA_ISSUER", "https://northwind-xaa.uma.lab");
    private final String idp = env("XAA_IDP_ISSUER", "https://northwind-idp.uma.lab/realms/employees");
    private final String adminClient = env("XAA_IDP_ADMIN_CLIENT", "northwind-idp-admin");
    private final Set<String> admins = Set.copyOf(Arrays.asList(env("XAA_ADMINS", "dana").split(",")));
    private final long ttl = Long.parseLong(env("XAA_JAG_TTL_S", "300"));
    private final Map<String, String> clients = JSON.readValue(env("XAA_CLIENTS", "{}"),
            new TypeReference<Map<String, String>>() {});
    private final Map<String, Map<String, Object>> connections = new LinkedHashMap<>();
    private final IdentityProviders providers;
    private final EventLog log = new EventLog("xaa-broker");
    private final java.security.KeyPair key = EdDsa.loadOrCreate(Path.of(
            env("XAA_KEY_PATH", "/keys/xaa-ed25519.pem")));
    private final Map<String, Object> publicKey = Jwks.okpPublicJwk(key.getPublic());
    private final String kid = Jwks.thumbprint(publicKey);

    XaaBroker() {
        if (ttl <= 0) {
            throw new IllegalArgumentException("XAA_JAG_TTL_S must be positive");
        }
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        String ca = env("UMA4A_CA_BUNDLE", env("UMA4A_CACERT", ""));
        if (!ca.isEmpty()) {
            http.sslContext(SslContexts.fromPem(Path.of(ca)));
        }
        providers = new IdentityProviders(http.build());
        var configured = JSON.readValue(env("XAA_SEED_CONNECTIONS", "[]"),
                new TypeReference<List<Map<String, Object>>>() {});
        for (var raw : configured) {
            var conn = parseConnection(raw);
            connections.put(text(conn.get("id")), conn);
            log.event("connection.seeded", null, "id", conn.get("id"),
                    "client", conn.get("requesting_client"), "audience", conn.get("audience"),
                    "resource", conn.get("resource"));
        }
        log.event("ready", null, "issuer", issuer, "idp", idp, "kid", kid,
                "clients", clients.keySet().stream().sorted().toList(), "connections", connections.size());
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<Map<String, Object>> exchange(HttpServletRequest request,
                                                  @RequestParam Map<String, String> form) {
        if (!EXCHANGE.equals(form.get("grant_type"))) {
            return error(400, "unsupported_grant_type", null);
        }
        if (!ID_JAG.equals(form.get("requested_token_type"))) {
            return error(400, "invalid_request", "requested_token_type must be " + ID_JAG);
        }
        String client;
        try {
            client = requireClient(request, form);
        } catch (IllegalArgumentException refused) {
            log.event("exchange.refused", null, "reason", "client-auth");
            return error(401, "invalid_client", null);
        }
        if (!ID_TOKEN.equals(form.get("subject_token_type"))) {
            return error(400, "invalid_request", "subject_token_type must be " + ID_TOKEN);
        }
        String audience = form.getOrDefault("audience", "");
        String resource = form.getOrDefault("resource", "");
        if (audience.isEmpty() || resource.isEmpty()) {
            return error(400, "invalid_target", "audience and resource are both required");
        }
        Map<String, Object> subject;
        try {
            subject = realmClaims(form.getOrDefault("subject_token", ""));
        } catch (IllegalArgumentException invalid) {
            return error(400, "invalid_grant", "subject token: " + invalid.getMessage());
        }
        if (!client.equals(subject.get("azp")) || !"ID".equals(subject.getOrDefault("typ", "ID"))) {
            return error(400, "invalid_grant", "subject token was not issued to this client");
        }
        if (text(subject.get("sub")).isEmpty()) {
            return error(400, "invalid_grant", "subject token has no subject");
        }
        var conn = connection(client, audience, resource);
        if (conn == null) {
            log.event("exchange.refused", null, "client", client, "reason", "no-connection",
                    "audience", audience, "resource", resource);
            return error(400, "invalid_target",
                    "no connection is configured from this application to that resource");
        }
        var allowed = ((List<?>) conn.get("scopes")).stream().map(String.class::cast).toList();
        var requested = words(form.get("scope"));
        var granted = requested.isEmpty() ? allowed : requested.stream().filter(allowed::contains).toList();
        if (!requested.isEmpty() && granted.isEmpty()) {
            log.event("exchange.refused", null, "client", client, "reason", "scope",
                    "requested", requested, "allowed", allowed);
            return error(400, "invalid_scope", "the connection does not carry that scope");
        }
        long now = Instant.now().getEpochSecond();
        var claims = new LinkedHashMap<String, Object>(Map.of(
                "iss", issuer, "sub", subject.get("sub"), "aud", audience, "client_id", client,
                "resource", resource, "scope", String.join(" ", granted), "jti", id(),
                "iat", now, "exp", now + ttl, "tenant", "northwind"));
        for (String attribute : List.of("preferred_username", "email", "auth_time")) {
            if (subject.get(attribute) != null) {
                claims.put(attribute, subject.get(attribute));
            }
        }
        var jwt = CompactJws.sign(Map.of("typ", JAG_TYPE, "kid", kid), claims, key.getPrivate());
        log.event("exchange.issued", null, "client", client, "sub", subject.get("sub"),
                "who", subject.get("preferred_username"), "audience", audience, "resource", resource,
                "scope", claims.get("scope"), "jti", claims.get("jti"));
        return ResponseEntity.ok(Map.of("issued_token_type", ID_JAG, "access_token", jwt,
                "token_type", "N_A", "expires_in", ttl, "scope", claims.get("scope")));
    }

    @GetMapping("/health")
    synchronized Map<String, Object> health() {
        return Map.of("ok", true, "issuer", issuer, "connections", connections.size());
    }

    @GetMapping("/jwks")
    Map<String, Object> jwks() {
        var jwk = new LinkedHashMap<>(publicKey);
        jwk.putAll(Map.of("kid", kid, "use", "sig", "alg", "EdDSA"));
        return Map.of("keys", List.of(jwk));
    }

    @GetMapping("/.well-known/openid-configuration")
    Map<String, Object> discovery() {
        return Map.of("issuer", issuer, "jwks_uri", issuer + "/jwks", "token_endpoint", issuer + "/token",
                "grant_types_supported", List.of(EXCHANGE), "token_endpoint_auth_methods_supported",
                List.of("client_secret_basic", "client_secret_post"), "subject_token_types_supported",
                List.of(ID_TOKEN), "requested_token_types_supported", List.of(ID_JAG),
                "id_jag_identity_provider", idp);
    }

    @GetMapping("/admin/connections")
    ResponseEntity<Map<String, Object>> listConnections(HttpServletRequest request) {
        try {
            requireAdmin(request);
        } catch (IllegalArgumentException invalid) {
            return error(401, invalid.getMessage(), null);
        }
        synchronized (this) {
            return ResponseEntity.ok(Map.of("connections", new ArrayList<>(connections.values())));
        }
    }

    @PostMapping("/admin/connections")
    ResponseEntity<Map<String, Object>> addConnection(HttpServletRequest request,
                                                        @RequestBody Map<String, Object> raw) {
        String admin;
        try {
            admin = requireAdmin(request);
        } catch (IllegalArgumentException invalid) {
            return error(401, invalid.getMessage(), null);
        }
        Map<String, Object> conn;
        try {
            conn = parseConnection(raw);
        } catch (IllegalArgumentException invalid) {
            return error(400, invalid.getMessage(), null);
        }
        synchronized (this) {
            connections.put(text(conn.get("id")), conn);
        }
        log.event("connection.configured", null, "by", admin, "id", conn.get("id"),
                "client", conn.get("requesting_client"), "audience", conn.get("audience"),
                "resource", conn.get("resource"), "scopes", conn.get("scopes"));
        return ResponseEntity.status(201).body(conn);
    }

    @DeleteMapping("/admin/connections/{id}")
    ResponseEntity<Map<String, Object>> dropConnection(HttpServletRequest request,
                                                         @PathVariable String id) {
        String admin;
        try {
            admin = requireAdmin(request);
        } catch (IllegalArgumentException invalid) {
            return error(401, invalid.getMessage(), null);
        }
        synchronized (this) {
            if (connections.remove(id) == null) {
                return error(404, "no such connection", null);
            }
        }
        log.event("connection.withdrawn", null, "by", admin, "id", id);
        return ResponseEntity.ok(Map.of("ok", true));
    }

    private synchronized Map<String, Object> connection(String client, String audience, String resource) {
        return connections.values().stream().filter(conn -> Boolean.TRUE.equals(conn.get("enabled"))
                && client.equals(conn.get("requesting_client")) && audience.equals(conn.get("audience"))
                && resource.equals(conn.get("resource"))).findFirst().orElse(null);
    }

    private static Map<String, Object> parseConnection(Map<String, Object> raw) {
        for (String field : List.of("requesting_client", "audience", "resource")) {
            if (text(raw.get(field)).isEmpty()) {
                throw new IllegalArgumentException(field + " is required");
            }
        }
        Object scopes = raw.getOrDefault("scopes", List.of());
        if (!(scopes instanceof List<?> list) || !list.stream().allMatch(String.class::isInstance)) {
            throw new IllegalArgumentException("scopes must be a list of strings");
        }
        return Map.of("id", value(text(raw.get("id")), id().substring(0, 12)),
                "requesting_client", raw.get("requesting_client"), "audience", raw.get("audience"),
                "resource", raw.get("resource"), "scopes", List.copyOf(list),
                "enabled", !Boolean.FALSE.equals(raw.get("enabled")),
                "created", value(text(raw.get("created")), EventLog.utcNow()));
    }

    private String requireAdmin(HttpServletRequest request) {
        String header = request.getHeader("authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)
                || header.length() == 7) {
            throw new IllegalArgumentException("no bearer token");
        }
        var claims = realmClaims(header.substring(7));
        if (!adminClient.equals(claims.get("azp"))) {
            throw new IllegalArgumentException("that token was not issued to the administration client");
        }
        String who = value(text(claims.get("preferred_username")), text(claims.get("sub")));
        if (!admins.contains(who)) {
            throw new IllegalArgumentException(who + " does not administer this provider");
        }
        return who;
    }

    private Map<String, Object> realmClaims(String jwt) {
        var claims = providers.claims(jwt, idp);
        PyJwtClaims.validateWithIat(claims, Instant.now().getEpochSecond(), "exp");
        return claims;
    }

    private String requireClient(HttpServletRequest request, Map<String, String> form) {
        String client = form.getOrDefault("client_id", "");
        String sent = form.getOrDefault("client_secret", "");
        String header = request.getHeader("authorization");
        if (header != null && header.regionMatches(true, 0, "Basic ", 0, 6)) {
            String raw = new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8);
            int delimiter = raw.indexOf(':');
            if (delimiter < 0) {
                throw new IllegalArgumentException("malformed basic credentials");
            }
            client = unquote(raw.substring(0, delimiter));
            sent = unquote(raw.substring(delimiter + 1));
        }
        String expected = clients.get(client);
        if (client.isEmpty() || expected == null || !MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), sent.getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException("unknown client or bad secret");
        }
        return client;
    }

    private static List<String> words(String value) {
        return value == null || value.isBlank() ? List.of() : List.of(value.strip().split("(?U)\\s+"));
    }

    private static ResponseEntity<Map<String, Object>> error(int status, String error, String detail) {
        return ResponseEntity.status(status).body(detail == null ? Map.of("error", error)
                : Map.of("error", error, "error_description", detail));
    }

    private static String unquote(String raw) { return URLDecoder.decode(raw.replace("+", "%2B"), StandardCharsets.UTF_8); }
    private static String text(Object value) { return value instanceof String s ? s : ""; }
    private static String value(String input, String fallback) { return input.isEmpty() ? fallback : input; }
    private static String env(String name, String fallback) { return System.getenv().getOrDefault(name, fallback); }
    private static String id() { return UUID.randomUUID().toString().replace("-", ""); }
}
