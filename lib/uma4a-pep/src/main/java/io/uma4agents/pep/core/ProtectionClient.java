package io.uma4agents.pep.core;

import io.uma4agents.common.EventLog;
import io.uma4agents.common.HttpSignature;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * The resource server's half of the UMA protection API against one owner's authorization
 * server: PAT lifecycle, ticket minting, introspection, consumption and access reporting.
 * Ported from the protection-API methods of the pinned {@code Enforcer}.
 */
public class ProtectionClient {

    /** Introspection could not reach the authority; not an answer about the grant. */
    public static final String UNAVAILABLE = "introspection_unavailable";
    /** The authority has not yet authorized this resource server. */
    public static final String PENDING = "authorization_pending";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    /** The authority has been asked about this resource server and has not answered. */
    public static final class PendingException extends RuntimeException {
        public PendingException(String message) {
            super(message);
        }
    }

    private final EnforcerSettings settings;
    private final EventLog log;
    private final OriginIdentity identity;
    private final String fixedBearer;
    private final HttpClient http;
    private final Object patLock = new Object();
    private String patToken;
    private long patExpires;
    private long establishAfter;

    public ProtectionClient(EnforcerSettings settings, EventLog log) {
        this(settings, log, null);
    }

    /** The origin credential for a relationship established without a shared secret. */
    public record OriginIdentity(PrivateKey key, String kid, String resourceUri, String name) {}

    public ProtectionClient(EnforcerSettings settings, EventLog log, OriginIdentity identity) {
        this(settings, log, identity, null,
                HttpClient.newBuilder().connectTimeout(TIMEOUT).build());
    }

    public ProtectionClient(EnforcerSettings settings, EventLog log, OriginIdentity identity,
                            HttpClient http) {
        this(settings, log, identity, null, http);
    }

    private ProtectionClient(EnforcerSettings settings, EventLog log, OriginIdentity identity,
                             String fixedBearer, HttpClient http) {
        this.settings = settings;
        this.log = log;
        this.identity = identity;
        this.fixedBearer = fixedBearer;
        this.http = http;
    }

    /** A configured enforcement-point credential for a cooperating organization. */
    public static ProtectionClient forOrganization(EnforcerSettings settings, EventLog log,
                                                   String bearer) {
        return new ProtectionClient(settings, log, null, bearer,
                HttpClient.newBuilder().connectTimeout(TIMEOUT).build());
    }

    /** The PAT, refreshed 60 s early; one per owner. */
    public String pat(boolean force) throws IOException {
        if (fixedBearer != null) {
            return fixedBearer;
        }
        synchronized (patLock) {
            long now = Instant.now().getEpochSecond();
            if (!force && patToken != null && now < patExpires - 60) {
                return patToken;
            }
            Map<String, String> form = new LinkedHashMap<>();
            form.put("grant_type", "client_credentials");
            form.put("client_id", settings.clientId());
            form.put("scope", "uma_protection");
            form.put("owner", settings.owner());
            if (identity == null) {
                form.put("client_secret", settings.clientSecret());
            }
            HttpResponse<String> r = tokenRequest(form);
            boolean withdrawn = r.statusCode() == 403 && "access_denied".equals(errorOf(r));
            if (identity != null && (withdrawn || r.statusCode() == 401)
                    && (withdrawn || now >= establishAfter)) {
                establishAfter = now + 30;
                establish();
                r = tokenRequest(form);
            }
            if (r.statusCode() == 403 && PENDING.equals(errorOf(r))) {
                throw new PendingException(settings.owner() + " has not yet authorized this "
                        + "resource server at " + settings.asPublic());
            }
            if (r.statusCode() >= 400) {
                throw new IOException("PAT request refused: HTTP " + r.statusCode());
            }
            Map<String, Object> body = parse(r.body());
            patToken = (String) body.get("access_token");
            establishAfter = 0;
            long expiresIn = body.get("expires_in") instanceof Number n ? n.longValue() : 3600;
            patExpires = now + expiresIn;
            return patToken;
        }
    }

    private HttpResponse<String> tokenRequest(Map<String, String> form) throws IOException {
        String body = formBody(form);
        String contentType = "application/x-www-form-urlencoded";
        return send(identity == null ? post("/token", body, contentType, null)
                : signedPost("/token", body, contentType, TIMEOUT));
    }

    private void establish() throws IOException {
        String body = json(Map.of("owner", settings.owner(), "resource_uri", identity.resourceUri(),
                "name", identity.name()));
        HttpResponse<String> response = send(signedPost("/rs/register", body, "application/json",
                Duration.ofSeconds(10)));
        log.event("resource_server.establish", null, "owner", settings.owner(),
                "authority", settings.asPublic(), "code", response.statusCode());
    }

    private HttpRequest signedPost(String path, String body, String contentType, Duration timeout) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        String authority = URI.create(settings.asPublic()).getRawAuthority();
        Map<String, String> headers = HttpSignature.sign("POST", authority, path, "",
                identity.key(), identity.kid(),
                new HttpSignature.SignOptions(null, null, null, null, bytes));
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(settings.asInternal() + path))
                .timeout(timeout).header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofByteArray(bytes));
        headers.forEach(request::header);
        return request.build();
    }

    /** Registers the attempted permission; returns the ticket, or null when it failed. */
    public String mintTicket(String resourceId, List<String> scopes) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resource_id", resourceId);
        body.put("resource_scopes", scopes);
        try {
            HttpResponse<String> r = protectedPost("/perm", json(body), "application/json");
            if (r.statusCode() >= 400) {
                log.event("permission.mint_refused", null, "authority", settings.asPublic(),
                        "client_id", settings.clientId(), "status", r.statusCode(),
                        "error", errorOf(r));
                return null;
            }
            return (String) parse(r.body()).get("ticket");
        } catch (IOException e) {
            log.event("permission.mint_failed", null, "error", String.valueOf(e.getMessage()));
            return null;
        }
    }

    /** Asks about an RPT without consuming it; inactive answers carry their reason. */
    public Map<String, Object> introspect(String token) {
        try {
            HttpResponse<String> r = protectedPost("/introspect",
                    formBody(Map.of("token", token, "consume", "false")),
                    "application/x-www-form-urlencoded");
            if (r.statusCode() >= 400) {
                return inactive(UNAVAILABLE);
            }
            return parse(r.body());
        } catch (PendingException e) {
            return inactive(PENDING);
        } catch (IOException e) {
            return inactive(UNAVAILABLE);
        }
    }

    /** Burns a single-use RPT; null when the authority could not be asked. */
    public Map<String, Object> consume(String token) {
        try {
            HttpResponse<String> r = protectedPost("/consume",
                    formBody(Map.of("token", token)), "application/x-www-form-urlencoded");
            return r.statusCode() >= 400 ? null : parse(r.body());
        } catch (IOException | PendingException e) {
            return null;
        }
    }

    /** Grounds the ledger's "touched" column in enforcement; never refuses the call. */
    public void reportAccess(String family, String tool, String summary) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("family", family);
        body.put("tool", tool);
        body.put("summary", summary);
        if (fixedBearer != null) {
            body.put("owner", settings.owner());
        }
        try {
            HttpResponse<String> r = protectedPost("/audit/access", json(body),
                    "application/json");
            if (r.statusCode() >= 400) {
                throw new IOException("HTTP " + r.statusCode());
            }
        } catch (IOException | PendingException e) {
            log.event("access.report_failed", null, "family", family, "tool", tool,
                    "error", String.valueOf(e.getMessage()));
        }
    }

    private HttpResponse<String> protectedPost(String path, String body, String contentType)
            throws IOException {
        HttpResponse<String> r = send(post(path, body, contentType, pat(false)));
        if (r.statusCode() == 401 && fixedBearer == null) {
            r = send(post(path, body, contentType, pat(true)));
        }
        return r;
    }

    private HttpRequest post(String path, String body, String contentType, String bearer) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(settings.asInternal() + path)).timeout(TIMEOUT)
                .header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) {
            b.header("Authorization", "Bearer " + bearer);
        }
        return b.build();
    }

    private HttpResponse<String> send(HttpRequest request) throws IOException {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted calling " + request.uri(), e);
        }
    }

    private static Map<String, Object> inactive(String reason) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("active", false);
        out.put("error", reason);
        return out;
    }

    private static String formBody(Map<String, String> form) {
        return form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private static String json(Object value) throws IOException {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JacksonException e) {
            throw new IOException("unserializable request body", e);
        }
    }

    private static String errorOf(HttpResponse<String> r) {
        try {
            Object error = parse(r.body()).get("error");
            return error == null ? "" : String.valueOf(error);
        } catch (IOException e) {
            return "";
        }
    }

    private static Map<String, Object> parse(String body) throws IOException {
        try {
            Map<String, Object> out = MAPPER.readValue(body, new TypeReference<>() {});
            if (out == null) {
                throw new IOException("empty response from the authorization server");
            }
            return out;
        } catch (JacksonException e) {
            throw new IOException("non-JSON response from the authorization server", e);
        }
    }
}
