package io.uma4agents.agent;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.HttpSignature;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * The requesting side of the four-beat grant, ported from the pinned {@code uma4a_grant.py}:
 * challenge parsing in both envelopes, RFC 9728 corroboration, the MyTerms agreement, the
 * pend loop with hand-back, and RFC 9421 request signing over the exact body bytes.
 */
public final class GrantClient {

    public static final String AGREEMENT_FORMAT =
            "https://u4a.ai/spec/terms/1.0#myterms-agreement-v1+jws";
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket";
    public static final String MCP_PROTOCOL_VERSION = "2026-07-28";
    static final int MAX_DICTATIONS = 3;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern AS_URI = Pattern.compile("as_uri=\"([^\"]+)\"");
    private static final Pattern TICKET = Pattern.compile("ticket=\"([^\"]+)\"");
    private static final Pattern RESOURCE_METADATA =
            Pattern.compile("resource_metadata=\"([^\"]+)\"");
    private static final Pattern FAMILY = Pattern.compile("[A-Za-z0-9_-]{1,128}");

    private GrantClient() {}

    /** The owner, her policy, or the requesting side ended the negotiation. */
    public static class GrantDeniedException extends RuntimeException {
        public GrantDeniedException(String message) {
            super(message);
        }
    }

    /** The requesting side declined the proffered terms. */
    public static class TermsRejectedException extends RuntimeException {
        public TermsRejectedException(String templateId) {
            super(templateId);
        }
    }

    /** The resource's published metadata contradicts what the client was told. */
    public static class DiscoveryMismatchException extends RuntimeException {
        public DiscoveryMismatchException(String message) {
            super(message);
        }
    }

    /** The owner has not decided, and the waiting is handed back rather than held open. */
    public static class PendingHandbackException extends RuntimeException {
        private final String asUri;
        private final String ticket;

        public PendingHandbackException(String asUri, String ticket) {
            super("the owner has not decided yet");
            this.asUri = asUri;
            this.ticket = ticket;
        }

        public String asUri() {
            return asUri;
        }

        public String ticket() {
            return ticket;
        }
    }

    /** A UMA challenge, from a WWW-Authenticate header or a JSON-RPC error's data. */
    public record Challenge(String asUri, String ticket, String resourceMetadata) {
        /** Parses a {@code WWW-Authenticate: UMA} header; null when it is not one. */
        public static Challenge parse(String wwwAuthenticate) {
            if (wwwAuthenticate == null || !wwwAuthenticate.contains("UMA")) {
                return null;
            }
            Matcher as = AS_URI.matcher(wwwAuthenticate);
            Matcher ticket = TICKET.matcher(wwwAuthenticate);
            if (!as.find() || !ticket.find()) {
                return null;
            }
            Matcher rm = RESOURCE_METADATA.matcher(wwwAuthenticate);
            return new Challenge(as.group(1), ticket.group(1), rm.find() ? rm.group(1) : null);
        }
    }

    /** A pend still outstanding when the hand-back deadline passed. */
    public record Pend(String asUri, long interval, long waitedSeconds, String ticket) {}

    /** What the requesting side asks: the parts of the grant it contributes. */
    public record Contribution(Map<String, Object> operation, String reason,
                               Map<String, Object> mission) {
        public static Contribution none() {
            return new Contribution(null, null, null);
        }
    }

    /** Callbacks for one negotiation. */
    public interface Negotiator {
        /** Whether the requesting side accepts the proffered terms. */
        boolean approveTerms(Map<String, Object> template);

        /** Whether to keep waiting on the owner; may throw PendingHandbackException. */
        default boolean keepWaiting(Pend pend) {
            throw new GrantDeniedException("timed out waiting for the owner");
        }

        default void status(String message) {}

        default void receipt(String jws) {}

        /** How long to poll a pend before asking {@link #keepWaiting}. */
        default long maxWaitSeconds() {
            return 120;
        }
    }

    /** Where a signed request goes: method, the authority it is signed for, and path. */
    public record Target(String method, String authority, String path) {}

    /** RFC 9728 §3: the well-known path goes between host and resource path. */
    public static String wellKnownPrmUrl(String resourceUrl) {
        URI u = URI.create(resourceUrl);
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        String port = u.getPort() == -1 ? "" : ":" + u.getPort();
        return u.getScheme() + "://" + u.getHost() + port
                + "/.well-known/oauth-protected-resource" + path;
    }

    /**
     * RFC 9728 §3.3 validation. {@code doc} must have been fetched from the resource called;
     * {@code named} (the challenge's resource_metadata) must point at that same document.
     */
    public static Map<String, Object> validateResourceMetadata(Map<String, Object> doc,
                                                               String resourceUrl, String asUri,
                                                               String named) {
        if (named != null && !named.equals(wellKnownPrmUrl(resourceUrl))) {
            throw new DiscoveryMismatchException("challenge names metadata at " + named
                    + ", not " + wellKnownPrmUrl(resourceUrl));
        }
        if (!resourceUrl.equals(doc.get("resource"))) {
            throw new DiscoveryMismatchException("metadata is for " + doc.get("resource")
                    + ", not " + resourceUrl);
        }
        Object servers = doc.get("authorization_servers");
        if (asUri != null && (!(servers instanceof List<?> list) || !list.contains(asUri))) {
            throw new DiscoveryMismatchException("challenge names AS " + asUri
                    + ", which the resource's metadata does not publish (" + servers + ")");
        }
        return doc;
    }

    /** The challenge carried in a JSON-RPC error's data, from a self-enforcing resource. */
    public static Challenge jsonRpcChallenge(Map<String, Object> payload) {
        if (payload == null || !(payload.get("error") instanceof Map<?, ?> error)
                || !(error.get("data") instanceof Map<?, ?> data)) {
            return null;
        }
        if ("insufficient_authorization".equals(data.get("error"))
                && data.get("as_uri") instanceof String as && data.get("ticket") instanceof String t) {
            return new Challenge(as, t, data.get("resource_metadata") instanceof String rm
                    ? rm : null);
        }
        return null;
    }

    /** The refusal value an enforcement point sent, and whether it is terminal. */
    public record Refusal(String value, boolean terminal) {}

    public static Refusal refusal(int status, Map<String, Object> body) {
        Object value = null;
        if (body != null && body.get("error") instanceof Map<?, ?> error
                && error.get("data") instanceof Map<?, ?> data) {
            value = data.get("error");
        } else if (body != null) {
            value = body.get("error");
        }
        String v = value instanceof String s && !s.isEmpty() ? s : "http_" + status;
        return new Refusal(v, !"temporarily_unavailable".equals(v));
    }

    /** The file a receipt is kept under; the family is held to its own alphabet. */
    public static String receiptFilename(String receiptJws) {
        String family;
        try {
            String[] parts = receiptJws.split("\\.");
            Map<String, Object> claims = MAPPER.readValue(
                    Base64.getUrlDecoder().decode(parts[1]), new TypeReference<>() {});
            family = claims.get("family") instanceof String f ? f : null;
        } catch (RuntimeException e) {
            family = null;
        }
        if (family == null || !FAMILY.matcher(family).matches()) {
            family = "unknown";
        }
        return family + ".receipt.jws";
    }

    /** Echo the proffered template, signed: the agreement half of the MyTerms exchange. */
    public static String signContract(Map<String, Object> template, AgentKeys keys,
                                      String asUri, Contribution contribution) {
        Map<String, Object> contract = new LinkedHashMap<>();
        contract.put("iss", "agent:" + keys.keyid);
        contract.put("aud", asUri);
        contract.put("iat", Instant.now().getEpochSecond());
        for (String field : List.of("template_id", "terms_uri", "purpose", "scope",
                "expires_in", "prohibited", "nonce", "family")) {
            contract.put(field, template.get(field));
        }
        if (contribution.operation() != null) {
            contract.put("operation", contribution.operation());
        }
        if (contribution.reason() != null && !contribution.reason().isEmpty()) {
            contract.put("reason", contribution.reason());
        }
        if (contribution.mission() != null && !contribution.mission().isEmpty()) {
            contract.put("mission", contribution.mission());
        }
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "myterms-agreement-v1+jws");
        header.put("kid", keys.keyid);
        if (keys.agentToken != null) {
            header.put("agent_token", keys.agentToken);
        } else {
            header.put("jwk", keys.publicJwk());
        }
        if (keys.clientId != null) {
            header.put("client_id", keys.clientId);
        }
        if (keys.signatureAgent != null) {
            header.put("signature_agent", keys.signatureAgent);
        }
        String jws = CompactJws.signWith(header, contract, keys.key.getPrivate(), keys.jwsAlg());
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(jws.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Walks beats 2–4 and returns the RPT. A pend outlasting {@code maxWaitSeconds} is put
     * to {@link Negotiator#keepWaiting}, which may hand it back by throwing.
     */
    public static String runGrant(HttpClient client, Challenge challenge, AgentKeys keys,
                                  Contribution contribution, Negotiator negotiator) {
        String asUri = challenge.asUri();
        String tokenUrl = asUri + "/token";
        negotiator.status("presenting ticket at Alice's AS");
        Map<String, Object> body = postForm(client, tokenUrl,
                Map.of("grant_type", GRANT_TYPE, "ticket", challenge.ticket()));
        for (int round = 0; round < MAX_DICTATIONS; round++) {
            Map<String, Object> template = termsTemplate(body);
            if (!"need_info".equals(body.get("error")) || template == null) {
                break;
            }
            negotiator.status("terms proffered: " + template.get("purpose") + " (expires "
                    + template.get("expires_in") + "s, prohibited: "
                    + joined(template.get("prohibited")) + ")");
            String held = String.valueOf(body.get("ticket"));
            if (!negotiator.approveTerms(template)) {
                postForm(client, tokenUrl, Map.of("grant_type", GRANT_TYPE, "ticket", held,
                        "decline", "true"));
                throw new TermsRejectedException(String.valueOf(template.get("template_id")));
            }
            String claim = signContract(template, keys, asUri, contribution);
            body = postForm(client, tokenUrl, Map.of("grant_type", GRANT_TYPE, "ticket", held,
                    "claim_token", claim, "claim_token_format", AGREEMENT_FORMAT));
        }
        body = awaitOwner(client, asUri, body, negotiator);
        if (body.get("access_token") instanceof String rpt) {
            negotiator.status("grant issued");
            if (body.get("receipt") instanceof String receipt) {
                negotiator.receipt(receipt);
            }
            return rpt;
        }
        Object description = body.get("error_description");
        throw new GrantDeniedException(String.valueOf(
                description != null ? description : body.getOrDefault("error", "unknown")));
    }

    private static Map<String, Object> awaitOwner(HttpClient client, String asUri,
                                                  Map<String, Object> first,
                                                  Negotiator negotiator) {
        long maxWaitSeconds = negotiator.maxWaitSeconds();
        String tokenUrl = asUri + "/token";
        Map<String, Object> body = first;
        long deadline = Instant.now().getEpochSecond() + maxWaitSeconds;
        while ("request_submitted".equals(body.get("error"))) {
            negotiator.status("Alice has been asked — holding the ticket");
            long interval = body.get("interval") instanceof Number n ? n.longValue() : 3;
            String ticket = String.valueOf(body.get("ticket"));
            if (Instant.now().getEpochSecond() > deadline) {
                if (!negotiator.keepWaiting(new Pend(asUri, interval, maxWaitSeconds, ticket))) {
                    throw new GrantDeniedException(
                            "the requesting side stopped waiting for the owner");
                }
                deadline = Instant.now().getEpochSecond() + maxWaitSeconds;
            }
            sleep(interval);
            try {
                body = postForm(client, tokenUrl, Map.of("grant_type", GRANT_TYPE,
                        "ticket", ticket));
            } catch (IllegalStateException e) {
                negotiator.status("poll did not complete (" + e.getMessage()
                        + "); asking again");
            }
        }
        return body;
    }

    /** One poll of a held pend: the token endpoint's answer, or null if it was unreachable. */
    public static Map<String, Object> poll(HttpClient client, String asUri, String ticket) {
        try {
            return postForm(client, asUri + "/token",
                    Map.of("grant_type", GRANT_TYPE, "ticket", ticket));
        } catch (IllegalStateException e) {
            return null;
        }
    }

    /** A W3C traceparent for this call, unless UMA4A_TRACING disables it. */
    public static String traceparent() {
        String tracing = System.getenv("UMA4A_TRACING");
        if (tracing != null && List.of("0", "false", "no").contains(tracing)) {
            return null;
        }
        byte[] trace = new byte[16];
        byte[] span = new byte[8];
        RANDOM.nextBytes(trace);
        RANDOM.nextBytes(span);
        HexFormat hex = HexFormat.of();
        return "00-" + hex.formatHex(trace) + "-" + hex.formatHex(span) + "-01";
    }

    /** Authorization, RFC 9421 signature (Content-Digest when a body is given) and trace. */
    public static Map<String, String> signedHeaders(Target target, String rpt, AgentKeys keys,
                                                    byte[] body) {
        String authorization = "PoP " + rpt;
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", authorization);
        headers.putAll(HttpSignature.sign(target.method(), target.authority(), target.path(),
                authorization,
                keys.key.getPrivate(), keys.keyid,
                new HttpSignature.SignOptions(keys.signatureAgent, null, null, "web-bot-auth",
                        body)));
        String tp = traceparent();
        if (tp != null) {
            headers.put("traceparent", tp);
        }
        return headers;
    }

    /** The per-request {@code _meta} a 2026-07-28 client sends. */
    public static Map<String, Object> mcpMeta(String clientName, String version) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("io.modelcontextprotocol/protocolVersion", MCP_PROTOCOL_VERSION);
        meta.put("io.modelcontextprotocol/clientCapabilities", Map.of());
        meta.put("io.modelcontextprotocol/clientInfo",
                Map.of("name", clientName, "version", version));
        return meta;
    }

    /** A JSON-RPC body, plain or as one SSE frame; null when empty. */
    public static Map<String, Object> mcpJson(String body, String contentType) {
        String text = body;
        if (contentType != null && contentType.contains("text/event-stream")) {
            text = null;
            for (String line : body.split("\n")) {
                if (line.startsWith("data:")) {
                    text = line.substring(5).strip();
                }
            }
        }
        if (text == null || text.isBlank()) {
            return null;
        }
        return parse(text);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> termsTemplate(Map<String, Object> body) {
        if (body.get("required_claims") instanceof List<?> list && !list.isEmpty()
                && list.get(0) instanceof Map<?, ?> first
                && first.get("terms_template") instanceof Map<?, ?> template) {
            return (Map<String, Object>) template;
        }
        return null;
    }

    private static String joined(Object list) {
        return list instanceof List<?> items
                ? items.stream().map(String::valueOf).collect(Collectors.joining(", ")) : "";
    }

    private static void sleep(long seconds) {
        try {
            Thread.sleep(Duration.ofSeconds(seconds));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GrantDeniedException("interrupted while waiting for the owner");
        }
    }

    static Map<String, Object> postForm(HttpClient client, String url,
                                        Map<String, String> params) {
        String form = params.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build();
        try {
            return parse(client.send(request, HttpResponse.BodyHandlers.ofString()).body());
        } catch (IOException e) {
            throw new IllegalStateException("could not reach " + url + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted calling " + url, e);
        }
    }

    static Map<String, Object> parse(String json) {
        try {
            Map<String, Object> out = MAPPER.readValue(json, new TypeReference<>() {});
            return out == null ? Map.of() : out;
        } catch (JacksonException e) {
            throw new IllegalStateException("non-JSON response: "
                    + json.substring(0, Math.min(200, json.length())), e);
        }
    }
}
