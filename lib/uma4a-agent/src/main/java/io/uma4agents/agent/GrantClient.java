package io.uma4agents.agent;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.uma4agents.common.HttpSignature;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The requesting-agent side of the four-beat grant loop — port of
 * {@code uma4a_grant.py}. Parses the UMA challenge, presents tickets, signs
 * the intent contract with the agent's Ed25519 key, waits out
 * request_submitted holds, and signs resource requests for proof-of-possession.
 *
 * <p>Terms approval is a callback so a shim can elicit its human while a
 * headless driver applies standing config.
 */
public final class GrantClient {

    public static final String AGREEMENT_FORMAT = "urn:uma4agents:format:myterms-agreement-v1+jws";
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern AS_URI = Pattern.compile("as_uri=\"([^\"]+)\"");
    private static final Pattern TICKET = Pattern.compile("ticket=\"([^\"]+)\"");
    private static final Pattern RESOURCE_METADATA =
            Pattern.compile("resource_metadata=\"([^\"]+)\"");

    private GrantClient() {}

    public static class GrantDeniedException extends RuntimeException {
        public GrantDeniedException(String message) {
            super(message);
        }
    }

    public static class TermsRejectedException extends RuntimeException {
        public TermsRejectedException(String templateId) {
            super(templateId);
        }
    }

    /**
     * A parsed WWW-Authenticate: UMA challenge. {@code resourceMetadata} is
     * the RFC 9728 pointer the resource may add so the client can corroborate
     * {@code asUri} against the resource's own published metadata.
     */
    public record Challenge(String asUri, String ticket, String resourceMetadata) {
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
            return new Challenge(as.group(1), ticket.group(1),
                    rm.find() ? rm.group(1) : null);
        }
    }

    /**
     * The resource's published metadata contradicts what the client was told —
     * wrong {@code resource} value, or a challenge naming an AS the resource
     * never published.
     */
    public static class DiscoveryMismatchException extends RuntimeException {
        public DiscoveryMismatchException(String message) {
            super(message);
        }
    }

    /** RFC 9728 §3: the well-known path goes between host and resource path. */
    public static String wellKnownPrmUrl(String resourceUrl) {
        URI u = URI.create(resourceUrl);
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return u.getScheme() + "://" + u.getRawAuthority()
                + "/.well-known/oauth-protected-resource" + path;
    }

    /**
     * RFC 9728 §3.3 client validation: the {@code resource} value must
     * identify the resource being accessed. When a challenge is in hand, its
     * as_uri must be among the published authorization_servers — the
     * TLS-anchored metadata corroborates the (unauthenticated) challenge
     * header.
     */
    public static Map<String, Object> validateResourceMetadata(
            Map<String, Object> doc, String resourceUrl, String asUri) {
        if (!resourceUrl.equals(doc.get("resource"))) {
            throw new DiscoveryMismatchException("metadata is for "
                    + doc.get("resource") + ", not " + resourceUrl);
        }
        Object servers = doc.get("authorization_servers");
        if (asUri != null && (!(servers instanceof List<?> list) || !list.contains(asUri))) {
            throw new DiscoveryMismatchException("challenge names AS " + asUri
                    + ", which the resource's metadata does not publish (" + servers + ")");
        }
        return doc;
    }

    /**
     * Echo the proffered template, signed — the agreement half of the MyTerms
     * exchange. Returns base64url-nopad of the compact JWS (the double
     * encoding the AS expects). Weakening any field is caught by the AS.
     */
    public static String signContract(Map<String, Object> template, AgentKeys keys,
                                      String asUri, Map<String, Object> operation) {
        Map<String, Object> contract = new LinkedHashMap<>();
        contract.put("iss", "aauth:agent:" + keys.keyid);
        contract.put("aud", asUri);
        contract.put("iat", Instant.now().getEpochSecond());
        contract.put("template_id", template.get("template_id"));
        contract.put("terms_uri", template.get("terms_uri"));
        contract.put("purpose", template.get("purpose"));
        contract.put("scope", template.get("scope"));
        contract.put("expires_in", template.get("expires_in"));
        contract.put("prohibited", template.get("prohibited"));
        contract.put("nonce", template.get("nonce"));
        contract.put("family", template.get("family"));
        if (operation != null) {
            contract.put("operation", operation);
        }
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "myterms-agreement-v1+jws");
        header.put("kid", keys.keyid);
        if (keys.agentToken != null) {
            header.put("agent_token", keys.agentToken);
        } else {
            header.put("jwk", keys.publicJwk());
        }
        String jws = io.uma4agents.common.CompactJws.sign(header, contract, keys.key.getPrivate());
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(jws.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Walks beats 2–4. Returns the RPT; the counter-signed MyTerms receipt is
     * delivered via {@code onReceipt}. Throws GrantDenied / TermsRejected.
     */
    public static String runGrant(HttpClient client, String asUri, String ticket,
                                  AgentKeys keys, Predicate<Map<String, Object>> approveTerms,
                                  Map<String, Object> operation, Consumer<String> onStatus,
                                  Consumer<String> onReceipt, long maxWaitSeconds) {
        String tokenUrl = asUri + "/token";

        onStatus.accept("presenting ticket at Alice's AS");
        Map<String, Object> body = postForm(client, tokenUrl, Map.of(
                "grant_type", GRANT_TYPE, "ticket", ticket));

        if ("need_info".equals(body.get("error"))) {
            Map<String, Object> template = termsTemplate(body);
            onStatus.accept("terms proffered: " + template.get("purpose")
                    + " (expires " + template.get("expires_in") + "s, prohibited: "
                    + joined(template.get("prohibited")) + ")");
            if (!approveTerms.test(template)) {
                // Refusals are records too (the owner's ledger notes the decline).
                postForm(client, tokenUrl, Map.of(
                        "grant_type", GRANT_TYPE,
                        "ticket", String.valueOf(body.get("ticket")),
                        "decline", "true"));
                throw new TermsRejectedException(String.valueOf(template.get("template_id")));
            }
            String claim = signContract(template, keys, asUri, operation);
            onStatus.accept("agreement signed, committing");
            body = postForm(client, tokenUrl, Map.of(
                    "grant_type", GRANT_TYPE,
                    "ticket", String.valueOf(body.get("ticket")),
                    "claim_token", claim,
                    "claim_token_format", AGREEMENT_FORMAT));
        }

        long deadline = Instant.now().getEpochSecond() + maxWaitSeconds;
        while ("request_submitted".equals(body.get("error"))) {
            onStatus.accept("Alice has been asked — holding the ticket");
            if (Instant.now().getEpochSecond() > deadline) {
                throw new GrantDeniedException("timed out waiting for the owner");
            }
            long interval = body.get("interval") instanceof Number n ? n.longValue() : 3;
            sleep(interval);
            body = postForm(client, tokenUrl, Map.of(
                    "grant_type", GRANT_TYPE, "ticket", String.valueOf(body.get("ticket"))));
        }

        if (body.get("access_token") instanceof String rpt) {
            onStatus.accept("grant issued");
            if (body.get("receipt") instanceof String receipt) {
                onReceipt.accept(receipt);
            }
            return rpt;
        }
        Object description = body.get("error_description");
        throw new GrantDeniedException(String.valueOf(
                description != null ? description : body.getOrDefault("error", "unknown")));
    }

    /** Authorization + RFC 9421 signature headers for a resource request. */
    public static Map<String, String> signedHeaders(String method, String authority, String path,
                                                    String rpt, AgentKeys keys) {
        String authorization = "PoP " + rpt;
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", authorization);
        headers.putAll(HttpSignature.sign(method, authority, path, authorization,
                keys.key.getPrivate(), keys.keyid));
        return headers;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> termsTemplate(Map<String, Object> body) {
        Object claims = body.get("required_claims");
        if (claims instanceof List<?> list && !list.isEmpty()
                && list.get(0) instanceof Map<?, ?> first
                && first.get("terms_template") instanceof Map<?, ?> template) {
            return (Map<String, Object>) template;
        }
        throw new GrantDeniedException("need_info without a terms template");
    }

    private static String joined(Object list) {
        if (list instanceof List<?> items) {
            return items.stream().map(String::valueOf).collect(Collectors.joining(", "));
        }
        return "";
    }

    private static Map<String, Object> postForm(HttpClient client, String url,
                                                Map<String, String> params) {
        String form = params.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("content-type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        try {
            HttpResponse<String> response =
                    client.send(request, HttpResponse.BodyHandlers.ofString());
            return MAPPER.readValue(response.body(), new TypeReference<>() {});
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GrantDeniedException("token endpoint unreachable: " + e.getMessage());
        }
    }

    private static void sleep(long seconds) {
        try {
            Thread.sleep(seconds * 1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GrantDeniedException("interrupted while waiting for the owner");
        }
    }
}
