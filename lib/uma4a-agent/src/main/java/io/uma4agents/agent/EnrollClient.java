package io.uma4agents.agent;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.uma4agents.common.Jwks;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * AAuth agent-server enrollment ceremony — port of {@code uma4a_enroll.py}.
 *
 * <p>The agent registers its persisted <em>stable</em> public key in a request
 * signed by its per-session <em>ephemeral</em> key ({@code hwk} scheme). First
 * contact pends until the principal approves; a known stable key re-registers
 * immediately. The issued {@code aa-agent+jwt} binds cnf.jwk to the ephemeral
 * key, so the key that signs contracts is the one the token vouches for.
 */
public final class EnrollClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private EnrollClient() {}

    public static class EnrollmentDeniedException extends RuntimeException {
        public EnrollmentDeniedException(String message) {
            super(message);
        }
    }

    /** Runs the registration ceremony; returns the aa-agent+jwt. */
    public static String enroll(HttpClient client, String issuer, KeyPair stableKey,
                                KeyPair ephemeralKey, String agentName, String personToken,
                                Consumer<String> onStatus, long maxWaitSeconds,
                                long pollIntervalSeconds) {
        String origin = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        Map<String, Object> meta = getJson(client,
                origin + "/.well-known/aauth-agent.json", null);
        String regUrl = String.valueOf(meta.get("registration_endpoint"));

        Map<String, Object> registration = new LinkedHashMap<>();
        registration.put("stable_pub", Jwks.okpPublicJwk(stableKey.getPublic()));
        registration.put("agent_name", agentName);
        String body;
        try {
            body = MAPPER.writeValueAsString(registration);
        } catch (tools.jackson.core.JacksonException e) {
            throw new EnrollmentDeniedException("unserializable registration: " + e.getMessage());
        }

        HttpResponse<String> response = send(client, signedRequest(
                "POST", regUrl, body, ephemeralKey));
        if (response.statusCode() == 200) {
            onStatus.accept("agent server recognized this agent — token issued");
            return (String) parse(response.body()).get("agent_token");
        }
        if (response.statusCode() != 202) {
            throw new EnrollmentDeniedException("register failed: " + response.statusCode()
                    + " " + truncate(response.body()));
        }

        String location = response.headers().firstValue("location").orElse("");
        String trimmed = location.endsWith("/")
                ? location.substring(0, location.length() - 1) : location;
        String pendingId = trimmed.substring(trimmed.lastIndexOf('/') + 1);
        String pollUrl = location.startsWith("/") ? origin + location : location;
        onStatus.accept("registration pending " + pendingId
                + " — awaiting the principal's approval");

        if (personToken != null) {
            HttpRequest approve = HttpRequest.newBuilder()
                    .uri(URI.create(origin + "/person/registrations/" + pendingId + "/approve"))
                    .header("Authorization", "Bearer " + personToken)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> approval = send(client, approve);
            if (approval.statusCode() != 200) {
                throw new EnrollmentDeniedException("person approval failed: "
                        + approval.statusCode() + " " + truncate(approval.body()));
            }
            onStatus.accept("[simulated-bob] approved his agent at his person server");
        } else {
            onStatus.accept("approve this agent in the person server UI: " + origin + "/ui");
        }

        long deadline = Instant.now().getEpochSecond() + maxWaitSeconds;
        while (Instant.now().getEpochSecond() < deadline) {
            HttpResponse<String> poll = send(client, signedRequest(
                    "GET", pollUrl, null, ephemeralKey));
            if (poll.statusCode() == 200) {
                return (String) parse(poll.body()).get("agent_token");
            }
            if (poll.statusCode() == 202) {
                try {
                    Thread.sleep(pollIntervalSeconds * 1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new EnrollmentDeniedException("interrupted while waiting");
                }
                continue;
            }
            throw new EnrollmentDeniedException("registration " + pendingId + ": "
                    + poll.statusCode() + " " + truncate(poll.body()));
        }
        throw new EnrollmentDeniedException("timed out waiting for the principal's approval");
    }

    private static HttpRequest signedRequest(String method, String url, String body,
                                             KeyPair ephemeralKey) {
        Map<String, String> signature = AauthHwkSigner.signRequest(method, url, ephemeralKey);
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url));
        if (body != null) {
            builder.header("Content-Type", "application/json");
        }
        signature.forEach(builder::header);
        if (body != null) {
            builder.method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return builder.build();
    }

    private static Map<String, Object> getJson(HttpClient client, String url, String bearer) {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).GET();
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return parse(send(client, builder.build()).body());
    }

    private static HttpResponse<String> send(HttpClient client, HttpRequest request) {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new EnrollmentDeniedException("agent server unreachable: " + e.getMessage());
        }
    }

    private static Map<String, Object> parse(String json) {
        try {
            return MAPPER.readValue(json, new TypeReference<>() {});
        } catch (tools.jackson.core.JacksonException e) {
            throw new EnrollmentDeniedException("non-JSON response: " + truncate(json));
        }
    }

    private static String truncate(String value) {
        return value == null ? "" : value.substring(0, Math.min(300, value.length()));
    }
}
