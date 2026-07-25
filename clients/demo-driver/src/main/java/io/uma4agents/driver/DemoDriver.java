package io.uma4agents.driver;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import io.uma4agents.agent.AgentKeys;
import io.uma4agents.agent.EnrollClient;
import io.uma4agents.agent.GrantClient;
import io.uma4agents.common.SslContexts;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * demo-driver — headless walker for the three demo acts, driving Alice's vault
 * MCP through the gateway. Same grant-loop code path as the agent-shim.
 * Bob's side approves terms via his standing config; with --simulate-alice the
 * pending approvals are granted via the owner API for headless runs.
 */
public final class DemoDriver {

    private static final String GATEWAY_AUTHORITY = "gateway.uma.lab";
    private static final String MCP_PATH = "/mcp";
    private static final long STANDING_MAX_EXPIRES = 7L * 24 * 3600;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, String> args;
    private final HttpClient client;
    private String ownerAccessToken;
    private long ownerTokenExpires;

    private DemoDriver(Map<String, String> args) {
        this.args = args;
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15));
        String cacert = args.get("cacert");
        if (cacert != null) {
            builder.sslContext(SslContexts.fromPem(Path.of(cacert)));
        }
        this.client = builder.build();
    }

    public static void main(String[] argv) {
        System.exit(new DemoDriver(parseArgs(argv)).run());
    }

    private static Map<String, String> parseArgs(String[] argv) {
        Map<String, String> args = new LinkedHashMap<>();
        args.put("act", "all");
        args.put("gateway", "https://gateway.uma.lab/mcp");
        args.put("as-internal", "https://alice-as.uma.lab");
        args.put("cacert", "certs/rootCA.pem");
        args.put("keystore", "keys/agent-stable-key.pem");
        args.put("oidc-issuer", "https://keycloak.uma.lab/realms/alice");
        args.put("alice-username", env("ALICE_USERNAME", "alice"));
        args.put("alice-password", env("ALICE_PASSWORD", "alice-demo"));
        args.put("agent-issuer", "https://ps.uma.lab");
        args.put("person-token", env("PS_ADMIN_TOKEN", "uma4agents-ps-admin"));
        for (int i = 0; i < argv.length; i++) {
            String arg = argv[i];
            if (!arg.startsWith("--")) {
                continue;
            }
            String key = arg.substring(2);
            if (key.equals("simulate-alice") || key.equals("pseudonymous")) {
                args.put(key, "true");
            } else if (i + 1 < argv.length) {
                args.put(key, argv[++i]);
            }
        }
        return args;
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static void say(String msg) {
        System.out.println("   " + msg);
    }

    private int run() {
        AgentKeys keys;
        if (args.containsKey("pseudonymous")) {
            keys = AgentKeys.loadOrCreate(Path.of(args.get("keystore")));
            say("running pseudonymously: the bare agent key is the identity");
        } else {
            System.out.println("\n== Prologue: Bob's agent enrolls with his agent server ==");
            keys = AgentKeys.loadOrCreateIdentified(Path.of(args.get("keystore")));
            try {
                keys.agentToken = EnrollClient.enroll(client, args.get("agent-issuer"),
                        keys.stable, keys.key, "Bob's advisory agent (Sterling & Vance)",
                        args.get("person-token"), DemoDriver::say, 300, 3);
                say("aa-agent+jwt in hand from " + args.get("agent-issuer")
                        + "; contracts will carry it");
            } catch (EnrollClient.EnrollmentDeniedException e) {
                System.out.println("enrollment failed: " + e.getMessage());
                return 1;
            }
        }
        List<String> acts = "all".equals(args.get("act"))
                ? List.of("tier1", "tier2", "tier3") : List.of(args.get("act"));

        McpSession session = new McpSession(client, args.get("gateway"));
        session.initialize();
        say("MCP session established through the gateway (discovery is open)");

        try {
            if (acts.contains("tier1")) {
                System.out.println(
                        "\n== Act 1 (midday): Bob's agent requests Alice's holdings summary ==");
                System.out.println(
                        "   (first contact: an unconnected agent pends until Alice connects it)");
                CallResult out = callTool(session, keys, "get_positions", Map.of(), null);
                showResult(out.payload());
            }
            if (acts.contains("tier2")) {
                System.out.println(
                        "\n== Act 2 (midday): transaction history — watch the terms tighten ==");
                CallResult out = callTool(session, keys, "get_transactions",
                        Map.of("account", "brokerage-main"), null);
                showResult(out.payload());
            }
            if (acts.contains("tier3")) {
                System.out.println(
                        "\n== Act 3 (afternoon): the market moves — Bob's agent proposes a trade ==");
                Map<String, Object> order = new LinkedHashMap<>();
                order.put("symbol", "VTI");
                order.put("side", "sell");
                order.put("quantity", 40);
                Map<String, Object> operation = new LinkedHashMap<>();
                operation.put("tool", "execute_trade");
                operation.put("params", order);
                CallResult out = callTool(session, keys, "execute_trade", order, operation);
                showResult(out.payload());

                System.out.println("\n== Act 3 epilogue: the same RPT, tried again ==");
                Map<String, String> headers = GrantClient.signedHeaders(
                        "POST", GATEWAY_AUTHORITY, MCP_PATH, out.rpt(), keys);
                Map<String, Object> params = new LinkedHashMap<>();
                params.put("name", "execute_trade");
                params.put("arguments", order);
                McpSession.Reply reply = session.request("tools/call", params, headers, false);
                say(reply.status() + ": single-use grant is consumed — approval permitted "
                        + "one walk through the door");
                if (reply.status() == 200) {
                    System.out.println("FAIL: single-use RPT was accepted twice");
                    return 1;
                }
            }
        } catch (GrantClient.GrantDeniedException | GrantClient.TermsRejectedException e) {
            System.out.println("grant denied: " + e.getMessage());
            return 1;
        }

        System.out.println("\nPASS: the requested acts completed");
        return 0;
    }

    private record CallResult(Map<String, Object> payload, String rpt) {}

    /** tools/call with the full grant dance on 401. */
    private CallResult callTool(McpSession session, AgentKeys keys, String tool,
                                Map<String, Object> toolArgs, Map<String, Object> operation) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", tool);
        params.put("arguments", toolArgs);
        McpSession.Reply reply = session.request("tools/call", params, null, false);
        if (reply.status() == 200) {
            return new CallResult(reply.payload(), null);
        }

        GrantClient.Challenge challenge = GrantClient.Challenge.parse(reply.wwwAuthenticate());
        if (reply.status() != 401 || challenge == null) {
            throw new IllegalStateException("unexpected response: " + reply.status()
                    + " " + reply.raw().substring(0, Math.min(200, reply.raw().length())));
        }
        say("challenged: 401 from the gateway, ticket "
                + challenge.ticket().substring(0, Math.min(20, challenge.ticket().length()))
                + "…, AS " + challenge.asUri());

        // First contact pends as a connection request regardless of tier; ask-me
        // tiers pend per operation. The simulated Alice approves whatever lands.
        if (args.containsKey("simulate-alice")) {
            Thread approver = new Thread(this::approveWhenPending);
            approver.setDaemon(true);
            approver.start();
        }

        String rpt = GrantClient.runGrant(client, challenge.asUri(), challenge.ticket(), keys,
                this::approveTerms, operation, DemoDriver::say, DemoDriver::holdReceipt, 120);

        Map<String, String> headers = GrantClient.signedHeaders(
                "POST", GATEWAY_AUTHORITY, MCP_PATH, rpt, keys);
        reply = session.request("tools/call", params, headers, false);
        if (reply.status() != 200) {
            throw new IllegalStateException("authorized call failed: " + reply.status()
                    + " " + reply.raw().substring(0, Math.min(300, reply.raw().length())));
        }
        return new CallResult(reply.payload(), rpt);
    }

    /** Bob's standing terms policy: what he accepts without being asked. */
    private boolean approveTerms(Map<String, Object> template) {
        long expiresIn = template.get("expires_in") instanceof Number n ? n.longValue() : 0;
        boolean ok = expiresIn <= STANDING_MAX_EXPIRES;
        say("[bob-standing-config] terms " + (ok ? "accepted" : "refused")
                + ": purpose='" + template.get("purpose") + "' expires_in=" + expiresIn
                + " prohibited=" + template.get("prohibited"));
        return ok;
    }

    private static void holdReceipt(String receiptJws) {
        try {
            String payload = receiptJws.split("\\.")[1];
            int pad = (4 - payload.length() % 4) % 4;
            Map<String, Object> claims = MAPPER.readValue(
                    Base64.getUrlDecoder().decode(payload + "=".repeat(pad)),
                    new TypeReference<>() {});
            String agreement = String.valueOf(claims.get("agreement"));
            say("receipt held (both sides now have the record): terms "
                    + claims.get("terms_uri") + " · agreement "
                    + agreement.substring(0, Math.min(20, agreement.length())) + "…");
        } catch (Exception e) {
            say("receipt held (unparsed): " + e.getMessage());
        }
    }

    /** Polls /owner/pending as the simulated Alice and approves the first item. */
    private void approveWhenPending() {
        try {
            for (int i = 0; i < 40; i++) {
                Thread.sleep(1500);
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(args.get("as-internal") + "/owner/pending"))
                        .header("Authorization", "Bearer " + ownerToken())
                        .GET().build();
                HttpResponse<String> response =
                        client.send(request, HttpResponse.BodyHandlers.ofString());
                List<Map<String, Object>> pending = MAPPER.readValue(response.body(),
                        new TypeReference<>() {});
                if (!pending.isEmpty()) {
                    Map<String, Object> p = pending.get(0);
                    say("[simulated-alice] approving " + p.get("kind") + " request "
                            + p.get("family") + " from the couch");
                    HttpRequest decide = HttpRequest.newBuilder()
                            .uri(URI.create(args.get("as-internal") + "/owner/pending/"
                                    + p.get("family") + "/decision"))
                            .header("Authorization", "Bearer " + ownerToken())
                            .header("content-type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    "{\"decision\": \"approved\"}"))
                            .build();
                    client.send(decide, HttpResponse.BodyHandlers.ofString());
                    return;
                }
            }
        } catch (Exception e) {
            say("[simulated-alice] approver stopped: " + e.getMessage());
        }
    }

    /** The simulated Alice authenticates like the real one (direct-access grant). */
    private synchronized String ownerToken() throws Exception {
        if (ownerAccessToken != null && ownerTokenExpires > Instant.now().getEpochSecond() + 15) {
            return ownerAccessToken;
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "password");
        form.put("client_id", "alice-portal");
        form.put("username", args.get("alice-username"));
        form.put("password", args.get("alice-password"));
        String encoded = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(args.get("oidc-issuer") + "/protocol/openid-connect/token"))
                .header("content-type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(encoded))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Alice login failed: " + response.statusCode());
        }
        Map<String, Object> body = MAPPER.readValue(response.body(), new TypeReference<>() {});
        ownerAccessToken = (String) body.get("access_token");
        long expiresIn = body.get("expires_in") instanceof Number n ? n.longValue() : 60;
        ownerTokenExpires = Instant.now().getEpochSecond() + expiresIn;
        say("[simulated-alice] logged in at her IdP (direct-access grant)");
        return ownerAccessToken;
    }

    private static void showResult(Map<String, Object> payload) {
        try {
            Object result = payload.get("result");
            Object content = ((Map<?, ?>) result).get("content");
            Object text = ((Map<?, ?>) ((List<?>) content).get(0)).get("text");
            Map<String, Object> data = MAPPER.readValue((String) text, new TypeReference<>() {});
            String json = MAPPER.writeValueAsString(data);
            say("data received: " + json.substring(0, Math.min(140, json.length())) + "…");
        } catch (Exception e) {
            try {
                String json = MAPPER.writeValueAsString(payload);
                say("result: " + json.substring(0, Math.min(200, json.length())));
            } catch (tools.jackson.core.JacksonException ignored) {
                say("result: " + payload);
            }
        }
    }
}
