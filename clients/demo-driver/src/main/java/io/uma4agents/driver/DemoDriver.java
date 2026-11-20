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

    private static final GrantClient.Target TARGET =
            new GrantClient.Target("POST", "gateway.uma.lab", "/mcp");
    private static final long STANDING_MAX_EXPIRES = 7L * 24 * 3600;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, String> args;
    private final HttpClient client;
    private Map<String, Object> prm;
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
                ? List.of("tier1", "tier2", "tier3", "revocation") : List.of(args.get("act"));

        // Beat 0 — declarative discovery (RFC 9728). Before touching a tool,
        // the agent reads the resource's published metadata: who the
        // authorization server is, and which tool surfaces are protected under
        // which scopes.
        System.out.println(
                "\n== Beat 0: the agent discovers the resource's shape (RFC 9728) ==");
        String prmUrl = GrantClient.wellKnownPrmUrl(args.get("gateway"));
        try {
            prm = GrantClient.validateResourceMetadata(
                    getJson(prmUrl), args.get("gateway"), null, null);
        } catch (Exception e) {
            System.out.println("resource metadata unavailable: " + e.getMessage());
            return 1;
        }
        say("resource metadata at " + prmUrl + " (signed: "
                + (prm.get("signed_metadata") != null ? "yes" : "no") + ")");
        say("authorization server(s): " + joined(prm.get("authorization_servers")));
        if (prm.get("tool_surfaces") instanceof List<?> surfaces) {
            for (Object surface : surfaces) {
                if (surface instanceof Map<?, ?> ts) {
                    say("tool surface: " + ts.get("tool")
                            + " (scopes " + joined(ts.get("resource_scopes")) + ")");
                }
            }
        }
        say("note: which resources belong to whom is not in the public document —"
                + " owner instances live behind the protected owner-resources endpoint");

        McpSession session = new McpSession(client, args.get("gateway"));
        session.initialize();
        say("MCP session established through the gateway (discovery is open)");

        try {
            if (acts.contains("tier1")) {
                System.out.println(
                        "\n== Act 1 (midday): Bob's agent requests Alice's holdings summary ==");
                System.out.println(
                        "   (first contact: an unconnected agent pends until Alice connects it)");
                CallResult out = callTool(session, keys, "get_positions", Map.of(), null, null);
                showResult(out.payload());
            }
            if (acts.contains("tier2")) {
                System.out.println(
                        "\n== Act 2 (midday): transaction history — watch the terms tighten ==");
                CallResult out = callTool(session, keys, "get_transactions",
                        Map.of("account", "brokerage-main"), null, null);
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

                // Between the grant and its one legitimate use, someone who has
                // seen the token replays it without the agent's key. A
                // single-use grant must survive that: if the resource spends
                // the token before checking the signature, anyone who can
                // observe it can destroy the approval Alice just gave.
                boolean[] replayHeld = {false};
                java.util.function.Consumer<String> replayWithStolenToken = rpt -> {
                    System.out.println(
                            "\n== Act 3 interlude: someone replays the grant unsigned ==");
                    Map<String, String> stolen = GrantClient.signedHeaders(TARGET, rpt, keys, null);
                    // Must match signedHeaders' exact key casing — a lowercase
                    // "signature" is a second header, not an override, and the
                    // forgery silently never happens.
                    stolen.put("Signature", "sig1=:" + "A".repeat(86) + ":");
                    Map<String, Object> params = new LinkedHashMap<>();
                    params.put("name", "execute_trade");
                    params.put("arguments", order);
                    McpSession.Reply r = session.request("tools/call", params, stolen, false);
                    say(r.status() + ": replay rejected — proof-of-possession failed");
                    replayHeld[0] = r.status() == 401;
                };

                CallResult out = callTool(session, keys, "execute_trade", order, operation,
                        replayWithStolenToken);
                if (!replayHeld[0]) {
                    System.out.println("FAIL: a forged signature was not rejected with 401");
                    return 1;
                }
                say("Alice's approval survived the replay — the honest call went through");
                showResult(out.payload());

                System.out.println("\n== Act 3 epilogue: the same RPT, tried again ==");
                Map<String, String> headers = GrantClient.signedHeaders(TARGET, out.rpt(), keys, null);
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
            if (acts.contains("revocation")) {
                int result = actRevocation(session, keys);
                if (result != 0) {
                    return result;
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

    /**
     * tools/call with the full grant dance on 401. {@code onGrant}, if given,
     * runs after the RPT is issued but before the authorized call — the window
     * where a replay attack would land.
     */
    private CallResult callTool(McpSession session, AgentKeys keys, String tool,
                                Map<String, Object> toolArgs, Map<String, Object> operation,
                                java.util.function.Consumer<String> onGrant) {
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

        // Corroborate the (unauthenticated) challenge header against the
        // resource's TLS-anchored published metadata before negotiating.
        if (prm != null) {
            try {
                GrantClient.validateResourceMetadata(prm, args.get("gateway"),
                        challenge.asUri(), challenge.resourceMetadata());
                say("challenge corroborated: as_uri is among the resource's "
                        + "published authorization servers");
            } catch (GrantClient.DiscoveryMismatchException e) {
                throw new IllegalStateException("refusing to negotiate: " + e.getMessage());
            }
        }

        // First contact pends as a connection request regardless of tier; ask-me
        // tiers pend per operation. The simulated Alice approves whatever lands.
        if (args.containsKey("simulate-alice")) {
            Thread approver = new Thread(this::approveWhenPending);
            approver.setDaemon(true);
            approver.start();
        }

        String rpt = GrantClient.runGrant(client, challenge, keys,
                new GrantClient.Contribution(operation, null, null), new GrantClient.Negotiator() {
                    @Override
                    public boolean approveTerms(Map<String, Object> template) {
                        return DemoDriver.this.approveTerms(template);
                    }

                    @Override
                    public void status(String message) {
                        say(message);
                    }

                    @Override
                    public void receipt(String jws) {
                        holdReceipt(jws);
                    }
                });

        if (onGrant != null) {
            onGrant.accept(rpt);
        }

        Map<String, String> headers = GrantClient.signedHeaders(TARGET, rpt, keys, null);
        reply = session.request("tools/call", params, headers, false);
        if (reply.status() != 200) {
            throw new IllegalStateException("authorized call failed: " + reply.status()
                    + " " + reply.raw().substring(0, Math.min(300, reply.raw().length())));
        }
        return new CallResult(reply.payload(), rpt);
    }

    /** Act 4: Alice revokes the agent; enforcement must answer terminally. */
    private int actRevocation(McpSession session, AgentKeys keys) {
        System.out.println("\n== Act 4 (evening): Alice revokes the agent ==");
        CallResult out = callTool(session, keys, "get_positions", Map.of(), null, null);
        say("agent holds a live grant for the holdings summary");

        String handle;
        int deactivated;
        try {
            List<Map<String, Object>> conns = ownerGet("/owner/connections");
            handle = conns.stream()
                    .filter(c -> "active".equals(c.get("status")))
                    .map(c -> (String) c.get("handle"))
                    .findFirst().orElse(null);
            if (handle == null) {
                System.out.println("FAIL: no active connection to revoke");
                return 1;
            }
            Map<String, Object> revoked = ownerPost("/owner/connections/revoke",
                    MAPPER.writeValueAsString(Map.of("handle", handle)));
            deactivated = revoked.get("rpts_deactivated") instanceof Number n
                    ? n.intValue() : 0;
        } catch (Exception e) {
            System.out.println("FAIL: revocation via the owner API failed: " + e.getMessage());
            return 1;
        }
        say("[alice] revoked " + handle.substring(0, Math.min(24, handle.length()))
                + "… — " + deactivated + " live grant(s) deactivated");

        // A revoked relationship is a decision the owner already made.
        // Answering 401 would invite the agent to negotiate again for an
        // outcome that is settled, so enforcement has to say so terminally.
        Map<String, String> sig = GrantClient.signedHeaders(TARGET, out.rpt(), keys, null);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", "get_positions");
        params.put("arguments", Map.of());
        McpSession.Reply reply = session.request("tools/call", params, sig, false);
        say(reply.status() + ": "
                + reply.raw().substring(0, Math.min(80, reply.raw().length())));
        if (reply.status() != 403) {
            System.out.println("FAIL: revoked agent got " + reply.status()
                    + ", expected a terminal 403");
            return 1;
        }
        say("revocation is terminal — not an invitation to re-negotiate");
        return 0;
    }

    private Map<String, Object> getJson(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).GET().build();
        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " from " + url);
        }
        return MAPPER.readValue(response.body(), new TypeReference<>() {});
    }

    private static String joined(Object values) {
        return values instanceof List<?> list
                ? list.stream().map(String::valueOf).collect(Collectors.joining(", "))
                : String.valueOf(values);
    }

    private List<Map<String, Object>> ownerGet(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(args.get("as-internal") + path))
                .header("Authorization", "Bearer " + ownerToken())
                .GET().build();
        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
        return MAPPER.readValue(response.body(), new TypeReference<>() {});
    }

    private Map<String, Object> ownerPost(String path, String json) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(args.get("as-internal") + path))
                .header("Authorization", "Bearer " + ownerToken())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new IllegalStateException("HTTP " + response.statusCode() + " from " + path);
        }
        return MAPPER.readValue(response.body(), new TypeReference<>() {});
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
        form.put("client_id", "meridian-portal");
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
