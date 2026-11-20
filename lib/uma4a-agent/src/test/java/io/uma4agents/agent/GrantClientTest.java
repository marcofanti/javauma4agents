package io.uma4agents.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.uma4agents.agent.GrantClient.Challenge;
import io.uma4agents.agent.GrantClient.DiscoveryMismatchException;
import io.uma4agents.agent.GrantClient.Negotiator;
import io.uma4agents.agent.GrantClient.PendingHandbackException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** JUnit port of the Phase A cases of the pinned {@code lib/test_client.py}, plus the pend. */
class GrantClientTest {

    private static final String RES = "https://rs.example/mcp";
    private static final Map<String, Object> PRM =
            Map.of("resource", RES, "authorization_servers", List.of("https://as.example"));

    private static String receipt(String familyJson) {
        String body = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"family\": " + familyJson + "}").getBytes(StandardCharsets.UTF_8));
        return "header." + body + ".signature";
    }

    @Test
    void receiptIsKeptUnderItsNegotiationsNameOnly() {
        assertEquals("fam_Ab3-x_9.receipt.jws",
                GrantClient.receiptFilename(receipt("\"fam_Ab3-x_9\"")));
        for (String family : List.of("\"../escaped\"", "\"/etc/cron.d/job\"", "\"a/b\"",
                "\"..\"", "\"\"", "null")) {
            assertEquals("unknown.receipt.jws", GrantClient.receiptFilename(receipt(family)),
                    family);
        }
        assertEquals("unknown.receipt.jws", GrantClient.receiptFilename("not-a-receipt"));
    }

    @Test
    void challengeIsCorroboratedOnlyAgainstTheResourceCalled() {
        assertSame(PRM, GrantClient.validateResourceMetadata(PRM, RES, "https://as.example",
                "https://rs.example/.well-known/oauth-protected-resource/mcp"));
        assertTrue(assertThrows(DiscoveryMismatchException.class,
                () -> GrantClient.validateResourceMetadata(PRM, RES, "https://evil.example", null))
                .getMessage().contains("does not publish"));
        assertTrue(assertThrows(DiscoveryMismatchException.class,
                () -> GrantClient.validateResourceMetadata(PRM, RES, "https://as.example",
                        "https://evil.example/.well-known/oauth-protected-resource/mcp"))
                .getMessage().contains("names metadata"));
        Map<String, Object> other = new HashMap<>(PRM);
        other.put("resource", "https://other.example/mcp");
        assertTrue(assertThrows(DiscoveryMismatchException.class,
                () -> GrantClient.validateResourceMetadata(other, RES, null, null))
                .getMessage().contains("metadata is for"));
    }

    @Test
    void refusalsAreFinalExceptUnavailability() {
        assertEquals(new GrantClient.Refusal("temporarily_unavailable", false),
                GrantClient.refusal(503, Map.of("error", "temporarily_unavailable")));
        assertEquals(new GrantClient.Refusal("something_added_later", true),
                GrantClient.refusal(403, Map.of("error", "something_added_later")));
        assertEquals(new GrantClient.Refusal("consequence_changed", true),
                GrantClient.refusal(200, Map.of("error", Map.of("code", -32002,
                        "data", Map.of("error", "consequence_changed")))));
        assertEquals(new GrantClient.Refusal("http_502", true),
                GrantClient.refusal(502, null));
    }

    @Test
    void inBandChallengeIsRecognisedAndOrdinaryErrorsAreNot() {
        Map<String, Object> emitted = Map.of("jsonrpc", "2.0", "id", 1, "error", Map.of(
                "code", -32001, "message", "authorization required",
                "data", Map.of("error", "insufficient_authorization",
                        "as_uri", "https://alice-as.example", "ticket", "tkt-1",
                        "resource_metadata", "https://rs.example/prm")));
        Challenge c = GrantClient.jsonRpcChallenge(emitted);
        assertEquals("https://alice-as.example", c.asUri());
        assertEquals("tkt-1", c.ticket());
        assertNull(GrantClient.jsonRpcChallenge(
                Map.of("error", Map.of("code", -32602, "message", "bad params"))));
    }

    @Test
    void wellKnownUrlKeepsAnExplicitPort() {
        assertEquals("http://h:9020/.well-known/oauth-protected-resource/mcp",
                GrantClient.wellKnownPrmUrl("http://h:9020/mcp/"));
    }

    @Test
    void keyIdIsDerivedFromTheKeyAndStableAcrossLoads(@TempDir Path dir) {
        Path pem = dir.resolve("agent.pem");
        AgentKeys first = AgentKeys.loadOrCreate(pem);
        AgentKeys again = AgentKeys.loadOrCreate(pem);
        assertTrue(first.keyid.matches("agent-[A-Za-z0-9_-]{16}"), first.keyid);
        assertEquals(first.keyid, again.keyid);
        assertTrue(first.thumbprint().startsWith("jkt:"));
    }

    /** A token endpoint that keeps a pend outstanding and records what it was sent. */
    private static HttpServer pendingAuthority(List<String> forms) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", ex -> {
            forms.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] out = "{\"error\":\"request_submitted\",\"ticket\":\"tkt-same\",\"interval\":0}"
                    .getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(403, out.length);
            try (OutputStream o = ex.getResponseBody()) {
                o.write(out);
            }
        });
        server.start();
        return server;
    }

    @Test
    void aPendOutlastingTheBudgetIsHandedBackWithItsTicket(@TempDir Path dir) throws IOException {
        List<String> forms = new ArrayList<>();
        HttpServer server = pendingAuthority(forms);
        try {
            String as = "http://127.0.0.1:" + server.getAddress().getPort();
            AgentKeys keys = AgentKeys.loadOrCreate(dir.resolve("k.pem"));
            Negotiator handsBack = new Negotiator() {
                @Override
                public boolean approveTerms(Map<String, Object> template) {
                    return true;
                }

                @Override
                public boolean keepWaiting(GrantClient.Pend pend) {
                    throw new PendingHandbackException(pend.asUri(), pend.ticket());
                }

                @Override
                public long maxWaitSeconds() {
                    return 0;
                }
            };
            PendingHandbackException e = assertThrows(PendingHandbackException.class,
                    () -> GrantClient.runGrant(HttpClient.newHttpClient(),
                            new Challenge(as, "tkt-first", null), keys,
                            GrantClient.Contribution.none(), handsBack));
            assertEquals("tkt-same", e.ticket());
            assertEquals(as, e.asUri());
            assertTrue(forms.get(0).contains("ticket=tkt-first"));
        } finally {
            server.stop(0);
        }
    }
}
