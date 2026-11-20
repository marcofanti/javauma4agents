package io.uma4agents.pep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJson;
import io.uma4agents.common.S256;
import io.uma4agents.pep.core.Decision.Outcome;
import io.uma4agents.pep.core.EnforcerSettings.ToolSurface;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/** JUnit port of the Phase A cases of the pinned {@code lib/test_pep.py}. */
class EnforcerTest {

    private static final KeyPair AGENT = EdDsa.generate();
    private static final KeyPair INTRUDER = EdDsa.generate();
    private static final String METADATA =
            "https://rs.example/.well-known/oauth-protected-resource/mcp";

    /** The authority, answering with fixed values; nothing reaches the network. */
    static final class Authority extends ProtectionClient {
        Map<String, Object> info;
        Map<String, Object> spend = Map.of("consumed", true);
        String ticket = "tkt-1";
        int consumed;
        int reported;
        EnforcerSettings settingsForTest;

        Authority(EnforcerSettings settings, Map<String, Object> info) {
            super(settings, new EventLog("test"));
            this.info = info;
        }

        @Override
        public Map<String, Object> introspect(String token) {
            return info;
        }

        @Override
        public Map<String, Object> consume(String token) {
            consumed++;
            return spend;
        }

        @Override
        public void reportAccess(String family, String tool, String summary) {
            reported++;
        }

        @Override
        public String mintTicket(String resourceId, List<String> scopes) {
            return ticket;
        }
    }

    private static EnforcerSettings settings(Set<String> origins, boolean requireDigest) {
        Map<String, ToolSurface> tools = new LinkedHashMap<>();
        tools.put("get_positions",
                new ToolSurface("alice-vault/get_positions", List.of("positions:read")));
        tools.put("execute_trade",
                new ToolSurface("alice-vault/execute_trade", List.of("trades:execute")));
        return new EnforcerSettings("alice", "http://uma-as.invalid:9000",
                "https://alice-as.example", "rs", "", "alice-vault", tools,
                Set.of("execute_trade"), Set.of("tools/call"),
                Set.of("initialize", "tools/list", "server/discover"), "rs.example", origins,
                METADATA, requireDigest);
    }

    private static Enforcer enforcer(Authority authority) {
        return new Enforcer(authority.settingsForTest, authority, new EventLog("test"));
    }

    private static Authority authority(Map<String, Object> info) {
        return authority(info, false);
    }

    private static Authority authority(Map<String, Object> info, boolean requireDigest) {
        EnforcerSettings s = settings(Set.of(), requireDigest);
        Authority a = new Authority(s, info);
        a.settingsForTest = s;
        return a;
    }

    private static AuthzFacts.Builder facts(String tool) {
        return AuthzFacts.builder()
                .mcp(new McpRequest("tools/call", tool, Map.of(), null))
                .headerMcpMethod("tools/call").headerMcpName(tool)
                .protocolVersion("2026-07-28");
    }

    private static Decision decide(Enforcer e, AuthzFacts f) {
        return e.authorize(f);
    }

    private static Decision present(Authority a, String tool, Map<String, Object> args,
                                    KeyPair key, byte[] body, byte[] sent) {
        String authorization = "PoP grant";
        Map<String, String> h = HttpSignature.sign("POST", "rs.example", "/mcp", authorization,
                key.getPrivate(), "agent", HttpSignature.SignOptions.none().withBody(body));
        AuthzFacts f = AuthzFacts.builder()
                .mcp(new McpRequest("tools/call", tool, args, null))
                .headerMcpMethod("tools/call").headerMcpName(tool)
                .protocolVersion("2026-07-28").authorization(authorization)
                .signature(h.get("Signature")).signatureInput(h.get("Signature-Input"))
                .body(sent != null ? sent : body).contentDigest(h.get("Content-Digest"))
                .build();
        return enforcer(a).authorize(f);
    }

    private static Decision present(Authority a) {
        return present(a, "get_positions", Map.of(), AGENT, null, null);
    }

    private static Map<String, Object> grant(String rid, List<String> scopes) {
        long at = Instant.now().getEpochSecond();
        Map<String, Object> perm = new LinkedHashMap<>();
        perm.put("resource_id", rid);
        perm.put("resource_scopes", scopes);
        perm.put("exp", at + 300);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("active", true);
        out.put("family", "fam_g");
        out.put("exp", at + 300);
        out.put("cnf", Map.of("jwk", Jwks.okpPublicJwk(AGENT.getPublic())));
        out.put("permissions", new ArrayList<>(List.of(perm)));
        return out;
    }

    private static Map<String, Object> grant() {
        return grant("alice-vault/get_positions", List.of("positions:read"));
    }

    private static String s256(String canonical) {
        return S256.of(canonical.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void refusesBeforeAnyoneIsAsked() {
        Enforcer e = new Enforcer(settings(Set.of("https://rs.example"), false),
                authority(Map.of()), new EventLog("test"));
        Decision open = decide(e, AuthzFacts.builder()
                .mcp(new McpRequest("tools/list", null, null, null))
                .headerMcpMethod("tools/list").protocolVersion("2026-07-28").build());
        assertEquals(Outcome.ALLOW, open.outcome());
        Decision unknown = decide(e, AuthzFacts.builder()
                .mcp(new McpRequest("tasks/get", null, null, null))
                .headerMcpMethod("tasks/get").protocolVersion("2026-07-28").build());
        assertEquals("unknown_method", unknown.error());
        assertEquals("header_body_mismatch",
                decide(e, facts("get_positions").headerMcpMethod("tools/list").build()).error());
        assertEquals("header_body_mismatch", decide(e,
                facts("get_positions").headerMcpName("get_transactions").build()).error());
        Decision missing = decide(e, facts("get_positions").headerMcpMethod(null)
                .headerMcpName(null).build());
        assertEquals("missing_routing_headers", missing.error());
        assertEquals(400, missing.status());
        assertEquals("invalid_origin", decide(e,
                facts("get_positions").origin("https://evil.example").build()).error());
        assertEquals("invalid_token", decide(e,
                facts("get_positions").authorization("Bearer not-a-pop-token").build()).error());
        assertEquals("unknown_tool", decide(e, facts("nonexistent").build()).error());
    }

    @Test
    void aBodyWithNoReadableMethodIsAnUnknownMethodNotAnError() {
        Enforcer e = enforcer(authority(Map.of()));
        Decision d = e.authorize(AuthzFacts.builder()
                .mcp(McpRequest.parse("not json".getBytes(StandardCharsets.UTF_8)))
                .protocolVersion("2026-07-28").build());
        assertEquals(403, d.status());
        assertEquals("unknown_method", d.error());
        assertEquals("None is not enforceable by this PEP", d.description());
    }

    @Test
    void anEmptyOriginAllowListRefusesEveryOriginButNotItsAbsence() {
        Enforcer e = new Enforcer(settings(Set.of(), false), authority(Map.of()),
                new EventLog("test"));
        assertEquals("invalid_origin", e.originRefused("https://gateway.uma.lab").error());
        assertEquals(null, e.originRefused(null));
        assertEquals(null, e.originRefused(""));
    }

    @Test
    void olderProtocolVersionsNeedNoRoutingHeaders() {
        Authority a = authority(Map.of());
        Decision d = enforcer(a).authorize(facts("get_positions").headerMcpMethod(null)
                .headerMcpName(null).protocolVersion("2025-11-25").build());
        assertEquals(Outcome.CHALLENGE, d.outcome());
    }

    @Test
    void challengeIsTheSameObjectInBothEnvelopes() throws Exception {
        Authority a = authority(Map.of());
        Enforcer e = enforcer(a);
        Decision ch = e.authorize(facts("execute_trade").build());
        assertEquals(Outcome.CHALLENGE, ch.outcome());
        String header = e.wwwAuthenticate(ch);
        Map<String, String> params = new LinkedHashMap<>();
        for (String part : header.substring("UMA ".length()).split(", ")) {
            String[] kv = part.split("=", 2);
            params.put(kv[0], kv[1].replaceAll("^\"|\"$", ""));
        }
        for (String k : List.of("realm", "error", "as_uri", "ticket", "resource_metadata",
                "scope", "authorization_remediation")) {
            assertTrue(params.containsKey(k), k + " missing from " + header);
        }
        assertEquals("insufficient_authorization", params.get("error"));
        byte[] blob = Base64.getUrlDecoder().decode(params.get("authorization_remediation"));
        Map<?, ?> decoded = new ObjectMapper().readValue(blob, Map.class);
        Map<String, Object> remediation = Enforcer.remediation(ch);
        assertEquals(new ObjectMapper().readValue(
                PyJson.compactOrdered(remediation), Map.class), decoded);
        assertEquals("https://alice-as.example", decoded.get("authorization_server"));
        assertEquals("tkt-1", decoded.get("ticket"));
        Map<String, Object> rpc = e.jsonRpcError(ch);
        assertEquals(Enforcer.UMA_CHALLENGE, rpc.get("code"));
        Map<?, ?> data = (Map<?, ?>) rpc.get("data");
        assertEquals(remediation, data.get("authorization_remediation"));
        assertEquals("trades:execute", data.get("scope"));
        String reference = s256(PyJson.compactSortedUnicode(ch.authorizationDetails()));
        assertEquals(reference, ch.authorizationReference());
    }

    @Test
    void ticketFailureIsUnavailableNotAChallenge() {
        Authority a = authority(Map.of());
        a.ticket = null;
        Decision d = enforcer(a).authorize(facts("get_positions").build());
        assertEquals(503, d.status());
        assertEquals("temporarily_unavailable", d.error());
    }

    @Test
    void grantMustCoverResourceScopeAndTime() {
        Authority honouring = authority(grant());
        assertEquals(Outcome.ALLOW, present(honouring).outcome());
        assertEquals(1, honouring.reported);
        Decision intruder = present(authority(grant()), "get_positions", Map.of(), INTRUDER,
                null, null);
        assertEquals("invalid_token", intruder.error());
        assertEquals(Outcome.CHALLENGE,
                present(authority(grant("alice-vault/get_positions", List.of()))).outcome());
        Map<String, Object> expired = grant();
        permission(expired).put("exp", Instant.now().getEpochSecond() - 5);
        assertEquals(Outcome.CHALLENGE, present(authority(expired)).outcome());
        Map<String, Object> early = grant();
        permission(early).put("nbf", Instant.now().getEpochSecond() + 600);
        assertEquals(Outcome.CHALLENGE, present(authority(early)).outcome());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> permission(Map<String, Object> grant) {
        List<Object> perms = (List<Object>) grant.get("permissions");
        Map<String, Object> copy = new LinkedHashMap<>((Map<String, Object>) perms.get(0));
        perms.set(0, copy);
        return copy;
    }

    @Test
    void operationBindingFollowsTheGrant() {
        Map<String, Object> trade = new LinkedHashMap<>();
        trade.put("symbol", "VTI");
        trade.put("qty", 40);
        Map<String, Object> unbound = grant("alice-vault/execute_trade", List.of("trades:execute"));
        unbound.put("single_use", true);
        assertEquals("operation_required",
                present(authority(unbound), "execute_trade", trade, AGENT, null, null).error());

        Map<String, Object> bound = grant("alice-vault/execute_trade", List.of("trades:execute"));
        bound.put("single_use", true);
        bound.put("operation", Map.of("tool", "execute_trade",
                "params_s256", s256("{\"qty\":40,\"symbol\":\"VTI\"}")));
        Authority spending = authority(bound);
        assertEquals(Outcome.ALLOW,
                present(spending, "execute_trade", trade, AGENT, null, null).outcome());
        assertEquals(1, spending.consumed);

        Map<String, Object> once = grant();
        once.put("single_use", true);
        once.put("operation", Map.of("tool", "get_positions", "params_s256", s256("{}")));
        Authority marked = authority(once);
        assertEquals(Outcome.ALLOW, present(marked).outcome());
        assertEquals(1, marked.consumed);
        assertEquals("operation_mismatch", present(authority(once), "get_positions",
                Map.of("account", "someone-else"), AGENT, null, null).error());
    }

    @Test
    void unicodeArgumentsBindAsCPythonHashesThem() {
        Map<String, Object> args = Map.of("note", "café");
        Map<String, Object> once = grant();
        once.put("single_use", true);
        once.put("operation", Map.of("tool", "get_positions",
                "params_s256", s256("{\"note\":\"café\"}")));
        assertEquals(Outcome.ALLOW,
                present(authority(once), "get_positions", args, AGENT, null, null).outcome());
    }

    @Test
    void inactiveReasonsMapAsPinned() {
        for (String reason : List.of("expired", "unknown_token", "revoked", "already_consumed",
                "invalid_signature", "authorization_pending")) {
            assertEquals(Outcome.CHALLENGE,
                    present(authority(Map.of("active", false, "error", reason))).outcome(),
                    reason);
        }
        for (String reason : List.of("connection_revoked", "organization_revoked",
                "a_reason_from_a_later_draft")) {
            Decision d = present(authority(Map.of("active", false, "error", reason)));
            assertEquals("access_revoked", d.error(), reason);
        }
        Decision d = present(authority(Map.of("active", false,
                "error", "introspection_unavailable")));
        assertEquals(503, d.status());
    }

    @Test
    void spendOutcomesAreToldApart() {
        Map<String, Object> once = grant();
        once.put("single_use", true);
        once.put("operation", Map.of("tool", "get_positions", "params_s256", s256("{}")));
        Authority unreachable = authority(once);
        unreachable.spend = null;
        Decision d = present(unreachable);
        assertEquals(503, d.status());
        assertTrue(!"already_consumed".equals(d.error()));
        Authority lost = authority(once);
        lost.spend = Map.of("consumed", false, "error", "already_consumed");
        assertEquals("already_consumed", present(lost).error());
        Authority revoked = authority(once);
        revoked.spend = Map.of("consumed", false, "error", "connection_revoked");
        assertEquals("access_revoked", present(revoked).error());
    }

    @Test
    void coveredBodyMustArriveUnchanged() {
        byte[] body = "{\"arguments\":{}}".getBytes(StandardCharsets.UTF_8);
        assertEquals(Outcome.ALLOW,
                present(authority(grant()), "get_positions", Map.of(), AGENT, body, null)
                        .outcome());
        byte[] changed = "{\"arguments\":{\"all\":true}}".getBytes(StandardCharsets.UTF_8);
        assertEquals("invalid_token", present(authority(grant()), "get_positions", Map.of(),
                AGENT, body, changed).error());
        Authority strict = authority(grant(), true);
        String authorization = "PoP grant";
        Map<String, String> h = HttpSignature.sign("POST", "rs.example", "/mcp", authorization,
                AGENT.getPrivate(), "agent", HttpSignature.SignOptions.none());
        Decision d = enforcer(strict).authorize(facts("get_positions")
                .authorization(authorization).signature(h.get("Signature"))
                .signatureInput(h.get("Signature-Input")).body("{}".getBytes(
                        StandardCharsets.UTF_8)).build());
        assertEquals("invalid_token", d.error());
    }

    @Test
    void parsesMcpBodies() {
        McpRequest call = McpRequest.parse(("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":"
                + "\"tools/call\",\"params\":{\"name\":\"execute_trade\",\"arguments\":"
                + "{\"quantity\":10}}}").getBytes(StandardCharsets.UTF_8));
        assertEquals("tools/call", call.method());
        assertEquals("execute_trade", call.tool());
        assertEquals(10, ((Number) call.args().get("quantity")).intValue());
        assertEquals(3, call.id().intValue());
        McpRequest list = McpRequest.parse(
                "{\"method\":\"tools/list\"}".getBytes(StandardCharsets.UTF_8));
        assertEquals("tools/list", list.method());
        assertEquals(null, list.tool());
        assertEquals(null, McpRequest.parse("[1]".getBytes(StandardCharsets.UTF_8)).method());
        assertEquals(null, McpRequest.parse("not json".getBytes(StandardCharsets.UTF_8))
                .method());
    }
}
