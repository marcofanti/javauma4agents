package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.uma4agents.common.Consequence;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Phase D against CPython: every case in {@code phase-d-vectors.json} was produced by the
 * pinned {@code policy.py}, {@code assurance.py}, {@code introduction.py} and
 * {@code uma4a_consequence.py} ({@code make vectors}). Refusal text must match wherever
 * the pin raises {@code ValueError}; the few inputs on which the pin raises another
 * exception type (an HTTP 500 there) must still be refused here.
 */
class PhaseDVectorsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path VECTORS = Path.of(
            "../../lib/uma4a-common/src/test/resources/pinned/phase-d-vectors.json");
    private static JsonNode root;

    @BeforeAll
    static void load() throws Exception {
        root = MAPPER.readTree(Files.readString(VECTORS));
    }

    @SuppressWarnings("unchecked")
    private static <T> T java(JsonNode node) {
        return (T) MAPPER.convertValue(node, Object.class);
    }

    /** Both sides as JSON, so 9 and BigInteger 9 compare equal. */
    private static JsonNode json(Object value) {
        return MAPPER.readTree(MAPPER.writeValueAsString(value));
    }

    private static void refusedAsAtThePin(JsonNode c, Runnable call, String where) {
        RuntimeException e = assertThrows(RuntimeException.class, call::run, where);
        if ("ValueError".equals(c.get("type").asString())) {
            assertEquals(c.get("error").asString(), e.getMessage(), where);
        }
    }

    // --- her rules --------------------------------------------------------

    @Test
    void defaultsVocabularyEnforcedAndLanesAreThePins() {
        JsonNode policy = root.get("policy");
        assertEquals(policy.get("defaults"), json(PolicyService.defaults()));
        assertEquals(policy.get("vocabulary"), json(Rules.vocabulary()));
        PolicyService.defaults().forEach((id, tier) -> assertEquals(
                policy.get("enforced").get(id), json(PolicyService.enforcedProhibitions(tier)),
                id));
        for (JsonNode c : policy.get("lanes")) {
            assertEquals(c.get("lane").asString(),
                    PolicyService.pendLane(java(c.get("axes"))), c.toString());
        }
    }

    @Test
    void rulesSaveOrAreRefusedInTheSameWords() {
        for (JsonNode c : root.get("policy").get("validate")) {
            Object rules = java(c.get("rules"));
            if (c.has("ok")) {
                Rules.validate(rules);
            } else {
                refusedAsAtThePin(c, () -> Rules.validate(rules), c.toString());
            }
        }
    }

    @Test
    void everyEvaluationMatches() {
        int n = 0;
        for (JsonNode c : root.get("policy").get("evaluate")) {
            Map<String, Object> tier = java(c.get("tier"));
            Map<String, Object> facts = java(c.get("facts"));
            if (!c.has("ok")) {
                fail("the pin raised on " + c);
            }
            Rules.Outcome got = Rules.evaluate(tier, facts);
            List<Object> expected = java(c.get("ok"));
            assertEquals(expected.get(0), got.requirement(), c.toString());
            assertEquals(expected.get(1), got.because(), c.toString());
            n++;
        }
        assertTrue(n > 1000, "too few cases: " + n);
    }

    @Test
    void durationsParseAsCPythonParsesThem() {
        for (JsonNode c : root.get("policy").get("durations")) {
            String text = c.get("text").asString();
            if (c.has("ok")) {
                assertEquals(c.get("ok").bigIntegerValue(), Rules.parseDuration(text), text);
            } else {
                assertThrows(IllegalArgumentException.class, () -> Rules.parseDuration(text),
                        text);
            }
        }
    }

    @Test
    void newTiersAreBuiltOrRefusedAsAtThePin() {
        Map<String, Map<String, Object>> existing = Map.of("tier1",
                Map.of("resources", List.of("alice-vault/get_positions")));
        Set<String> registered = Set.of("alice-vault/get_positions",
                "alice-vault/get_transactions", "alice-vault/execute_trade");
        for (JsonNode c : root.get("policy").get("new_tier")) {
            String id = c.get("id").asString();
            Map<String, Object> spec = java(c.get("spec"));
            if (c.has("ok")) {
                assertEquals(c.get("ok"), json(PolicyService.newTier(id, spec, existing,
                        registered, Set.of(), "alice")), id);
            } else {
                refusedAsAtThePin(c, () -> PolicyService.newTier(id, spec, existing,
                        registered, Set.of(), "alice"), id);
            }
        }
    }

    @Test
    void ownerEditsApplyAsAtThePin() {
        for (JsonNode c : root.get("policy").get("apply_patch")) {
            Map<String, Object> patch = java(c.get("patch"));
            if (c.has("ok")) {
                assertEquals(c.get("ok"), json(PolicyService.applyPatch(java(c.get("tier")),
                        patch)), c.toString());
            } else {
                refusedAsAtThePin(c, () -> PolicyService.applyPatch(java(c.get("tier")), patch),
                        c.toString());
            }
        }
    }

    // --- assurance and consequence ----------------------------------------

    @Test
    void assuranceAxesAndNotesMatch() {
        for (JsonNode c : root.get("assurance").get("assess")) {
            Map<String, Object> identity = java(c.get("identity"));
            assertEquals(c.get("axes"), json(Assurance.assess(identity)), c.toString());
            assertEquals(c.get("notes"), json(Assurance.describe(java(c.get("axes")), identity)),
                    c.toString());
        }
        for (JsonNode c : root.get("assurance").get("describe")) {
            assertEquals(c.get("notes"), json(Assurance.describe(java(c.get("axes")),
                    java(c.get("identity")))), c.toString());
        }
    }

    @Test
    void consequenceClassesMatch() {
        JsonNode c = root.get("consequence");
        for (JsonNode v : c.get("normalise")) {
            assertEquals(java(v.get("class")), Consequence.normalise(java(v.get("value"))),
                    v.toString());
        }
        for (JsonNode v : c.get("at_or_above")) {
            assertEquals(v.get("result").asBoolean(), Consequence.atOrAbove(
                    java(v.get("actual")), java(v.get("floor"))), v.toString());
        }
        for (JsonNode v : c.get("annotations")) {
            assertEquals(java(v.get("class")),
                    Consequence.fromMcpAnnotations(java(v.get("annotations"))), v.toString());
        }
        for (JsonNode v : c.get("single_use")) {
            assertEquals(v.get("single_use").asBoolean(),
                    Consequence.singleUse(java(v.get("value"))), v.toString());
        }
    }

    // --- introductions ------------------------------------------------------

    @Test
    void introductionsSignedByThePinnedClientVerifyAndRefuseAlike() {
        JsonNode intro = root.get("introduction");
        double now = intro.get("now").asDouble();
        String childJkt = intro.get("child_jkt").asString();
        String audience = intro.get("audience").asString();
        List<String> names = new ArrayList<>();
        for (JsonNode c : intro.get("verify")) {
            names.add(c.get("name").asString());
            String token = c.get("token").asString();
            if (c.has("ok")) {
                assertEquals(c.get("ok"), json(Introduction.verifyClaim(token, childJkt,
                        audience, now)), c.get("name").asString());
                continue;
            }
            Introduction.Refused e = assertThrows(Introduction.Refused.class,
                    () -> Introduction.verifyClaim(token, childJkt, audience, now));
            String expected = c.get("error").asString();
            if (expected.startsWith("introduction is not a JWS: ")) {
                // The parser's own words differ; the refusal and its prefix do not.
                assertTrue(e.getMessage().startsWith("introduction is not a JWS: "),
                        e.getMessage());
            } else {
                assertEquals(expected, e.getMessage(), c.get("name").asString());
            }
        }
        assertTrue(names.containsAll(List.of("good", "expired", "other_audience", "tampered")));
    }

    @Test
    void admissionRefusesInThePinsOrderAndWords() {
        for (JsonNode c : root.get("introduction").get("admit")) {
            Map<String, Object> parent = java(c.get("parent"));
            Map<String, Object> prior = java(c.get("child_prior"));
            boolean same = c.get("same_operator").asBoolean();
            int live = c.get("live_children").asInt();
            int fanout = c.get("fanout").asInt();
            if (c.has("ok")) {
                Introduction.admit(parent, prior, same, live, fanout);
            } else {
                Introduction.Refused e = assertThrows(Introduction.Refused.class,
                        () -> Introduction.admit(parent, prior, same, live, fanout));
                assertEquals(c.get("error").asString(), e.getMessage(), c.toString());
            }
        }
    }
}
