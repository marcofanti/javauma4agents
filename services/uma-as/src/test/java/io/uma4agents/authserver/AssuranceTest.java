package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AssuranceTest {

    @Test
    void levelsComeOnlyFromChecksThatRan() {
        assertEquals(Map.of("binding", 0, "provenance", 0, "accountability", 0),
                Assurance.assess(Map.of("level", "pseudonymous")));
        assertEquals(Map.of("binding", 1, "provenance", 1, "accountability", 2),
                Assurance.assess(Map.of("level", "identified", "key_bound", true,
                        "operator_attested", true,
                        "client_metadata", Map.of("verified", true))));
        assertEquals(1, Assurance.assess(Map.of("key_bound", true,
                "client_metadata", Map.of("verified", true))).get("accountability"));
        assertEquals(0, Assurance.assess(Map.of("operator_attested", true,
                "client_metadata", Map.of("verified", false))).get("accountability"),
                "an unresolved document is worth what no document is worth");
    }

    @Test
    void aDisplayNameIsInsertedLiterallyAsStrFormatDoes() {
        Map<String, Object> identity = Map.of("iss", "https://ps.uma.lab",
                "client_metadata", Map.of("client_name", "Evil {issuer} {operator} Ltd"));
        List<String> notes = Assurance.describe(
                Map.of("binding", 1, "provenance", 1, "accountability", 1), identity);
        assertEquals(List.of("bound to a key, recognisable next time",
                "credential issued by https://ps.uma.lab, signature verified",
                "Evil {issuer} {operator} Ltd says it operates this agent (self-asserted)"),
                notes);
    }

    @Test
    void anUnnamedOperatorAndIssuerReadAsSuch() {
        assertEquals(List.of("not bound to any key this server verified",
                "self-minted key — nothing to check it against", "no operator named"),
                Assurance.describe(Map.of(), Map.of()));
        assertEquals("an operator published this agent's signing key as its own",
                Assurance.describe(Map.of("accountability", 2), Map.of()).get(2));
    }
}
