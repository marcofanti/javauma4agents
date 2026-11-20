package io.uma4agents.operator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

class OperatorControllerTest {

    private static final Map<String, Object> JWK =
            Map.of("kty", "OKP", "crv", "Ed25519", "x", "abc");

    @Test
    void cimdNamesItsOwnUrl() {
        Map<String, Object> doc = new OperatorController().clientIdMetadata();
        assertEquals("https://agent.uma.lab/agent.json", doc.get("client_id"));
    }

    @Test
    void registeredKeyAppearsInTheDirectoryUnderItsKeyid() {
        OperatorController operator = new OperatorController();
        ResponseEntity<Map<String, Object>> r = operator.register(null,
                Map.of("keyid", "agent-1", "jwk", JWK));
        assertEquals(200, r.getStatusCode().value());
        ResponseEntity<Map<String, Object>> dir = operator.signaturesDirectory();
        assertEquals(OperatorController.DIRECTORY_TYPE, dir.getHeaders().getContentType());
        List<?> keys = (List<?>) dir.getBody().get("keys");
        assertEquals("agent-1", ((Map<?, ?>) keys.get(0)).get("kid"));
    }

    @Test
    void refusesARegistrationWithoutKeyidAndJwk() {
        assertEquals(400, new OperatorController().register(null, Map.of("keyid", "k"))
                .getStatusCode().value());
        assertEquals(400, new OperatorController().register(null, null)
                .getStatusCode().value());
    }
}
