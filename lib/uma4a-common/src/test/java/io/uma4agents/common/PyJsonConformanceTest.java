package io.uma4agents.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Locks PyJson to CPython json.dumps output via generated ground-truth vectors. */
class PyJsonConformanceTest {

    @Test
    @DisplayName("dumpsSorted and compactSorted match CPython for every vector")
    void matchesCPythonVectors() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode vectors;
        try (InputStream in = getClass().getResourceAsStream("/pyjson-vectors.json")) {
            vectors = mapper.readTree(in);
        }
        int count = 0;
        for (JsonNode vector : vectors) {
            JsonNode value = vector.get("value");
            assertEquals(vector.get("sorted").textValue(), PyJson.dumpsSorted(value),
                    "sorted mismatch for vector " + count);
            assertEquals(vector.get("compact").textValue(), PyJson.compactSorted(value),
                    "compact mismatch for vector " + count);
            count++;
        }
        org.junit.jupiter.api.Assertions.assertTrue(count > 20, "vector file looks truncated");
    }

    @Test
    void handlesPlainJavaGraphs() {
        Map<String, Object> params = Map.of("symbol", "VTI", "side", "sell", "quantity", 40);
        assertEquals("{\"quantity\": 40, \"side\": \"sell\", \"symbol\": \"VTI\"}",
                PyJson.dumpsSorted(params));
        assertEquals("{\"quantity\":40,\"side\":\"sell\",\"symbol\":\"VTI\"}",
                PyJson.compactSorted(params));
        assertEquals("[1, 2.5, null, true]",
                PyJson.dumpsSorted(java.util.Arrays.asList(1, 2.5, null, true)));
    }

    @Test
    void rejectsNonStringKeys() {
        assertThrows(IllegalArgumentException.class,
                () -> PyJson.dumpsSorted(Map.of(1, "x")));
    }
}
