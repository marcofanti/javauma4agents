package io.uma4agents.authserver.store;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** JSON-shaped records: deep copies, and the text form the JDBC store keeps in jsonb. */
public final class StoreJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private StoreJson() {}

    /** A deep copy of maps and lists; leaves are shared, being immutable. */
    @SuppressWarnings("unchecked")
    public static <T> T copy(T value) {
        return (T) copyValue(value);
    }

    private static Object copyValue(Object value) {
        return switch (value) {
            case Map<?, ?> map -> {
                Map<Object, Object> out = new LinkedHashMap<>();
                map.forEach((k, v) -> out.put(k, copyValue(v)));
                yield out;
            }
            case List<?> list -> {
                List<Object> out = new ArrayList<>(list.size());
                list.forEach(item -> out.add(copyValue(item)));
                yield out;
            }
            case null, default -> value;
        };
    }

    static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("record is not JSON-serializable: "
                    + e.getMessage(), e);
        }
    }

    static Map<String, Object> readMap(String json) {
        if (json == null) {
            return null;
        }
        try {
            return MAPPER.readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        } catch (JacksonException e) {
            throw new IllegalStateException("stored record is not a JSON object: "
                    + e.getMessage(), e);
        }
    }
}
