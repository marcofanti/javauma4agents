package io.uma4agents.vault;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/** The brokerage fixture data, loaded once at startup. */
@Component
public class Fixtures {

    private final Map<String, Object> data;

    public Fixtures(ObjectMapper mapper) {
        String configured = System.getenv("UMA_VAULT_FIXTURES");
        try (InputStream in = configured == null || configured.isBlank()
                ? getClass().getResourceAsStream("/fixtures.json")
                : Files.newInputStream(Path.of(configured))) {
            if (in == null) {
                throw new IllegalStateException("fixtures.json missing from classpath");
            }
            this.data = mapper.readValue(in, new TypeReference<>() {});
        } catch (IOException e) {
            throw new IllegalStateException("cannot read vault fixtures", e);
        }
    }

    public String asOf() {
        return (String) data.get("as_of");
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> positions() {
        return (List<Map<String, Object>>) data.get("positions");
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> transactions() {
        return (List<Map<String, Object>>) data.get("transactions");
    }
}
