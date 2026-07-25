package io.uma4agents.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One structured JSON log line per protocol event, identical in shape to the
 * Python reference: {@code {ts, event, corr, actor, details}}. Promtail promotes
 * {@code event} to a Loki label and the Grafana dashboard and smoke test key on
 * it — the shape is a contract, not a style choice.
 */
public final class EventLog {

    static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String actor;

    public EventLog(String actor) {
        this.actor = actor;
    }

    public static String utcNow() {
        return TS.format(java.time.Instant.now());
    }

    public void event(String name, String corr, Object... detailPairs) {
        Map<String, Object> details = new LinkedHashMap<>();
        for (int i = 0; i + 1 < detailPairs.length; i += 2) {
            details.put(String.valueOf(detailPairs[i]), detailPairs[i + 1]);
        }
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("ts", utcNow());
        line.put("event", name);
        line.put("corr", corr);
        line.put("actor", actor);
        line.put("details", details);
        try {
            System.out.println(MAPPER.writeValueAsString(line));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            System.out.println("{\"event\":\"" + name + "\",\"actor\":\"" + actor + "\"}");
        }
    }
}
