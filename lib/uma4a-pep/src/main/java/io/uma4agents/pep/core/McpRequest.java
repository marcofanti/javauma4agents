package io.uma4agents.pep.core;

import java.util.LinkedHashMap;
import java.util.Map;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The JSON-RPC method, tool name, tool arguments and id of an MCP POST body, as the pinned
 * {@code parse_mcp} reads them. A body that is not a JSON object yields all nulls.
 *
 * @param method JSON-RPC method, or null
 * @param tool tool name for tools/call, else null
 * @param args tool arguments for tools/call (empty when absent), else null
 * @param id the JSON-RPC id node, or null for a notification or unreadable body
 */
public record McpRequest(String method, String tool, Map<String, Object> args, JsonNode id) {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final McpRequest NONE = new McpRequest(null, null, null, null);

    /** Parses an MCP body; never throws. */
    public static McpRequest parse(byte[] body) {
        if (body == null || body.length == 0) {
            return NONE;
        }
        JsonNode msg;
        try {
            msg = MAPPER.readTree(body);
        } catch (JacksonException e) {
            return NONE;
        }
        if (msg == null || !msg.isObject()) {
            return NONE;
        }
        String method = msg.path("method").isString() ? msg.path("method").stringValue() : null;
        JsonNode id = msg.has("id") ? msg.get("id") : null;
        if (!"tools/call".equals(method)) {
            return new McpRequest(method, null, null, id);
        }
        JsonNode params = msg.path("params");
        String tool = params.path("name").isString() ? params.path("name").stringValue() : null;
        Map<String, Object> args = new LinkedHashMap<>();
        if (params.path("arguments").isObject()) {
            args = MAPPER.convertValue(params.get("arguments"),
                    MAPPER.getTypeFactory().constructMapType(LinkedHashMap.class, String.class,
                            Object.class));
        }
        return new McpRequest(method, tool, args, id);
    }
}
