package io.uma4agents.shim;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/** The shim's environment, with the pinned variable names and defaults. */
final class ShimEnv {

    final String gateway = env("UMA4A_GATEWAY", "https://gateway.uma.lab/mcp");
    final String cacert = env("UMA4A_CACERT", "certs/rootCA.pem");
    final String keystore = env("UMA4A_KEYSTORE",
            System.getProperty("user.home") + "/.uma4agents/agent-key.pem");
    final String receiptsDir = env("UMA4A_RECEIPTS", receiptsBeside(keystore));
    final long standingMaxExpires =
            Long.parseLong(env("UMA4A_STANDING_MAX_EXPIRES", "604800"));
    final String transport = env("UMA4A_SHIM_TRANSPORT", "stdio");
    final String host = env("UMA4A_SHIM_HOST", "127.0.0.1");
    final int port = Integer.parseInt(env("UMA4A_SHIM_PORT", "9030"));
    final String agentIssuer = env("UMA4A_AGENT_ISSUER", null);
    final String publishTo = trimmed(env("UMA4A_PUBLISH_TO", null));
    final String personToken = env("UMA4A_PERSON_TOKEN", null);
    final String agentName = env("UMA4A_AGENT_NAME", "Bob's agent via uma4agents shim");
    final String clientId = env("UMA4A_CLIENT_ID", null);
    final String registerToken = env("UMA4A_OPERATOR_REGISTER_TOKEN", null);
    final long pendHandbackSeconds = Long.parseLong(env("UMA4A_PEND_HANDBACK", "15"));
    final Map<String, Object> mission = mission();

    private static Map<String, Object> mission() {
        String approver = env("UMA4A_MISSION_APPROVER", null);
        String s256 = env("UMA4A_MISSION_S256", null);
        if (approver == null || s256 == null) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("approver", approver);
        out.put("s256", s256);
        return out;
    }

    private static String receiptsBeside(String keystore) {
        Path parent = Path.of(keystore).getParent();
        return (parent == null ? Path.of(".") : parent).resolve("receipts").toString();
    }

    private static String trimmed(String origin) {
        return origin == null ? null : origin.replaceAll("/+$", "");
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }
}
