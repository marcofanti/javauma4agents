package io.uma4agents.pep;

import io.uma4agents.common.EventLog;
import org.springframework.context.annotation.Configuration;

/** Environment-driven configuration, mirroring the Python service's env names. */
@Configuration
public class PepConfig {

    public final String asPublic = env("UMA_AS_PUBLIC", "https://alice-as.uma.lab");
    public final String asInternal = env("UMA_AS_INTERNAL", "http://uma-as:9000");
    public final String rsClientId = env("UMA_AS_RS_CLIENT_ID", "meridian-gateway");
    public final String rsClientSecret = env("UMA_AS_RS_CLIENT_SECRET", "gateway-dev-secret");
    public final String realm = env("UMA_REALM", "alice-vault");
    /**
     * The authority Alice's vault is served under. Signature verification
     * reconstructs the signed components from configuration rather than
     * trusting forwarded headers (the ext_authz hop rewrites Host).
     */
    public final String expectedAuthority = env("UMA_EXPECTED_AUTHORITY", "gateway.uma.lab");

    public final EventLog log = new EventLog("uma-pep");

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
