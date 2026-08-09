package io.uma4agents.pep;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.EventLog;
import java.nio.file.Path;
import java.security.KeyPair;
import org.springframework.context.annotation.Configuration;

/** Environment-driven configuration, mirroring the Python service's env names. */
@Configuration
public class PepConfig {

    public static final String PEP_KID = "uma-pep-1";

    public final String asPublic = env("UMA_AS_PUBLIC", "https://alice-as.uma.lab");
    public final String asInternal = env("UMA_AS_INTERNAL", "http://uma-as:9000");
    public final String rsClientId = env("UMA_AS_RS_CLIENT_ID", "meridian-gateway");
    public final String rsClientSecret = env("UMA_AS_RS_CLIENT_SECRET", "gateway-dev-secret");
    public final String realm = env("UMA_REALM", "alice-vault");
    /**
     * How the AS learns what this RS protects. "push": the classic FedAuthz
     * direction — this PEP registers each surface at /rreg on startup and
     * repairs on invalid_resource_id. "pull": the RS only <em>publishes</em> —
     * public structure in the RFC 9728 document, owner-bound instances behind
     * the protected owner-resources endpoint — and the AS comes and reads.
     */
    public final String registrationMode = env("REGISTRATION_MODE", "push");
    /** The owner whose instances this (single-owner) gateway fronts. */
    public final String owner = env("UMA_OWNER", "alice");
    /**
     * The authority Alice's vault is served under. Signature verification
     * reconstructs the signed components from configuration rather than
     * trusting forwarded headers (the ext_authz hop rewrites Host).
     */
    public final String expectedAuthority = env("UMA_EXPECTED_AUTHORITY", "gateway.uma.lab");
    /** The resource's signing key — signs RFC 9728 signed_metadata. */
    public final KeyPair signingKey = EdDsa.loadOrCreate(
            Path.of(env("UMA_PEP_SIGNING_KEY", "/keys/uma-pep-ed25519.pem")));

    public final EventLog log = new EventLog("uma-pep");

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
