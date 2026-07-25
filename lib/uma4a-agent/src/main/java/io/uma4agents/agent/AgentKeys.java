package io.uma4agents.agent;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Map;

/**
 * The requesting agent's signing identity — port of the Python AgentKeys.
 *
 * <p>Pseudonymous (AAuth level 0): {@code key} is the persisted long-term key
 * and its bare public JWK rides the contract's JWS header — the key <em>is</em>
 * the identity, so it must be stable across runs for the owner's standing
 * connection to recognize the agent.
 *
 * <p>Identified: {@code stable} is the persisted long-term key enrolled at the
 * agent server; {@code key} is a fresh per-session ephemeral key that the
 * issued aa-agent+jwt ({@code agentToken}) binds via cnf.jwk.
 */
public final class AgentKeys {

    public final KeyPair key;
    public final String keyid;
    public volatile String agentToken;
    public final KeyPair stable;

    private AgentKeys(KeyPair key, KeyPair stable) {
        this.key = key;
        this.keyid = "agent-req-1";
        this.stable = stable;
    }

    /** Pseudonymous identity: one persisted signing key. */
    public static AgentKeys loadOrCreate(Path path) {
        return new AgentKeys(EdDsa.loadOrCreate(path), null);
    }

    /**
     * Identified identity: persisted stable key + fresh session key. Enroll
     * with {@link EnrollClient} to obtain the agent token.
     */
    public static AgentKeys loadOrCreateIdentified(Path path) {
        return new AgentKeys(EdDsa.generate(), EdDsa.loadOrCreate(path));
    }

    public Map<String, Object> publicJwk() {
        return Jwks.okpPublicJwk(key.getPublic());
    }
}
