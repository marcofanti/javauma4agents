package io.uma4agents.agent;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jose;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.S256;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import tools.jackson.databind.ObjectMapper;

/**
 * The requesting agent's signing identity, ported from the pinned {@code AgentKeys}.
 *
 * <p>Pseudonymous: {@code key} is the persisted long-term key and its bare public JWK rides
 * the contract's JWS header, so the key is the identity. Identified: {@code stable} is the
 * persisted key enrolled at the agent server, and {@code key} is a fresh session key the
 * issued agent token binds. The key id is derived from the signing key.
 */
public final class AgentKeys {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public final KeyPair key;
    public final String keyid;
    public final KeyPair stable;
    public volatile String agentToken;
    /** CIMD URL sent as the contract header's client_id, or null. */
    public volatile String clientId;
    /** Web Bot Auth directory URL covered by request signatures, or null. */
    public volatile String signatureAgent;

    private AgentKeys(KeyPair key, KeyPair stable) {
        this.key = key;
        this.stable = stable;
        this.keyid = "agent-" + Jwks.b64url(S256.sha256(EdDsa.rawPublic(key.getPublic())))
                .substring(0, 16);
    }

    /** Pseudonymous identity: one persisted signing key (PKCS#8 PEM, readable by Python). */
    public static AgentKeys loadOrCreate(Path path) {
        return new AgentKeys(EdDsa.loadOrCreate(path), null);
    }

    /** Identified identity: persisted stable key plus a fresh session key. */
    public static AgentKeys loadOrCreateIdentified(Path path) {
        return new AgentKeys(EdDsa.generate(), EdDsa.loadOrCreate(path));
    }

    /**
     * The signing key's public JWK, naming {@code Ed25519} when the agent token binds a
     * key that names it, as the pinned client's {@code public_jwk} does.
     */
    public Map<String, Object> publicJwk() {
        Map<String, Object> jwk = Jwks.okpPublicJwk(key.getPublic());
        if (Jose.ED25519.equals(jwsAlg())) {
            jwk.put("alg", Jose.ED25519);
        }
        return jwk;
    }

    /**
     * The algorithm this agent's JWS are verified with: {@code Ed25519} when its agent
     * token's {@code cnf.jwk} names it (AAuth's current text), otherwise {@code EdDSA}.
     */
    public String jwsAlg() {
        String token = agentToken;
        if (token != null && CompactJws.parse(token).claims().get("cnf") instanceof Map<?, ?> cnf
                && cnf.get("jwk") instanceof Map<?, ?> jwk
                && Jose.ED25519.equals(jwk.get("alg"))) {
            return Jose.ED25519;
        }
        return Jose.EDDSA;
    }

    /**
     * The handle the owner's authority files this agent under: an identified agent's
     * subject qualified by its whole issuer (port and path included), otherwise the key's
     * thumbprint. Mirrors the authorization server's {@code connectionHandle}.
     */
    public String connectionHandle() {
        String token = agentToken;
        if (token == null) {
            return thumbprint();
        }
        Map<String, Object> claims = CompactJws.parse(token).claims();
        URI issuer = URI.create(String.valueOf(claims.getOrDefault("iss", "")));
        String path = issuer.getRawPath() == null ? "" : issuer.getRawPath();
        String where = issuer.getRawAuthority() + path.replaceAll("/+$", "");
        String sub = String.valueOf(claims.getOrDefault("sub", ""));
        return sub.endsWith("@" + where) ? sub : sub + "@" + where;
    }

    /** RFC 7638 thumbprint of the signing key, in the {@code jkt:} form. */
    public String thumbprint() {
        return Jwks.thumbprint(publicJwk());
    }

    /**
     * Publishes the signing key to the operator's Web Bot Auth directory. Returns the
     * Signature-Agent value, or null when the directory is unreachable: discovery is
     * additive, and the key in the RPT's cnf still verifies without it.
     */
    public String publish(HttpClient client, String operatorOrigin, String registerToken) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("keyid", keyid);
        body.put("jwk", publicJwk());
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder()
                    .uri(URI.create(operatorOrigin + "/register"))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(body)));
            if (registerToken != null && !registerToken.isEmpty()) {
                request.header("Authorization", "Bearer " + registerToken);
            }
            HttpResponse<String> r = client.send(request.build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() >= 400) {
                return null;
            }
            return operatorOrigin + "/.well-known/http-message-signatures-directory";
        } catch (java.io.IOException | RuntimeException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }
}
