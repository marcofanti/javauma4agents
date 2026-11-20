package io.uma4agents.vault;

import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * alice-vault-mcp — Alice's brokerage vault as an MCP server.
 *
 * <p>Fixture data through a real protocol path: positions, transaction history,
 * and a pretend trade-execution endpoint, served over MCP streamable-http.
 * This server never speaks UMA or AAuth — protection is conferred by the
 * gateway in front of it.
 */
@SpringBootApplication
public class VaultApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(VaultApplication.class);
        app.setDefaultProperties(tlsProperties(System.getenv("UMA_VAULT_TLS_CERT"),
                System.getenv("UMA_VAULT_TLS_KEY")));
        app.run(args);
    }

    /**
     * Standalone TLS, as the pinned vault serves it when {@code UMA_VAULT_TLS_CERT} is
     * set: the resource's own certificate and key, PEM, on the same port. Used where no
     * gateway or edge terminates TLS for it (the minimal fixture), because an
     * authorization server reads a resource's metadata only over https.
     *
     * @param cert PEM certificate path, or null/empty for plain HTTP
     * @param key PEM private key path, required with a certificate
     * @return the Spring Boot server properties to apply
     */
    static Map<String, Object> tlsProperties(String cert, String key) {
        if (cert == null || cert.isEmpty()) {
            return Map.of();
        }
        if (key == null || key.isEmpty()) {
            throw new IllegalStateException(
                    "UMA_VAULT_TLS_CERT is set but UMA_VAULT_TLS_KEY is not");
        }
        return Map.of("server.ssl.enabled", "true",
                "server.ssl.certificate", "file:" + cert,
                "server.ssl.certificate-private-key", "file:" + key);
    }
}
