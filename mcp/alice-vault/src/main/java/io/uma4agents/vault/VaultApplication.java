package io.uma4agents.vault;

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
        SpringApplication.run(VaultApplication.class, args);
    }
}
