package io.uma4agents.pep;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * uma-pep — the UMA policy-enforcement point for agentgateway (HTTP ext_authz).
 *
 * <p>Registers Alice's vault tool surfaces at her AS on startup, passes MCP
 * session bootstrap unauthenticated, challenges unauthorized tools/call with a
 * real permission ticket, and enforces introspection, proof-of-possession,
 * tool/scope checks, and single-use operation binding on presented RPTs.
 */
@SpringBootApplication
public class PepApplication {

    public static void main(String[] args) {
        SpringApplication.run(PepApplication.class, args);
    }
}
