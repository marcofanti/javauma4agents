package io.uma4agents.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * uma-as — the UMA-for-agents authorization service.
 *
 * <p>Implements the four-beat grant loop from docs/PROTOCOL.md:
 * challenge (ticket via /perm) → attempt (/token: need_info + dictated terms)
 * → commit (signed intent contract) → grant (PoP-bound RPT), with UMA 2.0's
 * request_submitted pending state for Alice's ask-me tier, an owner API for the
 * portal, and one structured log line per protocol event.
 *
 * <p>State lives in an owner-scoped store: in memory by default, where {@code make reset}
 * rewinds the story, or in Postgres ({@code UMA_AS_STORE=postgres}) shared by replicas.
 */
@SpringBootApplication
public class UmaAsApplication {

    public static void main(String[] args) {
        SpringApplication.run(UmaAsApplication.class, args);
    }
}
