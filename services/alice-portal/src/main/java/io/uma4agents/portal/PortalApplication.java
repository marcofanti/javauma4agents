package io.uma4agents.portal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * alice-portal — Alice's brokerage portal.
 *
 * <p>A first-party brokerage UI (dashboard, holdings, trade) with the
 * agent-authorization surface under Settings → Security. Alice reads and trades
 * her own vault directly (she owns it); the gateway and the grant loop exist for
 * <em>other people's</em> agents. Agent-authorization data comes from her
 * authorization server's owner API; the browser never sees the owner token —
 * the portal proxies it.
 */
@SpringBootApplication
public class PortalApplication {

    public static void main(String[] args) {
        SpringApplication.run(PortalApplication.class, args);
    }
}
