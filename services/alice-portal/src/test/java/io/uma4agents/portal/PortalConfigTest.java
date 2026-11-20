package io.uma4agents.portal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** A typo in the portal's auth mode refuses to start rather than serving her vault openly. */
class PortalConfigTest {

    @Test
    void onlyOidcAndNoneAreAuthModes() {
        assertEquals("oidc", PortalConfig.authMode("oidc"));
        assertEquals("none", PortalConfig.authMode("none"));
        for (String typo : new String[] {"OIDC", "odic", "off", ""}) {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> PortalConfig.authMode(typo));
            assertEquals("PORTAL_AUTH must be 'oidc' or 'none', not '" + typo + "'",
                    e.getMessage());
        }
    }
}
