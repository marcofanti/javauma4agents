package io.uma4agents.pep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

/** The pinned hosts' parsing of UMA_ALLOWED_ORIGINS and UMA_PEP_REQUIRE_CONTENT_DIGEST. */
class EnforcerSettingsTest {

    @Test
    void unsetOriginsDefaultToTheAuthorityAndThePortal() {
        assertEquals(Set.of("https://gateway.uma.lab", "https://portal.uma.lab"),
                EnforcerSettings.allowedOrigins(null, "gateway.uma.lab"));
    }

    @Test
    void anExplicitlyEmptyValueAdmitsNoOrigin() {
        assertEquals(Set.of(), EnforcerSettings.allowedOrigins("", "gateway.uma.lab"));
        assertEquals(Set.of(), EnforcerSettings.allowedOrigins(",,", "gateway.uma.lab"));
    }

    @Test
    void configuredItemsAreKeptAsWritten() {
        assertEquals(Set.of("https://a.example", " https://b.example"),
                EnforcerSettings.allowedOrigins("https://a.example, https://b.example",
                        "gateway.uma.lab"));
    }

    @Test
    void digestFlagIsCaseInsensitiveAndOffByDefault() {
        for (String on : new String[] {"1", "true", "TRUE", "Yes", "yes"}) {
            assertTrue(EnforcerSettings.flag(on), on);
        }
        for (String off : new String[] {null, "", "0", "false", "on", " true"}) {
            assertFalse(EnforcerSettings.flag(off), String.valueOf(off));
        }
    }
}
