package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The echo of her lifetime, compared whole: what was dictated is the ceiling. */
class AgreedTermsTest {

    private static Map<String, Object> template() {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("scope", List.of("positions:read"));
        t.put("prohibited", List.of("marketing"));
        t.put("expires_in", 900);
        return t;
    }

    private static Map<String, Object> contract(Object expiresIn) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("scope", List.of("positions:read"));
        c.put("prohibited", List.of("marketing"));
        c.put("expires_in", expiresIn);
        return c;
    }

    private static String refusal(Object expiresIn) {
        return assertThrows(IllegalArgumentException.class,
                () -> GrantService.checkAgreedTerms(contract(expiresIn), template())).getMessage();
    }

    @Test
    void anExpiryThatWouldWrapWhenNarrowedIsStillTooLong() {
        BigInteger wraps = BigInteger.TWO.pow(64).add(BigInteger.valueOf(60));
        assertEquals(60L, wraps.longValue(), "the value the old comparison saw");
        assertEquals("expiry was extended beyond dictated terms", refusal(wraps));
        assertEquals("expiry was extended beyond dictated terms",
                refusal(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE)));
        assertEquals("expiry was extended beyond dictated terms", refusal(Long.MAX_VALUE));
    }

    @Test
    void aNegativeExpiryThatWouldWrapPositiveIsRefused() {
        BigInteger negative = BigInteger.TWO.pow(64).negate().add(BigInteger.valueOf(60));
        assertEquals(60L, negative.longValue());
        assertEquals("expires_in must be a positive number of seconds", refusal(negative));
    }

    @Test
    void theDictatedLifetimeAndLessAreAccepted() {
        assertDoesNotThrow(() -> GrantService.checkAgreedTerms(contract(900), template()));
        assertDoesNotThrow(() -> GrantService.checkAgreedTerms(contract(1L), template()));
        assertDoesNotThrow(() -> GrantService.checkAgreedTerms(
                contract(BigInteger.valueOf(900)), template()));
        assertEquals("expiry was extended beyond dictated terms", refusal(901));
        assertEquals("expires_in must be a positive number of seconds", refusal(0));
        assertEquals("expires_in must be a positive number of seconds", refusal(900.0));
    }
}
