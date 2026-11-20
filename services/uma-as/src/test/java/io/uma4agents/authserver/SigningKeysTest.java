package io.uma4agents.authserver;

import static io.uma4agents.authserver.AsHarness.body;
import static io.uma4agents.authserver.AsHarness.template;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Signing-key rotation: what {@code rotation-check} asserts from the agent's side, here
 * from the authority's. A grant signed before the rotation still verifies, a new one
 * carries the new kid, both kids are published, and a retired key never signs again.
 */
class SigningKeysTest {

    @TempDir
    Path dir;

    private final KeyPair before = EdDsa.generate();
    private final KeyPair after = EdDsa.generate();

    private SigningKeys rotated() {
        return new SigningKeys(after, "uma-as-2", Map.of("uma-as-1", before.getPublic()));
    }

    @SuppressWarnings("unchecked")
    private static List<String> kids(SigningKeys keys) {
        return ((List<Map<String, Object>>) keys.jwks().get("keys")).stream()
                .map(k -> String.valueOf(k.get("kid"))).toList();
    }

    @Test
    void theAuthorityPublishesTheNewKeyAndTheRetiredOne() {
        assertEquals(List.of("uma-as-2", "uma-as-1"), kids(rotated()));
    }

    @Test
    void aGrantSignedBeforeTheRotationStillVerifiesAndOneAfterCarriesTheNewKid() {
        SigningKeys old = new SigningKeys(before, "uma-as-1", Map.of());
        String kept = CompactJws.sign(old.header("at+jwt"), Map.of("jti", "rpt_1"),
                before.getPrivate());
        SigningKeys keys = rotated();
        assertEquals("rpt_1", keys.verifyOwn(kept).claims().get("jti"));
        String fresh = CompactJws.sign(keys.header("at+jwt"), Map.of("jti", "rpt_2"),
                keys.current().getPrivate());
        assertEquals("uma-as-2", CompactJws.parse(fresh).header().get("kid"));
        assertEquals("rpt_2", keys.verifyOwn(fresh).claims().get("jti"));
    }

    @Test
    void aTokenNamingAKeyItNeverHeldIsCheckedAgainstTheCurrentOneAndFails() {
        KeyPair stranger = EdDsa.generate();
        for (String kid : new String[] {"uma-as-9", "uma-as-1"}) {
            String forged = CompactJws.sign(Map.of("typ", "at+jwt", "kid", kid),
                    Map.of("jti", "x"), stranger.getPrivate());
            assertThrows(SecurityException.class, () -> rotated().verifyOwn(forged));
        }
    }

    @Test
    void aKeyNoLongerListedNoLongerVerifies() {
        String kept = CompactJws.sign(Map.of("typ", "at+jwt", "kid", "uma-as-1"),
                Map.of("jti", "x"), before.getPrivate());
        SigningKeys dropped = new SigningKeys(after, "uma-as-2", Map.of());
        assertThrows(SecurityException.class, () -> dropped.verifyOwn(kept));
    }

    @Test
    void retiredKeysLoadFromPrivateOrPublicPemWithKidsOrThumbprints() throws Exception {
        Path current = dir.resolve("uma-as-2.pem");
        Files.writeString(current, EdDsa.toPkcs8Pem(after.getPrivate()));
        Path retiredPrivate = dir.resolve("uma-as-1.pem");
        Files.writeString(retiredPrivate, EdDsa.toPkcs8Pem(before.getPrivate()));
        KeyPair third = EdDsa.generate();
        Path retiredPublic = dir.resolve("older.pub");
        Files.writeString(retiredPublic, "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(third.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n");
        SigningKeys keys = SigningKeys.load(current.toString(), "uma-as-2",
                List.of(retiredPrivate.toString(), retiredPublic.toString()),
                List.of("uma-as-1"));
        String thumb = Jwks.thumbprint(Jwks.okpPublicJwk(third.getPublic()));
        assertEquals(List.of("uma-as-2", "uma-as-1", thumb), kids(keys));
        assertTrue(java.util.Arrays.equals(EdDsa.rawPublic(after.getPublic()),
                EdDsa.rawPublic(keys.current().getPublic())), "the retired key signs");
        IllegalStateException missing = assertThrows(IllegalStateException.class,
                () -> SigningKeys.load(current.toString(), "uma-as-2",
                        List.of(dir.resolve("gone.pem").toString()), List.of()));
        assertTrue(missing.getMessage().contains("gone.pem"));
    }

    @Test
    void theWholeGrantLoopSurvivesARotation() {
        AsHarness first = new AsHarness(new SigningKeys(before, "uma-as-1", Map.of()));
        first.connected();
        Map<String, Object> needInfo = first.dictated("alice-vault/get_positions",
                "positions:read");
        String rpt = String.valueOf(body(first.commit(needInfo,
                first.agreement(template(needInfo), Map.of()))).get("access_token"));
        String oldPat = first.pat();
        assertEquals("uma-as-1", CompactJws.parse(rpt).header().get("kid"));

        AsHarness second = new AsHarness(rotated(), first.store);
        assertEquals(second.config.ownerUsername,
                second.grants.requirePat(oldPat).owner(), "a PAT from before stopped working");
        assertEquals(true, second.protection.introspect(oldPat, rpt, null).get("active"),
                "a grant from before the rotation stopped working");
        String newPat = second.pat();
        assertEquals("uma-as-2", CompactJws.parse(newPat.substring(7)).header().get("kid"));
        assertEquals(true, second.protection.introspect(newPat, rpt, null).get("active"));
    }
}
