package io.uma4agents.pep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.Jwks;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/**
 * The resource server's copy of the authority's keys, against a counted JWKS endpoint:
 * the first signature that fails after the authority rotated gets a fresh read however
 * recently the cache was filled on schedule, and forced reads are floored so unsigned
 * traffic cannot become one request to the authority each.
 */
class AuthorityKeysTest {

    private static final String AUTHORITY = "gateway.uma.lab";
    private static final String PATH = "/owner-resources/alice";

    private final KeyPair oldKey = EdDsa.generate();
    private final KeyPair newKey = EdDsa.generate();
    private final AtomicInteger fetches = new AtomicInteger();
    private final AtomicReference<List<KeyPair>> published =
            new AtomicReference<>(List.of(oldKey));
    private HttpServer server;
    private String jwksUrl;

    @BeforeEach
    void serve() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", exchange -> {
            fetches.incrementAndGet();
            byte[] body = new ObjectMapper().writeValueAsString(Map.of("keys",
                    published.get().stream().map(k -> Jwks.okpPublicJwk(k.getPublic()))
                            .toList())).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        jwksUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String check(Publication.AuthorityKeys keys, KeyPair signer) {
        Map<String, String> h = HttpSignature.sign("GET", AUTHORITY, PATH, "",
                signer.getPrivate(), "uma-as", HttpSignature.SignOptions.none());
        return Publication.verifyOwnerAsQuery("GET", AUTHORITY, PATH,
                h.get("Signature-Input"), h.get("Signature"), keys);
    }

    @Test
    void aRotatedKeyIsLearnedOnTheFirstFailureAndForcedReadsAreFloored() {
        Publication.AuthorityKeys keys = new Publication.AuthorityKeys(jwksUrl,
                Duration.ofSeconds(300), Duration.ofSeconds(5));
        assertNull(check(keys, oldKey));
        assertEquals(1, fetches.get(), "the scheduled fill");

        published.set(List.of(newKey, oldKey));
        assertNull(check(keys, newKey), "a query signed with the new key was refused");
        assertEquals(2, fetches.get(), "the first failure after a rotation forces one read");

        assertTrue(check(keys, EdDsa.generate()) != null, "a stranger's key verified");
        assertEquals(2, fetches.get(), "a forced read inside the floor reached the authority");

        assertNull(check(keys, oldKey), "the retired key the authority still lists stopped");
        assertEquals(2, fetches.get());
    }

    @Test
    void unreadableKeysAreARefusalNotAnError() {
        server.stop(0);
        String reason = check(new Publication.AuthorityKeys(jwksUrl), oldKey);
        assertTrue(reason != null && reason.contains("could not be read"), reason);
    }

    @Test
    void anUnsignedQueryIsRefusedWithoutAskingTheAuthority() {
        Publication.AuthorityKeys keys = new Publication.AuthorityKeys(jwksUrl);
        assertEquals("no signature", Publication.verifyOwnerAsQuery("GET", AUTHORITY, PATH,
                "", "", keys));
        assertEquals(0, fetches.get());
    }
}
