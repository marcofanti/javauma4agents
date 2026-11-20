package io.uma4agents.authserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.uma4agents.authserver.store.MemoryStore;
import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.authserver.store.Seeds;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.HttpSignature;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;

/**
 * Owner authentication by her own key (RFC 9421), beside OIDC: what is accepted, and
 * every reason a request is refused. Mirrors the pinned {@code fixture_check.py}
 * owner beats and {@code require_owner}'s choice of which failure to report.
 */
class OwnerAuthTest {

    private static final String AUTHORITY = "alice-as.local";

    @TempDir
    Path dir;

    private final KeyPair owner = EdDsa.generate();
    private Path keyPath;
    private TokenVerifiers verifiers;

    @BeforeEach
    void writeOwnerKey() throws Exception {
        keyPath = dir.resolve("owner-ed25519.pub");
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(owner.getPublic().getEncoded());
        Files.writeString(keyPath, "-----BEGIN PUBLIC KEY-----\n" + b64
                + "\n-----END PUBLIC KEY-----\n");
        HttpClient http = HttpClient.newHttpClient();
        verifiers = new TokenVerifiers(new AsConfig(), http, new PeerFetch(http));
    }

    /** One shared store, as every replica shares one database. */
    private final OwnerStore shared = new MemoryStore(new Seeds(o -> Map.of(), o -> Map.of()))
            .owner("alice");

    private OwnerAuth auth(String... modes) {
        return new OwnerAuth(new OwnerAuth.Settings(List.of(modes), keyPath.toString(),
                "alice", AUTHORITY, "alice"), verifiers, shared);
    }

    private MockHttpServletRequest signed(String method, String path, byte[] body,
                                          KeyPair key) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        Map<String, String> headers = HttpSignature.sign(method, AUTHORITY, path, "",
                key.getPrivate(), "owner", HttpSignature.SignOptions.none().withBody(body));
        headers.forEach(request::addHeader);
        if (body != null) {
            request.setContent(body);
            request.setAttribute(OwnerAuth.BODY_ATTRIBUTE, body);
        }
        return request;
    }

    private static int status(Runnable call) {
        return assertThrows(ResponseStatusException.class, call::run).getStatusCode().value();
    }

    @Test
    void herSignedRequestIsAccepted() {
        assertEquals("alice", auth("local-key").requireOwner(
                signed("GET", "/owner/policies", null, owner)));
    }

    @Test
    void anUnsignedRequestIsRefused() {
        ResponseStatusException e = assertThrows(ResponseStatusException.class,
                () -> auth("local-key").requireOwner(
                        new MockHttpServletRequest("GET", "/owner/policies")));
        assertEquals(401, e.getStatusCode().value());
        assertTrue(e.getReason().contains("RFC 9421 signature"));
    }

    @Test
    void aKeySheDidNotEnrolIsRefused() {
        assertEquals(401, status(() -> auth("local-key").requireOwner(
                signed("GET", "/owner/policies", null, EdDsa.generate()))));
    }

    @Test
    void aSignatureForAnotherPathIsRefused() {
        MockHttpServletRequest request = signed("GET", "/owner/ledger", null, owner);
        request.setRequestURI("/owner/policies");
        assertEquals(401, status(() -> auth("local-key").requireOwner(request)));
    }

    @Test
    void aBodyMustBeCoveredByItsDigest() {
        byte[] approve = "{\"decision\":\"approved\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = signed("POST", "/owner/pending/fam_1/decision",
                approve, owner);
        byte[] flipped = "{\"decision\":\"denied\"}".getBytes(StandardCharsets.UTF_8);
        request.setAttribute(OwnerAuth.BODY_ATTRIBUTE, flipped);
        ResponseStatusException e = assertThrows(ResponseStatusException.class,
                () -> auth("local-key").requireOwner(request));
        assertEquals(401, e.getStatusCode().value());

        MockHttpServletRequest undigested = new MockHttpServletRequest("POST",
                "/owner/pending/fam_1/decision");
        HttpSignature.sign("POST", AUTHORITY, "/owner/pending/fam_1/decision", "",
                owner.getPrivate(), "owner", HttpSignature.SignOptions.none())
                .forEach(undigested::addHeader);
        undigested.setAttribute(OwnerAuth.BODY_ATTRIBUTE, approve);
        assertEquals(401, status(() -> auth("local-key").requireOwner(undigested)));
    }

    @Test
    void aChangingRequestIsAcceptedOnce() {
        OwnerAuth auth = auth("local-key");
        byte[] body = "{\"decision\":\"approved\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = signed("POST", "/owner/pending/fam_1/decision",
                body, owner);
        assertEquals("alice", auth.requireOwner(request));
        ResponseStatusException replay = assertThrows(ResponseStatusException.class,
                () -> auth.requireOwner(request));
        assertEquals("that signed request was already received", replay.getReason());
        MockHttpServletRequest read = signed("GET", "/owner/policies", null, owner);
        auth.requireOwner(read);
        assertEquals("alice", auth.requireOwner(read), "a read is not spent");
    }

    @Test
    void aSignedChangeAcceptedByOneReplicaIsRefusedByAnother() {
        byte[] body = "{\"decision\":\"approved\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = signed("POST", "/owner/pending/fam_x/decision",
                body, owner);
        OwnerAuth replicaA = auth("local-key");
        OwnerAuth replicaB = auth("local-key");
        assertEquals("alice", replicaA.requireOwner(request));
        ResponseStatusException replay = assertThrows(ResponseStatusException.class,
                () -> replicaB.requireOwner(request));
        assertEquals("that signed request was already received", replay.getReason());
    }

    @Test
    void aKeyRegisteredForAnotherOwnerIsForbidden() {
        OwnerAuth auth = new OwnerAuth(new OwnerAuth.Settings(List.of("local-key"),
                keyPath.toString(), "carol", AUTHORITY, "alice"), verifiers, shared);
        assertEquals(403, status(() -> auth.requireOwner(
                signed("GET", "/owner/policies", null, owner))));
    }

    @Test
    void eitherCredentialIsSufficientWhenBothAreConfigured() {
        assertEquals("alice", auth("oidc", "local-key").requireOwner(
                signed("GET", "/owner/policies", null, owner)));
        ResponseStatusException none = assertThrows(ResponseStatusException.class,
                () -> auth("oidc", "local-key").requireOwner(
                        new MockHttpServletRequest("GET", "/owner/policies")));
        assertEquals(401, none.getStatusCode().value());
    }

    @Test
    void aMissingKeyAndAnUnknownModeAreConfigurationErrors() throws Exception {
        Files.delete(keyPath);
        assertEquals(500, status(() -> auth("local-key").requireOwner(
                signed("GET", "/owner/policies", null, owner))));
        assertEquals(500, status(() -> auth("password").requireOwner(
                new MockHttpServletRequest("GET", "/owner/policies"))));
        assertEquals(500, status(() -> auth().requireOwner(
                new MockHttpServletRequest("GET", "/owner/policies"))));
    }

    @Test
    void oidcAloneDoesNotAcceptASignature() {
        ResponseStatusException e = assertThrows(ResponseStatusException.class,
                () -> auth("oidc").requireOwner(signed("GET", "/owner/policies", null, owner)));
        assertEquals(401, e.getStatusCode().value());
        assertEquals("bearer token required", e.getReason());
    }
}
