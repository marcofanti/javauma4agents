package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.HttpSignature;
import io.uma4agents.common.S256;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * Whoever calls the owner API has to be the owner. Each configured credential is
 * independently sufficient: {@code oidc}, her identity provider's token, and
 * {@code local-key}, an RFC 9421 signature by the Ed25519 key she holds. The two keep
 * separate verification and separate failure reporting; only the resulting owner is
 * shared. Ports {@code require_owner} and {@code require_owner_signature}.
 */
@Component
public class OwnerAuth {

    /** Request attribute holding the exact received body, set by {@link OwnerBodyFilter}. */
    public static final String BODY_ATTRIBUTE = "io.uma4agents.owner.body";
    static final long MAX_AGE_SECONDS = 60;
    static final long REPLAY_WINDOW_SECONDS = 120;

    /**
     * What owner authentication needs from configuration.
     *
     * @param ownerAuth the configured modes, {@code oidc} and/or {@code local-key}
     * @param ownerKeyPath her Ed25519 public key PEM
     * @param ownerKeyOwner whose key that is
     * @param ownerExpectedAuthority the authority signatures are checked against
     * @param ownerUsername the one owner this server serves
     */
    record Settings(List<String> ownerAuth, String ownerKeyPath, String ownerKeyOwner,
                    String ownerExpectedAuthority, String ownerUsername) {
        static Settings from(AsConfig config) {
            return new Settings(config.ownerAuth, config.ownerKeyPath, config.ownerKeyOwner,
                    config.ownerExpectedAuthority, config.ownerUsername);
        }
    }

    private final Settings config;
    private final TokenVerifiers verifiers;
    private final OwnerStore store;
    private volatile PublicKey ownerKey;

    @Autowired
    public OwnerAuth(AsConfig config, TokenVerifiers verifiers, OwnerStore store) {
        this(Settings.from(config), verifiers, store);
    }

    OwnerAuth(Settings settings, TokenVerifiers verifiers, OwnerStore store) {
        this.config = settings;
        this.verifiers = verifiers;
        this.store = store;
    }

    /**
     * Authenticates the owner by any configured credential.
     *
     * @param request the incoming owner-API request
     * @return the owner the credential proved
     * @throws ResponseStatusException the most advanced failure when no mode verifies
     */
    public String requireOwner(HttpServletRequest request) {
        if (config.ownerAuth().isEmpty() || config.ownerAuth().stream()
                .anyMatch(m -> !"oidc".equals(m) && !"local-key".equals(m))) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "UMA_AS_OWNER_AUTH must be a comma-separated list of local-key|oidc; got "
                            + (config.ownerAuth().isEmpty() ? "nothing" : config.ownerAuth()));
        }
        ResponseStatusException best = null;
        for (String mode : config.ownerAuth()) {
            try {
                String owner = "oidc".equals(mode)
                        ? verifiers.oidcOwner(request.getHeader("authorization"))
                        : signedOwner(request);
                if (!config.ownerUsername().equals(owner)) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                            "this authorization server serves a different owner");
                }
                return owner;
            } catch (ResponseStatusException e) {
                if (best == null || e.getStatusCode().value() > best.getStatusCode().value()) {
                    best = e;
                }
            }
        }
        throw best;
    }

    private String signedOwner(HttpServletRequest request) {
        String sigInput = request.getHeader("signature-input");
        String sig = request.getHeader("signature");
        if (isBlank(sigInput) || isBlank(sig)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "owner API requires an RFC 9421 signature from the owner's key");
        }
        String path = request.getRequestURI();
        if (request.getQueryString() != null) {
            path = path + "?" + request.getQueryString();
        }
        byte[] body = request.getAttribute(BODY_ATTRIBUTE) instanceof byte[] b ? b : new byte[0];
        boolean hasBody = body.length > 0;
        String authorization = request.getHeader("authorization");
        try {
            HttpSignature.verify(new HttpSignature.VerifyRequest(request.getMethod(),
                    config.ownerExpectedAuthority(), path,
                    authorization == null ? "" : authorization, sigInput, sig, ownerKey(),
                    MAX_AGE_SECONDS, null, hasBody ? body : null, hasBody,
                    request.getHeader("content-digest")));
        } catch (HttpSignature.VerifyException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "owner signature did not verify: " + e.getMessage());
        }
        String method = request.getMethod();
        if (!"GET".equals(method) && !"HEAD".equals(method) && !spendOnce(sig)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "that signed request was already received");
        }
        return config.ownerKeyOwner();
    }

    /**
     * A signed request that changes something is accepted once, by the deployment rather
     * than by this process: spent in the shared store, so a replica that has not seen it
     * cannot act on it a second time. Kept for twice the freshness window.
     */
    private boolean spendOnce(String signature) {
        String key = "owner-signature:" + java.util.HexFormat.of().formatHex(
                S256.sha256(signature.getBytes(StandardCharsets.UTF_8)));
        return store.spendOnce(key, System.currentTimeMillis() / 1000.0 + REPLAY_WINDOW_SECONDS);
    }

    private PublicKey ownerKey() {
        PublicKey cached = ownerKey;
        if (cached != null) {
            return cached;
        }
        try {
            String pem = Files.readString(Path.of(config.ownerKeyPath()));
            String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
            ownerKey = key;
            return key;
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "UMA_AS_OWNER_AUTH=local-key but no owner key at " + config.ownerKeyPath()
                            + ": " + e.getMessage());
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isEmpty();
    }
}
