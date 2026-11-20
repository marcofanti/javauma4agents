package io.uma4agents.authserver;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * This authority's signing key and every key it has retired.
 *
 * <p>Rotation: the new key becomes {@code UMA_AS_SIGNING_KEY} under a new
 * {@code UMA_AS_KID}, and the old one moves to {@code UMA_AS_PREVIOUS_KEYS} (PEM, private
 * or public; a private key is reduced to its public half and never signs again), with its
 * kid in {@code UMA_AS_PREVIOUS_KIDS} in the same order or, where absent, its RFC 7638
 * thumbprint. What {@code /jwks} publishes and what this server verifies its own tokens
 * with are the same set, so every grant, receipt and PAT the old key signed stays
 * verifiable while it is listed, and a verifier holding the old set learns the new one by
 * refetching on a kid it does not hold.
 */
public final class SigningKeys {

    private final KeyPair current;
    private final String kid;
    private final Map<String, PublicKey> verification;

    SigningKeys(KeyPair current, String kid, Map<String, PublicKey> retired) {
        this.current = current;
        this.kid = kid;
        Map<String, PublicKey> all = new LinkedHashMap<>();
        all.put(kid, current.getPublic());
        retired.forEach(all::putIfAbsent);
        this.verification = Collections.unmodifiableMap(all);
    }

    /**
     * Loads the signing key (creating it when absent, as at first start) and the retired
     * keys the configuration lists.
     *
     * @throws IllegalStateException naming the file when a retired key cannot be read
     */
    public static SigningKeys load(AsConfig config) {
        return load(config.keyPath, config.kid, config.previousKeyPaths, config.previousKids);
    }

    static SigningKeys load(String keyPath, String kid, List<String> previousKeyPaths,
                            List<String> previousKids) {
        KeyPair current = EdDsa.loadOrCreate(Path.of(keyPath));
        Map<String, PublicKey> retired = new LinkedHashMap<>();
        for (int i = 0; i < previousKeyPaths.size(); i++) {
            String path = previousKeyPaths.get(i);
            PublicKey key = readPublic(Path.of(path));
            String given = i < previousKids.size() ? previousKids.get(i) : "";
            String id = given.isEmpty()
                    ? Jwks.thumbprint(Jwks.okpPublicJwk(key))
                    : given;
            retired.put(id, key);
        }
        return new SigningKeys(current, kid, retired);
    }

    private static PublicKey readPublic(Path path) {
        String pem;
        try {
            pem = Files.readString(path);
        } catch (IOException e) {
            throw new IllegalStateException("UMA_AS_PREVIOUS_KEYS names " + path
                    + ", which cannot be read: " + e.getMessage(), e);
        }
        if (pem.contains("PRIVATE KEY")) {
            return EdDsa.publicFrom(EdDsa.privateFromPem(pem));
        }
        try {
            byte[] der = Base64.getDecoder().decode(
                    pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", ""));
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException(path + " is not an Ed25519 PEM key: "
                    + e.getMessage(), e);
        }
    }

    public KeyPair current() {
        return current;
    }

    /** The kid every token this server signs from now on carries. */
    public String kid() {
        return kid;
    }

    /** The JWS header for one of this server's own token types. */
    public Map<String, Object> header(String typ) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", typ);
        header.put("kid", kid);
        return header;
    }

    /** Every key a token of this server may name: the current one first, then the retired. */
    public Map<String, Object> jwks() {
        List<Map<String, Object>> keys = new ArrayList<>();
        verification.forEach((id, key) -> {
            Map<String, Object> jwk = Jwks.okpPublicJwk(key);
            jwk.put("kid", id);
            jwk.put("use", "sig");
            keys.add(jwk);
        });
        return Map.of("keys", keys);
    }

    /**
     * Verifies one of this server's own tokens against the key its kid names. A token
     * naming no kid, or one this server never held, is checked against the current key
     * and fails there unless it is ours.
     *
     * @throws SecurityException when the signature does not verify
     */
    public CompactJws.Parsed verifyOwn(String token) {
        Object named = CompactJws.parse(token).header().get("kid");
        PublicKey key = named instanceof String id && verification.containsKey(id)
                ? verification.get(id) : current.getPublic();
        return CompactJws.verify(token, key);
    }
}
