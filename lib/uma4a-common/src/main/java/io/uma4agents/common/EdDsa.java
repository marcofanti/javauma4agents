package io.uma4agents.common;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Ed25519 via the JDK provider (no external crypto deps), with PKCS8/X.509 PEM
 * interop matching Python {@code cryptography}'s output so Docker key volumes
 * survive the language swap.
 */
public final class EdDsa {

    // RFC 8410 DER prefixes for Ed25519 raw-key wrapping.
    private static final byte[] PKCS8_PREFIX = hex("302e020100300506032b657004220420");
    private static final byte[] X509_PREFIX = hex("302a300506032b6570032100");

    private EdDsa() {}

    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] data) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] data, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Loads the key at {@code path}, generating and persisting one if absent. */
    public static KeyPair loadOrCreate(Path path) {
        if (Files.exists(path)) {
            return load(path);
        }
        KeyPair pair = generate();
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            Files.writeString(path, toPkcs8Pem(pair.getPrivate()));
        } catch (IOException e) {
            throw new IllegalStateException("cannot persist key at " + path, e);
        }
        return pair;
    }

    public static KeyPair load(Path path) {
        try {
            PrivateKey priv = privateFromPem(Files.readString(path));
            return new KeyPair(publicFrom(priv), priv);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read key at " + path, e);
        }
    }

    public static String toPkcs8Pem(PrivateKey key) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(key.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    public static PrivateKey privateFromPem(String pem) {
        byte[] der = Base64.getMimeDecoder().decode(
                pem.replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .trim());
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("not an Ed25519 PKCS8 key", e);
        }
    }

    /**
     * Derives the public key from the private key's PKCS8 seed (RFC 8032 §5.1.5).
     * The JDK exposes no private-to-public derivation for EdDSA keys.
     */
    public static PublicKey publicFrom(PrivateKey priv) {
        byte[] pkcs8 = priv.getEncoded();
        byte[] seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
        return publicFromRaw(Ed25519Math.publicKeyFromSeed(seed));
    }

    public static PublicKey publicFromRaw(byte[] raw32) {
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, raw32)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("not a raw Ed25519 public key", e);
        }
    }

    public static byte[] rawPublic(PublicKey key) {
        byte[] x509 = key.getEncoded();
        return Arrays.copyOfRange(x509, x509.length - 32, x509.length);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
