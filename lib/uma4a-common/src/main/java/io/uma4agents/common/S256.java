package io.uma4agents.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** The lab's content hash: {@code "s256:" + base64url-nopad(sha256(bytes))}. */
public final class S256 {

    private S256() {}

    public static String of(byte[] data) {
        return "s256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(data));
    }

    public static String of(String data) {
        return of(data.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
