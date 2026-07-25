package io.uma4agents.common;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * Minimal RFC 9421 HTTP message signatures — a verbatim port of the lab's
 * {@code uma4a_http_sig.py}, shared by the agent side (signing) and uma-pep
 * (verification) so the two ends cannot drift.
 *
 * <p>Profile: covered components {@code "@method" "@authority" "@path"
 * "authorization"}, label {@code sig1}, params {@code created}, {@code keyid},
 * {@code alg="ed25519"}. Covering {@code authorization} binds the signature to
 * the presented RPT, which is what makes the RPT proof-of-possession.
 *
 * <p>Note: the {@code Signature} header value is <em>standard</em> base64 inside
 * colons (an SF byte sequence), unlike every hash in the protocol.
 */
public final class HttpSignature {

    private static final String[] COMPONENTS =
            {"\"@method\"", "\"@authority\"", "\"@path\"", "\"authorization\""};
    private static final String LABEL = "sig1";

    private HttpSignature() {}

    public static class VerifyException extends RuntimeException {
        public VerifyException(String message) {
            super(message);
        }

        public VerifyException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Returns the {@code Signature-Input} and {@code Signature} headers. */
    public static Map<String, String> sign(String method, String authority, String path,
                                           String authorization, PrivateKey key, String keyid) {
        long created = Instant.now().getEpochSecond();
        byte[] sig = EdDsa.sign(key, base(method, authority, path, authorization, created, keyid));
        return Map.of(
                "Signature-Input", LABEL + "=" + signatureParams(created, keyid),
                "Signature", LABEL + "=:" + Base64.getEncoder().encodeToString(sig) + ":");
    }

    /** Verifies the signature headers; returns the keyid or throws VerifyException. */
    public static String verify(String method, String authority, String path,
                                String authorization, String signatureInput, String signature,
                                PublicKey publicKey, long maxAgeSeconds) {
        long created;
        String keyid;
        String params;
        try {
            int eq = signatureInput.indexOf('=');
            if (eq < 0) {
                throw new VerifyException("malformed Signature-Input: no label");
            }
            String label = signatureInput.substring(0, eq);
            params = signatureInput.substring(eq + 1);
            if (!LABEL.equals(label)) {
                throw new VerifyException("unexpected signature label '" + label + "'");
            }
            String createdPart = params.split("created=", 2)[1].split(";", 2)[0];
            created = Long.parseLong(createdPart);
            keyid = params.split("keyid=\"", 2)[1].split("\"", 2)[0];
        } catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
            throw new VerifyException("malformed Signature-Input: " + e, e);
        }

        if (Math.abs(Instant.now().getEpochSecond() - created) > maxAgeSeconds) {
            throw new VerifyException("signature outside the freshness window");
        }

        String covered = params.split("\\);", 2)[0];
        while (covered.startsWith("(")) {
            covered = covered.substring(1);
        }
        if (!covered.equals(String.join(" ", COMPONENTS))) {
            throw new VerifyException("unexpected covered components: " + covered);
        }

        byte[] raw;
        try {
            int eq = signature.indexOf('=');
            String sigLabel = eq < 0 ? "" : signature.substring(0, eq);
            String sigVal = eq < 0 ? "" : signature.substring(eq + 1);
            if (!LABEL.equals(sigLabel) || !sigVal.startsWith(":") || !sigVal.endsWith(":")) {
                throw new VerifyException("malformed Signature header");
            }
            raw = Base64.getDecoder().decode(sigVal.substring(1, sigVal.length() - 1));
        } catch (IllegalArgumentException e) {
            throw new VerifyException("malformed Signature header: " + e, e);
        }

        boolean ok = EdDsa.verify(publicKey,
                base(method, authority, path, authorization, created, keyid), raw);
        if (!ok) {
            throw new VerifyException("signature verification failed");
        }
        return keyid;
    }

    public static String verify(String method, String authority, String path,
                                String authorization, String signatureInput, String signature,
                                PublicKey publicKey) {
        return verify(method, authority, path, authorization, signatureInput, signature,
                publicKey, 60);
    }

    private static String signatureParams(long created, String keyid) {
        return "(" + String.join(" ", COMPONENTS) + ");created=" + created
                + ";keyid=\"" + keyid + "\";alg=\"ed25519\"";
    }

    private static byte[] base(String method, String authority, String path,
                               String authorization, long created, String keyid) {
        String base = "\"@method\": " + method.toUpperCase(java.util.Locale.ROOT) + "\n"
                + "\"@authority\": " + authority + "\n"
                + "\"@path\": " + path + "\n"
                + "\"authorization\": " + authorization + "\n"
                + "\"@signature-params\": " + signatureParams(created, keyid);
        return base.getBytes(StandardCharsets.UTF_8);
    }
}
