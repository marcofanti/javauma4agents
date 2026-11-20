package io.uma4agents.common;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * RFC 9421 HTTP message signatures, ported from the pinned upstream
 * {@code lib/uma4a_http_sig.py} and shared by every signer and verifier in the lab.
 *
 * <p>Profile: label {@code sig1}; the covered components always include {@code "@method"
 * "@authority" "@path" "authorization"}, optionally followed by {@code "signature-agent"}
 * (Web Bot Auth) and {@code "content-digest"} (RFC 9530). Parameters are {@code created},
 * optional {@code expires}, {@code keyid}, {@code alg="ed25519"}, optional {@code nonce}
 * and {@code tag}. On verify the parameter string is echoed exactly as received, because
 * re-serializing it would change the signed bytes.
 *
 * <p>The {@code Signature} header value is <em>standard</em> base64 inside colons.
 */
public final class HttpSignature {

    private static final List<String> REQUIRED_COMPONENTS =
            List.of("\"@method\"", "\"@authority\"", "\"@path\"", "\"authorization\"");
    private static final String SIGNATURE_AGENT = "\"signature-agent\"";
    private static final String CONTENT_DIGEST = "\"content-digest\"";
    private static final String LABEL = "sig1";
    private static final SecureRandom RANDOM = new SecureRandom();

    private HttpSignature() {}

    /** Raised for any signature that does not verify, with the reason. */
    public static class VerifyException extends RuntimeException {
        public VerifyException(String message) {
            super(message);
        }

        public VerifyException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * What a signer may add beyond the required components.
     *
     * @param signatureAgent Web Bot Auth directory URL to cover and emit, or null
     * @param expiresIn seconds until the signature expires, or null for none
     * @param nonce nonce to use, or null for a fresh random one
     * @param tag the {@code tag} parameter, or null
     * @param body request body whose RFC 9530 digest to cover and emit, or null
     */
    public record SignOptions(String signatureAgent, Integer expiresIn, String nonce,
                              String tag, byte[] body) {
        public static SignOptions none() {
            return new SignOptions(null, null, null, null, null);
        }

        public SignOptions withBody(byte[] newBody) {
            return new SignOptions(signatureAgent, expiresIn, nonce, tag, newBody);
        }
    }

    /**
     * One request to verify, as the verifier reconstructs it.
     *
     * @param method HTTP method
     * @param authority the configured public authority, never a forwarded value
     * @param path the public request path
     * @param authorization the Authorization header value ("" when absent)
     * @param signatureInput the Signature-Input header
     * @param signature the Signature header
     * @param publicKey the key the signature must verify under
     * @param maxAgeSeconds freshness window for {@code created}
     * @param signatureAgent the Signature-Agent header if sent, else null
     * @param body the exact received body bytes, or null if the host could not read them
     * @param requireDigest whether the signature must cover content-digest
     * @param digestHeader the Content-Digest header if sent, else null
     */
    public record VerifyRequest(String method, String authority, String path,
                                String authorization, String signatureInput, String signature,
                                PublicKey publicKey, long maxAgeSeconds, String signatureAgent,
                                byte[] body, boolean requireDigest, String digestHeader) {}

    /** RFC 9530 Content-Digest of a body. */
    public static String contentDigest(byte[] body) {
        return "sha-256=:" + Base64.getEncoder().encodeToString(S256.sha256(body)) + ":";
    }

    /** Returns Signature-Input, Signature, and Signature-Agent / Content-Digest when covered. */
    public static Map<String, String> sign(String method, String authority, String path,
                                           String authorization, PrivateKey key, String keyid,
                                           SignOptions options) {
        String nonce = options.nonce() != null ? options.nonce() : randomNonce();
        long created = Instant.now().getEpochSecond();
        List<String> covered = new ArrayList<>(REQUIRED_COMPONENTS);
        if (options.signatureAgent() != null) {
            covered.add(SIGNATURE_AGENT);
        }
        String digest = options.body() != null ? contentDigest(options.body()) : null;
        if (digest != null) {
            covered.add(CONTENT_DIGEST);
        }
        Long expires = options.expiresIn() != null && options.expiresIn() != 0
                ? created + options.expiresIn() : null;
        String params = paramsString(covered, created, keyid, expires, nonce, options.tag());
        Map<String, String> values = values(method, authority, path, authorization,
                options.signatureAgent(), digest);
        byte[] sig = EdDsa.sign(key, base(covered, values, params));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Signature-Input", LABEL + "=" + params);
        headers.put("Signature", LABEL + "=:" + Base64.getEncoder().encodeToString(sig) + ":");
        if (options.signatureAgent() != null) {
            headers.put("Signature-Agent", options.signatureAgent());
        }
        if (digest != null) {
            headers.put("Content-Digest", digest);
        }
        return headers;
    }

    /** Verifies the request's signature; returns the keyid or throws VerifyException. */
    public static String verify(VerifyRequest r) {
        return verify(r, Instant.now().getEpochSecond());
    }

    static String verify(VerifyRequest r, long nowSeconds) {
        String params = labelledParams(r.signatureInput());
        if (!params.contains(";created=")) {
            throw new VerifyException("signature has no created parameter");
        }
        long created = parseLongParam(params, "created=", "malformed Signature-Input");
        String keyid = quotedParam(params, "keyid=\"");
        if (keyid == null) {
            throw new VerifyException("malformed Signature-Input: no keyid");
        }
        String alg = quotedParam(params, "alg=\"");
        if (alg != null && !"ed25519".equals(alg)) {
            throw new VerifyException("alg '" + alg + "' is not ed25519");
        }
        checkTimes(params, created, r.maxAgeSeconds(), nowSeconds);

        List<String> covered = coveredComponents(params);
        List<String> missing = REQUIRED_COMPONENTS.stream().filter(c -> !covered.contains(c))
                .toList();
        if (!missing.isEmpty()) {
            throw new VerifyException("signature does not cover " + String.join(", ", missing));
        }
        if (r.signatureAgent() != null && !r.signatureAgent().isEmpty()
                && !covered.contains(SIGNATURE_AGENT)) {
            throw new VerifyException(
                    "Signature-Agent was sent but the signature does not cover it");
        }
        String digest = checkedDigest(r, covered);
        Map<String, String> values = values(r.method(), r.authority(), r.path(),
                r.authorization(), r.signatureAgent(), digest);
        List<String> unknown = covered.stream().filter(c -> !values.containsKey(c)).toList();
        if (!unknown.isEmpty()) {
            throw new VerifyException(
                    "cannot reconstruct covered components: " + String.join(", ", unknown));
        }
        byte[] raw = signatureBytes(r.signature());
        if (!EdDsa.verify(r.publicKey(), base(covered, values, params), raw)) {
            throw new VerifyException("signature verification failed");
        }
        return keyid;
    }

    private static String labelledParams(String signatureInput) {
        int eq = signatureInput == null ? -1 : signatureInput.indexOf('=');
        if (eq < 0) {
            throw new VerifyException("malformed Signature-Input: no label");
        }
        String label = signatureInput.substring(0, eq);
        if (!LABEL.equals(label)) {
            throw new VerifyException("unexpected signature label '" + label + "'");
        }
        return signatureInput.substring(eq + 1);
    }

    private static void checkTimes(String params, long created, long maxAgeSeconds,
                                   long now) {
        if (Math.abs(now - created) > maxAgeSeconds) {
            throw new VerifyException("signature outside the freshness window");
        }
        if (params.contains("expires=")) {
            long expires = parseLongParam(params, "expires=", "malformed expires");
            if (now > expires) {
                throw new VerifyException("signature expired");
            }
        }
    }

    private static String checkedDigest(VerifyRequest r, List<String> covered) {
        if (r.requireDigest() && !covered.contains(CONTENT_DIGEST)) {
            throw new VerifyException("signature does not cover content-digest");
        }
        if (!covered.contains(CONTENT_DIGEST)) {
            return null;
        }
        if (r.digestHeader() == null || r.digestHeader().isEmpty()) {
            throw new VerifyException("signature covers content-digest but none was sent");
        }
        if (r.body() == null) {
            throw new VerifyException("signature covers content-digest but no body was read");
        }
        String digest = r.digestHeader().strip();
        if (!digest.equals(contentDigest(r.body()))) {
            throw new VerifyException("content-digest does not match the body");
        }
        return digest;
    }

    private static List<String> coveredComponents(String params) {
        String coveredStr = params.split("\\);", 2)[0];
        while (coveredStr.startsWith("(")) {
            coveredStr = coveredStr.substring(1);
        }
        List<String> covered = new ArrayList<>();
        for (String c : coveredStr.split(" ")) {
            if (!c.isEmpty()) {
                covered.add(c);
            }
        }
        return covered;
    }

    private static byte[] signatureBytes(String signature) {
        int eq = signature == null ? -1 : signature.indexOf('=');
        String sigLabel = eq < 0 ? "" : signature.substring(0, eq);
        String sigVal = eq < 0 ? "" : signature.substring(eq + 1);
        if (!LABEL.equals(sigLabel) || sigVal.length() < 2 || !sigVal.startsWith(":")
                || !sigVal.endsWith(":")) {
            throw new VerifyException("malformed Signature header");
        }
        try {
            return Base64.getDecoder().decode(sigVal.substring(1, sigVal.length() - 1));
        } catch (IllegalArgumentException e) {
            throw new VerifyException("malformed Signature header: " + e.getMessage(), e);
        }
    }

    private static long parseLongParam(String params, String prefix, String error) {
        String[] after = params.split(prefix, 2);
        if (after.length < 2) {
            throw new VerifyException(error + ": no " + prefix);
        }
        try {
            return Long.parseLong(after[1].split(";", 2)[0]);
        } catch (NumberFormatException e) {
            throw new VerifyException(error + ": " + e.getMessage(), e);
        }
    }

    private static String quotedParam(String params, String prefix) {
        String[] after = params.split(java.util.regex.Pattern.quote(prefix), 2);
        if (after.length < 2) {
            return null;
        }
        int end = after[1].indexOf('"');
        return end < 0 ? null : after[1].substring(0, end);
    }

    private static String paramsString(List<String> covered, long created, String keyid,
                                       Long expires, String nonce, String tag) {
        StringBuilder s = new StringBuilder("(").append(String.join(" ", covered))
                .append(");created=").append(created);
        if (expires != null) {
            s.append(";expires=").append(expires);
        }
        s.append(";keyid=\"").append(keyid).append("\";alg=\"ed25519\"");
        if (nonce != null) {
            s.append(";nonce=\"").append(nonce).append('"');
        }
        if (tag != null) {
            s.append(";tag=\"").append(tag).append('"');
        }
        return s.toString();
    }

    private static Map<String, String> values(String method, String authority, String path,
                                              String authorization, String signatureAgent,
                                              String digest) {
        Map<String, String> v = new LinkedHashMap<>();
        v.put("\"@method\"", method.toUpperCase(Locale.ROOT));
        v.put("\"@authority\"", authority);
        v.put("\"@path\"", path);
        v.put("\"authorization\"", authorization == null ? "" : authorization);
        if (signatureAgent != null && !signatureAgent.isEmpty()) {
            v.put(SIGNATURE_AGENT, signatureAgent);
        }
        if (digest != null) {
            v.put(CONTENT_DIGEST, digest);
        }
        return v;
    }

    private static byte[] base(List<String> covered, Map<String, String> values,
                               String params) {
        StringBuilder sb = new StringBuilder();
        for (String c : covered) {
            sb.append(c).append(": ").append(values.get(c)).append('\n');
        }
        sb.append("\"@signature-params\": ").append(params);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String randomNonce() {
        byte[] raw = new byte[12];
        RANDOM.nextBytes(raw);
        return Jwks.b64url(raw);
    }
}
