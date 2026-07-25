package io.uma4agents.agent;

import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * AAuth request signing, {@code hwk} scheme — a Java transcription of
 * {@code aauth_signing.signer.sign_request} (draft-hardt-httpbis-signature-key).
 *
 * <p>This is a different RFC 9421 profile than the lab's PoP profile: label
 * {@code sig}, covered components {@code @method @authority @path [@query]
 * signature-key}, only {@code created} in the params, and the Signature header
 * carries <em>base64url-nopad</em> inside colons.
 */
public final class AauthHwkSigner {

    private AauthHwkSigner() {}

    /** Returns Signature-Input, Signature, and Signature-Key headers. */
    public static Map<String, String> signRequest(String method, String targetUri,
                                                  KeyPair ephemeralKey) {
        URI uri = URI.create(targetUri);
        String authority = uri.getAuthority();
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty()
                ? "/" : uri.getRawPath();
        String query = uri.getRawQuery();

        String label = "sig";
        Map<String, Object> jwk = Jwks.okpPublicJwk(ephemeralKey.getPublic());
        String signatureKey = label + "=hwk;" + sfParameters(List.of(
                Map.entry("kty", String.valueOf(jwk.get("kty"))),
                Map.entry("crv", String.valueOf(jwk.get("crv"))),
                Map.entry("x", String.valueOf(jwk.get("x")))));

        List<String> covered = new ArrayList<>(List.of("@method", "@authority", "@path"));
        if (query != null && !query.isEmpty()) {
            covered.add("@query");
        }
        covered.add("signature-key");

        long created = Instant.now().getEpochSecond();
        String componentList = covered.stream()
                .map(c -> "\"" + c + "\"").collect(Collectors.joining(" "));
        String signatureParams = "(" + componentList + ");created=" + created;

        List<String> baseLines = new ArrayList<>();
        for (String component : covered) {
            switch (component) {
                case "@method" -> baseLines.add("\"@method\": " + method);
                case "@authority" -> baseLines.add("\"@authority\": " + authority);
                case "@path" -> baseLines.add("\"@path\": " + path);
                case "@query" -> baseLines.add("\"@query\": ?" + query);
                case "signature-key" -> baseLines.add("\"signature-key\": " + signatureKey);
                default -> throw new IllegalStateException("unknown component " + component);
            }
        }
        baseLines.add("\"@signature-params\": " + signatureParams);
        byte[] base = String.join("\n", baseLines).getBytes(StandardCharsets.UTF_8);

        byte[] signature = EdDsa.sign(ephemeralKey.getPrivate(), base);
        String signatureB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Signature-Input", label + "=" + signatureParams);
        headers.put("Signature", label + "=:" + signatureB64 + ":");
        headers.put("Signature-Key", signatureKey);
        return headers;
    }

    /** RFC 8941 Item parameters: {@code key="value"} joined by semicolons. */
    private static String sfParameters(List<Map.Entry<String, String>> pairs) {
        return pairs.stream()
                .map(e -> e.getKey() + "=\"" + e.getValue()
                        .replace("\\", "\\\\").replace("\"", "\\\"") + "\"")
                .collect(Collectors.joining(";"));
    }
}
