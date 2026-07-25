package io.uma4agents.common;

import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * Compact JWS with arbitrary protected headers (the contracts carry non-standard
 * members like {@code jwk} and {@code agent_token}), EdDSA (Ed25519) only.
 */
public final class CompactJws {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private CompactJws() {}

    /** A parsed compact JWS: protected header, payload claims, and raw segments. */
    public record Parsed(Map<String, Object> header, Map<String, Object> claims,
                         String signingInput, byte[] signature, String compact) {}

    public static String sign(Map<String, Object> header, Map<String, Object> claims,
                              PrivateKey key) {
        Map<String, Object> fullHeader = new java.util.LinkedHashMap<>(header);
        fullHeader.put("alg", "EdDSA");
        String input = Jwks.b64url(toJson(fullHeader)) + "." + Jwks.b64url(toJson(claims));
        byte[] sig = EdDsa.sign(key, input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + Jwks.b64url(sig);
    }

    public static Parsed parse(String compact) {
        String[] parts = compact.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("not a compact JWS (expected 3 segments)");
        }
        Map<String, Object> header = fromJson(Jwks.b64urlDecode(parts[0]));
        Map<String, Object> claims = fromJson(Jwks.b64urlDecode(parts[1]));
        return new Parsed(header, claims, parts[0] + "." + parts[1],
                Jwks.b64urlDecode(parts[2]), compact);
    }

    /** Parses and verifies the EdDSA signature; throws on any failure. */
    public static Parsed verify(String compact, PublicKey key) {
        Parsed parsed = parse(compact);
        Object alg = parsed.header().get("alg");
        if (!"EdDSA".equals(alg)) {
            throw new SecurityException("unexpected JWS alg: " + alg);
        }
        boolean ok = EdDsa.verify(key,
                parsed.signingInput().getBytes(StandardCharsets.US_ASCII), parsed.signature());
        if (!ok) {
            throw new SecurityException("JWS signature verification failed");
        }
        return parsed;
    }

    private static byte[] toJson(Map<String, Object> value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("unserializable JWS content", e);
        }
    }

    private static Map<String, Object> fromJson(byte[] json) {
        try {
            return MAPPER.readValue(json, MAP_TYPE);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("malformed JWS segment", e);
        }
    }
}
