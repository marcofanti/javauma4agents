package io.uma4agents.portal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * HMAC-signed session cookie carrying only {@code {sid, user}} — the analogue of
 * Starlette's SessionMiddleware. Tokens themselves never enter the cookie.
 */
@Component
public class SessionCookies {

    static final String COOKIE_NAME = "session";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final byte[] secret;

    public SessionCookies(PortalConfig config) {
        this.secret = config.sessionSecret.getBytes(StandardCharsets.UTF_8);
    }

    public Map<String, String> read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return new HashMap<>();
        }
        for (Cookie cookie : cookies) {
            if (!COOKIE_NAME.equals(cookie.getName())) {
                continue;
            }
            String[] parts = cookie.getValue().split("\\.", 2);
            if (parts.length != 2) {
                return new HashMap<>();
            }
            byte[] payload;
            byte[] mac;
            try {
                payload = Base64.getUrlDecoder().decode(parts[0]);
                mac = Base64.getUrlDecoder().decode(parts[1]);
            } catch (IllegalArgumentException e) {
                return new HashMap<>();
            }
            if (!MessageDigest.isEqual(mac, hmac(payload))) {
                return new HashMap<>();
            }
            try {
                return MAPPER.readValue(payload, new TypeReference<>() {});
            } catch (java.io.IOException e) {
                return new HashMap<>();
            }
        }
        return new HashMap<>();
    }

    public void write(HttpServletResponse response, Map<String, String> session) {
        byte[] payload;
        try {
            payload = MAPPER.writeValueAsBytes(session);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("unserializable session", e);
        }
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(payload)
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(payload));
        response.addHeader("Set-Cookie",
                COOKIE_NAME + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Lax");
    }

    public void clear(HttpServletResponse response) {
        response.addHeader("Set-Cookie",
                COOKIE_NAME + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
    }

    private byte[] hmac(byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
