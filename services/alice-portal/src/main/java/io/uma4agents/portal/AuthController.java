package io.uma4agents.portal;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/** OIDC login / callback / logout, mirroring the authlib flow in Python. */
@RestController
public class AuthController {

    private final OidcService oidc;
    private final SessionCookies cookies;

    public AuthController(OidcService oidc, SessionCookies cookies) {
        this.oidc = oidc;
        this.cookies = cookies;
    }

    @GetMapping("/auth/login")
    public ResponseEntity<Void> login() {
        String redirectUri = callbackUrl();
        return redirect(oidc.authorizationUrl(redirectUri));
    }

    @GetMapping("/auth/callback")
    public ResponseEntity<Void> callback(@RequestParam(required = false) String code,
                                         @RequestParam(required = false) String state,
                                         HttpServletResponse response) {
        Map<String, String> result = oidc.handleCallback(code, state, callbackUrl());
        if (result == null) {
            return redirect("/login");
        }
        Map<String, String> session = new HashMap<>();
        session.put("sid", result.get("sid"));
        session.put("user", result.get("user"));
        cookies.write(response, session);
        return redirect("/");
    }

    @GetMapping("/auth/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        oidc.drop(cookies.read(request).get("sid"));
        cookies.clear(response);
        return redirect("/login");
    }

    /** The callback URL as seen through the TLS edge (forces https, like Python). */
    private static String callbackUrl() {
        String url = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/auth/callback").build().toUriString();
        return url.replace("http://", "https://");
    }

    private static ResponseEntity<Void> redirect(String location) {
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", location).build();
    }
}
