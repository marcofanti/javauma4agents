package io.uma4agents.portal;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.stereotype.Component;

/** Login-state helper shared by the controllers (Python's current_user()). */
@Component
public class Sessions {

    private final PortalConfig config;
    private final SessionCookies cookies;
    private final OidcService oidc;

    public Sessions(PortalConfig config, SessionCookies cookies, OidcService oidc) {
        this.config = config;
        this.cookies = cookies;
        this.oidc = oidc;
    }

    /**
     * The logged-in user's display name, or null. A signed cookie can outlive
     * the server-side token store (portal restart): a session without live
     * tokens is not a login.
     */
    public String currentUser(HttpServletRequest request) {
        if (!"oidc".equals(config.authMode)) {
            return "alice";
        }
        Map<String, String> session = cookies.read(request);
        if (!oidc.hasTokens(session.get("sid"))) {
            return null;
        }
        return session.get("user");
    }

    public String sid(HttpServletRequest request) {
        return cookies.read(request).get("sid");
    }
}
