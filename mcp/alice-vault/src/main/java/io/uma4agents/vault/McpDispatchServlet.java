package io.uma4agents.vault;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Sends each request at /mcp to the transport for its protocol generation. A request that
 * declares {@code MCP-Protocol-Version} 2026-07-28 or later is stateless and goes to the
 * modern transport; everything else (the portal's {@code initialize}, its session GET and
 * DELETE) goes to the legacy session transport. Both share the vault's tools.
 */
final class McpDispatchServlet extends HttpServlet {

    private final HttpServlet modern;
    private final HttpServlet legacy;

    McpDispatchServlet(HttpServlet modern, HttpServlet legacy) {
        this.modern = modern;
        this.legacy = legacy;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        modern.init(config);
        legacy.init(config);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        if (isModern(req.getHeader("MCP-Protocol-Version"))) {
            modern.service(req, resp);
        } else {
            legacy.service(req, resp);
        }
    }

    static boolean isModern(String protocolVersion) {
        return protocolVersion != null
                && protocolVersion.compareTo(VaultMcpConfig.MODERN_VERSION) >= 0;
    }

    @Override
    public void destroy() {
        modern.destroy();
        legacy.destroy();
        super.destroy();
    }
}
