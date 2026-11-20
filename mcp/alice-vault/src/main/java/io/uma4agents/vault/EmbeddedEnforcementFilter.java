package io.uma4agents.vault;

import io.uma4agents.pep.core.AuthzFacts;
import io.uma4agents.pep.core.Decision;
import io.uma4agents.pep.core.McpRequest;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/**
 * Embedded enforcement: the vault protecting itself, with no gateway in front. Runs ahead
 * of both MCP transports on every request under /mcp. It applies the Origin rule to all of
 * them (the stream GET and session DELETE included), reads the body once, and decides each
 * tools/call with the shared enforcement core over the exact received bytes, before any
 * tool can run. A refusal is rendered in-band as a JSON-RPC error; an allowed call continues
 * to the SDK with the same bytes.
 */
final class EmbeddedEnforcementFilter extends OncePerRequestFilter {

    private static final int MAX_BODY_BYTES = 1024 * 1024;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final VaultSettings settings;

    EmbeddedEnforcementFilter(VaultSettings settings) {
        this.settings = settings;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/mcp");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        Decision refused = settings.enforcer().originRefused(request.getHeader("origin"));
        if (refused != null) {
            writeJson(response, refused.status(), Map.of("error", refused.error()));
            return;
        }
        if (!"POST".equals(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        byte[] body;
        try (InputStream in = request.getInputStream()) {
            body = in.readNBytes(MAX_BODY_BYTES + 1);
        }
        if (body.length > MAX_BODY_BYTES) {
            writeJson(response, 413, Map.of("error", "invalid_request",
                    "error_description", "request body too large"));
            return;
        }
        McpRequest mcp = McpRequest.parse(body);
        if ("tools/call".equals(mcp.method())) {
            Decision d = settings.enforcer().authorize(facts(request, body, mcp));
            if (!d.allowed()) {
                Map<String, Object> rpc = new LinkedHashMap<>();
                rpc.put("jsonrpc", "2.0");
                rpc.put("id", mcp.id());
                rpc.put("error", settings.enforcer().jsonRpcError(d));
                writeJson(response, 200, rpc);
                return;
            }
        }
        chain.doFilter(new CachedBodyRequest(request, body), response);
    }

    private AuthzFacts facts(HttpServletRequest request, byte[] body, McpRequest mcp) {
        return AuthzFacts.builder().mcp(mcp).httpMethod(request.getMethod()).path("/mcp")
                .authorization(request.getHeader("authorization"))
                .signature(request.getHeader("signature"))
                .signatureInput(request.getHeader("signature-input"))
                .origin(request.getHeader("origin"))
                .headerMcpMethod(request.getHeader("mcp-method"))
                .headerMcpName(request.getHeader("mcp-name"))
                .protocolVersion(request.getHeader("mcp-protocol-version"))
                .signatureAgent(request.getHeader("signature-agent"))
                .traceparent(request.getHeader("traceparent"))
                .body(body).contentDigest(request.getHeader("content-digest")).build();
    }

    private static void writeJson(HttpServletResponse response, int status, Object body)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getOutputStream().write(MAPPER.writeValueAsBytes(body));
    }

    /** The request with its already-read body served again to whatever reads it next. */
    static final class CachedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream in = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return in.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    throw new UnsupportedOperationException("synchronous body only");
                }

                @Override
                public int read() {
                    return in.read();
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    return in.read(b, off, len);
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(),
                    StandardCharsets.UTF_8));
        }

        @Override
        public int getContentLength() {
            return body.length;
        }

        @Override
        public long getContentLengthLong() {
            return body.length;
        }
    }
}
