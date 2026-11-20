package io.uma4agents.pep.core;

import java.util.Map;

/**
 * One inbound MCP request, reduced to what a verdict depends on. Deliberately not an HTTP
 * request or an MCP context: each host fills it in from what it has.
 *
 * <p>There is no authority here on purpose: the RFC 9421 base is reconstructed from the
 * enforcer's configured authority, never from the request, because an ext_authz hop rewrites
 * Host and a forwarded value would let a caller choose what it signed over.
 *
 * @param tool tool name from a tools/call body, or null
 * @param args tool arguments, or null
 * @param mcpMethod JSON-RPC method from the body, or null
 * @param httpMethod HTTP method
 * @param path public request path the signature covers
 * @param authorization Authorization header, or null
 * @param signature Signature header ("" when absent)
 * @param signatureInput Signature-Input header ("" when absent)
 * @param origin Origin header, or null
 * @param headerMcpMethod Mcp-Method header, or null
 * @param headerMcpName Mcp-Name header, or null
 * @param protocolVersion MCP-Protocol-Version header, or null
 * @param signatureAgent Signature-Agent header, or null
 * @param body exact received body bytes, or null when the host could not read them
 * @param contentDigest Content-Digest header, or null
 * @param traceparent W3C traceparent header, or null
 */
public record AuthzFacts(String tool, Map<String, Object> args, String mcpMethod,
                         String httpMethod, String path, String authorization, String signature,
                         String signatureInput, String origin, String headerMcpMethod,
                         String headerMcpName, String protocolVersion, String signatureAgent,
                         byte[] body, String contentDigest, String traceparent) {

    public static Builder builder() {
        return new Builder();
    }

    /** Fills the facts field by field; unset strings default as the Python dataclass does. */
    public static final class Builder {
        private String tool;
        private Map<String, Object> args;
        private String mcpMethod;
        private String httpMethod = "POST";
        private String path = "/mcp";
        private String authorization;
        private String signature = "";
        private String signatureInput = "";
        private String origin;
        private String headerMcpMethod;
        private String headerMcpName;
        private String protocolVersion;
        private String signatureAgent;
        private byte[] body;
        private String contentDigest;
        private String traceparent;

        public Builder mcp(McpRequest request) {
            this.mcpMethod = request.method();
            this.tool = request.tool();
            this.args = request.args();
            return this;
        }

        public Builder httpMethod(String value) {
            this.httpMethod = value;
            return this;
        }

        public Builder path(String value) {
            this.path = value;
            return this;
        }

        public Builder authorization(String value) {
            this.authorization = value;
            return this;
        }

        public Builder signature(String value) {
            this.signature = value == null ? "" : value;
            return this;
        }

        public Builder signatureInput(String value) {
            this.signatureInput = value == null ? "" : value;
            return this;
        }

        public Builder origin(String value) {
            this.origin = value;
            return this;
        }

        public Builder headerMcpMethod(String value) {
            this.headerMcpMethod = value;
            return this;
        }

        public Builder headerMcpName(String value) {
            this.headerMcpName = value;
            return this;
        }

        public Builder protocolVersion(String value) {
            this.protocolVersion = value;
            return this;
        }

        public Builder signatureAgent(String value) {
            this.signatureAgent = value;
            return this;
        }

        public Builder body(byte[] value) {
            this.body = value;
            return this;
        }

        public Builder contentDigest(String value) {
            this.contentDigest = value;
            return this;
        }

        public Builder traceparent(String value) {
            this.traceparent = value;
            return this;
        }

        public AuthzFacts build() {
            return new AuthzFacts(tool, args, mcpMethod, httpMethod, path, authorization,
                    signature, signatureInput, origin, headerMcpMethod, headerMcpName,
                    protocolVersion, signatureAgent, body, contentDigest, traceparent);
        }
    }
}
