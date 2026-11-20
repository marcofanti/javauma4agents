package io.uma4agents.vault;

import io.modelcontextprotocol.modern.McpSchema;
import io.modelcontextprotocol.modern.server.McpAsyncResponse;
import io.modelcontextprotocol.modern.server.McpFeature;
import io.modelcontextprotocol.modern.server.McpRequestContext;
import io.uma4agents.pep.core.Enforcer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import reactor.core.publisher.Mono;

/**
 * Advertises {@code dev.uma4agents/uma-enforcement} in the {@code server/discover}
 * capabilities when the vault protects itself, so a client learns from discovery which
 * authorization server governs it and which JSON-RPC code carries the challenge. The
 * enforcement itself runs in {@link EmbeddedEnforcementFilter}, ahead of the SDK, where the
 * exact request bytes are available.
 */
final class EnforcementExtension implements McpFeature {

    static final String IDENTIFIER = "dev.uma4agents/uma-enforcement";

    private final VaultSettings settings;

    EnforcementExtension(VaultSettings settings) {
        this.settings = settings;
    }

    @Override
    public Set<String> methods() {
        return Set.of();
    }

    @Override
    public Mono<? extends McpAsyncResponse<? extends McpSchema.Result>> handle(
            McpRequestContext context, Object params) {
        return Mono.error(new IllegalStateException(IDENTIFIER + " handles no methods"));
    }

    @Override
    public void capabilities(McpSchema.ServerCapabilities.Builder builder) {
        Map<String, Object> settingsDoc = new LinkedHashMap<>();
        settingsDoc.put("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        settingsDoc.put("authorization_servers", List.of(settings.asPublic));
        settingsDoc.put("challenge", Map.of("jsonrpc_error_code", Enforcer.UMA_CHALLENGE));
        builder.extension(IDENTIFIER, settingsDoc);
    }
}
