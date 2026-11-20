package io.uma4agents.authserver;

import io.uma4agents.common.CompactJws;
import io.uma4agents.common.Jose;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.PyJwtClaims;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Sub-agent introductions, as pure functions: {@link #verifyClaim} settles what the
 * document settles on its own, {@link #admit} decides from facts the caller fetched. An
 * introduction is not a token, a grant or a delegation; it buys only not having to be
 * introduced to the owner from nothing. Ported from the pinned {@code introduction.py}.
 */
public final class Introduction {

    public static final String TYP = "u4a-introduction-v1+jws";
    public static final int MAX_BYTES = 4096;

    /** An introduction that will not be honoured, and why. Never fatal to the request. */
    public static final class Refused extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Refused(String message) {
            super(message);
        }
    }

    private Introduction() {}

    /**
     * What the document settles alone: the introducing key, for this child, at this
     * authority, now. Nothing here decides whose key the introducing key is.
     *
     * @return {@code parent_jwk}, {@code agent_token}, {@code jti}, {@code exp}
     * @throws Refused saying why it is not a well-formed introduction
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyClaim(Object intro, String childJkt, String issuer,
                                                  double now) {
        if (!(intro instanceof String token) || token.isEmpty()) {
            throw new Refused("introduction must be a compact JWS");
        }
        if (token.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw new Refused("introduction exceeds " + MAX_BYTES + " bytes");
        }
        Map<String, Object> header;
        try {
            header = CompactJws.parse(token).header();
        } catch (RuntimeException e) {
            throw new Refused("introduction is not a JWS: " + e.getMessage());
        }
        if (!TYP.equals(header.get("typ"))) {
            throw new Refused("introduction must be typ " + TYP);
        }
        if (!(header.get("jwk") instanceof Map<?, ?> jwk)) {
            throw new Refused("introduction must carry the introducing key in its header");
        }
        Map<String, Object> parentJwk = (Map<String, Object>) jwk;
        Map<String, Object> claims;
        try {
            PublicKey key = Jwks.toPublicKey(parentJwk);
            claims = CompactJws.verifyWith(token, key, Jose.algOf(parentJwk)).claims();
            PyJwtClaims.validateWithAudience(claims, now, issuer,
                    "exp", "iat", "jti", "sub", "aud");
        } catch (RuntimeException e) {
            throw new Refused("introduction does not verify: " + e.getMessage());
        }
        if (!childJkt.equals(claims.get("sub"))) {
            throw new Refused("introduction vouches for a different key than the one that "
                    + "signed this contract");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("parent_jwk", parentJwk);
        out.put("agent_token", header.get("agent_token"));
        out.put("jti", claims.get("jti"));
        out.put("exp", claims.get("exp"));
        return out;
    }

    /**
     * Whether an introduction is honoured, cheapest and most absolute reason first.
     *
     * @throws Refused saying why not
     */
    public static void admit(Map<String, Object> parentConn, Map<String, Object> childPrior,
                             boolean sameOperator, int liveChildren, int fanout) {
        if (parentConn == null) {
            throw new Refused("the introducing agent is not a connection of this owner");
        }
        if (!"active".equals(parentConn.get("status"))) {
            throw new Refused("the introducing agent's connection is not active");
        }
        if (!(parentConn.get("tiers_approved") instanceof List<?> approved)
                || approved.isEmpty()) {
            throw new Refused("the introducing agent has nothing this owner approved in person");
        }
        if (Py.truthy(parentConn.get("parent_handle"))) {
            throw new Refused("an agent that was itself introduced may not introduce another");
        }
        if (childPrior != null && !"active".equals(childPrior.get("status"))) {
            throw new Refused("this agent's connection was revoked and cannot be restored by "
                    + "an introduction");
        }
        if (!sameOperator) {
            throw new Refused("the two agents are not published by the same operator");
        }
        if (liveChildren >= fanout) {
            throw new Refused("the introducing agent already has " + liveChildren
                    + " sub-agents, which is the limit (" + fanout + ")");
        }
    }
}
