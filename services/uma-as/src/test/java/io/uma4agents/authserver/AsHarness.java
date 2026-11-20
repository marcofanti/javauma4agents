package io.uma4agents.authserver;

import io.uma4agents.authserver.store.MemoryStore;
import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.authserver.store.Seeds;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EdDsa;
import io.uma4agents.common.Jwks;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;

/** The authorization server's components, wired as Spring wires them, over a memory store. */
final class AsHarness {

    final AsConfig config = new AsConfig();
    final AsState state = new AsState();
    final OwnerStore store;
    final SigningKeys keys;
    final PolicyService policy;
    final Standing standing;
    final Commitment commitment;
    final FakeHttp http = new FakeHttp();
    final GrantService grants;
    final RegistrationPuller puller;
    final TokenController token;
    final ProtectionController protection;

    final KeyPair agent = EdDsa.generate();
    final Map<String, Object> agentJwk = Jwks.okpPublicJwk(agent.getPublic());

    AsHarness() {
        this(new SigningKeys(EdDsa.generate(), "uma-as-1", Map.of()));
    }

    AsHarness(SigningKeys keys) {
        this(keys, null);
    }

    /** A second process over the same store, as after a restart on a durable one. */
    AsHarness(SigningKeys keys, OwnerStore shared) {
        this.keys = keys;
        this.store = shared != null ? shared : new MemoryStore(new Seeds(
                o -> PolicyService.defaults(), o -> StoreConfig.defaultResourceServers(config)))
                .owner(config.ownerUsername);
        store.seed();
        policy = new PolicyService(store, config);
        PeerFetch fetch = new PeerFetch(http);
        TokenVerifiers verifiers = new TokenVerifiers(config, http, fetch);
        RequesterMetadata requesters = new RequesterMetadata(fetch, state, config);
        grants = new GrantService(config, state, store, keys, policy, verifiers, requesters);
        standing = new Standing(config, store, grants, requesters, verifiers);
        puller = new RegistrationPuller(config, state, store, keys, http);
        Organization organization = new Organization(config, state, store, policy, grants,
                puller, fetch, http);
        commitment = new Commitment(config, state, store, policy, grants, standing, organization);
        token = new TokenController(config, state, store, policy, grants, commitment,
                new ResourceServerSignatures(config, fetch), organization, new EnterpriseFederation(config));
        protection = new ProtectionController(config, state, store, keys, grants, puller,
                organization);
    }

    String pat() {
        return "Bearer " + grants.issuePat(config.rsClientId).get("access_token");
    }

    /** Registers a resource as served by the configured resource server. */
    void registered(String resourceId, String... scopes) {
        state.updateResources(r -> {
            Map<String, Object> desc = new LinkedHashMap<>();
            desc.put("resource_scopes", List.of(scopes));
            desc.put("sources", new ArrayList<>(List.of(config.rsClientId)));
            r.put(resourceId, desc);
        });
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> body(ResponseEntity<Object> response) {
        return (Map<String, Object>) response.getBody();
    }

    /** Beats 1 and 2: a ticket, then her terms. Returns the need_info answer. */
    @SuppressWarnings("unchecked")
    Map<String, Object> dictated(String resourceId, String scope) {
        registered(resourceId, scope);
        ResponseEntity<Object> perm = protection.registerPermission(pat(),
                Map.of("resource_id", resourceId, "resource_scopes", List.of(scope)));
        String ticket = String.valueOf(body(perm).get("ticket"));
        return body(token.token("urn:ietf:params:oauth:grant-type:uma-ticket", ticket, null,
                null, null, null, null, null));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> template(Map<String, Object> needInfo) {
        List<Map<String, Object>> claims = (List<Map<String, Object>>) needInfo.get(
                "required_claims");
        return (Map<String, Object>) claims.getFirst().get("terms_template");
    }

    /** The agreement an honest agent signs over the dictated template, changed by {@code edit}. */
    String agreement(Map<String, Object> template, Map<String, Object> edit) {
        Map<String, Object> claims = new LinkedHashMap<>();
        for (String k : List.of("nonce", "family", "template_id", "terms_uri", "purpose",
                "scope", "prohibited", "expires_in")) {
            claims.put(k, template.get(k));
        }
        claims.put("aud", config.issuer);
        claims.putAll(edit);
        claims.values().removeIf(v -> v == REMOVE);
        String jws = CompactJws.sign(Map.of("typ", "JWT", "jwk", agentJwk), claims,
                agent.getPrivate());
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(jws.getBytes(StandardCharsets.UTF_8));
    }

    /** Marks a claim to drop from the agreement. */
    static final Object REMOVE = new Object();

    ResponseEntity<Object> commit(Map<String, Object> needInfo, String claimToken) {
        return token.token("urn:ietf:params:oauth:grant-type:uma-ticket",
                String.valueOf(needInfo.get("ticket")), claimToken, AsConfig.AGREEMENT_FORMAT,
                null, null, null, null);
    }

    ResponseEntity<Object> poll(String ticket) {
        return token.token("urn:ietf:params:oauth:grant-type:uma-ticket", ticket, null, null,
                null, null, null, null);
    }

    String handle() {
        return Jwks.thumbprint(agentJwk);
    }

    /**
     * Admits the agent outright, as an earlier approval would have, and lets tier 1 grant
     * it quietly. Her default tier-1 rule asks about any agent nobody stands behind, which
     * this test agent is; these tests are about grant mechanics, so the rule is removed
     * here the way she would remove it, through a policy edit. Policy is tested apart.
     */
    void connected() {
        policy.updateTier("tier1", Map.of("rules", List.of()));
        Map<String, Object> conn = new LinkedHashMap<>();
        conn.put("handle", handle());
        conn.put("status", "active");
        conn.put("first_seen", "2026-01-01T00:00:00Z");
        conn.put("revocations", 0);
        conn.put("tiers_granted", new ArrayList<>(List.of("tier1")));
        conn.put("tiers_approved", new ArrayList<>(List.of("tier1")));
        store.putConnection(conn);
    }
}
