package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.Jwks;
import java.net.URI;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * What her own authority has seen of an agent, and the lineage it may arrive with. Kept
 * apart from assurance because only standing may relax a requirement: it is the one kind
 * of evidence the requesting side had no hand in producing. Ported from the pinned
 * {@code app.py} ({@code standing_facts}, {@code first_party_fact}, {@code introduction_ok}
 * and their neighbours); the facts are dicts so {@link Rules} stays a pure function.
 */
@Component
public class Standing {

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern(
            "yyyy-MM-dd'T'HH:mm:ss'Z'");

    private final AsConfig config;
    private final OwnerStore store;
    private final GrantService grants;
    private final RequesterMetadata requesterMetadata;
    private final TokenVerifiers verifiers;

    public Standing(AsConfig config, OwnerStore store, GrantService grants,
                    RequesterMetadata requesterMetadata, TokenVerifiers verifiers) {
        this.config = config;
        this.store = store;
        this.grants = grants;
        this.requesterMetadata = requesterMetadata;
        this.verifiers = verifiers;
    }

    /** The origin of the operator an agent names, or null when it names none. */
    @SuppressWarnings("unchecked")
    public static String operatorOrigin(Map<String, Object> identity) {
        Map<String, Object> meta = identity != null
                && identity.get("client_metadata") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Map.of();
        if (!(meta.get("client_id") instanceof String clientId) || clientId.isEmpty()) {
            return null;
        }
        try {
            URI uri = URI.create(clientId);
            String scheme = uri.getScheme();
            String authority = uri.getRawAuthority();
            return scheme != null && authority != null && !authority.isEmpty()
                    ? scheme + "://" + authority : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Did she activate this agent herself: an origin she claimed, and her authority found
     * this agent's key in that operator's own directory (accountability 2). Both halves.
     */
    public boolean firstParty(Map<String, Object> identity, Map<String, Object> axes) {
        if (!(axes.get("accountability") instanceof Number n)
                || n.intValue() != Assurance.ACCOUNTABILITY_ATTESTED) {
            return false;
        }
        String origin = operatorOrigin(identity);
        return origin != null && store.ownedOperators().containsKey(origin);
    }

    /**
     * Who introduced an agent and the parent's revocation count when that was decided, or
     * why the introduction is not honoured. The count pins the parent's generation: a
     * revocation followed by readmission leaves it active but makes it a different
     * relationship.
     */
    public record Lineage(String parentHandle, int parentRevocations, String whyNot) {}

    /**
     * Whether an introduction is honoured, and by whom. A refusal is never fatal: the agent
     * falls back to being a stranger. An identified agent's issuer naming its
     * {@code parent_agent} is an introduction the issuer signed.
     */
    @SuppressWarnings("unchecked")
    public Lineage introduction(Map<String, Object> intro, Map<String, Object> identity,
                                Map<String, Object> childPrior) {
        if (intro == null && identity.get("parent_agent") instanceof String parent
                && !parent.isEmpty()) {
            Map<String, Object> parentIdentity = new LinkedHashMap<>();
            parentIdentity.put("level", "identified");
            parentIdentity.put("iss", identity.get("iss"));
            parentIdentity.put("sub", parent);
            String parentHandle = grants.connectionHandle(parentIdentity, Map.of());
            return admit(parentHandle, childPrior, true);
        }
        if (intro == null) {
            return new Lineage(null, 0, "no lineage was offered");
        }
        Map<String, Object> parentJwk = (Map<String, Object>) intro.get("parent_jwk");
        String parentHandle;
        if (Py.truthy(intro.get("agent_token"))) {
            Map<String, Object> claims;
            try {
                claims = verifiers.verifyAgentToken(String.valueOf(intro.get("agent_token")));
            } catch (RuntimeException e) {
                return new Lineage(null, 0,
                        "the introducing agent's token did not verify: " + e.getMessage());
            }
            Map<String, Object> bound = (Map<String, Object>)
                    ((Map<String, Object>) claims.get("cnf")).get("jwk");
            if (!Jwks.thumbprint(bound).equals(Jwks.thumbprint(parentJwk))) {
                return new Lineage(null, 0, "the introducing agent's token is bound to a "
                        + "different key than the one that signed");
            }
            Map<String, Object> parentIdentity = new LinkedHashMap<>();
            parentIdentity.put("level", "identified");
            parentIdentity.put("iss", claims.get("iss"));
            parentIdentity.put("sub", claims.get("sub"));
            parentHandle = grants.connectionHandle(parentIdentity, parentJwk);
        } else {
            parentHandle = Jwks.thumbprint(parentJwk);
        }
        // One operator publishing both keys, in the same directory under the same client
        // id, so an agent cannot attest to its own sibling from a directory of its own.
        boolean sameOperator = false;
        if (Py.truthy(identity.get("operator_attested"))
                && identity.get("operator_directory") instanceof String directory
                && !directory.isEmpty()
                && identity.get("operator_client_id") instanceof String clientId
                && !clientId.isEmpty()) {
            sameOperator = requesterMetadata.operatorPublishedKey(clientId, directory, parentJwk);
        }
        return admit(parentHandle, childPrior, sameOperator);
    }

    private Lineage admit(String parentHandle, Map<String, Object> childPrior,
                          boolean sameOperator) {
        Map<String, Object> parentConn = store.connection(parentHandle);
        int liveChildren = parentConn == null ? 0 : store.countChildren(parentHandle);
        try {
            Introduction.admit(parentConn, childPrior, sameOperator, liveChildren,
                    config.subagentFanout);
        } catch (Introduction.Refused e) {
            return new Lineage(null, 0, e.getMessage());
        }
        return new Lineage(parentHandle, TokenController.revocations(parentConn), "");
    }

    /**
     * The record for an agent admitted on an introduction: who put it forward, nothing
     * approved for it, and the revocation count of any prior record carried forward.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> introducedConnection(String handle,
                                                           Map<String, Object> identity,
                                                           String parentHandle,
                                                           Map<String, Object> prior) {
        Map<String, Object> meta = identity.get("client_metadata") instanceof Map<?, ?> m
                ? (Map<String, Object>) m : Map.of();
        Map<String, Object> conn = new LinkedHashMap<>();
        conn.put("handle", handle);
        conn.put("identity", identity);
        conn.put("label", Py.truthy(meta.get("client_name")) ? meta.get("client_name")
                : "introduced agent");
        conn.put("status", "active");
        conn.put("parent_handle", parentHandle);
        conn.put("first_seen", EventLog.utcNow());
        conn.put("last_access", null);
        conn.put("tiers_granted", new ArrayList<>());
        conn.put("tiers_approved", new ArrayList<>());
        conn.put("revocations", TokenController.revocations(prior));
        return conn;
    }

    /**
     * Her standing facts about this agent at this tier. {@code age_seconds} is null when she
     * has never met it: younger than everything, older than nothing.
     */
    public static Map<String, Object> facts(Map<String, Object> conn, String tierId,
                                            Map<String, Object> trajectory,
                                            boolean firstParty, List<String> lineageApproved,
                                            double now) {
        Map<String, Object> traj = trajectory != null ? trajectory
                : Map.of("denials", 0, "tiers", List.of(), "calls", 0);
        Map<String, Object> out = new LinkedHashMap<>();
        if (conn == null || !"active".equals(conn.get("status"))) {
            out.put("active", false);
            out.put("age_seconds", null);
            out.put("first_at_tier", true);
            out.put("first_party", firstParty);
            out.put("introduced", false);
            out.put("lineage_new_at_tier", true);
            out.put("approved_tiers", List.of());
            out.put("trajectory", traj);
            out.put("revocations", TokenController.revocations(conn));
            return out;
        }
        List<?> granted = conn.get("tiers_granted") instanceof List<?> l ? l : List.of();
        List<?> approved = conn.get("tiers_approved") instanceof List<?> l ? l : List.of();
        List<?> lineage = lineageApproved != null && !lineageApproved.isEmpty()
                ? lineageApproved : approved;
        out.put("active", true);
        out.put("age_seconds", ageSeconds(conn.get("first_seen"), now));
        out.put("first_party", firstParty);
        out.put("first_at_tier", !granted.contains(tierId));
        out.put("approved_tiers", new ArrayList<>(approved));
        out.put("introduced", Py.truthy(conn.get("parent_handle")));
        out.put("lineage_new_at_tier", !lineage.contains(tierId));
        out.put("revocations", TokenController.revocations(conn));
        out.put("trajectory", traj);
        return out;
    }

    private static Long ageSeconds(Object firstSeen, double now) {
        if (!(firstSeen instanceof String stamp) || stamp.isEmpty()) {
            return null;
        }
        try {
            long seen = LocalDateTime.parse(stamp, STAMP).toEpochSecond(ZoneOffset.UTC);
            return Math.max(0L, (long) (now - seen));
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** Tiers she personally approved across this agent's lineage; its own when it has none. */
    public List<String> lineage(Map<String, Object> conn) {
        if (conn == null || !"active".equals(conn.get("status"))) {
            return List.of();
        }
        Object root = Py.truthy(conn.get("parent_handle")) ? conn.get("parent_handle")
                : conn.get("handle");
        if (!Py.truthy(root)) {
            List<String> own = new ArrayList<>();
            if (conn.get("tiers_approved") instanceof List<?> l) {
                l.forEach(t -> own.add(String.valueOf(t)));
            }
            return own;
        }
        return store.lineageApprovals(String.valueOf(root));
    }

    /** This agent's recent history from her ledger, over {@code UMA_AS_TRAJECTORY_WINDOW}. */
    public Map<String, Object> trajectory(String handle) {
        long window = Rules.parseDuration(config.trajectoryWindow).longValueExact();
        String since = STAMP.format(Instant.ofEpochSecond((long) AsState.now() - window)
                .atOffset(ZoneOffset.UTC));
        return store.trajectory(handle, since);
    }
}
