package io.uma4agents.authserver;

import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.common.Clearance;
import io.uma4agents.common.CompactJws;
import io.uma4agents.common.EventLog;
import io.uma4agents.common.Jwks;
import io.uma4agents.common.OrganizationEnvelope;
import io.uma4agents.common.OrganizationPatterns;
import io.uma4agents.common.PyJwtClaims;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** The owner's side of an organization membership and the charter it applies. */
@Component
final class Organization {
    static final String NOTICE_TYPE = "u4a-org-notice+jwt";
    static final String ADMIN_TYPE = "u4a-org-admin+jwt";
    private static final ObjectMapper JSON = new ObjectMapper();

    final AsConfig config;
    final AsState state;
    final OwnerStore store;
    private final PolicyService policy;
    private final GrantService grants;
    private final RegistrationPuller puller;
    private final PeerFetch fetch;
    private final HttpClient http;
    private final long ttl = seconds("UMA_AS_ORG_TTL_S", "30");
    private final long maxStale = seconds("UMA_AS_ORG_STALE_MAX_S", "600");
    private final long retry = seconds("UMA_AS_ORG_RETRY_S", "15");
    private final Duration timeout = Duration.ofMillis(seconds("UMA_AS_ORG_TIMEOUT_S", "5"));
    private String trackedToken;
    private long fetchedAt;
    private long triedAt;
    private String problem;
    private String clearanceToken;
    private long clearanceFetched;
    private String cachedIssuer;
    private long keysFetched;
    private List<Map<String, Object>> keys = List.of();

    Organization(AsConfig config, AsState state, OwnerStore store, PolicyService policy,
                 GrantService grants, RegistrationPuller puller, PeerFetch fetch,
                 HttpClient http) {
        this.config = config;
        this.state = state;
        this.store = store;
        this.policy = policy;
        this.grants = grants;
        this.puller = puller;
        this.fetch = fetch;
        this.http = http;
    }

    record Reply(int status, Map<String, Object> body) {
        boolean ok() { return status >= 200 && status < 300; }
    }

    record Attestation(List<String> problems, Map<String, Object> facts) {}

    synchronized Map<String, Object> current(boolean force) {
        Map<String, Object> rec = store.organization();
        if (rec == null || !(rec.get("token") instanceof String token)
                || !(rec.get("issuer") instanceof String issuer)) {
            return null;
        }
        long now = System.currentTimeMillis();
        if (!token.equals(trackedToken)) {
            reset(token, number(rec.get("fetched_at"), now));
        }
        if (!force && (now - fetchedAt < ttl || problem != null && now - triedAt < retry)) {
            return rec;
        }
        triedAt = now;
        try {
            Reply answer = send(issuer, "GET", "/member/envelope", token, null);
            if (answer.status() == 403) {
                end(rec, "your organization ended this membership");
                return store.organization();
            }
            if (!answer.ok() || !issuer.equals(answer.body().get("issuer"))) {
                throw new IllegalStateException("organization envelope returned HTTP " + answer.status());
            }
            long completed = System.currentTimeMillis();
            if (store.updateOrganization(token, Map.of("envelope", answer.body(), "fetched_at", completed))) {
                fetchedAt = completed;
                problem = null;
                Map<String, Object> before = object(rec.get("envelope"));
                if (!answer.body().equals(before)) {
                    apply(answer.body(), before, token);
                }
            }
            return store.organization();
        } catch (RuntimeException unavailable) {
            problem = unavailable.getMessage();
            return store.organization();
        }
    }

    private void reset(String token, long now) {
        trackedToken = token;
        fetchedAt = now;
        triedAt = 0;
        problem = null;
        clearanceToken = null;
    }

    synchronized List<Map<String, Object>> joined(String issuer, String token, Map<String, Object> envelope) {
        long now = System.currentTimeMillis();
        store.putOrganization(row("issuer", issuer, "token", token, "envelope", envelope,
                "joined", EventLog.utcNow(), "fetched_at", now));
        reset(token, now);
        List<Map<String, Object>> powers = new ArrayList<>();
        for (Object item : list(object(envelope.get("powers")).get("can"))) {
            powers.add(object(item));
        }
        ledger("org_joined", "-", row("organization", envelope.get("name"),
                "charter_version", envelope.get("charter_version"), "requires", envelope.get("summary"),
                "agreed_to", powers.stream().map(item -> item.get("what")).toList()), null);
        List<Map<String, Object>> changes = apply(envelope, Map.of(), token);
        store.notify(row("type", "organization", "state", "joined", "name", envelope.get("name")));
        return changes;
    }

    synchronized void end(Map<String, Object> rec, String why) {
        String token = text(rec.get("token"));
        if (store.clearOrganization(token)) {
            reset(null, 0);
            resync(Map.of(), effectiveEnvelope(store, rec));
            ledger("org_left", "-", Map.of("why", why), null);
            store.notify(Map.of("type", "organization", "state", "ended", "why", why));
        }
    }

    Map<String, Object> envelope() {
        return effectiveEnvelope(store, current(false));
    }

    static Map<String, Object> envelopeOf(Map<String, Object> rec) {
        return rec == null ? Map.of() : object(rec.get("envelope"));
    }

    static Map<String, Object> effectiveEnvelope(OwnerStore store, Map<String, Object> rec) {
        return withJointExclusions(store, envelopeOf(rec));
    }

    static Map<String, Object> withJointExclusions(OwnerStore store, Map<String, Object> envelope) {
        if (envelope.isEmpty()) {
            return envelope;
        }
        List<?> shares = list(envelope.get("grants"));
        var excluded = jointPatterns(store).stream()
                .filter(resource -> !OrganizationPatterns.matches(resource, shares))
                .distinct().sorted().toList();
        var effective = new LinkedHashMap<>(envelope);
        effective.put("excluded", excluded);
        return effective;
    }

    static List<String> jointPatterns(OwnerStore store) {
        return store.mandates().values().stream()
                .flatMap(record -> list(object(record.get("mandate")).get("resources")).stream())
                .filter(String.class::isInstance).map(String.class::cast).toList();
    }

    synchronized String block(String resource) {
        Map<String, Object> envelope = envelope();
        if (!OrganizationEnvelope.reaches(resource, envelope)) {
            return null;
        }
        if (unreadable()) {
            return envelope.get("name") + "'s policy could not be read, and access to its "
                    + "resources does not proceed without it";
        }
        if (!OrganizationPatterns.matches(resource, list(envelope.get("grants")))) {
            String role = text(envelope.get("role_name"));
            return envelope.get("name") + " has not shared this resource with you"
                    + (role.isEmpty() ? ", and you hold no role there" : " — your role here is " + role);
        }
        return null;
    }

    boolean blockedAgent(String resource, String handle, Map<String, Object> identity) {
        Map<String, Object> rec = store.organization();
        if (!OrganizationEnvelope.reaches(resource, effectiveEnvelope(store, rec))) {
            return false;
        }
        Map<String, Object> blocked = object(rec.get("blocked"));
        String operator = Standing.operatorOrigin(identity);
        return object(blocked.get("handles")).containsKey(handle)
                || operator != null && object(blocked.get("operators")).containsKey(operator);
    }

    Map<String, Object> decision(Map<String, Object> negotiation, Map<String, Object> contract,
                                 Map<String, Object> facts) {
        Map<String, Object> rec = current(false);
        Map<String, Object> envelope = effectiveEnvelope(store, rec);
        String resource = text(negotiation.get("resource_id"));
        if (!OrganizationEnvelope.reaches(resource, envelope)) {
            return Map.of();
        }
        Map<String, Object> evidence = row("resource_id", resource,
                "scopes", negotiation.get("resource_scopes"), "tier", negotiation.get("tier"),
                "expires_in", contract.getOrDefault("expires_in", 0), "purpose", contract.get("purpose"),
                "reason", contract.get("reason"), "mission", contract.get("mission"),
                "operation", contract.get("operation"), "assurance", facts.get("assurance"),
                "standing", facts.get("standing"));
        Map<String, Object> result;
        try {
            Reply response = send(text(rec.get("issuer")), "POST", "/decision",
                    text(rec.get("token")), evidence);
            if (!response.ok() || !Set.of("allow", "ask", "refuse")
                    .contains(text(response.body().get("effect")))) {
                throw new IllegalStateException("the organization refused the decision credential");
            }
            result = new LinkedHashMap<>(response.body());
        } catch (RuntimeException unavailable) {
            result = row("effect", "refuse", "because", List.of(
                    "the organization could not be reached, and its policy is not something "
                            + "this request may proceed without"), "governed", true);
        }
        result.put("organization", envelope.get("name"));
        result.put("org", envelope.get("org"));
        return result;
    }

    synchronized Attestation attest(Map<String, Object> tier, String resource) {
        Map<String, Object> rec = current(false);
        Map<String, Object> envelope = effectiveEnvelope(store, rec);
        Map<String, Object> requirement = Clearance.tighten(tier.get("clearance"),
                OrganizationEnvelope.reaches(resource, envelope) ? envelope.get("require_clearance") : null);
        if (requirement.isEmpty()) {
            return new Attestation(List.of(), Map.of());
        }
        if (rec == null) {
            return noClearance("these terms require a clearance, and this authority has no "
                    + "organization that could attest to one");
        }
        String issuer = text(rec.get("issuer"));
        try {
            long now = System.currentTimeMillis();
            if (clearanceToken == null || now - clearanceFetched >= ttl) {
                Reply reply = send(issuer, "GET", "/member/clearance", text(rec.get("token")), null);
                if (reply.status() == 404) {
                    clearanceToken = null;
                    return noClearance("the organization holds no clearance for this owner");
                }
                if (!reply.ok()) {
                    return noClearance("the organization could not be reached to check the clearance: "
                            + "HTTP " + reply.status());
                }
                clearanceToken = text(reply.body().get("clearance"));
                clearanceFetched = now;
            }
            Map<String, Object> facts;
            try {
                facts = Clearance.verify(clearanceToken, keys(issuer, false), issuer, config.issuer,
                        config.ownerUsername, AsState.now());
            } catch (IllegalArgumentException invalid) {
                facts = Clearance.verify(clearanceToken, keys(issuer, true), issuer, config.issuer,
                        config.ownerUsername, AsState.now());
            }
            return new Attestation(Clearance.unmet(requirement, facts), facts);
        } catch (RuntimeException invalid) {
            return noClearance(invalid.getMessage() == null ? "the clearance could not be checked"
                    : invalid.getMessage());
        }
    }

    Map<String, Object> verify(String jwt, String typ, Map<String, Object> rec, boolean notice) {
        if (rec == null) {
            return null;
        }
        String issuer = text(rec.get("issuer"));
        CompactJws.Parsed parsed = CompactJws.parse(jwt);
        if (!typ.equals(parsed.header().get("typ")) || !issuer.equals(parsed.claims().get("iss"))
                || !config.ownerUsername.equals(parsed.claims().get("sub"))) {
            return null;
        }
        for (boolean fresh : List.of(false, true)) {
            for (Map<String, Object> key : keys(issuer, fresh)) {
                Object kid = parsed.header().get("kid");
                if (kid != null && !kid.equals(key.get("kid"))) {
                    continue;
                }
                try {
                    Map<String, Object> claims = CompactJws.verify(jwt, Jwks.toPublicKey(key)).claims();
                    if (notice) {
                        PyJwtClaims.validateWithIat(claims, AsState.now(), "exp", "iat", "jti");
                    } else {
                        PyJwtClaims.validateWithIat(claims, AsState.now(), "exp", "iat", "admin");
                    }
                    return claims;
                } catch (RuntimeException invalid) {
                    // Another published signing key may be the one that signed.
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private synchronized List<Map<String, Object>> keys(String issuer, boolean fresh) {
        long now = System.currentTimeMillis();
        if (issuer.equals(cachedIssuer) && now - keysFetched < (fresh ? 60_000 : 300_000)) {
            return keys;
        }
        Map<String, Object> pub = fetch.getJson(issuer + "/jwks");
        keys = list(pub.get("keys")).stream().filter(Map.class::isInstance)
                .map(key -> (Map<String, Object>) key).toList();
        cachedIssuer = issuer;
        keysFetched = now;
        return keys;
    }

    private List<Map<String, Object>> apply(Map<String, Object> proposed, Map<String, Object> before,
                                             String token) {
        List<Map<String, Object>> changes = new ArrayList<>();
        Set<String> fields = new LinkedHashSet<>();
        var envelope = withJointExclusions(store, proposed);
        policy.tiers().forEach((id, tier) -> {
            var narrowed = OrganizationEnvelope.clamp(tier, envelope);
            if (!narrowed.patch().isEmpty()) {
                Map<String, Object> stored = policy.updateTier(id, narrowed.patch());
                grants.publishTerms(id, stored);
                narrowed.changes().forEach(change -> {
                    changes.add(Map.of("tier", id, "text", change.get("text")));
                    fields.add((String) change.get("field"));
                });
                ledger("org_clamped", "-", row("tier", id, "organization", envelope.get("name"),
                        "charter_version", envelope.get("charter_version"),
                        "changes", narrowed.changes().stream().map(c -> c.get("text")).toList()), null);
            }
        });
        resync(envelope, withJointExclusions(store, before));
        report(envelope, token, fields);
        return changes;
    }

    private void resync(Map<String, Object> envelope, Map<String, Object> before) {
        puller.pullAll();
        // On absence, retire only resources previously attributed to the charter.
        state.updateResources(resources -> resources.keySet().removeIf(rid ->
                OrganizationEnvelope.reaches(rid, before)
                        && !OrganizationPatterns.matches(rid, list(envelope.get("grants")))));
    }

    void report(Map<String, Object> envelope, String token, Set<String> changed) {
        try {
            send(text(envelope.get("issuer")), "POST", "/member/compliance", token,
                    OrganizationEnvelope.compliance(policy.tiers(), state.resources().keySet(),
                            envelope, changed));
        } catch (RuntimeException unavailable) {
            state.log.event("org.compliance_unavailable", null);
        }
    }

    Reply send(String issuer, String method, String path, String token, Object body) {
        URI url = URI.create(issuer.replaceFirst("/+$", "") + path);
        if (!"https".equals(url.getScheme()) || url.getHost() == null || url.getUserInfo() != null) {
            throw new IllegalArgumentException("organization endpoints must use https");
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(url).timeout(timeout);
        if (token != null && !token.isEmpty()) {
            request.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(body)));
        try {
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            Map<String, Object> result = JSON.readValue(response.body(), new TypeReference<>() {});
            return new Reply(response.statusCode(), result == null ? Map.of() : result);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("organization request interrupted", interrupted);
        } catch (IOException unavailable) {
            throw new IllegalStateException("the organization could not be reached", unavailable);
        }
    }

    boolean stale() { return System.currentTimeMillis() - fetchedAt >= ttl; }
    boolean unreadable() { return System.currentTimeMillis() - fetchedAt >= maxStale; }
    String lastError() { return problem; }

    void ledger(String kind, String family, Map<String, Object> entry, String handle) {
        store.ledgerAdd(kind, family, EventLog.utcNow(), entry, handle);
    }

    private static Attestation noClearance(String error) {
        return new Attestation(List.of(error), Map.of());
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value) {
        return value instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    static List<?> list(Object value) {
        return value instanceof List<?> l ? l : List.of();
    }

    static String text(Object value) {
        return value instanceof String s ? s : "";
    }

    static long number(Object value, long fallback) {
        return value instanceof Number n ? n.longValue() : fallback;
    }

    static Map<String, Object> row(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            result.put((String) pairs[i], pairs[i + 1]);
        }
        return result;
    }

    private static long seconds(String name, String fallback) {
        return (long) (1_000 * Double.parseDouble(System.getenv().getOrDefault(name, fallback)));
    }
}
