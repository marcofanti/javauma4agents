package io.uma4agents.pep;

import io.uma4agents.common.JointMandate;
import io.uma4agents.common.JointPeer;
import io.uma4agents.common.JointVerdicts;
import io.uma4agents.common.SslContexts;
import io.uma4agents.pep.core.AuthzFacts;
import io.uma4agents.pep.core.Decision;
import io.uma4agents.pep.core.Enforcer;
import io.uma4agents.pep.core.EnforcerSettings;
import io.uma4agents.pep.core.ProtectionClient;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
final class JointRoutes {
    private final PepConfig config;
    private final String issuer = PepConfig.env("UMA_PEP_JOINT_TALLY", "");
    private final String internal = PepConfig.env("UMA_PEP_JOINT_TALLY_INTERNAL", issuer);
    private final String secret = PepConfig.env("UMA_PEP_JOINT_SECRET", "");
    private final String prefix = PepConfig.env("UMA_PEP_JOINT_PREFIX", "mcp/joint")
            .replaceAll("^/+|/+$", "");
    private final List<String> accounts = Arrays.stream(PepConfig.env("UMA_PEP_JOINT_ACCOUNTS", "")
            .split(",")).map(String::strip).filter(value -> !value.isEmpty()).toList();
    private final long ttl = milli("UMA_PEP_MANDATE_TTL_S", "30");
    private final long grace = milli("UMA_PEP_STALE_GRACE_S", "300");
    private final Map<String, Cached> mandates = new ConcurrentHashMap<>();
    private final Map<String, ProtectionClient> clients = new ConcurrentHashMap<>();
    private final JointPeer peer;

    private record Cached(JointMandate mandate, long fetchedAt) {}
    record Joint(Enforcer enforcer, JointMandate mandate) {}

    static final class Unavailable extends RuntimeException {
        Unavailable(String account) { super("the tally for " + account + " could not be reached"); }
    }

    JointRoutes(PepConfig config) {
        this.config = config;
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER);
        String ca = PepConfig.env("UMA4A_CA_BUNDLE", "");
        if (!ca.isEmpty()) {
            http.sslContext(SslContexts.fromPem(Path.of(ca)));
        }
        peer = new JointPeer(http.build());
    }

    String accountAt(String path) {
        String pattern = "/" + prefix + "/";
        return path.startsWith(pattern) ? path.substring(pattern.length()).split("/", 2)[0] : null;
    }

    String leaf(String account) { return prefix + "/" + account; }

    Joint route(String account) {
        JointMandate mandate = mandate(account);
        if (mandate == null) {
            return null;
        }
        var tools = tools(account, mandate);
        var settings = new EnforcerSettings(account, internal, issuer, config.rsClientId,
                secret, account, tools, EnforcerSettings.singleUseTools(tools), java.util.Set.of("tools/call"),
                EnforcerSettings.GATEWAY_OPEN_METHODS, config.expectedAuthority, config.allowedOrigins,
                config.publicBase + "/.well-known/oauth-protected-resource/" + leaf(account),
                config.requireContentDigest);
        ProtectionClient protection = clients.computeIfAbsent(account,
                ignored -> ProtectionClient.forOrganization(settings, config.log, secret));
        return new Joint(new Enforcer(settings, protection, config.log), mandate);
    }

    Decision authorize(Joint joint, AuthzFacts facts) {
        String account = joint.enforcer().settings().owner();
        return joint.enforcer().authorize(facts, (grant, surface) -> {
            Map<String, String> trusted = new LinkedHashMap<>();
            for (var holder : joint.mandate().holders()) {
                PepConfig.OwnerRoute owner = config.ownerRoute(holder.owner());
                if (owner != null) {
                    trusted.put(holder.owner(), owner.settings().asPublic());
                }
            }
            String breach;
            try {
                breach = JointVerdicts.checkGrant(grant, account, surface.resourceId(), joint.mandate(),
                        trusted, peer::keys, Instant.now().getEpochSecond(),
                        Double.parseDouble(PepConfig.env("UMA_PEP_CLOCK_SKEW_S", "60")));
            } catch (RuntimeException unavailable) {
                return Decision.deny(503, "temporarily_unavailable",
                        "the keys of a holder's authority could not be read");
            }
            return breach == null ? null : Decision.deny(403, "joint_mandate_unsatisfied", breach);
        }, false);
    }

    Map<String, Map<String, EnforcerSettings.ToolSurface>> resources(String owner) {
        Map<String, Map<String, EnforcerSettings.ToolSurface>> shared = new LinkedHashMap<>();
        for (String account : accounts) {
            JointMandate mandate = mandate(account);
            if (mandate != null && mandate.holder(owner) != null) {
                shared.put(account, tools(account, mandate));
            }
        }
        return shared;
    }

    private Map<String, EnforcerSettings.ToolSurface> tools(String account, JointMandate mandate) {
        var result = new LinkedHashMap<String, EnforcerSettings.ToolSurface>();
        config.ownerRoute(config.owner).settings().tools().forEach((tool, original) -> {
            String rid = account + "/" + tool;
            if (mandate.governs(rid)) {
                result.put(tool, new EnforcerSettings.ToolSurface(rid, original.scopes(),
                        original.consequence()));
            }
        });
        return result;
    }

    private JointMandate mandate(String account) {
        if (issuer.isEmpty() || !account.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
                || !accounts.isEmpty() && !accounts.contains(account)) {
            return null;
        }
        long now = System.currentTimeMillis();
        Cached cached = mandates.get(account);
        if (cached != null && now - cached.fetchedAt() < ttl) {
            return cached.mandate();
        }
        try {
            JointMandate answer = peer.mandate(issuer, account);
            if (answer != null && !accounts.isEmpty()) {
                mandates.put(account, new Cached(answer, now));
            } else if (answer == null) {
                mandates.remove(account);
            }
            return answer;
        } catch (RuntimeException failed) {
            if (cached != null && now - cached.fetchedAt() < ttl + grace) {
                return cached.mandate();
            }
            throw new Unavailable(account);
        }
    }

    private static long milli(String key, String fallback) {
        return (long) (1_000 * Double.parseDouble(PepConfig.env(key, fallback)));
    }
}
