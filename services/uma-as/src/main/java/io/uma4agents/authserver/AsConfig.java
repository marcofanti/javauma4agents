package io.uma4agents.authserver;

import io.uma4agents.common.SslContexts;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Environment-driven configuration, mirroring the Python service's env names. */
@Configuration
public class AsConfig {

    public static final String AGREEMENT_FORMAT =
            "https://u4a.ai/spec/terms/1.0#myterms-agreement-v1+jws";
    public static final String AGREEMENT_CLAIM = "https://u4a.ai/spec/terms/1.0#myterms-agreement";
    public static final int PAT_TTL = 3600;
    public static final int TICKET_TTL = 300;
    public static final int PENDING_TTL =
            Integer.parseInt(env("UMA_AS_PENDING_TTL", "3600"));
    public static final int POLL_INTERVAL = 3;
    public static final int JWKS_CACHE_TTL = 300;

    public final String issuer = env("UMA_AS_ISSUER", "https://alice-as.uma.lab");
    public final String keyPath = env("UMA_AS_SIGNING_KEY", "/keys/uma-as-ed25519.pem");
    /** The kid the current signing key signs under. */
    public final String kid = env("UMA_AS_KID", "uma-as-1");
    /** Retired signing keys, still published and still verified with; see {@link SigningKeys}. */
    public final List<String> previousKeyPaths =
            commaList(env("UMA_AS_PREVIOUS_KEYS", ""), false);
    /** Their kids, in the same order; an empty entry falls back to the key's thumbprint. */
    public final List<String> previousKids = commaList(env("UMA_AS_PREVIOUS_KIDS", ""), true);

    /**
     * Where her authorization server keeps its memory: {@code memory} (the Compose
     * default, rewound by a restart) or {@code postgres} over {@code UMA_AS_DATABASE_URL}.
     */
    public final String store = env("UMA_AS_STORE", "memory").toLowerCase(Locale.ROOT);
    public final String databaseUrl = env("UMA_AS_DATABASE_URL", null);
    /**
     * How stale her resource listing may be before her portal's read pulls it again. The
     * pulled registry is a per-process cache of what resource servers publish.
     */
    public final double resourceRefreshSeconds =
            Double.parseDouble(env("UMA_AS_RESOURCE_REFRESH_S", "15"));
    public final String ownerIssuer =
            env("UMA_AS_OWNER_ISSUER", "https://keycloak.uma.lab/realms/alice");
    public final String ownerUsername = env("UMA_AS_OWNER", "alice");
    public final Set<String> ownerAudiences = new LinkedHashSet<>(
            Arrays.asList(env("UMA_AS_OWNER_CLIENTS", "meridian-portal").split(",")));
    public final String rsClientId = env("UMA_AS_RS_CLIENT_ID", "meridian-gateway");
    public final String rsClientSecret = env("UMA_AS_RS_CLIENT_SECRET", "gateway-dev-secret");
    public final boolean seedResourceServer = !Set.of("0", "false", "no").contains(
            env("UMA_AS_SEED_RS", "1").toLowerCase(Locale.ROOT));
    final int rsMaxBytes = Integer.parseInt(env("UMA_AS_RS_MAX_BYTES", "65536"));
    final double rsMetadataTtl = Double.parseDouble(env("UMA_AS_RS_META_TTL", "300"));
    final double rsMissTtl = Double.parseDouble(env("UMA_AS_RS_MISS_TTL", "30"));
    final String orgIssuer = env("UMA_AS_ORG_ISSUER", "");
    final String orgCallback = env("UMA_AS_ORG_CALLBACK", issuer);
    /**
     * Where the RS publishes itself — the root of declarative registration
     * (RFC 9728 metadata is derived from this identifier).
     */
    public final String rsResourceUri =
            env("UMA_AS_RS_RESOURCE_URI", "https://gateway.uma.lab/mcp");
    public final String caBundle = env("UMA4A_CA_BUNDLE", null);
    /** The RPT audience, under the pinned variable name. */
    public final String rptAudience = env("UMA_AS_RPT_AUDIENCE", "https://gateway.uma.lab");

    /** Longest agent-written reason she is shown, in UTF-8 bytes. */
    public final int maxReason = Integer.parseInt(env("UMA_AS_MAX_REASON", "512"));
    /** Live sub-agents one introducing agent may have: a ceiling, not a rule of hers. */
    public final int subagentFanout = Integer.parseInt(env("UMA_AS_SUBAGENT_FANOUT", "3"));
    /** How far back "recently" reaches in trajectory rules. */
    public final String trajectoryWindow = env("UMA_AS_TRAJECTORY_WINDOW", "7d");
    /** Strangers nobody checkable stands behind, waiting on her at once. */
    public final int pendBudget = Integer.parseInt(env("UMA_AS_PEND_BUDGET", "5"));
    /** Strangers whose named operator published their key, waiting on her at once. */
    public final int pendBudgetAttributed =
            Integer.parseInt(env("UMA_AS_PEND_BUDGET_ATTRIBUTED", "40"));

    /**
     * The agent providers whose tokens this authority believes. An issuer not listed is
     * never fetched; with none listed no agent token is accepted.
     */
    public final List<String> agentIssuers = splitList(env("UMA_AS_AGENT_ISSUERS", ""));
    /** How long an operator's Web Bot Auth directory hit is trusted, in seconds. */
    public final double directoryTtl =
            Double.parseDouble(env("UMA_AS_DIRECTORY_TTL", "300"));

    /**
     * How the owner proves she is the owner: {@code oidc} (her identity provider's
     * token), {@code local-key} (RFC 9421 with her own Ed25519 key), or both,
     * comma-separated, each independently sufficient.
     */
    public final List<String> ownerAuth = ownerAuthModes(env("UMA_AS_OWNER_AUTH", "oidc"));
    /** Her public key, in local-key mode: an Ed25519 SubjectPublicKeyInfo PEM. */
    public final String ownerKeyPath = env("UMA_AS_OWNER_KEY", "/keys/owner-ed25519.pub");
    /** Whose key that is: a signature proves a holder, configuration names the owner. */
    public final String ownerKeyOwner = env("UMA_AS_OWNER_KEY_OWNER", ownerUsername);
    /**
     * The authority an owner signature base is reconstructed against. Configuration,
     * never the request; defaults to the host part of the issuer.
     */
    public final String ownerExpectedAuthority =
            env("UMA_AS_OWNER_AUTHORITY", issuerAuthority(issuer));

    static String issuerAuthority(String issuer) {
        String rest = issuer.contains("://") ? issuer.substring(issuer.indexOf("://") + 3)
                : issuer;
        int slash = rest.indexOf('/');
        return slash < 0 ? rest : rest.substring(0, slash);
    }

    static List<String> splitList(String raw) {
        List<String> out = new ArrayList<>();
        for (String item : raw.split("[\\s,]+")) {
            if (!item.isEmpty()) {
                out.add(item);
            }
        }
        return List.copyOf(out);
    }

    /** Comma-separated, stripped; empty entries kept only where position matters. */
    static List<String> commaList(String raw, boolean keepEmpty) {
        List<String> out = new ArrayList<>();
        if (raw.isBlank()) {
            return List.of();
        }
        for (String item : raw.split(",", -1)) {
            String value = item.strip();
            if (keepEmpty || !value.isEmpty()) {
                out.add(value);
            }
        }
        return List.copyOf(out);
    }

    static List<String> ownerAuthModes(String raw) {
        List<String> out = new ArrayList<>();
        for (String mode : raw.split(",")) {
            String m = mode.strip().toLowerCase(Locale.ROOT);
            if (!m.isEmpty()) {
                out.add(m);
            }
        }
        return List.copyOf(out);
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Outbound client for Keycloak JWKS and AAuth issuer discovery over lab TLS. */
    @Bean
    public HttpClient httpClient() {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5));
        if (caBundle != null) {
            builder.sslContext(SslContexts.fromPem(Path.of(caBundle)));
        }
        return builder.build();
    }
}
