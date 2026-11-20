package io.uma4agents.authserver;

import io.uma4agents.authserver.store.JdbcStore;
import io.uma4agents.authserver.store.MemoryStore;
import io.uma4agents.authserver.store.OwnerStore;
import io.uma4agents.authserver.store.PgDsn;
import io.uma4agents.authserver.store.Seeds;
import io.uma4agents.authserver.store.Store;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The store this process runs on and the owner it serves. {@code memory} is the default,
 * so the Compose stack gains no database; {@code postgres} is the durable shape several
 * replicas share.
 */
@Configuration
public class StoreConfig {

    @Bean
    public SigningKeys signingKeys(AsConfig config) {
        return SigningKeys.load(config);
    }

    /**
     * Started here, before anything serves a request. A database too old to use refuses
     * startup with a message saying so; an unreachable one is retried, then refused.
     */
    @Bean(destroyMethod = "close")
    public Store store(AsConfig config, AsState state) {
        Seeds seeds = new Seeds(PolicyService::defaults,
                owner -> defaultResourceServers(config));
        Store store = switch (config.store) {
            case "memory" -> new MemoryStore(seeds);
            case "postgres" -> new JdbcStore(PgDsn.parse(config.databaseUrl), seeds, state.log);
            default -> throw new IllegalStateException(
                    "UMA_AS_STORE must be memory|postgres, got '" + config.store + "'");
        };
        store.start();
        return store;
    }

    /**
     * The one owner this server serves, seeded at startup so a cold database is
     * serviceable. Seeding is once per owner: what she has changed since stays changed.
     */
    @Bean
    public OwnerStore ownerStore(Store store, AsConfig config) {
        OwnerStore owner = store.owner(config.ownerUsername);
        owner.seed();
        return owner;
    }

    /**
     * The resource server provisioned alongside her authority: a shared secret, consented
     * at provisioning. {@code status} is a live control the Protection API reads on every
     * call, which is why it is stored rather than held in configuration.
     */
    static Map<String, Map<String, Object>> defaultResourceServers(AsConfig config) {
        if (!config.seedResourceServer) {
            return Map.of();
        }
        Map<String, Object> rs = new LinkedHashMap<>();
        rs.put("secret", config.rsClientSecret);
        rs.put("name", "Meridian Wealth API gateway");
        rs.put("status", "active");
        rs.put("consented", "seeded at provisioning (Alice linked her brokerage)");
        rs.put("last_pat_issued", null);
        rs.put("resource_uri", config.rsResourceUri);
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        out.put(config.rsClientId, rs);
        return out;
    }
}
