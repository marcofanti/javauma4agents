package io.uma4agents.authserver;

import io.uma4agents.authserver.store.StoreJson;
import io.uma4agents.common.EventLog;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import org.springframework.stereotype.Component;

/**
 * What one process keeps for itself: its event log and its copy of the registry it pulls
 * from the resource servers she approved. Everything the grant loop remembers (negotiations,
 * tickets, grants, connections, the ledger, her policy) lives in the
 * {@link io.uma4agents.authserver.store.OwnerStore}, so that two replicas agree on it.
 *
 * <p>The registry is a cache by design: it is re-pullable at any time, and the events that
 * change it happen at the resource server.
 */
@Component
public class AsState {

    private static final SecureRandom RANDOM = new SecureRandom();

    public final EventLog log = new EventLog("uma-as");

    /**
     * Resource id to its pulled description, including {@code sources}: every approved
     * resource server whose listing carries it. Guarded by its own monitor.
     */
    private final Map<String, Map<String, Object>> resources = new LinkedHashMap<>();

    public static long now() {
        return java.time.Instant.now().getEpochSecond();
    }

    public static String urlsafeToken(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /** A copy of the registry. */
    public Map<String, Map<String, Object>> resources() {
        synchronized (resources) {
            return StoreJson.copy(new LinkedHashMap<>(resources));
        }
    }

    public Map<String, Object> resource(String id) {
        synchronized (resources) {
            return StoreJson.copy(resources.get(id));
        }
    }

    /** Applies one pull's result atomically with respect to readers. */
    void updateResources(Consumer<Map<String, Map<String, Object>>> change) {
        synchronized (resources) {
            change.accept(resources);
        }
    }
}
