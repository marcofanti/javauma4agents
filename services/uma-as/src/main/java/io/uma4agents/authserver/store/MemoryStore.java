package io.uma4agents.authserver.store;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The in-process store: the Compose default, correct for exactly one replica. Many
 * owners, one process, and no state shared between owners for a query to leak across.
 * {@code make reset} rewinds it by restarting the service.
 */
public final class MemoryStore implements Store {

    private final Seeds seeds;
    private final Map<String, MemoryOwnerStore> owners = new ConcurrentHashMap<>();

    public MemoryStore(Seeds seeds) {
        this.seeds = seeds;
    }

    @Override
    public void start() {
        // Nothing to connect to.
    }

    @Override
    public OwnerStore owner(String owner) {
        return owners.computeIfAbsent(owner, o -> new MemoryOwnerStore(o, seeds));
    }

    /** Seeded owners only: reading an owner's state makes a record for her here. */
    @Override
    public List<String> owners() {
        List<String> out = new ArrayList<>();
        new TreeMap<>(owners).forEach((name, store) -> {
            if (store.seeded()) {
                out.add(name);
            }
        });
        return out;
    }

    @Override
    public void close() {
        // Nothing to release.
    }

    static double now() {
        return System.currentTimeMillis() / 1000.0;
    }

    static double expiresOf(Map<String, Object> rec) {
        return rec.get("expires") instanceof Number n ? n.doubleValue() : 0.0;
    }

    static final Comparator<Map<String, Object>> BY_FIRST_SEEN_DESC = Comparator.comparing(
            (Map<String, Object> c) -> String.valueOf(c.get("first_seen"))).reversed();
}
