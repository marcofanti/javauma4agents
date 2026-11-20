package io.uma4agents.authserver;

import io.uma4agents.common.Jwks;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * What an agent says about who operates it, resolved and shown but never trusted: its
 * Client ID Metadata Document, and whether the operator named there publishes the agent's
 * key in its Web Bot Auth directory. Neither changes the connection handle or the grant's
 * key binding. Ports {@code resolve_client_id}, {@code operator_published_key} and
 * {@code KeyDirectories} from the pinned AS.
 */
@Component
public class RequesterMetadata {

    static final int MAX_ENTRIES = 1024;
    static final int MAX_DIRECTORIES = 256;
    static final double FAILURE_FLOOR_S = 60;

    private record Directory(double fetched, List<?> keys) {}

    private final PeerFetch fetch;
    private final AsState state;
    private final double directoryTtl;
    private final BoundedMap<String, Map<String, Object>> clientMetadata =
            new BoundedMap<>(MAX_ENTRIES);
    private final BoundedMap<String, Object[]> clientFailures = new BoundedMap<>(MAX_ENTRIES);
    private final BoundedMap<String, Directory> directories = new BoundedMap<>(MAX_DIRECTORIES);
    private final BoundedMap<String, Object[]> directoryFailures =
            new BoundedMap<>(MAX_DIRECTORIES);

    public RequesterMetadata(PeerFetch fetch, AsState state, AsConfig config) {
        this.fetch = fetch;
        this.state = state;
        this.directoryTtl = config.directoryTtl;
    }

    private static double now() {
        return System.currentTimeMillis() / 1000.0;
    }

    /**
     * Fetches and validates a Client ID Metadata Document; a failure downgrades to
     * unresolved rather than refusing the contract.
     *
     * @param clientId the https URL the agent offered
     * @return the display record, with {@code verified} saying whether it resolved
     */
    public Map<String, Object> resolveClientId(String clientId) {
        Map<String, Object> cached = clientMetadata.get(clientId);
        if (cached != null) {
            return cached;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("client_id", clientId);
        out.put("verified", false);
        try {
            if (!clientId.startsWith("https://")) {
                throw new IllegalStateException("client_id must be an https URL");
            }
            checkFloor(clientFailures, clientId);
            Map<String, Object> doc;
            try {
                doc = fetch.getJson(clientId);
            } catch (RuntimeException e) {
                clientFailures.put(clientId, new Object[] {now(), truncate(e.getMessage())});
                throw e;
            }
            if (!clientId.equals(doc.get("client_id"))) {
                throw new IllegalStateException(
                        "document does not claim the URL it was fetched from");
            }
            out = new LinkedHashMap<>();
            out.put("client_id", clientId);
            out.put("verified", true);
            for (String field : List.of("client_name", "client_uri", "logo_uri", "policy_uri",
                    "tos_uri", "contacts")) {
                out.put(field, doc.get(field));
            }
            state.log.event("client_metadata.resolved", null, "client_id", clientId,
                    "client_name", out.get("client_name"));
            clientMetadata.put(clientId, out);
        } catch (RuntimeException e) {
            out.put("error", truncate(e.getMessage()));
            state.log.event("client_metadata.unresolved", null, "client_id", clientId,
                    "reason", truncate(e.getMessage()));
        }
        return out;
    }

    /**
     * Whether the operator named by {@code clientId} publishes this signing key in the
     * directory the agent named. The directory must share the client_id's https origin;
     * an unreadable directory is not held against the agent.
     *
     * @param clientId the agent's CIMD URL
     * @param directory the agent's Web Bot Auth directory URL
     * @param signerJwk the key the agent signs with
     * @return true only when that operator's directory holds the key
     */
    public boolean operatorPublishedKey(String clientId, String directory,
                                        Map<String, Object> signerJwk) {
        if (!sameHttpsOrigin(clientId, directory)) {
            state.log.event("operator_directory.rejected", null, "client_id", clientId,
                    "directory", directory, "reason", "not same origin as client_id");
            return false;
        }
        String thumbprint = Jwks.thumbprint(signerJwk);
        Directory cached = directories.get(directory);
        if (cached != null && now() - cached.fetched() < directoryTtl
                && holds(cached.keys(), thumbprint)) {
            state.log.event("operator_directory.checked", null, "directory", directory,
                    "published", true, "from_cache", true);
            return true;
        }
        boolean found;
        try {
            found = holds(readDirectory(directory), thumbprint);
        } catch (RuntimeException e) {
            state.log.event("operator_directory.unresolved", null, "directory", directory,
                    "reason", truncate(e.getMessage()));
            return false;
        }
        state.log.event("operator_directory.checked", null, "directory", directory,
                "published", found, "from_cache", false);
        return found;
    }

    private List<?> readDirectory(String directory) {
        checkFloor(directoryFailures, directory);
        List<?> keys;
        try {
            Object raw = fetch.getJson(directory).get("keys");
            keys = raw instanceof List<?> list ? list : List.of();
        } catch (RuntimeException e) {
            directoryFailures.put(directory, new Object[] {now(),
                    directory + " could not be read: " + e.getMessage()});
            throw e;
        }
        directoryFailures.remove(directory);
        directories.put(directory, new Directory(now(), keys));
        return keys;
    }

    private static void checkFloor(BoundedMap<String, Object[]> failures, String key) {
        Object[] hit = failures.get(key);
        if (hit != null) {
            double age = now() - (double) hit[0];
            if (age < FAILURE_FLOOR_S) {
                throw new IllegalStateException(hit[1] + " (not retried for "
                        + Math.round(FAILURE_FLOOR_S - age) + "s)");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static boolean holds(List<?> keys, String thumbprint) {
        for (Object key : keys) {
            if (key instanceof Map<?, ?> jwk && jwk.get("kty") != null
                    && jwk.get("crv") != null && jwk.get("x") != null
                    && thumbprint.equals(Jwks.thumbprint((Map<String, Object>) jwk))) {
                return true;
            }
        }
        return false;
    }

    static boolean sameHttpsOrigin(String a, String b) {
        try {
            URI ua = URI.create(a);
            URI ub = URI.create(b);
            return "https".equals(ua.getScheme()) && "https".equals(ub.getScheme())
                    && ua.getRawAuthority() != null
                    && ua.getRawAuthority().equals(ub.getRawAuthority());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String truncate(String s) {
        String text = String.valueOf(s);
        return text.length() <= 120 ? text : text.substring(0, 120);
    }

    /** A synchronized map that forgets its oldest entry past a bound. */
    static final class BoundedMap<K, V> {
        private final Map<K, V> map;

        BoundedMap(int max) {
            this.map = new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                    return size() > max;
                }
            };
        }

        synchronized V get(K key) {
            return map.get(key);
        }

        synchronized void put(K key, V value) {
            map.remove(key);
            map.put(key, value);
        }

        synchronized void remove(K key) {
            map.remove(key);
        }
    }
}
