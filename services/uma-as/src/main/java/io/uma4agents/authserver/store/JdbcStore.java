package io.uma4agents.authserver.store;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.uma4agents.common.EventLog;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.postgresql.PGConnection;
import org.postgresql.PGNotification;

/**
 * The durable store over the pinned upstream DDL ({@code schema.sql}), in plain JDBC.
 * Every single-use guarantee is one statement or one transaction; the owner's live feed
 * is {@code LISTEN/NOTIFY} carrying a row id; every query filters on the owner.
 *
 * <p>Several replicas share one database. Each applies the schema at startup (the
 * {@code IF NOT EXISTS} losers are no-ops), refuses a database whose primary keys predate
 * multi-owner, and keeps one dedicated listening connection that reconnects after a
 * failover.
 */
public final class JdbcStore implements Store {

    /** Retention for the owner's event feed; the ledger is the durable history. */
    static final int EVENT_RETENTION_SECONDS = 3600;

    /**
     * The tables an owner-scoped upsert names. Kept beside the check rather than derived,
     * so a table added to the DDL without deciding its scope shows up here as a question.
     */
    static final List<String> OWNER_KEYED = List.of("negotiations", "tickets", "rpts",
            "connections", "resource_servers", "blocked_operators", "owned_operators",
            "terms_docs", "tiers", "spent");

    private final PgDsn dsn;
    private final Seeds seeds;
    private final EventLog log;
    private final int attempts;
    private final Duration retryDelay;
    private final Map<String, List<Subscription>> subscribers = new ConcurrentHashMap<>();
    private volatile HikariDataSource pool;
    private volatile Sql sql;
    private volatile Thread listener;
    private volatile Connection listening;
    private volatile boolean closed;

    /**
     * @param dsn where the database is
     * @param seeds what a new owner starts with
     * @param log the service's event log
     * @param attempts how many times to try to reach the database at startup
     * @param retryDelay the wait between attempts
     */
    public JdbcStore(PgDsn dsn, Seeds seeds, EventLog log, int attempts, Duration retryDelay) {
        this.dsn = dsn;
        this.seeds = seeds;
        this.log = log;
        this.attempts = attempts;
        this.retryDelay = retryDelay;
    }

    /** Thirty attempts two seconds apart: a failover is routine, not a crash loop. */
    public JdbcStore(PgDsn dsn, Seeds seeds, EventLog log) {
        this(dsn, seeds, log, 30, Duration.ofSeconds(2));
    }

    @Override
    public void start() {
        String schema = loadSchema();
        RuntimeException last = null;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                HikariDataSource candidate = openPool();
                pool = candidate;
                String server;
                try (Connection conn = candidate.getConnection();
                     Statement statement = conn.createStatement()) {
                    statement.execute(schema);
                    assertOwnerKeys(conn);
                    server = conn.getMetaData().getDatabaseProductVersion();
                }
                sql = new Sql(candidate);
                startListener();
                log.event("store.started", null, "backend", "postgres", "database",
                        dsn.describe(), "server_version", server);
                return;
            } catch (SchemaTooOld e) {
                // Not transient. Retrying would bury the one message that says what to do.
                closePool();
                throw e;
            } catch (SQLException | RuntimeException e) {
                last = e instanceof RuntimeException r ? r
                        : new StoreException(e.getMessage(), e);
                closePool();
                log.event("store.connect_retry", null, "attempt", attempt,
                        "error", truncate(e.getMessage()));
                if (attempt < attempts) {
                    sleep(retryDelay);
                }
            }
        }
        throw new StoreException("could not reach the grant database at " + dsn.describe()
                + " after " + attempts + " attempts: "
                + (last == null ? "" : last.getMessage()), last);
    }

    private HikariDataSource openPool() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(dsn.jdbcUrl());
        config.setUsername(dsn.user());
        config.setPassword(dsn.password());
        config.setMinimumIdle(1);
        config.setMaximumPoolSize(8);
        // Do not wait forever on a primary that is being replaced.
        config.setConnectionTimeout(10_000);
        config.setPoolName("uma-as-store");
        return new HikariDataSource(config);
    }

    private static String loadSchema() {
        try (InputStream in = JdbcStore.class.getResourceAsStream("/schema.sql")) {
            if (in == null) {
                throw new IllegalStateException("schema.sql is not on the classpath; the "
                        + "uma-as build packages it from conformance/upstream");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read schema.sql: " + e.getMessage(), e);
        }
    }

    /**
     * Refuses a database whose primary keys predate multi-owner. The DDL backfills the
     * owner column but deliberately does not rebuild primary keys, so such a database
     * looks upgraded and then fails its first upsert with 42P10. Better here, once.
     */
    static void assertOwnerKeys(Connection conn) throws SQLException {
        List<String> stale = new ArrayList<>();
        for (String table : OWNER_KEYED) {
            Boolean keyed = Sql.one(conn,
                    "SELECT EXISTS (SELECT 1 FROM pg_index i"
                            + " JOIN pg_class c ON c.oid = i.indrelid"
                            + " JOIN pg_attribute a ON a.attrelid = c.oid"
                            + "  AND a.attnum = ANY (i.indkey)"
                            + " WHERE i.indisprimary AND c.relname = ? AND a.attname = 'owner')",
                    rs -> rs.getBoolean(1), table);
            if (!Boolean.TRUE.equals(keyed)) {
                stale.add(table);
            }
        }
        if (!stale.isEmpty()) {
            throw new SchemaTooOld("this database predates multi-owner: "
                    + String.join(", ", stale) + " still key on a single owner's rows. The "
                    + "owner column backfills but the primary keys are not retrofitted, so "
                    + "every upsert would fail. Recreate the database (under Compose, remove "
                    + "the Postgres volume, or make down && make up).");
        }
    }

    // --- the owner's live feed ----------------------------------------------

    private void startListener() throws SQLException {
        listening = listen();
        Thread thread = new Thread(this::listenLoop, "uma-as-store-listener");
        thread.setDaemon(true);
        listener = thread;
        thread.start();
    }

    /**
     * One dedicated connection, not from the pool: a listening connection is occupied for
     * the life of the process and would quietly shrink the pool by one.
     */
    private Connection listen() throws SQLException {
        Connection conn = DriverManager.getConnection(dsn.jdbcUrl(), dsn.user(), dsn.password());
        try (Statement statement = conn.createStatement()) {
            statement.execute("LISTEN owner_events");
        }
        return conn;
    }

    private void listenLoop() {
        while (!closed) {
            try {
                PGNotification[] notes = listening.unwrap(PGConnection.class)
                        .getNotifications(500);
                if (notes != null) {
                    for (PGNotification note : notes) {
                        fanout(Long.parseLong(note.getParameter()));
                    }
                }
            } catch (SQLException | RuntimeException e) {
                if (closed) {
                    return;
                }
                // A failover closes this connection and nothing else would notice: the
                // owner's live feed would simply stop. Listen again.
                log.event("store.listener_lost", null, "error", truncate(e.getMessage()));
                relisten();
            }
        }
    }

    private void relisten() {
        closeQuietly(listening);
        long delayMs = 1000;
        while (!closed) {
            try {
                listening = listen();
                log.event("store.listener_reconnected", null);
                return;
            } catch (SQLException e) {
                log.event("store.listener_reconnect_failed", null,
                        "error", truncate(e.getMessage()));
                sleep(Duration.ofMillis(delayMs));
                delayMs = Math.min(delayMs * 2, 30_000);
            }
        }
    }

    /** Routed, not broadcast: every replica hears every event, each owner gets her own. */
    private void fanout(long eventId) {
        if (subscribers.isEmpty()) {
            return;
        }
        Map.Entry<String, String> row = sql.one(
                "SELECT owner, payload::text FROM owner_events WHERE id = ?",
                rs -> Map.entry(rs.getString(1), rs.getString(2)), eventId);
        if (row == null) {
            return;
        }
        Map<String, Object> payload = StoreJson.readMap(row.getValue());
        for (Subscription subscription : subscribers.getOrDefault(row.getKey(), List.of())) {
            subscription.deliver(payload);
        }
    }

    Subscription subscribe(String owner) {
        List<Subscription> list =
                subscribers.computeIfAbsent(owner, o -> new CopyOnWriteArrayList<>());
        Subscription subscription = new Subscription(list::remove);
        list.add(subscription);
        return subscription;
    }

    /** Closes the listening connection out from under the loop, as a failover would. */
    void dropListenerForTest() {
        closeQuietly(listening);
    }

    // --- the store ----------------------------------------------------------

    @Override
    public OwnerStore owner(String owner) {
        return new JdbcOwnerStore(this, owner);
    }

    @Override
    public List<String> owners() {
        return sql().list("SELECT owner FROM owners ORDER BY owner", rs -> rs.getString(1));
    }

    Sql sql() {
        Sql current = sql;
        if (current == null) {
            throw new IllegalStateException("the grant database store was not started");
        }
        return current;
    }

    Seeds seeds() {
        return seeds;
    }

    @Override
    public void close() {
        closed = true;
        closeQuietly(listening);
        Thread thread = listener;
        if (thread != null) {
            thread.interrupt();
        }
        closePool();
    }

    private void closePool() {
        HikariDataSource current = pool;
        pool = null;
        sql = null;
        if (current != null) {
            current.close();
        }
    }

    private static void closeQuietly(Connection conn) {
        if (conn == null) {
            return;
        }
        try {
            conn.close();
        } catch (SQLException e) {
            // Already gone, which is the state being asked for.
        }
    }

    private static void sleep(Duration delay) {
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String truncate(String value) {
        return value == null ? "" : value.substring(0, Math.min(160, value.length()));
    }
}
