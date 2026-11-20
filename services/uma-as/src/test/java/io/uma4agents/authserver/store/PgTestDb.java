package io.uma4agents.authserver.store;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.uma4agents.common.EventLog;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;

/**
 * The real-Postgres side of the store tests. {@code UMA_AS_TEST_DSN} names a disposable
 * Postgres 17 database; every test class starts from empty tables, so never point it at a
 * database whose contents matter. Without it these tests are skipped, unless
 * {@code -Duma.store.requirePostgres=true} is set ({@code make store-test} sets it), in
 * which case a missing database is a failure rather than a silent skip.
 */
final class PgTestDb {

    private PgTestDb() {}

    static PgDsn dsn() {
        String raw = System.getenv("UMA_AS_TEST_DSN");
        if (raw == null || raw.isBlank()) {
            if (Boolean.getBoolean("uma.store.requirePostgres")) {
                fail("UMA_AS_TEST_DSN is not set and the Postgres store tests are required");
            }
            assumeTrue(false, "UMA_AS_TEST_DSN not set; Postgres store tests skipped");
        }
        return PgDsn.parse(raw);
    }

    static Connection connect(PgDsn dsn) throws SQLException {
        return DriverManager.getConnection(dsn.jdbcUrl(), dsn.user(), dsn.password());
    }

    /** Drops every table the pinned DDL creates, so the next start builds them fresh. */
    static void reset(PgDsn dsn) throws SQLException {
        try (Connection conn = connect(dsn); Statement s = conn.createStatement()) {
            s.execute("DROP TABLE IF EXISTS tickets, negotiations, rpts, connections, "
                    + "resource_servers, ledger, terms_docs, tiers, owner_events, "
                    + "blocked_operators, owned_operators, owners, organizations, mandates, "
                    + "spent CASCADE");
        }
    }

    static JdbcStore store(PgDsn dsn) {
        return new JdbcStore(dsn, StoreContract.testSeeds(), new EventLog("store-test"), 3,
                Duration.ofMillis(200));
    }
}
