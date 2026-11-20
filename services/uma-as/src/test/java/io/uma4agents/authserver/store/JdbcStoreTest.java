package io.uma4agents.authserver.store;

import java.sql.SQLException;
import org.junit.jupiter.api.Tag;

/** The store properties against real Postgres over the pinned DDL. */
@Tag("postgres")
class JdbcStoreTest extends StoreContract {

    @Override
    Store newStore() {
        PgDsn dsn = PgTestDb.dsn();
        try {
            PgTestDb.reset(dsn);
        } catch (SQLException e) {
            throw new IllegalStateException("cannot reset the test database: " + e.getMessage(), e);
        }
        return PgTestDb.store(dsn);
    }
}
