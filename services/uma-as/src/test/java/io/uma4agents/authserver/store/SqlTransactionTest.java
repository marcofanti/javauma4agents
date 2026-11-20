package io.uma4agents.authserver.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The one transaction helper every multi-statement guarantee rests on: it commits only
 * work that returned, and nothing that unwound, however it unwound and however the
 * cleanup itself fails, can be committed afterwards.
 */
@Tag("postgres")
class SqlTransactionTest {

    private PgDsn dsn;

    /** Every call the helper made on the connections it was given. */
    private final List<String> calls = new ArrayList<>();

    @BeforeEach
    void table() throws SQLException {
        dsn = PgTestDb.dsn();
        try (Connection c = PgTestDb.connect(dsn); Statement s = c.createStatement()) {
            s.execute("DROP TABLE IF EXISTS tx_probe; CREATE TABLE tx_probe (v text)");
        }
        calls.clear();
    }

    private int rows() throws SQLException {
        try (Connection c = PgTestDb.connect(dsn); Statement s = c.createStatement();
             var rs = s.executeQuery("SELECT count(*) FROM tx_probe")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private static void insert(Connection conn) throws SQLException {
        Sql.update(conn, "INSERT INTO tx_probe (v) VALUES ('x')");
    }

    @Test
    void returnedWorkCommits() throws SQLException {
        new Sql(source(null)).inTransaction(conn -> {
            insert(conn);
            return null;
        });
        assertEquals(1, rows());
    }

    @Test
    void aRuntimeExceptionRollsBack() throws SQLException {
        assertThrows(IllegalStateException.class, () -> new Sql(source(null)).inTransaction(c -> {
            insert(c);
            throw new IllegalStateException("boom");
        }));
        assertEquals(0, rows());
    }

    @Test
    void anSqlExceptionRollsBack() throws SQLException {
        assertThrows(StoreException.class, () -> new Sql(source(null)).inTransaction(c -> {
            insert(c);
            Sql.update(c, "INSERT INTO no_such_table VALUES (1)");
            return null;
        }));
        assertEquals(0, rows());
    }

    @Test
    void anErrorRollsBackAndIsNeverCommittedByTheAutocommitReset() throws SQLException {
        assertThrows(AssertionError.class, () -> new Sql(source(null)).inTransaction(c -> {
            insert(c);
            throw new AssertionError("an Error, not an Exception");
        }));
        assertEquals(0, rows());
        assertFalse(calls.contains("commit"), calls.toString());
        assertTrue(calls.indexOf("rollback") < calls.lastIndexOf("setAutoCommit:true"),
                calls.toString());
    }

    @Test
    void aFailedRollbackAbortsTheConnectionInsteadOfCommittingIt() throws SQLException {
        assertThrows(AssertionError.class, () -> new Sql(source("rollback")).inTransaction(c -> {
            insert(c);
            throw new AssertionError("unwinding");
        }));
        assertEquals(0, rows());
        assertFalse(calls.contains("commit"), calls.toString());
        assertFalse(calls.contains("setAutoCommit:true"), calls.toString());
        assertTrue(calls.contains("abort"), calls.toString());
    }

    @Test
    void aFailedCommitRollsBack() throws SQLException {
        assertThrows(StoreException.class, () -> new Sql(source("commit")).inTransaction(c -> {
            insert(c);
            return null;
        }));
        assertEquals(0, rows());
        assertTrue(calls.contains("rollback"), calls.toString());
    }

    /**
     * Real connections, with every call recorded and the named method made to fail the
     * way a dead socket would.
     */
    private DataSource source(String failing) {
        return new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                Connection real = PgTestDb.connect(dsn);
                return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                        new Class<?>[] {Connection.class}, (proxy, method, args) -> {
                            String name = method.getName();
                            calls.add("setAutoCommit".equals(name) ? name + ":" + args[0] : name);
                            if (name.equals(failing)) {
                                throw new SQLException("simulated " + name + " failure",
                                        "08006");
                            }
                            try {
                                return method.invoke(real, args);
                            } catch (InvocationTargetException e) {
                                throw e.getCause();
                            }
                        });
            }

            @Override
            public Connection getConnection(String user, String password) {
                throw new UnsupportedOperationException();
            }

            @Override
            public PrintWriter getLogWriter() {
                return null;
            }

            @Override
            public void setLogWriter(PrintWriter out) {
                // Unused.
            }

            @Override
            public void setLoginTimeout(int seconds) {
                // Unused.
            }

            @Override
            public int getLoginTimeout() {
                return 0;
            }

            @Override
            public Logger getParentLogger() {
                return Logger.getGlobal();
            }

            @Override
            public <T> T unwrap(Class<T> iface) {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) {
                return false;
            }
        };
    }
}
