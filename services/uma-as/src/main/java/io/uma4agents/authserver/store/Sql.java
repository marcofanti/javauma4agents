package io.uma4agents.authserver.store;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/** Plain JDBC: one statement, positional parameters, rows mapped by the caller. */
final class Sql {

    /** Reads one row. */
    @FunctionalInterface
    interface Row<T> {
        T map(ResultSet rs) throws SQLException;
    }

    /** Work inside one transaction. */
    @FunctionalInterface
    interface Work<T> {
        T run(Connection conn) throws SQLException;
    }

    private final DataSource pool;

    Sql(DataSource pool) {
        this.pool = pool;
    }

    int update(String sql, Object... params) {
        try (Connection conn = pool.getConnection()) {
            return update(conn, sql, params);
        } catch (SQLException e) {
            throw failed(sql, e);
        }
    }

    <T> T one(String sql, Row<T> row, Object... params) {
        try (Connection conn = pool.getConnection()) {
            return one(conn, sql, row, params);
        } catch (SQLException e) {
            throw failed(sql, e);
        }
    }

    <T> List<T> list(String sql, Row<T> row, Object... params) {
        try (Connection conn = pool.getConnection()) {
            return list(conn, sql, row, params);
        } catch (SQLException e) {
            throw failed(sql, e);
        }
    }

    /**
     * Runs {@code work} in one transaction. It commits only when the work returns and the
     * commit succeeds. Any other exit, an {@link Error} included, rolls back. When the
     * rollback or the reset to autocommit fails, the connection is aborted rather than
     * returned, so nothing left open can be committed later by whoever reuses it.
     */
    <T> T inTransaction(Work<T> work) {
        Connection conn;
        try {
            conn = pool.getConnection();
        } catch (SQLException e) {
            throw failed("transaction", e);
        }
        boolean committed = false;
        try {
            conn.setAutoCommit(false);
            T out = work.run(conn);
            conn.commit();
            committed = true;
            return out;
        } catch (SQLException e) {
            throw failed("transaction", e);
        } finally {
            release(conn, committed);
        }
    }

    private static void release(Connection conn, boolean committed) {
        boolean reusable = committed || rollback(conn);
        if (reusable) {
            try {
                // Safe only now: nothing is pending, so turning autocommit on commits nothing.
                conn.setAutoCommit(true);
            } catch (SQLException | RuntimeException e) {
                reusable = false;
            }
        }
        if (!reusable) {
            abort(conn);
        }
        try {
            conn.close();
        } catch (SQLException | RuntimeException e) {
            // Aborted or already gone; the pool discards it either way.
        }
    }

    private static boolean rollback(Connection conn) {
        try {
            conn.rollback();
            return true;
        } catch (SQLException | RuntimeException e) {
            return false;
        }
    }

    /** Kills the physical connection so the pool evicts it instead of reusing it. */
    private static void abort(Connection conn) {
        try {
            conn.abort(Runnable::run);
        } catch (SQLException | RuntimeException e) {
            // The connection is unusable either way; close() below finishes the job.
        }
    }

    static int update(Connection conn, String sql, Object... params) throws SQLException {
        try (PreparedStatement ps = prepare(conn, sql, params)) {
            return ps.executeUpdate();
        }
    }

    static <T> T one(Connection conn, String sql, Row<T> row, Object... params)
            throws SQLException {
        try (PreparedStatement ps = prepare(conn, sql, params);
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? row.map(rs) : null;
        }
    }

    static <T> List<T> list(Connection conn, String sql, Row<T> row, Object... params)
            throws SQLException {
        List<T> out = new ArrayList<>();
        try (PreparedStatement ps = prepare(conn, sql, params);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                out.add(row.map(rs));
            }
        }
        return out;
    }

    private static PreparedStatement prepare(Connection conn, String sql, Object... params)
            throws SQLException {
        PreparedStatement ps = conn.prepareStatement(sql);
        for (int i = 0; i < params.length; i++) {
            Object value = params[i];
            switch (value) {
                case null -> ps.setNull(i + 1, Types.VARCHAR);
                case String s -> ps.setString(i + 1, s);
                case Double d -> ps.setDouble(i + 1, d);
                case Boolean b -> ps.setBoolean(i + 1, b);
                case Integer n -> ps.setInt(i + 1, n);
                case Long n -> ps.setLong(i + 1, n);
                default -> throw new IllegalArgumentException(
                        "unsupported parameter type " + value.getClass().getName());
            }
        }
        return ps;
    }

    private static StoreException failed(String what, SQLException e) {
        String verb = what.strip().split("\\s+", 2)[0];
        return new StoreException("grant database call failed (" + verb + "): "
                + e.getMessage() + " [SQLState " + e.getSQLState() + "]", e);
    }
}
