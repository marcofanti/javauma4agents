package io.uma4agents.authserver.store;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * A libpq-style connection URI ({@code postgres://user:pass@host:5432/db?sslmode=...}),
 * the form {@code UMA_AS_DATABASE_URL} and {@code UMA_AS_TEST_DSN} take on both runtimes,
 * as the JDBC URL, user and password the driver wants.
 *
 * @param jdbcUrl the {@code jdbc:postgresql://} URL, query parameters kept
 * @param user the user, or null
 * @param password the password, or null
 */
public record PgDsn(String jdbcUrl, String user, String password) {

    /**
     * Parses a connection URI.
     *
     * @throws IllegalArgumentException naming what is wrong, never echoing a password
     */
    public static PgDsn parse(String dsn) {
        if (dsn == null || dsn.isBlank()) {
            throw new IllegalArgumentException("no database URL: set UMA_AS_DATABASE_URL to "
                    + "postgres://user:password@host:5432/database");
        }
        URI uri;
        try {
            uri = new URI(dsn.strip());
        } catch (URISyntaxException e) {
            // Neither the input nor the parser's exception travels on: both carry the raw
            // URL, password included. The reason and position are enough to fix it.
            throw new IllegalArgumentException("the database URL is not a URI ("
                    + e.getReason() + " at index " + e.getIndex() + ")");
        }
        String scheme = uri.getScheme();
        if (!"postgres".equals(scheme) && !"postgresql".equals(scheme)) {
            throw new IllegalArgumentException("the database URL must start postgres:// or "
                    + "postgresql://, not " + scheme + "://");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("the database URL names no host");
        }
        String user = null;
        String password = null;
        if (uri.getRawUserInfo() != null) {
            String[] parts = uri.getRawUserInfo().split(":", 2);
            user = decode(parts[0]);
            password = parts.length > 1 ? decode(parts[1]) : null;
        }
        int port = uri.getPort() < 0 ? 5432 : uri.getPort();
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        String url = "jdbc:postgresql://" + uri.getHost() + ":" + port + path + query;
        return new PgDsn(url, user, password);
    }

    /** The same server and credentials, connected to another database. */
    public PgDsn withDatabase(String database) {
        String base = jdbcUrl;
        int query = base.indexOf('?');
        String suffix = query < 0 ? "" : base.substring(query);
        String head = query < 0 ? base : base.substring(0, query);
        int slash = head.indexOf('/', "jdbc:postgresql://".length());
        String root = slash < 0 ? head : head.substring(0, slash);
        return new PgDsn(root + "/" + database + suffix, user, password);
    }

    /** Where it points, without credentials, for log lines. */
    public String describe() {
        int query = jdbcUrl.indexOf('?');
        return (query < 0 ? jdbcUrl : jdbcUrl.substring(0, query))
                .substring("jdbc:postgresql://".length());
    }

    /**
     * Percent-decoding as libpq does for a connection URI. Unlike form decoding, a literal
     * {@code +} stays a plus; only {@code %XX} is decoded.
     */
    static String decode(String value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < value.length()) {
            int c = value.codePointAt(i);
            if (c == '%' && isHex(value, i + 1) && isHex(value, i + 2)) {
                out.write(Integer.parseInt(value.substring(i + 1, i + 3), 16));
                i += 3;
            } else if (c == '%') {
                throw new IllegalArgumentException(
                        "the database URL's user or password has a malformed percent escape");
            } else {
                byte[] bytes = Character.toString(c).getBytes(StandardCharsets.UTF_8);
                out.write(bytes, 0, bytes.length);
                i += Character.charCount(c);
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static boolean isHex(String value, int index) {
        return index < value.length() && Character.digit(value.charAt(index), 16) >= 0;
    }

    @Override
    public String toString() {
        return "PgDsn[" + describe() + "]";
    }
}
