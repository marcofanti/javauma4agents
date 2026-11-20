package io.uma4agents.authserver.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** The libpq-style URI both runtimes take, read the way libpq reads it. */
class PgDsnTest {

    private static final String SECRET = "s3cr3t-Pa55";

    @Test
    void readsTheComposeForm() {
        PgDsn dsn = PgDsn.parse("postgres://u4a:u4a@pg:5432/u4a");
        assertEquals("jdbc:postgresql://pg:5432/u4a", dsn.jdbcUrl());
        assertEquals("u4a", dsn.user());
        assertEquals("u4a", dsn.password());
    }

    @Test
    void keepsQueryParametersAndDefaultsThePort() {
        PgDsn dsn = PgDsn.parse("postgresql://u@db.example/app?sslmode=require");
        assertEquals("jdbc:postgresql://db.example:5432/app?sslmode=require", dsn.jdbcUrl());
        assertNull(dsn.password());
    }

    @Test
    void aLiteralPlusStaysAPlusAndAnEncodedOneDecodesToAPlus() {
        PgDsn dsn = PgDsn.parse("postgres://a+b:p+q%2Br@pg/u4a");
        assertEquals("a+b", dsn.user());
        assertEquals("p+q+r", dsn.password());
    }

    @Test
    void percentEscapesDecodeAsUtf8() {
        PgDsn dsn = PgDsn.parse("postgres://u:%40%3A%2F%C3%A9@pg/u4a");
        assertEquals("@:/é", dsn.password());
    }

    @Test
    void aMalformedUriNamesNoCredentialAnywhereInTheChain() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PgDsn.parse("postgres://u4a:" + SECRET + "@pg:5432/u4a db"));
        assertNull(e.getCause());
        for (Throwable t = e; t != null; t = t.getCause()) {
            assertFalse(String.valueOf(t.getMessage()).contains(SECRET), t.toString());
        }
    }

    @Test
    void aMalformedEscapeIsRefusedWithoutEchoingIt() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PgDsn.parse("postgres://u4a:" + SECRET + "%zz@pg/u4a"));
        assertFalse(e.getMessage().contains(SECRET));
    }

    @Test
    void refusesOtherSchemesAndMissingHosts() {
        assertThrows(IllegalArgumentException.class, () -> PgDsn.parse("mysql://u:p@h/d"));
        assertThrows(IllegalArgumentException.class, () -> PgDsn.parse(""));
    }

    @Test
    void describesWithoutCredentialsAndSwitchesDatabase() {
        PgDsn dsn = PgDsn.parse("postgres://u4a:" + SECRET + "@pg:5432/u4a?sslmode=disable");
        assertEquals("pg:5432/u4a", dsn.describe());
        assertFalse(dsn.toString().contains(SECRET));
        assertEquals("jdbc:postgresql://pg:5432/probe?sslmode=disable",
                dsn.withDatabase("probe").jdbcUrl());
    }
}
