package io.uma4agents.authserver.store;

/**
 * A database whose primary keys predate multi-owner. Never retried: waiting changes
 * nothing, and the connect-retry loop is for a database that is coming back, not for one
 * that is the wrong shape.
 */
public final class SchemaTooOld extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SchemaTooOld(String message) {
        super(message);
    }
}
