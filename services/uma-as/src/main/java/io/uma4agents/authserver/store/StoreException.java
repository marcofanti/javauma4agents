package io.uma4agents.authserver.store;

/** The grant database could not do what was asked; the request fails closed. */
public final class StoreException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public StoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
