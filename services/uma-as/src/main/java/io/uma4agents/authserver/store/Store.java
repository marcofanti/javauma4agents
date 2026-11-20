package io.uma4agents.authserver.store;

import java.util.List;

/**
 * The authorization server's memory, behind one interface with two implementations: the
 * in-process {@link MemoryStore} the Compose stack runs by default, and the
 * {@link JdbcStore} over the pinned Postgres DDL ({@code UMA_AS_STORE=postgres}).
 *
 * <p>The store holds no owner's state itself. {@link #owner(String)} hands back one
 * owner's {@link OwnerStore}, and every method there is scoped to that owner without
 * being told again: a forgotten {@code owner} argument is how one owner reads another's
 * ledger, so the scoping is structural rather than a parameter.
 */
public interface Store extends AutoCloseable {

    /**
     * Connects and creates the schema where there is one. Idempotent: every replica calls
     * it at startup and exactly one of them wins.
     */
    void start();

    /** One owner's state. Cheap: no I/O. */
    OwnerStore owner(String owner);

    /** Every owner this store has seeded. Administrative; the grant loop never asks. */
    List<String> owners();

    @Override
    void close();
}
