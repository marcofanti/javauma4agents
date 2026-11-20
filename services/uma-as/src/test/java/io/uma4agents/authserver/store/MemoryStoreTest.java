package io.uma4agents.authserver.store;

/** The store properties against the in-process store the Compose stack runs. */
class MemoryStoreTest extends StoreContract {

    @Override
    Store newStore() {
        return new MemoryStore(testSeeds());
    }
}
