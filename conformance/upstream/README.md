# Vendored upstream conformance clients

These files are copied unchanged from
[nickgamb/uma4agents](https://github.com/nickgamb/uma4agents) at the pin recorded in
the first line of [`MANIFEST`](MANIFEST). They are the independent clients that the
Java services must satisfy: the upstream check scripts and demo driver, the Python client
library they import, and the TypeScript agent. One file is not a client: the
authorization server's Postgres DDL, `services/uma-as/schema.sql`, which the Java `uma-as`
build packages unchanged so both runtimes apply the same schema.

Do not edit them. Java-specific adaptations live in the Compose services, the Makefile
and the launcher stubs under [`conformance/runtime/`](../runtime/).

- `make vendor-verify` compares each file with its pinned git blob hash and rejects files
  that are not in the manifest.
- `scripts/vendor-upstream.sh <upstream-repo> <pin>` regenerates the tree for a new pin.
