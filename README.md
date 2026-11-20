# UMA for Agents (Java)

A **Java implementation** of the
[uma4agents](https://github.com/nickgamb/uma4agents) proof-of-concept that
carries [User-Managed Access (UMA)
2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
into the agent era: the owner sets policy once, and other people's AI agents
negotiate access to her resources against it — while she's offline for the easy
cases, and with a tap for the sensitive ones.

The custom services (`uma-as`, `uma-pep`, `alice-portal`, `alice-vault-mcp`,
`agent-operator`) and the agent-side clients (grant loop, agent shim, an example
walker) are Spring Boot 4 / Java 26 in a multi-module Maven build
(`lib/uma4a-common`, `lib/uma4a-pep`, `lib/uma4a-agent`, `services/*`, `mcp/*`,
`clients/*`). This Java port targets upstream
[`77649287dc883b75ef563c59f96de8613ecf10d0`](https://github.com/nickgamb/uma4agents/tree/77649287dc883b75ef563c59f96de8613ecf10d0)
for the [Compose release scope](docs/PORT-PLAN.md). It implements the phased
transport, identity, persistence, policy, ownership, and integration work.
The upstream check scripts, demo driver and TypeScript agent run
unchanged against the Java services — see [Conformance](#conformance). Third-party infrastructure
(Keycloak, Envoy edge, agentgateway, hickory-dns, Grafana/Loki/Promtail, and
the upstream AAuth person-server) is unchanged.

The whole stack runs locally with one command. It binds to
[AAuth](https://github.com/dickhardt/AAuth) for agent identity and
proof-of-possession.

> **The question.** Agent-identity protocols answer *"is this my agent doing my
> task?"* The harder question — *"may your agent touch my stuff?"* — needs an
> authority on the owner's side and a negotiation to fill it. AAuth's four-party
> mode puts that authority in the right place; what stays unspecified is how an
> *offline* owner actually answers. UMA worked that out a decade ago. This binds
> the two, and shows what it looks like with agent-shaped mechanics.

See **[FINDINGS.md](FINDINGS.md)** for the recommendations to spec authors,
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the system design, and
**[docs/PROTOCOL.md](docs/PROTOCOL.md)** for the wire contract.

## The demo

Alice is a brokerage client at *Meridian Wealth*. Bob is her new financial
advisor, and his firm runs an agent. Over one day:

0. **Enrollment** — Bob's agent registers with his AAuth person/agent server
   and receives a verifiable agent token; Alice's authorization server checks
   it against the issuer's published keys before believing a word of it.
1. **Holdings summary** — Bob's agent asks; because Alice has connected it and
   her terms permit it, the grant is automatic, purpose-bound, and expiring.
2. **Transaction history** — granted too, under visibly stricter terms her
   authorization server dictates.
3. **A trade** — Alice's policy says *ask me*. The request pends, her portal
   buzzes, she approves the specific order from the couch, and the agent
   receives a single-use grant good for exactly that trade.

At any point Alice opens her portal and sees which agents are connected, what
each promised, what it touched, and the one action she personally approved —
and can revoke any of them.

## Screenshots

### Alice's Brokerage 
![Dashboard](screenshots/Dashboard.png)
![Holdings](screenshots/Holdings.png)
![Trade](screenshots/Trade.png)
*A brokerage portal, with MCP, holding Alice's portfolio — which she would like to give her financial advisor's agent access to*

### New Agent Requests to Connect to Alice's Brokerage 
![New Agent](screenshots/New_Agent.png)
*An agent with **no standing connection** pends on first contact regardless of tier*

### Manage Agent Access & Revocation
![Agent Access](screenshots/Resource_Approval.png)
*(Connected Agents → Revoke) deactivates the connection and any live RPTs immediately.*

### Edit RO Policy Terms as Forms or as Code
![RO Policy](screenshots/RO_Policy.png)
![RO Policy Code](screenshots/RO_Policy_Monoco.png)
*Express the resource owner policy terms that agents agree to in a form or as code*

### A Sensitive Operation Pends for Alice — One Approval, One Trade
![Trade approval](screenshots/Trade_Approval_Identified.png)
*An ask-me tier holds the request until Alice taps. The agent is **identified** — its `aauth:…@ps.uma.lab` identity was verified against its issuer's published keys, not claimed — and her approval releases a single-use grant bound to exactly this order.*

### Discovery, Split Into Public and Protected (RFC 9728)
![Registration before and after PRM](docs/prm-at-a-glance.svg)
*Registration flips from pushed to pulled; the challenge gains a second witness; the ticket keeps its job*

![Protected Resource Metadata](screenshots/prm-metadata.png)
*The resource's public metadata is **structural**: tool surfaces and scopes, the owner's authorization server, `jwks_uri`, `signed_metadata` — and a pointer to the protected owner-resources endpoint. Whose resources these are is deliberately not here.*

![Owner resources are protected](screenshots/prm-as-only.png)
*The owner-resources listing refuses anyone who can't prove they're the owner's authorization server — "a kind of protected webfinger for Alice's stuff"*

![Resource servers and pulled registry](screenshots/prm-myact.png)
*Alice's view of both standing relationships: the gateway holding a PAT issued in her name (revocable), and every protected resource her AS **pulled** from the gateway's published metadata (`Source: published · pulled`)*

### Activity Ledger
![Activity Ledger](screenshots/Activity_Ledger_Identified.png)
*The full trail of one afternoon: what the agent **promised** (the signed terms, hash and all), what Alice **personally approved** (and denied), and what was actually **touched** — every row correlated by its negotiation id*

## Quick start

Prerequisites: Docker Desktop (or Engine + Compose v2) and
[mkcert](https://github.com/FiloSottile/mkcert) (`brew install mkcert`).

```bash
make init        # local CA, TLS certs, signing keys, Alice's device key, DNS for *.uma.lab
make up          # the whole stack
make smoke-alice # verify every service, including the live grant challenge
```

Then either watch it run headlessly, or drive it with your own agent:

```bash
make demo-acts-a      # walk the acts with the upstream driver, Alice's taps simulated
make demo-acts-b      # the same acts as an enrolled (identified) agent
make flow-check       # four identity regimes, one unchanged owner
make audit            # print the promised / touched / approved ledger
```

The protocol on its own, with no identity provider, database, gateway or `make init`:

```bash
make fixture          # Java uma-as + vault, owner signs with her own key
make fixture-down
```

Open **https://portal.uma.lab** to sign in as Alice (`alice` / `alice-demo`),
watch approvals arrive live, edit her terms, and manage connected agents.
Observability is at **https://grafana.uma.lab**.

`make init` offers to configure `/etc/resolver/uma.lab` (sudo) and you can run
`make trust-ca` so your browser trusts the local certificates.

**Upgrading a Phase A checkout.** Phase B bind-mounts Alice's public device key
(`certs/owner-ed25519.pub`) into `uma-as`. `make up` runs `make owner-key` first, so a
plain `make up` provisions it. If you already have `certs/owner-ed25519.pem`, it derives
the public half from it and never rotates it. Start the stack with `make up` rather
than `docker compose up`: Compose creates a directory at a missing bind path, and
`make owner-key` then refuses until that directory is removed (see
[Troubleshooting](#troubleshooting)).

## Connect your own agent

Bob's agent can be an unmodified MCP client. A small local shim (a Java stdio
MCP server) handles agent identity, request signing, and the grant negotiation
— surfacing Alice's terms for you to approve. See
[clients/agent-shim/README.md](clients/agent-shim/README.md).

## Building locally (optional)

Docker builds everything; for local development you need JDK 26 and Maven:

```bash
mvn test          # unit tests incl. CPython-generated canonicalization vectors
mvn package       # all service jars
```

## Architecture at a glance

![Architecture](docs/architecture.svg)

## How it works, briefly

Before anything else, the agent can read the resource's published metadata
(RFC 9728): who the authorization server is and what tool surfaces exist —
though never *whose* they are; that lives behind a protected listing only
Alice's authorization server may query. An agent then calls a tool through
the gateway and is challenged with a permission ticket (the challenge names
the metadata, and the agent checks the two against each other). It presents
the ticket to Alice's authorization server, which dictates the terms it
requires; the agent signs those terms as an intent contract and commits. For a known agent under a permissive tier the grant is immediate; for
a new agent or a sensitive action the request pends until Alice approves in her
portal. The grant is a proof-of-possession token scoped to exactly what was
agreed. Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Make targets

| Target | Purpose |
|---|---|
| `make init` | Local CA, TLS certs, signing keys, DNS |
| `make up` / `make down` | Start the stack / tear it down, deleting its volumes |
| `make smoke-alice` | Verify every service end to end (Phase A smoke profile) |
| `make demo-acts-a` | Walk tiers 1–3 and revocation with the upstream driver |
| `make demo-acts-b` | The same acts as an identified agent enrolled with the person server |
| `make flow-check` | Four identity regimes against one unchanged owner, and an agent withdrawn at the person server |
| `make fixture` / `make fixture-down` | The standalone fixture: local-key owner, vault serving its own TLS, own Compose project |
| `make owner-key` | Provision Alice's Ed25519 device key (`certs/owner-ed25519.pem`; the AS reads only the `.pub`). Run by `make up` and `make init`; derives a missing public half, never rotates, refuses a directory or mismatched pair |
| `make token-test` | Focused AAuth agent-token, owner-authentication and handle tests |
| `make vectors` | Regenerate the CPython ground-truth vectors from the pinned modules |
| `make demo-tier1/2/3` | Walk one act (add `SIM=1` to auto-approve) |
| `make check-unit` / `make check-live` / `make check-all` | Unit gate, live upstream gates, both |
| `make vendor-verify` | Check the vendored upstream clients against their pinned hashes |
| `make audit` | Print Alice's activity ledger |
| `make reset` | Rewind demo state (the memory store; a durable store is reset by replacing its database) |
| `make store-test` | Store properties on memory and real Postgres 17, two replicas on one database; Postgres required |
| `make rotation-check` | Rotate the authority's signing key under live grants (pinned check, Postgres-backed recreate, restores) |
| `make establishment-check` | Exercise an independently configured resource server's introduction, owner approval and withdrawal |
| `make multi-owner-check` | Verify Alice and Carol each use their own authority, signing key, identity realm, policy and holdings |
| `make org-check` | Verify Northwind membership, charter enforcement, role changes and delegated administration |
| `make clearance-check` | Verify owner clearance attestation, withdrawal and the digest carried in the RPT |
| `make rego-test` | Re-run the shared charter pattern vectors in the pinned OPA version |
| `make joint-check` | Exercise the same UMA grant at every-holder and either-holder accounts |
| `make xaa-check` | Verify discovery-driven enterprise exchange and the owner and resource boundaries |
| `make smoke-test` | Verify the full stack, including Carol, ID-JAG discovery and the workforce realm |
| `make adapter-check` | Reach the lab using an ordinary MCP client through the Java adapter |
| `make kwaai-check` / `make paios-check` | Verify the owner device key and the pAI-OS ability |
| `make n8n-check` | Run a protected n8n workflow through the Java sidecar |
| `make owner ARGS='pending'` | List pending requests from the fixture using the Java owner CLI |
| `make portal-check` | Sign into both owner portals and the organization console and exercise their APIs |
| `make trust-ca` | Trust the local CA in your system store |

## Conformance

The independent clients are vendored byte-for-byte from upstream under
[`conformance/upstream/`](conformance/upstream/) and checked by `make vendor-verify`.
`make check-live` runs them against the Compose stack: the agent-shim check (through a
launcher that execs the Java shim), the TypeScript agent, the upstream demo driver, the
embedded-enforcement check, a supplemental decline check and the Alice-only smoke
profile. Phase B adds the pinned `flow_check.py` (`make flow-check`), the driver's
identified acts (`make demo-acts-b`) and `fixture_check.py` against
[`compose.fixture.yml`](compose.fixture.yml) (`make fixture`). Results against both the
Python reference and this port are in
[PHASE-A-GATES.md](docs/port-plan-review/PHASE-A-GATES.md),
[PHASE-B-GATES.md](docs/port-plan-review/PHASE-B-GATES.md) and
[PHASE-C-GATES.md](docs/port-plan-review/PHASE-C-GATES.md). Phase C adds the pinned
`rotation_check.py` (`make rotation-check`) and `make store-test`.
[Phase D](docs/port-plan-review/PHASE-D-GATES.md) adds the intent, assurance,
consequence, first-party and sub-agent checks and the full simulated demo.
[Phase E1](docs/port-plan-review/PHASE-E1-CODEX-VERIFICATION.md) adds the
establishment and multi-owner checks.
[Phase E2](docs/port-plan-review/PHASE-E2-CODEX-VERIFICATION.md) adds the
organization, clearance and Rego gates.
[Phase E3](docs/port-plan-review/PHASE-E3-CODEX-VERIFICATION.md) adds the
joint ownership check.
[Phase E4](docs/port-plan-review/PHASE-E4-CODEX-VERIFICATION.md) adds the
Cross App Access check and the full smoke gate.

[Phase F](docs/port-plan-review/PHASE-F-CODEX-VERIFICATION.md) covers the
MCP adapter, Kwaai and pAI-OS, the n8n sidecar, the Java owner CLI, and
OIDC portal sessions. `make check-all` runs Maven and the staged Compose
checks in order on the running lab. Start the lab with `make up` and use
a fresh memory store for its simulated approvals.

### Integrations and the standalone owner CLI

The [Kwaai guide](docs/KWAAI-BINDING.md) explains the device-key and pAI-OS
runs. The [n8n guide](integrations/n8n/README.md) describes the lab workflow
and the standalone sidecar configuration.

The owner CLI runs with the no-gateway fixture's device key.

```sh
make fixture
make owner ARGS=policy
make owner ARGS=pending
make owner ARGS=watch
```

Use `make owner ARGS='approve fam_…'` or `make owner ARGS='deny fam_…'`
for a listed request, and `make owner ARGS='revoke jkt:…'` for a connection.
To use the packaged CLI outside Docker, build it with
`mvn -pl clients/owner-cli -am package` and run
`java -jar clients/owner-cli/target/owner.jar --help`.

Alice's vault is available at `https://gateway.uma.lab/mcp`, and Carol's at
`https://gateway.uma.lab/mcp/carol`. Carol signs into
`https://carol-portal.uma.lab` with the lab's `carol` / `carol-demo` user.
The first protected request to her vault can prompt Meridian to register with
her authority. Carol approves it under **Resource servers** in her portal.

Northwind administers its charter at `https://org-console.uma.lab` using the
lab account `dana` / `dana-demo`. Alice and Carol can preview and explicitly
accept a version of the charter in their own portals. Their member paths
`/mcp/shared/alice` and `/mcp/shared/carol` reach the same Northwind vault.

**Where state lives.** `uma-as` keeps what the grant loop remembers in a store:
`UMA_AS_STORE=memory` (the default; `make reset` rewinds it by restarting) or
`postgres` over `UMA_AS_DATABASE_URL` (`postgres://user:pass@host:5432/db`), applying
upstream's pinned `schema.sql` unchanged. Several AS processes can share one database. A
database whose keys predate multi-owner is refused at startup, naming the tables, and
must be recreated. Signing-key rotation uses `UMA_AS_SIGNING_KEY` and `UMA_AS_KID` for
the new key and `UMA_AS_PREVIOUS_KEYS`/`UMA_AS_PREVIOUS_KIDS` for the ones still
published.

Live gates share one stack, so run them one at a time (`make check-live` does) from known
seed state (`make reset`). To run beside another stack, give this one its own Compose
project and host ports:

```bash
export COMPOSE_PROJECT_NAME=java-b UMA4A_EDGE_PORT=8443 UMA4A_DNS_PORT=5054
make up && make reset && make check-live
FIXTURE_PROJECT=java-b-fixture make fixture
```

The smoke probes reach the edge with `curl --connect-to`, so they follow
`UMA4A_EDGE_PORT`. The fixture publishes no host ports.

The person server is built from the pinned source with its own `uv.lock`, installed with
hashes ([`aauth/person-server.Dockerfile`](aauth/person-server.Dockerfile)). That holds
`aauth-signing` at 0.1.2. An unconstrained `pip install -e .` resolves 0.2.0, which
fails enrollment with a 500 (`Missing or unsupported fully-specified alg`).

## Demo credentials — not secrets

This is a self-contained local lab, so it ships with fixed development
credentials in `docker-compose.yml` and the Keycloak realm. **They are demo
defaults, not secrets** — do not reuse them anywhere real, and do not deploy
this stack as-is on a public network.

| What | Value | Where |
|---|---|---|
| Alice's login | `alice` / `alice-demo` | `keycloak/alice-realm.json` |
| Keycloak admin | `admin` / `uma4agents-admin` | `KC_ADMIN_PASSWORD` |
| Gateway's OAuth client secret (exchanged for its PAT) | `gateway-dev-secret` | `UMA_AS_RS_CLIENT_SECRET` |
| Portal session secret | `dev-session-secret` | `PORTAL_SESSION_SECRET` |
| Person-server admin token | `uma4agents-ps-admin` | `PS_ADMIN_TOKEN` |
| uma-as OIDC client secret | `uma-as-demo-secret` | `keycloak/alice-realm.json` |

Every value in the table's right column except the two in the realm file can be
overridden via a `.env` file (see `.env.example`); the realm values live in
`keycloak/alice-realm.json`. The tokens that actually flow — Alice's owner
token, the gateway's PAT, the agent's `aa-agent+jwt` — are all issued at
runtime (OIDC login, `client_credentials`, and AAuth enrollment
respectively); none of them are configured strings.

## Troubleshooting

| Issue | Fix |
|---|---|
| `mkcert: command not found` | `brew install mkcert` (macOS) |
| Browser can't resolve `*.uma.lab` | `make dns-setup`, then restart the browser |
| TLS warnings in the browser | `make trust-ca` |
| `owner-key: … owner-ed25519.pub exists but is not a regular file` | A stack was started before the key existed and Docker created a directory at the bind path. Keeping the volumes: `docker compose stop uma-as`, `rmdir certs/owner-ed25519.pub` (it is empty), then `make up`, which provisions the key first. Not `make down`: it deletes every volume |
| `owner-key: … does not match …` or `… exists without …` | The key pair in `certs/` is inconsistent. Restore the missing or matching half, or move both aside to make a new pair. The target never rotates a key |
| A config edit isn't picked up | `docker compose up -d --force-recreate <svc>` (single-file mounts go stale on inode swap) |

## License & attribution

Licensed under the [Apache License 2.0](LICENSE). This is a Java port of
[uma4agents](https://github.com/nickgamb/uma4agents) (Apache 2.0, Nick Gamb) —
a collaboration exploring UMA's fit for agentic authorization, with Eve Maler.

[NOTICE](NOTICE) carries the full attribution list: the specifications this
profiles (UMA 2.0, RFC 9728, RFC 9421, AAuth, IEEE 7012), and the third-party
components the lab uses. Nothing third-party is vendored here — Maven, `make`,
and `docker compose` fetch each piece from its own origin, under its own
license.

Two things worth reading there before you build on this:

- The **AAuth Person Server** is cloned from
  [christian-posta/aauth-person-server](https://github.com/christian-posta/aauth-person-server)
  (Apache-2.0) at the ref pinned in the Makefile and built locally — it is
  fetched, not vendored. The default demo path (pseudonymous agent keys) does
  not need it.
- **Grafana and Loki** are AGPL-3.0, used unmodified as container images for
  observability only.

Brokerage figures are fixture data flowing through a real protocol path — no
market data, real accounts, or real orders. "Meridian Wealth" is fictional.
