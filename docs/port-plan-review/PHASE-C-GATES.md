# Phase C gate results

Phase C of [the port plan](../PORT-PLAN.md) covers owner-scoped state, signing-key
rotation, and the shared hardening from upstream #38, #41 and #43. Codex verified the
work independently; its record is
[PHASE-C-CODEX-VERIFICATION.md](PHASE-C-CODEX-VERIFICATION.md), with output in
[`phase-c-evidence/`](phase-c-evidence/). This file records the inputs, the repo-owned
gate commands and their results, where each plan requirement is met, and the audit of
the three upstream changes. The work is uncommitted on `phase-c-owner-store`, on top of
the verified Phase A and B worktree.

## Inputs

| Input | Value |
| --- | --- |
| Plan revision (SHA-256) | `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f` |
| Upstream | nickgamb/uma4agents `77649287dc883b75ef563c59f96de8613ecf10d0` |
| Hardening changes | #38 `5818dba`, #41 `ea9d86f`, #43 `931f5e2`, all ancestors of the pin and none of the Java baseline (`f6e6068`) |
| Postgres DDL | `services/uma-as/schema.sql`, git blob `2748f8cd`, vendored unchanged as `conformance/upstream/services/uma-as/schema.sql` and packaged into the `uma-as` JAR from there; `make vendor-verify` checks 40 blobs |
| Rotation check | `rotation_check.py`, blob `41ec77f5`, unchanged |
| Database | `postgres:17-alpine`, server 17.12 as reported by the JDBC connection (`store.started` event, `server_version`) |
| JDBC | `org.postgresql:postgresql` 42.7.11 and HikariCP 7.0.2, both as managed by Spring Boot 4.1.0 |
| Python clients | `python:3.12.12-slim`; `httpx==0.28.1`, `pyjwt[crypto]==2.15.1`, `cryptography==50.0.2`, as in Phase B |

## Gates

| Plan gate | Command | Result |
| --- | --- | --- |
| `rotation-check` | `make rotation-check` ([`scripts/rotation-check.sh`](../../scripts/rotation-check.sh)) | Pass. Before: 2/2. After: 5/5 (both kids published, the kept grant spends, the new grant carries `uma-as-2` and spends, and the resource server accepted the pull signed with the new key while the PEP stayed up). The restore was then verified from the running container: memory store, no database URL, original key as `uma-as-1`, nothing retired, and `/jwks` publishing `uma-as-1` alone |
| Store properties on memory and real Postgres, `UMA_AS_TEST_DSN` required | `make store-test` ([`scripts/store-test.sh`](../../scripts/store-test.sh)) | Pass: 92 tests, none skipped (memory 32, JDBC 32, two replicas 14, transactions 6, DSN 8), against PostgreSQL 17.12 |
| Two AS instances on one database: single use, competing decisions, owner event isolation | `JdbcReplicaTest` (two `JdbcStore`s, each with its own pool and listening connection), and Codex's live two-Alice-process run | Pass. Live: two Alice AS processes and a Carol AS on one database (Codex) |
| Restart, reseed, stale-schema startup | `JdbcReplicaTest.stateSurvivesARestart…`, `aDatabaseFromBeforeMultiOwner…`; Codex's live recreate | Pass. A stale database fails within two seconds, naming `negotiations`, `tickets` and `tiers` and only those, and is not retried |
| AS and PEP assertions the live checks bypass | `GrantLoopTest`, `RegistryPullTest`, `SigningKeysTest`, `OwnerRealmKeysTest`, `OwnerAuthTest`, `AuthorityKeysTest`, `PortalConfigTest` | Pass (see [Unit evidence](#unit-evidence)) |
| `mvn verify`, zero warnings | `make check-unit`; CI runs it with a Postgres 17 service and `-Duma.store.requirePostgres=true` | Pass: 206 tests, 0 skipped with the DSN set, 0 `[WARNING]` lines |
| Phase A and B regressions | `make check-live` | Pass. Nine A/B gates, then `rotation-check` and `store-test`, one at a time; see below |

`make check-live` now runs `shim-test ts-agent-check decline-check demo-acts-a
demo-acts-b flow-check embedded-check smoke-alice fixture rotation-check store-test`. I
ran it twice on Compose project `claude-phase-c` (edge 24443, DNS 25553; Codex used
14443/15553). Both runs started from `make reset`:

1. **Run 1**, on images built before the last hardening edits: exit 0, all 11 gates.
   Embedded `check=0 switch=0 restore=0`.
2. **Run 2**, on images rebuilt from the final sources: see
   [Final live run](#final-live-run).

### Running them

```bash
export COMPOSE_PROJECT_NAME=<project> UMA4A_EDGE_PORT=<port> UMA4A_DNS_PORT=<port>
make up && make reset
make -j8 check-live FIXTURE_PROJECT=<fixture-project>
make check-unit                     # Postgres tests skip here without UMA_AS_TEST_DSN
make store-test                     # Postgres required; starts its own if no DSN is set
```

`store-test` uses `UMA_AS_TEST_DSN` when it is set, and that database must be
disposable, because every test class drops the store's tables. Otherwise the script
starts one `postgres:17-alpine` under a name unique to the run, on an ephemeral loopback
port, and removes it on exit by the id `docker run` returned. `rotation-check` starts
`pg` fresh under the Compose `test` profile, so durable test state is reset by replacing
the database, and removes it afterwards. Neither publishes a fixed host port.

## Requirements and where they are met

| Plan requirement | Source | Evidence |
| --- | --- | --- |
| Owner-scoped store interface, memory and JDBC | `store/Store`, `OwnerStore`, `MemoryStore`/`MemoryOwnerStore`, `JdbcStore`/`JdbcOwnerStore`; one owner store per owner, every SQL statement filters on `owner` | `StoreContract`, run unchanged against both backends |
| Pinned DDL through plain JDBC, composite owner keys | `JdbcStore.start` applies `schema.sql` in one statement on every start; `Sql` is a small `PreparedStatement` helper; HikariCP pool of 8; a dedicated listening connection | `JdbcStoreTest`, `JdbcReplicaTest` |
| Family identity across ticket rotation | `consumeTicket` deletes only the ticket row; the negotiation stays keyed by `(owner, family)` | `aNegotiationOutlivesItsTicketAndKeepsItsFamilyAcrossRotation`; replica test `aDecisionOnOneReplicaIsCollectedByAPollOnTheOther` |
| Atomic ticket and RPT consumption | `DELETE … RETURNING` joined to the negotiation; `UPDATE rpts … WHERE NOT consumed RETURNING` | 32-way races on each backend and across replicas |
| Atomic decisions | One guarded `UPDATE` writing `decision` and `decided_by`; upserts keep a stored decision (`UPSERT_NEGOTIATION`) | Decision races; a stale-copy write keeps the decision and its author |
| Atomic seeding | `owners` row as the claim, inside one transaction; once per owner, so edits and revocations survive | `seedingIsOncePerOwner…`, `seedingTwoOwnersAtOnce…`, restart test |
| Atomic revocation | Connection and its live RPTs in one transaction. Admission and grant recording are conditional on the revocation count the decision was made under, serialized on the same connection row (`admitConnection`, `recordRptIfConnected`) | Revocation-vs-spend and revocation-vs-record races on both backends and across replicas; injected-order regressions in `GrantLoopTest` |
| Owner-scoped event delivery | Memory: a subscriber list per owner. JDBC: an `owner_events` row plus `pg_notify(id)`, read back and routed to that owner's subscribers on every replica; the listening connection reconnects after a failover | `anEventReachesASubscriber`, `ownersCannotSeeEachOther`, `anEventOnOneReplicaReaches…`, `aReplicaWhoseListenerWasCutListensAgain` |
| Memory as the Compose default, restart-based `make reset` | `UMA_AS_STORE=memory` default (`StoreConfig`); Compose passes `${UMA_AS_STORE:-memory}` | Live gates run on memory; Codex verified the restart-based reset live |
| Durable restarts and recreates keep grants and owner state | JDBC store; terms republished write-once at startup | `stateSurvivesARestart…`; `rotation-check` spends a grant across the recreate |
| Clear refusal of obsolete single-owner schemas | `JdbcStore.assertOwnerKeys` (`SchemaTooOld`, never retried), the same check and message intent as `_assert_owner_keys` | `aDatabaseFromBeforeMultiOwner…` |
| AS signing-key rotation and retired verification keys | `SigningKeys`: `UMA_AS_SIGNING_KEY`, `UMA_AS_KID`, `UMA_AS_PREVIOUS_KEYS`, `UMA_AS_PREVIOUS_KIDS` (thumbprint kid when absent); `/jwks` and own-token verification by kid; PAT, RPT and receipt headers use the current kid | `SigningKeysTest` (6), live `rotation-check` |
| PEP refresh when the AS pull-signing key changes | `Publication.AuthorityKeys` (ported in A): the first failed signature forces one read; forced reads are floored at 5 s, and scheduled fills don't count toward the floor. The AS pull now signs with the current kid | `AuthorityKeysTest` (3, counted JWKS endpoint); live `rotation-check` "accepted a pull signed with the new key" |
| `UMA_AS_TEST_DSN` integration gate | `PgTestDb` skips without it unless `-Duma.store.requirePostgres=true`, which makes a missing database a failure; `make store-test` and CI set it | `make store-test`; CI service |

## Unit evidence

| Class | Tests | What it ports or proves |
| --- | --- | --- |
| `StoreContract` (memory, JDBC) | 32 each | The pinned `test_store.py` cases for operations with callers in this phase, plus secret-update, spend-once, conditional-admission and grant-recording cases |
| `JdbcReplicaTest` | 14 | Two instances on one database: ticket, RPT, decision and spend-once races; a poll on one replica collecting a decision made on the other; revocation crossing replicas; events crossing for the right owner only; listener reconnect; restart without reseeding; stale schema; an unreachable database retried, then reported without its password |
| `SqlTransactionTest` | 6 | Commit only on return; rollback for runtime exceptions, SQL exceptions and `Error`; a failed rollback aborts the connection rather than letting the autocommit reset commit it; a failed commit rolls back |
| `PgDsnTest` | 8 | libpq URI reading: a literal `+` stays a plus, `%2B` decodes to one, UTF-8 escapes decode, and a malformed URI's exception chain carries no credential |
| `GrantLoopTest` | 21 | `test_as.py`: what an agreement may say (widened, zero or fractional lifetime, missing or empty scope, toolless per-operation, refused before she is asked); terms re-dictated when changed before commit; grant lifetime, resource, `at+jwt`, `sub == client_id ==` handle; live introspection; another owner's PAT told `unknown_token` for introspect and consume; revocation not revived by readmission; an approval refused after a revocation; readmission keeping the count; poll keeping its ticket; attribution of an allowed call; provisioned secret rotation; an empty secret never opened; a revocation landing during secret reprovisioning, admission or grant recording staying a revocation |
| `RegistryPullTest` | 13 | `test_as.py` pull and `/perm` sections, plus the pinned decode's claim checks on `signed_metadata`, https same-origin documents, the 1 MiB bound, malformed listings refused without withdrawal, and revoked servers writing nothing |
| `SigningKeysTest` | 6 | Rotation from the authority's side, including a full grant across a rotation over one store |
| `OwnerRealmKeysTest` | 2 | A rotated realm key learned by one forced read, floored at 60 s |
| `OwnerAuthTest` | 11 | Phase B cases, plus a signed change accepted by one replica refused by another (spent in the shared store) |
| `AuthorityKeysTest` | 3 | The PEP's key cache against a counted JWKS server |
| `PortalConfigTest` | 1 | `PORTAL_AUTH` other than `oidc` or `none` refuses to start |

I mutation-checked each new safeguard by reverting it and confirming its test fails:
- the withdrawn-since-asked re-check;
- the owner-mismatch answer;
- the scope-widening refusal;
- the metadata claim checks;
- strict listing entries;
- the whole-row secret write;
- unconditional admission;
- unconditional grant recording;
- form-decoding in the DSN parser;
- the chained exception cause;
- the transaction helper's `Error` path.

## Audit of #38, #41 and #43

Phase A ported from the pin, so most of these three changes arrived with A or B. The
table lists every safeguard in the three changes that bears on a service or client this
port has. For each, it gives where the safeguard lives now, or the phase that owns it.
Kubernetes, site, drafts, devcontainer and changelog changes are outside release scope
(plan, Scope).

| Change | Safeguard | Status in Java |
| --- | --- | --- |
| #38 | Fail closed on an empty policy decision | Rules engine arrives in D. Now: a resource no tier governs is refused (`no-tier`) |
| #38 | Refuse re-enrolment; members matched on verified claims; break-glass; stale organization answers; organization text escaped | E2 |
| #38 | Refuse unknown enforcement routes | Present (A): `CheckController` `unknown-route` |
| #38 | Credential required to publish to the operator directory | Present (A/B): `UMA4A_OPERATOR_REGISTER_TOKEN` |
| #38 | Refuse other accounts at the portal | **C**: `UMA_PORTAL_OWNER`; any other `preferred_username` gets 403 "This portal belongs to another account." before any token is stored |
| #38 | Pull only approved resource servers | **C**: `RegistrationPuller.approved()` |
| #38 | Terms ids and agent key ids keyed by owner and key | **C** for terms (owner-scoped `terms_docs`); per-owner template namespacing arrives with E1 |
| #38 | Narrow grant scopes to what was offered and agreed | Present (A): `grantedScopes` |
| #38 | Refuse approvals after an operator block; re-check a parent before its child | D (operator blocks, sub-agents) |
| #38 | Bind identity asks to the negotiating server | E4 |
| #38 | Relisten after failover | **C**: `JdbcStore.relisten`, tested by cutting the listening connection |
| #38 | Registry per owner; `content-digest` forwarded to the PEP | **C** for the registry (single served owner; owner routing E1). Present: `gateway/agw.yaml` forwards `content-digest` |
| #38 | Tool-call bodies signed with Content-Digest; canonical operation hash | Present (A) |
| #38 | AS outages answered as unavailable; external inputs bounded and authenticated | Present (A/B): `temporarily_unavailable`, `PeerFetch` bounds. **C**: registry fetches bounded at 1 MiB, no redirects |
| #38 | End portal sessions the provider ended | **C**: a failed refresh drops the session's tokens |
| #41 | Unknown portal auth mode refused; session rotated at login | **C**: `PortalConfig.authMode`. Present: a fresh `sid` is minted at the callback |
| #41 | Another owner's grant answered `unknown_token` before any reason, in introspect and consume | **C**: `ProtectionController.otherOwners` |
| #41 | PEP classifies reasons once; consume 503; 401 retried with a fresh PAT | Present (A): `Enforcer`, `ProtectionClient.protectedPost` |
| #41 | Agreement with no scope array, or a per-operation agreement naming no tool, refused before she is asked | **C**: `GrantService.checkAgreedTerms` |
| #41 | Reason and mission bounds; rules failing towards her | D |
| #41 | Owner-resources key refetch floor; unreadable keys a refusal; first failure after a rotation refetches | Present (A); **C** test `AuthorityKeysTest` |
| #41 | Signature verifier refuses other algs and an uncovered Signature-Agent | Present (A): `HttpSignature` |
| #41 | Origin on every MCP request; handle in the body | Present (A) |
| #41 | Tier creation re-reads listings | D (tier creation) |
| #41 | Organization, tally, invitations, joint mandate moved | E2, E3 |
| #43 | Re-check what she withdrew before an approval becomes a grant | **C** for revocation and a disconnected operation agent, made atomic with admission and grant recording. Operator blocks: D. Organization and clearance: E2 |
| #43 | Grants last as long as the agreement | Present (A); tested in C |
| #43 | Agreement naming no scope refused; terms changed before commit dictated again | **C** |
| #43 | Introduced and joint requests counted against the attention budget | D, E3 |
| #43 | Registry keyed by owner and resource; another owner's listing refused; `/perm` only for a server that publishes the resource; every approved server a source | **C**: `sources`, `servedBy`, `pullAll` at startup until every approved server answers |
| #43 | Unauthenticated requests no longer create owners | **C**: seeded at startup and after an authenticated PAT request only. Owner routing: E1 |
| #43 | Organization blocks atomic; notices and identity assertions spent once in the shared store | **C** provides `spendOnce` (used for owner signatures); its organization and ID-JAG callers arrive in E |
| #43 | Peer, realm and holder keys refetched once with a floor | Peer present (B). **C**: realm keys (`TokenVerifiers`, 60 s floor). Holder: E3 |
| #43 | PEP retries every Protection API call on 401; failed access reports recorded | Present (A): `protectedPost`, `access.report_failed` |
| #43 | Owner's signed change refused when sent twice | Present (B), **C**: spent in the shared store across replicas |
| #43 | Signatures carry `created`; signer adds a nonce | Present (A/B) |
| #43 | Client finds metadata from the resource called | Present: vendored clients unchanged; `GrantClient` checks the pointer |
| #43 | Seeded resource-server registration follows the provisioned secret | **C**, made atomic (see Decisions) |
| #43 | Re-register after withdrawal | E1 (introduction) |
| #43 | Rotation-check restores on every exit and fails when the restore fails | **C**, with the restore verified from the container's environment and `/jwks` |

## Decisions and deviations

- **Store operations in this phase.** The interface has the pinned operations with
  callers in A to C, plus `spendOnce`. Organization, mandate, operator block and claim,
  lineage, trajectory, tier create and delete, and tier-grant bookkeeping arrive with
  their callers in D and E, and their `test_store.py` cases with them. The schema is the
  whole pinned DDL, so those tables already exist.
- **Reads return copies on both backends.** A change persists only through a write, so
  code that works on memory can't depend on in-place mutation Postgres doesn't have.
  Upstream's memory store hands back live objects.
- **Revocation boundaries made atomic.** The pin reads the revocation count, then admits
  or records the grant in separate steps. On the pin's memory store nothing interleaves
  between them; on Postgres a revocation can land in between. There it would be
  overwritten by the admission, or the grant would miss its burn and come back on
  readmission. `admitConnection` and `recordRptIfConnected` take the connection row's
  lock that `revokeConnection` takes, and write only when the count is unchanged.
  - Wire outcome: unchanged except in that window. It becomes 403 `request_denied`,
    "this agent was revoked after it asked", recorded as `refused`. The token signed for
    a refused grant is never returned or recorded.
  - Cost: one row lock per issuance, contended only by the same agent.
- **Secret reprovisioning made atomic.** The pin writes back the whole record it read,
  which can put back an `active` status she has just revoked. The store now sets the
  secret alone and returns the live record, and the status is read from that record.
  Ordinary outcomes are unchanged: the rotated secret works, a stale one gets 401, and a
  revoked registration gets 403.
- **Registry pulls.** A malformed listing is refused before anything is applied; Python
  applies the entries before the bad one and then raises. A `resource_scopes` that is
  not an array of strings is refused rather than stored.
- **Metadata claim checks** use PyJWT 2.15.1's default order and messages, with `iat`
  on: `PyJwtClaims.validateWithIat`. The agent-token path keeps Phase B's `iat`-off
  behaviour.
- **Rotation key generation** runs in a helper container (`rotation-keygen`), because
  the Java image has no Python (completion rule 1). The recreate's health probe uses
  `curl`.
- **SSE keepalive.** The owner stream sends a comment every 15 s, as sse-starlette pings
  do upstream. This finds subscribers that have gone away.

## Not in Phase C, by plan

Owner routing and ticket owner-marking (`<owner>~tkt_…`), multi-owner resource-server
introduction and per-owner template namespacing are E1. Intent, assurance, consequence,
operator blocks, sub-agent lineage and rules are D. Organization, clearance, joint and
XAA are E2 to E4. Python-to-Java database interchange and PEP signing-key rotation are
outside this release (DECISIONS, CX-6).

## Final live run

Run 2 is on images rebuilt from the final sources. It starts from `make reset` on
project `claude-phase-c`:

`make -j8 check-live FIXTURE_PROJECT=claude-phase-c-fixture` exited 0, one gate at a
time:

| Gate | Result |
| --- | --- |
| `shim-test` | 8 passed |
| `ts-agent-check` | 11 passed |
| `decline-check` | 4 passed |
| `demo-acts-a` | tier1, tier2, tier3, revocation, pseudonymous: all four PASS |
| `demo-acts-b` | the same four acts as an identified agent: all four PASS |
| `flow-check` | PASS: agent identity stayed on the requesting side |
| `embedded-check` | `check=0 switch=0 restore=0` |
| `smoke-alice` | every probe OK, including Loki protocol and trace events |
| `fixture` | PASS |
| `rotation-check` | before 2/2, after 5/5, PASS; restore verified (memory store, `uma-as-1` alone) |
| `store-test` | 92 tests, 0 skipped, PostgreSQL 17.12 |

Logs: [`claude-check-live-run1.txt`](phase-c-evidence/claude-check-live-run1.txt) and
[`claude-check-live-run2.txt`](phase-c-evidence/claude-check-live-run2.txt).

## Blocking failures

None.
