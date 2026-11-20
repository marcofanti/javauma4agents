# Independent Phase C verification

The plan revision is `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f`.
The Python reference is `77649287dc883b75ef563c59f96de8613ecf10d0`. The
user asked to complete the full signed plan. Phase D follows C, then the four
ordered E slices and Phase F.

## Pinned reference controls

- The pinned store test ran unchanged against memory and PostgreSQL 17.12.
  It passed 236 assertions, including owner-isolated event delivery, atomic
  spending and decisions, and a clear refusal of obsolete schemas.
- The pinned PEP, AS, and gateway suites passed 62, 89, and 24 assertions.
- The unchanged live `make rotation-check` verified both signing keys in
  discovery, spending an old grant, issuance and use of a new grant, and a
  pull refreshed against the new signing key. After completion, I independently
  checked that the AS used memory and published only its original key.
- The reference projects used isolated networks and disposable volumes, with no
  host-published ports. The person-server build retained the upstream lockfile
  configuration verified in Phase B. [Selected control output](phase-c-evidence/codex-python-controls.txt).
- Hardening references in the signed plan resolve at the pin to `5818dba` (#38),
  `ea9d86f` (#41), and `931f5e2` (#43). The Java audit will verify the shared
  checks in C and keep organization and joint behavior in their assigned slices.
- A separate PostgreSQL 17 probe used two independent Python store pools on
  one database. Across 32 requests each, exactly one ticket consumer, one
  owner decision and one RPT consumer won. The family stayed available after
  spending the ticket, and Alice received a notification from the other pool
  without receiving Carol's. The separate Java gate will exercise the two
  AS processes required by the plan.
- I booted the pinned Python AS itself with a database containing the three
  old single-owner primary keys. It exited 3 and named `negotiations`,
  `tickets`, and `tiers` in the stale-schema error.
- A supplemental wire control booted two independent Alice AS processes and a
  Carol AS on one isolated PostgreSQL 17 database. Using the pinned local-key
  and grant clients, Alice's pending event crossed the AS process boundary
  without reaching Carol. One of 12 competing owner decisions and one of 12
  competing single-use RPT consumes succeeded across the Alice processes.
  After changing Alice's tier purpose through one process, both recreated AS
  processes retained her policy and ledger. Carol's tier stayed unchanged.

## Java verification in progress

- The first complete memory-store snapshot passed an independent Maven probe.
  It raced 32 calls for each single-use operation, checked that consuming and
  rotating the ticket preserved the negotiated family and the first decision,
  and checked that Carol could neither read nor spend Alice's records. A
  separate assertion verified reseeding preserved Alice's edited policy and
  notifications stayed owner-scoped.
- Two targeted DSN checks exposed compatibility and redaction defects in the
  first parser. A literal plus in URI credential data was decoded as a space.
  A malformed URI also retained the raw credential in its exception chain.
  The implementation owner has both reproductions.
- I independently reran the corrected DSN parser against a disposable
  PostgreSQL 17 database. Both literal and percent-encoded plus credentials
  opened a real JDBC connection. A malformed URI's exception and cause chain
  contained no credential. All eight focused DSN tests and both independent
  memory-store probes passed in a Maven snapshot.
- The upstream manifest verifies 40 blobs. The vendored `schema.sql` matches
  upstream `7764928` byte-for-byte, and an independently built Java AS JAR
  contains those same bytes at `BOOT-INF/classes/schema.sql`.
- An independent PostgreSQL 17 transaction probe reproduced that a Java
  `Error` escaping a JDBC callback could commit its earlier write when the
  helper restored autocommit. The corrected helper now passed the same probe:
  a successful callback committed, and SQL exceptions, runtime exceptions,
  and Java errors all rolled back. A separate injected JDBC rollback failure
  aborted the connection without restoring autocommit or committing partial
  work.
- The Java JDBC store passed an independent two-pool run on PostgreSQL 17.12.
  Concurrent seeding preserved one owner's defaults, and the ticket, decision,
  and single-use RPT races each had one winner. The first decision survived a
  stale ticket rotation. Revoking a connection burned its live grant. Owner
  isolation held for reads, spends, and notifications. Reopening the store
  preserved both owners' policies and state. The same suite rejected an
  obsolete single-owner schema and named the affected tables.
- A PostgreSQL backend termination disconnected only the test listener.
  The JDBC store reopened the LISTEN session. The existing owner subscription
  received the next event from the other instance and still ignored the
  other owner's event. [Selected Java store output](phase-c-evidence/codex-java-store-probes.txt).
  These checks exercise the store directly. The two-process Java AS,
  rotation and A/B gate runs are still required.
- The repository's own memory, JDBC, replica, and DSN tests passed 71/71 on
  PostgreSQL 17.12 with `-Duma.store.requirePostgres=true`. I then ran
  `JdbcReplicaTest` without a DSN as the ordinary unit gate does. All 11
  cases errored rather than skipping because teardown closed a null store
  after setup aborted. I also identified that the cross-replica decision test
  compared newly constructed owner handles by object identity, causing every
  racing request to use the same decision. Both findings were sent to Opus.
- Both replica-test fixes passed independent reruns. With no DSN, the unit
  invocation succeeded and all 12 replica cases skipped cleanly. With a DSN
  required and absent, it failed explicitly on the missing
  `UMA_AS_TEST_DSN` and had no cleanup error. With PostgreSQL 17.12, the
  expanded focused suite passed 80/80, including the opposite-decision race,
  listener recovery, and the transaction fault tests.
- The independent live Java replica fixture now has the same checked Compose
  topology as the reference. The wire probe sends approvals on one replica
  and denials on the other, checks the single winning outcome, and obtains a
  separate grant for the spend race if the winning decision was denial.
- An isolated Java signing-key probe verified the new and both retired keys
  with PAT, RPT, and receipt headers. The retired PKCS#8 key kept its explicit
  kid and the public PEM key used its JWK thumbprint. JWKS exposed only
  public keys. Old signatures were rejected after removing their key and
  under an unrecognized kid. This probe runs the component on its own. The
  live PEP cache refresh and persistence checks still need the integrated
  stack. [Signing probe output](phase-c-evidence/codex-java-signing-probe.txt).
- A subsequent Java snapshot compiled the integrated AS. I updated the old
  five-argument `GrantService` fixture to the seven-argument constructor in
  the scratch checkout only. Maven verified that snapshot, with 45 optional
  database cases skipped. Opus was informed about the shared test fixture.
- The unchanged Python fixture client passed against the live Java AS on
  PostgreSQL 17.12. The client prints its usual no-database banner, which
  describes its default fixture. The independent overlay put two Alice AS
  processes and one Carol AS on the same PostgreSQL database. Alice's SSE
  event crossed processes and did not reach Carol. Exactly one competing
  approval or denial and one single-use RPT consume succeeded across the two
  Alice processes. After recreating both Alice AS containers, her edited
  policy and ledger survived and Carol's policy stayed separate.
- The Java AS process itself refused to boot against the old single-owner
  schema and named `negotiations`, `tickets`, and `tiers`. Java returned
  exit 1 and the pinned Python AS returned exit 3. The signed gate requires
  refusal and the schema diagnostic. [Selected replica and startup output](phase-c-evidence/codex-java-replica-live.txt).
- All nine Phase A/B live gates passed on the integrated Java snapshot in
  the isolated main and fixture projects, including both driver batches,
  embedded enforcement, and the project-scoped smoke. The smoke exercised a
  truncated request and checked the named refusal.
- A scratch Compose overlay ran the unchanged checker from the pin
  (blob `41ec77f5519381c195ebca9b41b5da08b71379fb`), using a real PostgreSQL
  backend and a separate key-generation container. Before rotation, 2/2
  checks passed. After recreating the AS with the new key, 5/5 passed. The
  same running PEP accepted the newly signed pull. Restore returned the
  authority to memory and its original signing kid, verified through TLS.
  The repository's own rotation target still needs its final run.
- The later focused hardening snapshot passed 31/31. Grant tests covered
  revocation before collection, readmission and refusal of prior grants,
  stale terms and cross-owner PAT isolation. Registry tests confirmed that
  expired or otherwise invalid JWT metadata is refused and malformed
  listings preserve the prior registry, while a valid empty listing
  withdraws its source. [Selected gates, rotation, and test output](phase-c-evidence/codex-java-integrated-snapshot.txt).
- The route-condition audit matched the shared Alice-only cases at the pin.
  A running Java PEP challenged on the four configured Alice paths. It
  refused five unconfigured or misplaced paths with `invalid_resource_id`.
  The owner listing refused unsigned access and returned 404 for an
  unconfigured owner. Envoy served the configured TLS authority and returned
  404 for an unconfigured Host. The latest `make check-unit` passed with
  143 executed tests, 45 optional PostgreSQL cases skipped, and all 40
  vendored blobs verified. [Route and unit output](phase-c-evidence/codex-java-route-and-unit.txt).
- A separate live ticket race passed on both runtimes. Twelve concurrent
  presentations of a fresh ticket were split across independent Alice AS
  processes. One returned terms and rotated the ticket. Eleven returned
  `invalid_grant`. The other replica accepted the replacement ticket and
  processed the agent's decline.
- The repository `make store-test` also passed all 80 checks with no skips,
  using an explicitly supplied DSN. An independent SQL query against that
  DSN's disposable database reported PostgreSQL 17.12.
  [Ticket and store gate output](phase-c-evidence/codex-java-ticket-and-store-gate.txt).
- Resource server credential reprovision now changes only the secret and
  returns the current registration state. The deterministic parallel
  revocation test passed. I reverted just that write in scratch and the same
  test failed, confirming it catches the former loss of revocation.
  [Regression output](phase-c-evidence/codex-java-reprovision-regression.txt).
- The updated self-provisioning `make store-test` passed 85/85 on PostgreSQL
  17.12 with no skips and removed the container it had created. This
  includes both backends and a two-pool test of revocation concurrent with
  a credential update.
- Rotation orchestration with all six caller overrides set ignored them in
  each recreate. In fault injection, a failed first recreate skipped the
  checker and restored memory (exit 1). A failed checker preserved its exit
  code 7 after a successful restore. A failed restore caused the run to fail
  (exit 1). The mock verified every restored setting; the live aggregate
  separately exercises the actual service and pinned checker.
  [Gate guard output](phase-c-evidence/codex-java-gate-guards.txt).
- A fresh isolated repository `make -j8 check-all` with an explicit
  PostgreSQL 17.12 DSN exited 0 through all eleven gates. Rotation's
  unchanged Python checker passed 2/2 before and 5/5 after. The PEP
  container ID and startup timestamp stayed the same across rotation.
  The AS readback showed memory and only `uma-as-1` through TLS.
  This aggregate predates the credential reprovision fix and the stricter
  rotation restore guard. A second fresh aggregate is running with both.
  [Repository aggregate output](phase-c-evidence/codex-java-repository-check-all.txt).

## Revocation ordering at final audit

The working snapshot checks a connection's revocation count before
admitting a previously revoked agent and before collecting an approved
operation. The admission and RPT writes are still separate from that
check. Two independent tests in a scratch checkout injected an owner
revocation immediately before each store write. Both returned an issued
grant where the revocation should win. Phase C sign-off remains open while
these write boundaries are corrected and rechecked.
[Local test output](phase-c-evidence/codex-java-revocation-ordering.txt).

The guarded writes share the connection revocation count. Memory performs
each check and write under its existing monitor. JDBC locks the connection
row before conditionally admitting or recording the grant, and revocation
burns recorded grants under that same row lock. An absent row is written
only for an initial admission expecting zero revocations. Both independent
tests passed against the new write boundaries, along with the 48 focused
grant and memory tests in that snapshot. The repository's PostgreSQL tests
and live gates still need the final source run.

The ordered-write repository store gate now passed 92/92 on PostgreSQL
17.12, with no skips. It included real JDBC and memory cases for refusal
without creating a missing connection, readmission against the current
count, and competing revocation and RPT recording across two pools. The
full independent Java live rerun with the ordered writes is underway.

The aggregate containing the credential update and restore checks
finished with all eleven gates green, including 85 PostgreSQL store
tests and rotation restore readback. In the same disposable stack, a
signed owner edit changed the tier purpose. `make reset` dropped the edit
and reseeded the tier in memory. The separate aggregate with guarded
admission and RPT recording is still underway.
[Aggregate and reset output](phase-c-evidence/codex-java-repository-check-all.txt).

The live two-Alice-process and Carol fixture also passed on the guarded
build. The ticket, decision, RPT and owner event checks were repeated, then
the Alice containers were recreated and retained her edited policy and
ledger. The release AS JAR includes the unchanged pinned SQL blob
`2748f8cd062495376a6f0929e0e3a4c2f997527e`. I compared the disposable
aggregate snapshot to the working tree across 245 code and harness paths.
The initial run caught a test fixture using two different agent keys.
With the corrected fixture and the same production image, the aggregate
passed Maven and proceeded through the live gates.
[Replica rerun output](phase-c-evidence/codex-java-replica-live.txt).

## Independent Phase C sign-off

**Passed.** The final `make -j8 check-all` exited 0 against isolated Java
services. Maven passed and the ordered live run completed all eleven gates,
including the unchanged Python rotation checker and 92 store tests on
PostgreSQL 17.12 with no skips. TLS readback showed memory and only the
original signing key after rotation. The PEP process stayed up. The final
snapshot matched all 245 code and harness paths in the working tree.
The repeated live replica check covered ticket rotation, one winning
decision and RPT burn, owner-only SSE, and policy and ledger survival.
[Final gate output](phase-c-evidence/codex-java-final-all.txt).
