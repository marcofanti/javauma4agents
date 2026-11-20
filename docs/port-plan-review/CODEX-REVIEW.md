# Codex review of the port plan

Initial review on 2026-11-19. I compared the plan with upstream `7764928` and the Java baseline `966e1db`, verified the SDK release and Maven artifact, and did not run the stacks. The findings below are proposals for discussion.

## CX-1 · Fix phase dependencies and identity handles

Move `establishment-check` from B to the first E milestone, alongside BYOAS. It needs Carol's AS and `/mcp/carol` and exercises introduction and approval of an unknown resource server. Move the end-to-end `clearance-check` from D to the organization milestone in E. It edits the organization charter and attested member clearance. Keep consequence in D.

In B, group pseudonymous, CIMD-described, and Web Bot Auth-published agents under key-thumbprint identities. AAuth-identified agents use the issuer-qualified subject. CIMD and Web Bot Auth add attribution. Cover ID-JAG with `xaa-check` in E or an explicit earlier test if acceptance lands in B.

Sources [Establishment setup](https://github.com/nickgamb/uma4agents/blob/7764928/clients/demo-driver/establishment_check.py#L52-L64) · [Clearance setup](https://github.com/nickgamb/uma4agents/blob/7764928/clients/demo-driver/clearance_check.py#L269-L317) · [Identity assertions](https://github.com/nickgamb/uma4agents/blob/7764928/clients/demo-driver/flow_check.py#L288-L320)

## CX-2 · Put the owner-scoped store before intent and assurance

Keep C before D. Establish the owner-scoped store interface and memory/JDBC implementations in C, with composite owner keys, atomic ticket and RPT consumption, and a negotiation family that remains addressable when its ticket is spent. Add remaining store operations with the features that need them. This front-loads the owner boundary and avoids reworking single-owner SQL during E.

Run two AS instances against one real Postgres database to check single-use consumption, competing owner decisions, and owner event isolation. Decide explicitly whether assurance admission must enforce a hard cap under concurrent requests. Upstream counts before admission, so an atomic hard cap would be a deliberate change.

Sources [Store contract](https://github.com/nickgamb/uma4agents/blob/7764928/services/uma-as/store.py#L28-L64) · [Schema](https://github.com/nickgamb/uma4agents/blob/7764928/services/uma-as/schema.sql#L53-L101) · [Assurance admission](https://github.com/nickgamb/uma4agents/blob/7764928/services/uma-as/app.py#L4443-L4488)

## CX-3 · Give the Phase A SDK spike a decision criterion

Pin Java SDK 2.2.0 for the spike. Prove that the actual Servlet and gateway preserve original request bytes for authorization before tool execution, the embedded challenge code and data and their HTTP envelope, routing-header reconciliation, Origin handling, and trace context. Exercise the shim's stdio and HTTP entry points, including pend and resume. Characterize what the unchanged shim client's `ClientSession.initialize()` sends before writing a blanket rule for all endpoints. If the SDK cannot preserve the required behavior with a small adapter, use the hand-rolled transport at that boundary and share the authorization and tool code.

Sources [Java vault wiring](../../mcp/alice-vault/src/main/java/io/uma4agents/vault/VaultMcpConfig.java) · [SDK release](https://github.com/modelcontextprotocol/java-sdk/releases/tag/v2.2.0) · [Pinned SDK server docs](https://github.com/modelcontextprotocol/java-sdk/blob/v2.2.0/docs/server-modern.md#streamable-http-servlet) · [Embedded interceptor](https://github.com/nickgamb/uma4agents/blob/7764928/mcp/alice-vault/uma_extension.py#L76-L145)

## CX-4 · Keep upstream check bodies unchanged and adapt the launchers

The shim check spawns Python at a fixed `clients/agent-shim/shim.py` path. Supply an execution shim at that path in the Java test image and verify that the child process is Java. Port orchestration that probes Python service containers or generates a rotation key inside them. Run the pinned harness against the Python reference first, then against Java in an isolated Compose project. Record the implementations under test and the fixture and TTL settings. Serialize scenarios that mutate shared policy or recreate services.

Sources [Shim launcher](https://github.com/nickgamb/uma4agents/blob/7764928/clients/agent-shim/test_shim.py#L62-L73) · [Rotation and embedded runners](https://github.com/nickgamb/uma4agents/blob/7764928/Makefile#L601-L648) · [Clearance timing](https://github.com/nickgamb/uma4agents/blob/7764928/clients/demo-driver/clearance_check.py#L103-L114)

## CX-5 · Move independent wire checks forward and fill coverage gaps

Run `ts-agent-check` in A and thereafter. Add a targeted decline assertion because the upstream TypeScript script can skip that assertion when its second challenge is absent. Add `smoke-test` and `fixture` to the matrix. Put the fixture at the earliest phase with local-key owner authentication and standalone vault TLS, and name that phase explicitly. The embedded check still uses lab infrastructure for the rest of its flow.

Use upstream's `spec/conformance.yaml` as an index to the wire and implementation guarantees. Port the relevant Python-internal AS, PEP, and store assertions into JUnit and Postgres tests. Generate vectors using the pinned implementation for each signing or hashing profile. Clearance is a concrete example where the register cites RFC 8785 and the issuer hashes compact, sorted CPython JSON.

Sources [TypeScript assertions](https://github.com/nickgamb/uma4agents/blob/7764928/clients/ts-agent/src/check.ts#L57-L109) · [Upstream check matrix](https://github.com/nickgamb/uma4agents/blob/7764928/Makefile#L654-L666) · [Minimal fixture](https://github.com/nickgamb/uma4agents/blob/7764928/compose.fixture.yml#L1-L20) · [Clearance requirement](https://github.com/nickgamb/uma4agents/blob/7764928/spec/conformance.yaml#L845-L848) · [Clearance serialization](https://github.com/nickgamb/uma4agents/blob/7764928/services/uma-as/app.py#L3577-L3584)

## CX-6 · Define Postgres fidelity and reset separately

Start from upstream's pinned DDL and preserve its transactional and ownership semantics. If database interchange is a goal, add a Python-to-Java and Java-to-Python database handoff test. Upstream's store tests instantiate Python stores, so a pass against Java service endpoints gives no evidence of interchange. Cover the startup behavior for old single-owner primary keys if compatibility with those databases is in scope.

Keep memory as the Compose default so restart-based `make reset` retains its demo behavior. Define how durable-mode state gets reset separately. `rotation-check` proves AS key rotation, including acceptance of pulls signed by the new AS key. If PEP signing-key rotation stays in C, give it an independent gate and cite its upstream contract.

Sources [Store suite](https://github.com/nickgamb/uma4agents/blob/7764928/lib/test_store.py#L897-L931) · [Compose defaults](https://github.com/nickgamb/uma4agents/blob/7764928/docker-compose.yml#L134-L146) · [Reset](https://github.com/nickgamb/uma4agents/blob/7764928/Makefile#L443-L453) · [Rotation contract](https://github.com/nickgamb/uma4agents/blob/7764928/Makefile#L595-L603)

## CX-7 · Keep the Python demo and bound deployment scope

Run the pinned Python driver for `make demo-all SIM=1`. The driver itself is 529 lines. The larger directory includes the check scripts and helper clients. A small Java example can exercise the Java agent library. Keep Kubernetes and the devcontainer outside Compose sign-off. Include the upstream gateway and edge routing, CA and DNS setup, realms, fixture data, and person-server dependency where the checks use them. Declare the pin as the supported version and handle any head refresh separately.

Sources [Demo entry point](https://github.com/nickgamb/uma4agents/blob/7764928/Makefile#L322-L335) · [Demo and check directory](https://github.com/nickgamb/uma4agents/tree/7764928/clients/demo-driver) · [Gateway routing](https://github.com/nickgamb/uma4agents/blob/7764928/gateway/agw.yaml) · [Edge routing](https://github.com/nickgamb/uma4agents/blob/7764928/edge/envoy.yaml)

## CX-8 · Re-estimate after the risky pieces have evidence

Treat 15–20 sessions as optimistic. Budget 18–25 for the Compose port, excluding Kubernetes and a head refresh. Revisit the estimate after the A transport and harness spike and the C store spike. Split E into independently gated BYOAS, organization plus clearance, and joint plus XAA milestones so failures can be attributed to specific authority boundaries.

## Codex follow-up · 2026-11-19

- **CX-5 and CX-7.** Upstream's full `smoke-test` requires the Carol hosts and ID-JAG discovery, and its `demo-all` includes first-party behavior with Alice's own operator. Phase A should use an Alice-only smoke profile and a single pinned pseudonymous demo act. Require the full smoke and demo once their dependencies land. [Smoke recipe](https://github.com/nickgamb/uma4agents/blob/7764928/Makefile#L354-L441) · [Demo defaults and acts](https://github.com/nickgamb/uma4agents/blob/7764928/clients/demo-driver/driver.py#L229-L294)
- **CX-3.** `adapter-check` is an ordinary MCP client against the HTTP shim, alongside the stdio check. The two tests call the Python SDK's `ClientSession.initialize()` entry point. Verify the actual handshake on both boundaries. Schedule the full adapter gate when its configured identity can work. [HTTP adapter check](https://github.com/nickgamb/uma4agents/blob/7764928/clients/demo-driver/adapter_check.py#L82-L108)
- **CX-1 and CX-5.** The default embedded lab check also exercises an unseeded vault's signed resource-server introduction and owner approval. Include Alice's path in A so the original check can pass, and reuse it for Carol's BYOAS slice. The standalone fixture is preseeded and complements this with local-key owner authorization. [Embedded admission](https://github.com/nickgamb/uma4agents/blob/7764928/clients/demo-driver/embedded_check.py#L82-L131) · [Standalone fixture setup](https://github.com/nickgamb/uma4agents/blob/7764928/compose.fixture.yml#L106-L118)

## Phase A verification · 2026-11-19

Compared all 39 vendored blobs and Alice's realm directly with upstream `7764928`. The isolated `refstack` Python control recorded exit status 0 for `embedded-check`, `shim-test`, `ts-agent-check`, the four pseudonymous demo acts, and the full upstream smoke check. The shim recorded eight passing assertions and the TypeScript agent recorded 11, including its decline branch on this run. The Java release gate still needs the separate decline assertion because the upstream TypeScript script can skip that branch.

The signed-off plan supersedes the review's earlier suggestion about embedded admission. Phase A uses the pinned Compose setup's pre-provisioned Alice resource server. Signed admission for an unprovisioned resource belongs to E1.

An isolated snapshot of the Phase A harness and realm changes passed Maven verification with 13 tests. `actionlint` and `zizmor` exited successfully for the new workflow. The current `check-live` target is a placeholder, so a successful `check-all` at this point would show only the Maven and vendor checks. At sign-off, verify that `check-live` actually invokes every Phase A scenario, reports failures, and runs mutating scenarios serially even when Make is invoked with parallel jobs.

The new pinned JSON and HTTP signature fixtures regenerated byte-for-byte in two runs. The updated common-module suite passed all 17 tests in a clean snapshot. It verifies the five pinned signature shapes against the fixture clock and checks rejection of stale signatures and mismatched body digests. The full Maven reactor still stopped at the old call in `RegistrationPuller` when checked. Repeat the reactor after production callers migrate, then verify actual request bytes and envelope behavior through both Java enforcement hosts.

Gateway config review for Opus. Preserve the pin's environment parsing when wiring both hosts. Python lowercases `UMA_PEP_REQUIRE_CONTENT_DIGEST` before recognizing `1`, `true`, or `yes`. The Java gateway's current set lookup is case-sensitive. Upstream also distinguishes unset `UMA_ALLOWED_ORIGINS` (defaults) from explicitly empty (no allowed Origin values), while the shared Java helper treats an empty value as unset. Test both variants with ordinary configuration tests. [Pinned digest setting](https://github.com/nickgamb/uma4agents/blob/7764928/lib/uma4a_pep.py#L86-L91) · [Pinned gateway Origin configuration](https://github.com/nickgamb/uma4agents/blob/7764928/services/uma-pep/app.py#L71-L82)

Gateway request validation review for Opus. In the pinned ext_authz host, an unreadable nonempty body reaches the enforcer without an MCP method and returns the `403 unknown_method` verdict. Java's `Enforcer.requestShape` currently passes the nullable method to immutable `Set.of` membership checks, which can throw instead of returning that verdict. Handle a missing method explicitly before set lookup and keep the existing body-limit response separate. [Pinned gateway parsing](https://github.com/nickgamb/uma4agents/blob/7764928/services/uma-pep/app.py#L692-L735) · [Pinned enforcer verdict](https://github.com/nickgamb/uma4agents/blob/7764928/lib/uma4a_pep.py#L919-L924)

Pull-only discovery review for Opus. The Java AS removed its `/rreg` handlers, but [DiscoveryController](../../services/uma-as/src/main/java/io/uma4agents/authserver/DiscoveryController.java) still advertises `resource_registration_endpoint` at that path. The pinned Python AS omits that discovery member. Remove the stale advertisement with the registration cleanup and assert its absence in the ordinary discovery check.

AS response review for Opus. The pinned active introspection response contains `sub` and always contains `consequence` (null when absent). It does not echo `client_id` or `owner` from the access token. The current Java [ProtectionController](../../services/uma-as/src/main/java/io/uma4agents/authserver/ProtectionController.java) echoes those claims and omits `consequence`. Keep the claims in the RPT, and match the separate introspection response shape, including null before Phase D adds consequence behavior. [Pinned introspection response](https://github.com/nickgamb/uma4agents/blob/7764928/services/uma-as/app.py#L1363-L1376)

Independent service checks passed in isolated snapshots. The gateway served signed resource metadata and its Ed25519 JWKS. The embedded vault advertised its UMA extension through SDK 2.2.0 and returned the expected in-band challenge after a test authority issued a PAT and permission ticket. The Java AS advertised `/consume` at both discovery paths, omitted the retired RReg endpoint, and returned 404 at `/rreg`. With the Java AS and PEP running together on loopback, the signed owner-resource pull populated all three Alice resources. These runs used local HTTP and do not supply the planned TLS, shim resume, or Java Compose gate evidence.

The full reactor later passed Maven verification in a clean snapshot, with 17 common-library tests and 11 PEP tests. An independent loopback run using the pinned Python MCP SDK 2.3.0 negotiated `2025-11-25` with the Java shim on both streamable HTTP and stdio and listed all three tools. The unchanged shim scenario and HTTP pending/resume still require an end-to-end run.

Independent Java Compose verification now passes the unchanged TypeScript agent (all 11 assertions, including its conditional decline branch), stdio shim (all eight, including pending handback and completion), and embedded check. Gateway mode was restored before running the pinned Python driver's `tier1`, `tier2`, `tier3`, and `revocation` acts with `--pseudonymous --simulate-alice`. All four exited successfully. The Alice-only smoke target passed with TLS verification, including discovery, resource metadata, challenge and denial body, service health, and an allowed event with caller trace context in Loki. This run used an isolated Compose project and an alternate local TLS port. Maven verification in the independently built snapshot passed 31 tests.

The current [Makefile](../../Makefile#L231) lists live checks as parallelizable prerequisites, and the embedded target suppresses both recovery commands' status. With parallel Make, an embedded vault recreation can overlap the gateway test clients. A failed gateway restoration can also leave the live suite with a false green for the embedded target. Enforce ordering in the recipe, wait for the restored vault and gateway, and report a recovery failure while preserving the embedded test's own failure. The separate unconditional decline gate remains required by [the signed plan](../PORT-PLAN.md#phase-a--mcp-transport-and-enforcement).

Additional independent Compose probes used the unchanged Python MCP SDK and vendored UMA client library against Java. The HTTP shim negotiated `2025-11-25`, listed three tools, returned `PENDING` on a fresh identity, and resumed the same operation after Alice approved its family. Alice's owner registry returned `meridian-gateway` as active for `https://gateway.uma.lab/mcp`. An unconditional decline probe required a real 401 UMA ticket, declined one offered agreement, and observed `TermsRejected` with no grant or receipt. These ad hoc probes provide wire evidence for the snapshot. Keep the repeatable decline gate and HTTP readiness wiring in the Phase A harness.

The packaged supplemental decline target passed against the isolated Java stack. It observed `403 request_denied` on a real decline and `400 invalid_grant` on reuse of that ticket.

The new [HTTP spike runner](../../conformance/supplemental/shim_spike.py#L57) approves every request returned by Alice's pending queue. This can approve unrelated owner decisions when the lab already has pending work, and another approval can incorrectly satisfy the count assertion. Scope the approval to the fresh shim key's handle and its single pending family, as the unchanged stdio test already does for its keys. My independent run took a snapshot of the queue before the tool call and approved only the new family in the isolated stack. The startup wait at line 99 also uses blocking `readline()` within a wall-clock loop. Probe the listener with bounded attempts and check the process's exit status so a process that stays alive without printing cannot hang the gate.

The packaged `make -j1 check-live` passed end to end in the isolated TLS stack, including the supplemental decline. The smoke query currently reads event names across all Docker containers discovered by Promtail. I repeated the Loki query with the Java audit gateway PEP's container label and found 19 of its 21 allowed events carrying a valid W3C traceparent. Scope the smoke query to the current Compose service so an adjacent reference stack cannot provide the trace evidence.

The packaged `make shim-spike` also passed all six assertions in the isolated stack. Both Python SDK transports negotiated `2025-11-25`. A newer Maven snapshot passed all 38 tests, including seven in the agent grant client.

Two more independent probes passed against the Java Compose snapshot. An actual HTTPS request through the gateway returned the `401` UMA challenge, its denial body, and a decodable `authorization_remediation` value that named the same ticket, authority, and requested tool. The embedded servlet returned the matching remediation in its HTTP 200 JSON-RPC `-32001` response and returned `-32002` with status data on a non-challenge denial. The servlet also rejected an unapproved Origin on GET and DELETE. The probe restored the isolated vault to gateway mode afterwards.

An OIDC login through the Alice portal completed against the pinned Keycloak realm. The authenticated portal listed all three Alice resources and the active seeded `meridian-gateway` entry. A fresh HTTP shim identity received `PENDING`. Approving only its family through the portal's own decision route allowed the same MCP call to resume. This exercises the portal's session and proxy path in addition to the existing checks that approve directly at the AS.

The fresh-stack logs now in [PHASE-A-GATES.md](PHASE-A-GATES.md) corroborate the serial Java success and pinned Python control. I independently reproduced the remaining harness failures. A temporary Make probe saw `make -j8 check-all` start the embedded switch alongside the shim, TypeScript, decline, demo, smoke, and unit targets. Injecting a failed gateway restore left `make embedded-check` with exit 0. In the isolated Java lab, I created one synthetic pending request on a different shim key. Before the packaged spike it was still pending. Afterwards it had been approved even though the spike reported all six checks passing. These are failures of the signed plan's serial mutation and restore rules and of the spike's approval isolation. I left the phase implementation unchanged.

After the implementation handoff, I rebuilt the Java portal from the latest worktree in the isolated Compose stack. An OIDC-authenticated session approved a fresh shim connection. The connection appeared as active and the tool returned its data. The pinned `POST /api/agent/connections/revoke` route accepted `{"handle": …}`, reported one or more deactivated RPTs, and the same handle appeared as revoked in the portal connection list. This closes the portal verification gap in the implementation handoff.

An independent exact-body test used a fresh, owner-approved single-use grant against the running embedded servlet. Appending one newline to otherwise identical JSON was refused with `-32002`; signing the same bytes for the internal hop rather than the configured public authority was also refused with `-32002`. After both refusals the original bytes and public authority still executed the fixture trade once. Reusing the spent grant returned the pinned retry challenge `-32001`. The isolated vault and gateway were restored successfully.

The implemented wire-parity fixes now pass independent checks against rebuilt Java images. An unreadable ext_authz body returns `403 unknown_method`. The default Origins admit the portal, while an explicitly empty list rejects that same Origin. Uppercase `UMA_PEP_REQUIRE_CONTENT_DIGEST=TRUE` refuses a genuine PoP request whose signature omits Content-Digest. For a real active RPT, PAT-authenticated AS introspection returned exactly the pin's fields, with null `consequence` and without echoed `client_id` or `owner`. The audit restored its original settings. A fresh `make check-unit` verified all 39 pinned blobs and passed 45 tests, including the new PEP and introspection regressions.

The revised gateway restore helper passed two injected failure cases. It reports a failed restore and returns 1 after a passing check, and it preserves a failed check's exit 17 while separately reporting a failed restore. A third injection exposed a remaining shell edge case in [switch_vault](../../scripts/embedded-check.sh#L15). Bash disables `errexit` for that function when it is evaluated by `if` or `&&`. If Compose's `up --force-recreate --wait` fails and an existing container already reports the requested mode, the function continues and the gate exits 0. I reproduced this by starting the probe in embedded mode and failing the new embedded `up`. Guard the Docker `up` and mode lookup explicitly so the failed recreation is detected even with a matching stale container.

The new Compose `adapter` profile became ready in the isolated stack. The pinned Python SDK connected over the lab network, negotiated `2025-11-25`, and listed the three tools. Separate fault probes confirmed the corrected spike readiness returns for a silent live child within its attempt budget and reports exit status 9 for an early child exit. The full named `adapter-check` remains a Phase F gate.

The rewritten aggregate passed independently as `make -j8 check-live`. It ran every gate in order, preserved the embedded check result, verified gateway recovery, and scoped both Loki assertions to the isolated Java PEP container. I reran the cross-request regression against the rewritten HTTP spike. The synthetic request from the other identity stayed pending before and after the run. The spike approved its own pending family, resumed its HTTP call, and passed all seven assertions.

I validated the proposed explicit error guards in a disposable copy of the helper. When Compose failed to recreate an already-embedded vault, the guarded copy skipped the check, restored gateway mode, and returned exit 1. The current workflow also passed `actionlint` and offline `zizmor`. The guarded copy did not change the port's worktree.

The explicit recreation and mode-read guards have landed in the worktree. Five injected cases passed against that script. A normal run returned 0. A failed gateway recovery returned 1. A check that returned 17 kept exit 17 even when recovery failed. Both a failed recreation with a stale matching embedded container and a failed mode lookup skipped the embedded check, restored gateway mode, and failed the target.

## Independent Phase A sign-off

Verified the local `phase-a-transport` implementation against signed plan revision
`21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f` and upstream `7764928`
on 2026-11-19. The tested Java services, Compose and Make wiring, and changed harness files
match the worktree. The test stack used an isolated Compose project and its own local TLS port.

- **Controls and reproducibility.** The pinned Python reference passed the applicable checks.
  The Java aggregate verified all 39 upstream files and passed 45 Maven tests. The pinned realm,
  both signing profiles' CPython vectors, and CI workflow checks were verified independently.
- **Transport and enforcement.** The unchanged embedded and gateway clients exercised
  2026-07-28 discovery, routing, both denial envelopes and remediation, Origin rules, and
  signed access. Targeted probes covered exact body bytes, public authority, burn-last,
  pull-only discovery and active seeded registration, PAT-authenticated introspection, and
  the caller's W3C trace context in this Java PEP's Loki events.
- **Shim, portal, and operator.** The unchanged stdio check passed 8 assertions. The HTTP
  spike passed 7, including a pend that resumed after its own family was approved while
  another identity's request stayed pending. The Compose adapter reached readiness and
  negotiated the pinned SDK handshake. The live OIDC portal listed resources and approved
  and revoked a fresh connection. The operator's CIMD and signature directory passed smoke.
- **Final live aggregate.** `make -j8 check-all` exited 0. The unchanged TypeScript client
  passed 11 assertions, the supplemental decline check passed 4, all four pinned driver acts
  passed, and the embedded and Alice smoke checks passed. Gates ran in order despite
  parallel Make. The independent restore tests covered success and four failure cases.
- **Publication.** The checks, SDK decision, and wire evidence are recorded locally in the
  shared review folder. The work remains uncommitted, so the phase's PR evidence link has not
  been created.

[Independent command output](phase-a-evidence/java/codex-check-all.txt) records the final
aggregate, the scoped Loki trace result, and the HTTP spike's pending-queue regression.

After the final handoff, I independently verified the last Compose wiring change.
The unchanged stdio check ran with `PYTHONPATH=/runtime/lib`, passed all eight
assertions, and left an unrelated pending request untouched in the isolated lab.
The vendored blob verifier still passed for all 39 files. Opus's
[final gate report](PHASE-A-GATES.md#audit-fixes--2026-11-19) records the clean-queue
aggregate on the same revision.
