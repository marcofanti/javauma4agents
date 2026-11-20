# Phase A gate results

Phase A of [the port plan](../PORT-PLAN.md) against upstream `7764928`. Every live gate ran
first against the pinned Python reference stack and then against the Java stack, on
2026-11-19. Logs, trimmed of pip and HTTP-client noise, are in
[`phase-a-evidence/`](phase-a-evidence/). The SDK decision and the reconciliation table are
in [PHASE-A-SPIKE.md](PHASE-A-SPIKE.md).

## Results

| Gate | Command | Python reference | Java |
| --- | --- | --- | --- |
| Unit: `mvn verify`, zero warnings | `make check-unit` | n/a | Pass: 45 tests, 0 warnings (after the audit fixes; 38 before) |
| Vendored clients match the pin | `make vendor-verify` | n/a | Pass: 39 blobs |
| Shim | `make shim-test` | Pass (8/8) | Pass (8/8). The launcher logs `exec java -jar /app/shim.jar` |
| TypeScript agent | `make ts-agent-check` | Pass (11/11) | Pass (11/11) |
| Supplemental decline | `make decline-check` | Pass (4/4) | Pass (4/4) |
| Driver acts | `make demo-acts-a` (`tier1`, `tier2`, `tier3`, `revocation`, `--pseudonymous --simulate-alice`) | Pass | Pass |
| Embedded enforcement | `make embedded-check` | Pass | Pass |
| Smoke, Alice-only profile | `make smoke-alice` | Full `smoke-test` passed | Pass (17 probes after the audit fixes, including the trace-context event) |
| Spike evidence, shim boundaries | `make shim-spike` | n/a | Pass (7/7 after the audit fixes), see below |

The Java run of `make check-live`, which runs all of the live gates above in one serial pass,
started from freshly built images and empty volumes:
[`java/check-live.log`](phase-a-evidence/java/check-live.log).

`make shim-spike` against the Java shim, with Python `mcp` 2.3.0:

```text
stdio negotiated 2025-11-25; server alice-vault-via-uma; tools capability True
PASS: stdio: the Python SDK's initialize is answered
[agent-shim] listening on 127.0.0.1:9031 (streamable-http)
http negotiated 2025-11-25
PASS: http: the Python SDK's initialize is answered
PASS: http: the three tools are listed
PASS: http: a pend with nobody to ask is handed back, not held open
PASS: http: the owner's pending request is there to approve
PASS: http: calling again resumes the held request
```

## Run conditions

- **Python client versions.** The Java runs install exact versions: `mcp==2.3.0`, `httpx==0.28.1`, `pyjwt[crypto]==2.15.1`, `cryptography==50.0.2` and `aauth==0.3.2`. Python is 3.12.12 for the checks and the driver. The shim image uses Ubuntu's Python 3.14 beside the JRE.
  - The reference used upstream's floating `mcp>=2,<3`, which resolved to 2.3.0 on the run date.
- **Timing.** The same TTL configuration applies on both sides: `UMA4A_PEND_HANDBACK` comes from the check itself, and `UMA_AS_PENDING_TTL` is at its default of 3600.
- **CA bundle.** Both stacks used the same local CA.
- **No overlap.** The reference and Java stacks never ran at the same time, because they bind the same host ports.
- **Embedded mode.** `embedded-check` recreates the vault in embedded mode and restores gateway mode afterwards. `check-live` runs it after the gateway-mode gates.

## Not gated in Phase A, by plan

- **Later phases.** The full upstream `smoke-test` (Carol's hosts and ID-JAG advertising) runs in E4, `demo-all SIM=1` in D, `adapter-check` in F, and `fixture` in B.
- **Phase A coverage of the HTTP shim.** The spike evidence above covers it.

## Phase A requirements, item by item

Checked against plan revision `21267cdd…3a89f`. Both reviewer sign-offs on that revision are
recorded in [DECISIONS.md](DECISIONS.md).

| Plan requirement | Where it is met |
| --- | --- |
| First deliverable: transport and harness spike, decision note | [PHASE-A-SPIKE.md](PHASE-A-SPIKE.md); `make shim-spike` |
| 0: reconcile the cherry-picks; pinned Alice realm; `meridian-portal` | The reconciliation table in PHASE-A-SPIKE.md; `keycloak/alice-realm.json` is byte-identical to the pin |
| 1: 2026-07-28 discovery, per-request metadata, routing headers, sessionless; the shim-facing handshake kept; superseded paths removed | The vault's dual transport; `Upstream` in the shim; `/.well-known/aauth-resource.json` removed |
| 2: one `uma4a-pep` core for both hosts; both envelopes; signed metadata and owner listing; origin rules; original body; remediation; trace; single-use burned last | `lib/uma4a-pep` (`EnforcerTest`); `uma-pep` and the vault both use it |
| 3: legacy RReg push removed; pre-provisioned Alice resource server; seeded entry asserted | `/rreg` and `REGISTRATION_MODE` removed; `embedded-check`'s "provisioned under a name" branch passed against the seeded `meridian-gateway` entry |
| 4: non-blocking pend and resume; HTTP shim with readiness log; portal discovery and approval paths; operator CIMD and WBA directory | `shim-test` 3a–3c; `make shim-spike`; `make adapter` readiness; portal `/api/agent/pending`, `/decision`, `/resources`, `/resource-servers`, `/connections/revoke`; `services/agent-operator` with the `smoke-alice` probes |
| Gates | Results table above |
| Completion rule 1: vendored tree, manifest, `UMA4A_REPO` launcher | `conformance/`, `make vendor-verify` |
| Rule 2: Python control results | Reference column above |
| Rule 3: `mvn verify`, CI workflow, `check-unit`/`check-live`/`check-all`, CPython vectors | `.github/workflows/verify.yml`, the Makefile, `lib/uma4a-common/src/test/resources/pinned/` with `make vectors` |
| Rule 4: phase documentation and runnable gate commands | README "Conformance" section, `docs/PROTOCOL.md`, this file |

The plan's own Phase A gate text puts the full `smoke-test` and `demo-all SIM=1` later and
`adapter-check` in F. Tier rules and assurance are Phase D scope. Portal surfaces for
organization, joint ownership, operators and resource-server admission come with those
features (E1, E2, E3, F). The work is uncommitted on `phase-a-transport`, as directed.

## Audit fixes · 2026-11-19

Codex's audit at the end of [CODEX-REVIEW.md](CODEX-REVIEW.md) reproduced three harness
failures and listed wire-parity findings. Each was checked against the pin and fixed in
Phase A. Upstream scripts are unchanged; `make vendor-verify` still matches all 39 blobs.

| Finding | Fix | Rerun evidence (`phase-a-evidence/java/audit-fixes/`) |
| --- | --- | --- |
| Live gates overlapped under `make -jN` | `check-live` runs `LIVE_GATES` one at a time through `$(MAKE) -j1`, stopping at the first failure; `check-all` runs `check-unit`, then `check-live`, as recipes rather than prerequisites | `make-j8-check-all.log`, `make-j8-check-live-final.log`: timestamped `=== gate` markers, each starting after the previous gate finished |
| A failed gateway restore exited 0 | [`scripts/embedded-check.sh`](../../scripts/embedded-check.sh): explicit `ENFORCEMENT_MODE=gateway` restore with `--wait`, a mode read-back, a gateway restart, and a bounded `server/discover` through agentgateway. It prints `check=… switch=… restore=…`, exits with the check's status when the check failed, and otherwise exits 1 when the switch or restore failed | `inject-failed-restore.log`: check passed, restore injected to fail, exit non-zero, `RESTORE FAILED`. `inject-failed-check.log`: check injected to exit 7, restore real, exit 7, vault back in gateway mode |
| A stale embedded container could mask a failed recreate (errexit is off inside `if` and `&&`) | `switch_vault` guards `docker compose up` and the mode read-back explicitly | `inject-stale-embedded-recreate-fails.log`: vault already embedded, embedded recreate injected to fail. Result: check skipped, `switch=1`, gateway restored, exit 1 |
| The HTTP spike approved every pending item; its readiness wait could hang | `shim_spike.py` uses a fresh random key per run, snapshots Alice's queue, and approves only the one new family filed under that key's thumbprint. Readiness is a bounded TCP probe that also reports an early child exit | `shim-spike-isolation.log`: an unrelated pend (`synthetic_pend.py`) is pending before and after; spike 7/7 |
| HTTP shim readiness wiring | An `agent-shim` Compose service in the `adapter` profile, as at the pin, running the Java jar. `make adapter` waits up to 60 s for `listening on`, fails if the container exits, and logs the tail on failure. `make adapter-down` stops it | `adapter-readiness.log` |
| Loki probes could be satisfied by an adjacent stack | Both smoke queries select `container` equal to this project's `uma-pep` container | final run: `loki events: OK (javauma4agents-uma-pep-1)` |
| `UMA_PEP_REQUIRE_CONTENT_DIGEST` was case-sensitive | `EnforcerSettings.flag`: lowercase, then 1, true or yes (both hosts) | `EnforcerSettingsTest` |
| Empty `UMA_ALLOWED_ORIGINS` was treated as unset | Unset gives the defaults; set, even to empty, gives exactly its non-empty, unstripped items | `EnforcerSettingsTest`; `EnforcerTest.anEmptyOriginAllowList…` |
| A body with no readable method threw in `Set.of` lookups | Checked before the lookups; `403 unknown_method`, "None is not enforceable by this PEP" | `EnforcerTest.aBodyWithNoReadableMethod…` |
| Introspection echoed `client_id` and `owner`, and omitted `consequence` | `ProtectionController.activeResponse`: the pinned members only, with `consequence` always present (null until D); `clearance` lands in E2 | `IntrospectionResponseTest` |
| `/rreg` advertisement | Already absent; now asserted | `smoke-alice`: `no RReg: OK` (metadata member absent and `/rreg` not 200) |

A rerun also found a harness gap of the same kind as the spike's. The pinned `test_shim.py`
limits its simulated approvals to its own keys only when it can import `uma4a_grant`. Our
launcher had not put the vendored library on the test's own `PYTHONPATH`, so with an
unrelated request left in Alice's queue (by `synthetic_pend.py`) it approved that request
instead of its own, and the run failed 6/8. The `shim-test` service now sets
`PYTHONPATH=/runtime/lib`. That also confirms Python reads the Java shim's PKCS#8 keys and
derives the handles the AS files them under. `shim-test-isolation.log` shows 8/8 with the
unrelated request still pending afterwards. The pinned demo driver approves the first item
in the queue by design, so live gates start from known seed state (`make reset`), per
completion rule 2.

Final rerun: `make check-unit` passed 45 tests with 0 warnings (`check-unit.log`). Then
`make reset` and `make -j8 check-live` exited 0 (`make-j8-check-live-final.log`): shim 8/8,
TypeScript 11/11, decline 4/4, four driver acts, embedded `check=0 switch=0 restore=0`, and
every smoke probe.

## Blocking failures

None.

## Independent verification of the final worktree

The table above records the initial controlled run. The final independent Java run
of `make -j8 check-all` exited 0 with 45 Maven tests, all 39 vendored files verified,
and all live gates passing in order. The stdio shim passed 8 assertions, the
TypeScript client passed 11, and the unconditional decline check passed 4. All
four pinned Python driver acts, embedded enforcement, and Alice smoke passed.
The trace assertion queried this Compose project's Java PEP container.

The revised HTTP spike passed 7 assertions and left a separate pending request
untouched. The adapter negotiated `2025-11-25` using the pinned Python SDK. The
embedded helper passed five normal and fault-injection cases, including a failed
recreation with a stale vault and a failed mode lookup. The OIDC portal's
resource listing, decision, and pinned revocation route passed live.

See the [independent sign-off](CODEX-REVIEW.md#independent-phase-a-sign-off) and
[command output](phase-a-evidence/java/codex-check-all.txt). The work remains
uncommitted on `phase-a-transport`, with the evidence recorded locally.
