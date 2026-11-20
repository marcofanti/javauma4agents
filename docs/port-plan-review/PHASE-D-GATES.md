# Phase D gate results

Phase D of [the port plan](../PORT-PLAN.md) covers intent, assurance, consequence and
agent relationships. This file records the inputs, the repo-owned gate commands and their
results, where each plan requirement is met, the decisions and deviations, and the
findings raised during review. The work is uncommitted on `phase-d-intent-assurance`, on
top of the signed-off Phase A to C worktree (archived C source at
`javauma4agents-phase-c-checkpoint.8qRZpX/source/phase-c-source.tar.gz`). Codex runs the
pinned Python controls and the independent Java verification; that record lands beside
this one.

## Inputs

| Input | Value |
| --- | --- |
| Plan revision (SHA-256) | `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f` |
| Upstream | nickgamb/uma4agents `77649287dc883b75ef563c59f96de8613ecf10d0` |
| Gate scripts | `intent_check.py` `6d60361f`, `assurance_check.py` `376e87f3`, `consequence_check.py` `4ae1e28b`, `first_party_check.py` `5ab95e5f`, `subagent_check.py` `088385b2`, `driver.py` `90412ce9`, all vendored unchanged |
| Vendored tree | 47 blobs (`make vendor-verify`). New in D: the portal SPA (`app.js`, `index.html`, `login.html`, `styles.css`) and the pure AS modules `policy.py`, `assurance.py`, `introduction.py`, used only to generate vectors |
| Python clients | `python:3.12.12-slim`; `httpx==0.28.1`, `pyjwt[crypto]==2.15.1`, `cryptography==50.0.2`, as in B and C |
| Database | `postgres:17-alpine` for `store-test` and `rotation-check` |
| Compose project | `claude-phase-d`, edge 34443, DNS 35553; fixture `claude-phase-d-fixture` |

## Gates

| Plan gate | Command | Result |
| --- | --- | --- |
| `intent-check` | `make intent-check` | Pass, 42 passed, 0 failed |
| `assurance-check` | `make assurance-check` | Pass, 26 passed, 0 failed |
| `consequence-check` | `make consequence-check` | Pass, 22 passed, 0 failed |
| `first-party-check` | `make first-party-check` | Pass, 14 passed, 0 failed |
| `subagent-check` | `make subagent-check` | Pass, 22 passed, 0 failed |
| Full pinned `make demo-all SIM=1` | `make demo-all SIM=1` (`demo-all-sim` in `check-live`) | Pass: tier1, tier2, tier3 with replay and re-presentation, first-party, revocation |
| `mvn verify`, zero warnings | `make check-unit` | Pass: 244 tests, 63 PostgreSQL cases skipped without a DSN (the only three `[WARNING]` lines are those skips, as in C); 47 vendored blobs verified |
| PostgreSQL 17 integration | `make store-test` | Pass: 114 tests, 0 skipped, PostgreSQL 17.12 (memory 43, JDBC 43, replicas 14, transactions 6, DSN 8); the disposable container was removed |
| Phase A to C regressions | `make check-live` | See [Final runs](#final-runs) |

The counts match Codex's pinned Python controls for the five checks (42, 26, 22, 14, 22).

`check-live` now runs the eleven A to C gates, then the five D checks and `demo-all-sim`,
one at a time and stopping at the first failure:

```bash
export COMPOSE_PROJECT_NAME=<project> UMA4A_EDGE_PORT=<port> UMA4A_DNS_PORT=<port>
make up && make reset
make -j8 check-live FIXTURE_PROJECT=<fixture-project>
make check-unit
make store-test            # PostgreSQL required; starts its own if UMA_AS_TEST_DSN is unset
make vectors               # regenerates the CPython vectors; byte-identical at this pin
```

## Requirements and where they are met

| Plan requirement | Source | Evidence |
| --- | --- | --- |
| Intent declarations: the echo checked field by field | `GrantService.verifyContract`, `checkAgreedTerms` (lifetime compared as a whole integer) | `intent-check` echo section; `AgreedTermsTest` |
| Reason carried, bounded, never judged; mission as a citation | `GrantService.requesterClaims` (`UMA_AS_MAX_REASON`, UTF-8 bytes; mission normalised to `approver`, `s256`, length in code points) | `intent-check`; promised entry, pending view and notification carry both |
| Owner record and drift reads | `/owner/ledger?handle=`; `OwnerStore.trajectory` over `UMA_AS_TRAJECTORY_WINDOW`; `touched` filed under the grant's tier | `intent-check` trajectory and drift sections; `StoreContract` trajectory cases |
| Which prohibitions are enforced | `PolicyService.enforcedProhibitions`; `DiscoveryController.annotateEnforced` on read, current version only, in JSON, HTML and JSON-LD | `intent-check` "refused and only promised" section |
| Assurance axes, no composite | `Assurance.assess`, `describe` (one-pass named substitution, as `str.format`) | `assurance-check`; `AssuranceTest`; vectors |
| Rules: grammar, validation, restrictions beat relaxations, only her decisions relax, unevaluable rules fail towards her | `Rules` (pure, dict-shaped facts); CPython `int`, `float`, `str.strip` and truthiness in `Py`, `PyStr` | 1,242 evaluation and 38 validation vectors; all five checks |
| Onboarding and attention-budget lanes, count-before-admission | `Commitment.attentionBudget`; `PolicyService.pendLane`/`pendBudget` (`UMA_AS_PEND_BUDGET` 5, `UMA_AS_PEND_BUDGET_ATTRIBUTED` 40) | `assurance-check` budget and newcomer sections. Concurrency limit documented [below](#count-before-admission) |
| Owner configuration | `POST /owner/policies` (`PolicyService.newTier`, version numbering continued across delete), `DELETE`, `PUT` (rules, clearance, terms), `GET /owner/policy-vocabulary` | All five checks write and restore her policy through these; vectors for `new_tier` and `apply_patch` |
| Portal visibility | Pinned SPA served unchanged from `conformance/upstream`; portal routes for policy create/delete, vocabulary, operators (block/unblock, as at the pin), ledger by handle | Codex's authenticated portal probe; pending view carries assurance, notes, because, reason, mission, first contact |
| Consequence from the provider | `EnforcerSettings.ToolSurface.consequence`; `Publication` puts it in `tool_surfaces` (signed) and the owner listing; single-use derived from it | `consequence-check` sections 1 and 2 |
| Through policy | `request.consequence_at_or_above`, `request.consequence_unknown` | `consequence-check` sections 3 and 4 |
| Through RPT and introspection | `GrantService.issueRpt` adds `consequence`; `/introspect` returns it | `consequence-check` trade flow |
| Through enforcement | `Enforcer.consequenceRaised` → 403 `consequence_changed`; remediation `authorization_details[0].consequence` | `consequence-check` challenge; gateway and embedded hosts share the core |
| First-party operator claims | `/owner/operators/claim`, `disclaim`; `Standing.firstParty` needs the claimed origin and accountability 2 | `first-party-check`; `demo-all` Act 4 |
| Operator block | `/owner/operators/block` revokes the operator's agents and their sub-agents once each; `unblock` restores the right to ask only; re-checked at collection | `assurance-check` operator section |
| Activation and delegated children | `Introduction` (verify, admit), `Standing.introduction` (sibling document or AAuth `parent_agent`), introduced connection written conditionally and re-checked against the parent's generation; revocation cascade | `subagent-check`; introduction vectors |
| Alice operator as a separate instance of the same service | `alice-operator` in Compose (same image, `AGENT_OPERATOR_ORIGIN=https://alice-agent.uma.lab`, `AGENT_OPERATOR_NAME`); Envoy route and edge alias | `first-party-check`, `subagent-check`, `smoke-alice` probe |
| Atomic store guarantees kept; pinned DDL; feature store methods with callers | `noteTierGrant`/`noteTierApproval` (append-if-absent in one statement), `lineageApprovals`, `countChildren`, operator tables, `trajectory`, `createTier` (uniqueness and write in one statement), `deleteTier`, on memory and JDBC | `StoreContract` D cases on both backends, including races |
| Both RFC 9421 profiles, CPython JSON fidelity | Unchanged | A to C gates in `check-live`; existing vectors regenerate byte-identically |
| New signature or hash has generated vectors | The introduction JWS: 11 verification cases signed by the pinned `sign_introduction` under a frozen clock, plus 9 admission cases | `PhaseDVectorsTest` |

## Unit evidence

| Class | Tests | What it proves |
| --- | --- | --- |
| `PhaseDVectorsTest` | 10 | Defaults, vocabulary, enforced prohibitions, lanes, rule validation (refusal text), 1,242 evaluations, durations, tier creation and owner edits, assurance, consequence, introduction verification and admission, all against CPython output from the vendored modules |
| `StoreContract` D cases (memory, JDBC) | 11 each (43 per backend in all) | The pinned `test_store.py` cases for tier notes, lineage, revocation count, tier create/delete, blocked and claimed origins, trajectory; plus 32-way concurrent tier notes and tier creation, a null tier not counted, and another owner's rows invisible |
| `AssuranceTest` | 3 | Levels only from checks that ran; a display name containing `{issuer}` stays literal |
| `AgreedTermsTest` | 3 | An agreed lifetime of 2^64+60 or Long.MAX_VALUE+1 is refused, a negative that wraps positive is refused |
| `GrantLoopTest`, `SigningKeysTest` | 21, 6 | The C grant mechanics, now through the D grant loop |

## Decisions and deviations

- **Clearance stays inert until E2.** `new_tier` and `apply_patch` validate a clearance
  requirement as the pin does, so malformed input gets the pinned message, and then refuse
  any non-empty one with 400. Evaluating a requirement arrives with organizations; until
  then a stored prerequisite would be ignored at the grant, which fails open. The pinned
  `"clearance": {}` shape is kept.
- **Introduced connections are written conditionally.** The pin uses `put_connection` and
  re-reads the parent. Java uses `admitConnection` on the child's revocation count, and
  checks the parent before and after against the revocation count observed when the
  introduction was honoured. A revocation and readmission of the parent in between is a
  different relationship and refuses the child. Outcome otherwise unchanged.
- **Block and cascade revoke each handle once.** A revocation bumps her count each time it
  runs, so a stale snapshot must not revoke a sub-agent twice.
- **Trajectory tiers.** A ledger row whose tier is null or empty is not a tier reached, on
  both backends. The pinned memory store skips it; the pinned SQL would count a null tier.
- **Owner refusals where the pin raises a non-`ValueError`.** A rule that is not an object,
  a condition that is not a string, or a duration like `1e400d` raise `AttributeError` or
  `OverflowError` at the pin (HTTP 500). Java refuses them with 400. All `ValueError`
  refusals match word for word (vectors).
- **Introduction parse errors.** "introduction is not a JWS: …" keeps its prefix; the
  parser's own words after it differ from PyJWT's.
- **Rules arguments read as CPython reads them.** Unicode digits, underscores, surrounding
  Unicode whitespace (`str.strip`, which includes NBSP and em space, unlike Java's
  `isBlank`), and arbitrary-precision integers.
- **Portal SPA.** The pinned assets are vendored and verified rather than copied into the
  service, and the earlier Java copies are removed. Organization and joint panels call
  routes that arrive in E; the SPA already tolerates their absence.

### Count-before-admission

The attention budget counts the pending queue in that lane and then admits (the pinned
semantics, kept for this release per DECISIONS CX-2). It is not one atomic step: two
strangers in the same lane arriving together can both see one free slot, so a lane can
briefly hold more than its budget, by at most the number of requests in flight at once.
The overshoot drains as she answers. The budget bounds her backlog against a flood; it is
not a security boundary, and nothing it admits skips her policy.

## Findings fixed in this phase

| Finding | Where | Fix |
| --- | --- | --- |
| Java read `UMA_RPT_AUDIENCE`; the pin reads `UMA_AS_RPT_AUDIENCE` | `AsConfig` | Renamed to the pinned variable |
| `PyJwtClaims` checked `sub`/`jti` before `nbf`/`exp`; PyJWT 2.15.1 checks required, `iat`, `nbf`, `exp`, `iss`, `aud`, `sub`, `jti` | `PyJwtClaims` | Pinned order; audience step added for introductions |
| The terms HTML did not escape interpolated values, and did not mark refused prohibitions | `DiscoveryController.termsAsHtml` | `html.escape` semantics, quotes included; pinned refused/undertaken marking; hours rounded as CPython |
| `str.format` vs chained `replace` in assurance notes (Codex) | `Assurance.describe` | One-pass substitution, regression test |
| Lifetime narrowed before comparison (Codex) | `GrantService.checkAgreedTerms` | Whole-integer comparison, regression test |
| Clearance stored but not enforced (Codex) | `PolicyService` | Refused until E2 |
| Parent generation across child admission (Codex) | `Commitment.writeIntroduced` | Revocation count pinned |
| Double revocation in a block (Codex) | `OwnerController` | Each handle once |
| `make vectors` did not mount the AS modules (Codex) | `Makefile`, `vendor-upstream.sh` | Modules vendored and verified; vectors regenerate byte-identically |

## Not in Phase D, by plan

Organization verdicts, clearance evaluation, org blocks and administrator decisions (E2);
joint verdicts and the consequence comparison on a tally's verdict (E3); ID-JAG (E4);
owner routing and per-owner template namespacing (E1); `UMA_PEP_TOOLS` for a custom tool
surface (not exercised by any D gate; the lab surface is built in); owner CLI and
adapter (F).

## Final runs

Codex's independent fresh-stack rerun passed all 17 live gates on the
final production sources. The updated operator smoke passed separately
on that stack. The final PostgreSQL store suite passed 114 tests with none
skipped and full Maven verification passed 244 with none skipped. See
[the independent sign-off](PHASE-D-CODEX-VERIFICATION.md#sign-off).

### Repository runs

Both aggregate runs used Compose project `claude-phase-d` (edge 34443, DNS 35553) with
fixture project `claude-phase-d-fixture`, and each started from `make reset`:

1. **Run 1**, on images built before the last fixes (parent generation, single
   revocation per handle): exit 0, all 17 gates.
   [`claude-check-live-run1.txt`](phase-d-evidence/claude-check-live-run1.txt)
2. **Run 2**, on every image rebuilt from the final sources (`make up`), with the new
   `smoke-alice` probe of Alice's operator: exit 0, all 17 gates, below.
   [`claude-check-live-run2.txt`](phase-d-evidence/claude-check-live-run2.txt)

| Gate | Run 2 result |
| --- | --- |
| `shim-test` | 8 passed |
| `ts-agent-check` | 11 passed |
| `decline-check` | 4 passed |
| `demo-acts-a` | tier1, tier2, tier3, revocation (pseudonymous): all four PASS |
| `demo-acts-b` | the same four acts as an identified agent: all four PASS |
| `flow-check` | PASS: agent identity stayed on the requesting side |
| `embedded-check` | `check=0 switch=0 restore=0` |
| `smoke-alice` | every probe OK, including `alice operator CIMD: OK` |
| `fixture` | PASS |
| `rotation-check` | before 2/2, after 5/5, PASS; restore verified (memory store, `uma-as-1`, nothing retired) |
| `store-test` | 114 tests, 0 skipped, PostgreSQL 17.12 |
| `intent-check` | 42 passed, 0 failed |
| `assurance-check` | 26 passed, 0 failed |
| `consequence-check` | 22 passed, 0 failed |
| `first-party-check` | 14 passed, 0 failed |
| `subagent-check` | 22 passed, 0 failed |
| `demo-all-sim` (`make demo-all SIM=1`) | PASS: the requested acts completed (tier 3 restored to its shipped rules after Act 4) |

The first individual run of each D gate, before the aggregates, is in
[`phase-d-evidence/`](phase-d-evidence/) as `claude-<gate>-try1.txt`. Unit and PostgreSQL
runs: [`claude-check-unit.txt`](phase-d-evidence/claude-check-unit.txt),
[`claude-store-test.txt`](phase-d-evidence/claude-store-test.txt).

## Blocking failures

None.
