# Independent Phase D verification

The signed plan is `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f`.
The Python reference is `77649287dc883b75ef563c59f96de8613ecf10d0`.
The Java baseline is the independently verified Phase C worktree, preserved
before the branch switched to `phase-d-intent-assurance`.

## Wire gates

| Gate | Pinned script blob | What the client checks |
| --- | --- | --- |
| `intent-check` | `6d60361f` | Terms bounds, agent reason and mission kept as supplied, per-agent history, receipt and terms representations, rules that restrict on recorded behavior |
| `assurance-check` | `376e87f3` | Binding and accountability, per-tier onboarding, queue lanes, refusal past the owner budget, operator block and revocation |
| `consequence-check` | `4ae1e28b` | Signed publication and owner registry, policy conditions, owner decision, grant and enforcement |
| `first-party-check` | `5ab95e5f` | Alice operator activation and withdrawal, operator proof, treatment of Bob's agent, configurable relief from owner prompts |
| `subagent-check` | `088385b2` | Separate agent keys and grants, sponsorship and tier ceiling, approval propagation, and revocation of descendants |
| `demo-all SIM=1` | `90412ce9` | Full pinned Python driver, including first-party behavior |

The pinned Python Compose control publishes no host ports. Each gate gets
a restart-based policy reset and waits for `/health/registry` before
negotiation. The first abbreviated topology produced 503 errors because
the pinned PEP requires answers from its organization and tally services
before it publishes the owner registry. The rerun supplies both services
without changing client or server behavior.

The live clients read the owner APIs directly. Portal presentation and
escaping need a separate check. The attention cap retains the pinned
count-before-admission semantics. A sequential check does not establish
a hard upper bound across concurrent admissions.

The pinned `rules-test` passed 112 assertions and `introduction-test`
passed 24. The earlier pinned AS and PEP controls passed 89 and 62.
[Phase D unit output](phase-d-evidence/codex-python-unit-controls.txt).

The corrected topology passed `intent-check` with 42 assertions. The
remaining unchanged live controls are running in the same isolated
project. [Live control output](phase-d-evidence/codex-python-live-controls.txt).

The pinned controls also passed all 26 assurance and 22 consequence
assertions. That covers the attention lanes, limits on assurance rules,
and propagation of the resource's declared consequence.

For the new introduction JWS, the pinned signer minted a deterministic
vector using fixed synthetic keys and a fixed clock, and the pinned AS
validator accepted it. Its bare-key header fields are `alg`, `jwk`, `kid`
and `typ`. The claims carry `aud`, `exp`, `iat`, `jti` and `sub`.
The typical lifetime is 300 seconds. This vector is an independent
reference for the Java introduction verifier.
[Introduction oracle output](phase-d-evidence/codex-python-introduction-oracle.txt).

All six pinned live controls finished successfully. The five named
checks passed 42 intent, 26 assurance, 22 consequence, 14 first-party,
and 22 subagent assertions. The full simulated driver completed all
four acts. [Final Python control results](phase-d-evidence/codex-python-final-controls.txt).

A separate Python policy oracle covers 13 decision and reason cases
and all 24 editor vocabulary entries. It captures strict numeric
thresholds, no-lineage defaults for older records, Python whitespace
handling, and the fail-closed decision for a condition already stored
but no longer understood. [Policy oracle output](phase-d-evidence/codex-python-policy-oracle.txt).

## Java verification in progress

The Java consequence classifier matched the pinned Python results for
525 cases, covering normalization, ordering, single-use, and MCP
annotation precedence. CPython 3.12.12 confirmed the reference results.
The Java whitespace helper matched Python over every Unicode code point,
and strip removed only the leading and trailing occurrences of the 29
whitespace characters. These checks cover the shared components ahead of
the wire-level consequence and intent gates.
[Java differential output](phase-d-evidence/codex-java-common-oracles.txt).

The Java rule evaluator matched all 13 pinned decision-and-reason
cases. Its full ordered editor vocabulary matched all 24 entries
field for field. The test ran in a scratch Maven snapshot and compares
the Java implementation directly to the Python oracle, including the
absence of a reason when it contains only Unicode whitespace.
[Java policy comparison](phase-d-evidence/codex-java-policy-oracle.txt).

The rule-save validator matched all 205 CPython acceptance and refusal
results, including the exact refusal messages for malformed rule arguments.
The assurance comparison matched all three computed axes across 189
identities. It exposed one difference in the owner-facing descriptions.
A literal `{issuer}` in the operator's display name was expanded by Java,
where the pinned renderer preserved it. The finding and the stale
test-fixture constructor were sent to the implementation owner.
[Validation and assurance output](phase-d-evidence/codex-java-validation-and-assurance.txt).

The assurance renderer now preserves literal placeholders in operator
names, and all 189 cases passed for scores and descriptions. The Java
introduction verifier accepted the deterministic JWS minted by pinned
Python and matched its result. It refused the same fixture for another
child, another authority, and at expiry. Maven passed all five scratch
tests across those comparisons and the two policy oracles.
[Java introduction and assurance output](phase-d-evidence/codex-java-introduction-and-assurance.txt).

A separate scope finding remains under review. The new tier validator
accepts nonempty clearance requirements while their enforcement belongs
to E2. Phase D must refuse those settings or keep the facility disabled
so an owner cannot save a requirement that the authority ignores.

The clearance guard passed separate tests. Tier creation and edits
refuse nonempty clearance before E2, and empty clearance keeps the
pinned neutral response shape. For supported fields, Java matched
19 pinned tier creation and edit cases, including resource ownership,
Unicode tier IDs, unsupported rules, and terms version bumps.
[Tier write comparison](phase-d-evidence/codex-java-tier-writes.txt).

Java matched 25 pinned requester-claim results for reason and mission
validation. The comparison covered the UTF-8 byte cap, supplementary
characters in mission citations, preserved reason text, and removal of
mission fields outside the citation. A separate source review found that
the terms expiry check narrows arbitrary integers before comparing them
to the dictated limit. I asked the implementation owner to compare the
full value before narrowing so the check cannot overflow.
[Requester-claim comparison](phase-d-evidence/codex-java-requester-claims.txt).

The partial Java integration passed `make check-unit` in scratch.
It verified 40 vendored blobs and ran 170 tests, including the scratch
comparisons. The 52 PostgreSQL cases were skipped on this optional
unit run. The required database and wire reruns remain part of sign-off.
[Midpoint unit output](phase-d-evidence/codex-java-midpoint-unit.txt).

The expiry fix now compares full integers. The independent boundary
suite passed three tests covering the exact dictated limit, durations
above the limit including values wider than a Java long, and refusal
of nonpositive, boolean and fractional inputs.
[Expiry boundary output](phase-d-evidence/codex-java-expiry-boundary.txt).

The new standing operations passed independent tests on memory and
PostgreSQL 17.12. A child contributed only tiers actually approved by
the owner and stopped contributing after revocation. Operator claims
and blocks kept the first timestamp, and the trajectory filtered by
owner, handle and timestamp. The scratch gate required a real database
and skipped no tests.
[Standing store output](phase-d-evidence/codex-java-standing-store.txt).

The first independent live Java probe passed on a partial Phase D snapshot.
It verified the resource metadata signature before comparing the declared
consequence classes with the AS's pulled registry. Signed owner requests
could claim and disclaim an operator. The policy API returned 400 for a rule
that would relax on consequence and for an unsupported clearance setting.
The snapshot needed one scratch-only compile substitution in
`DiscoveryController`: invoking the public `PyJson.compactOrdered` formatter
for a rounded number to avoid calling a package-private helper.
[Live owner and resource output](phase-d-evidence/codex-java-owner-wire.txt).

The lineage generation fix passed an independent two-case test through
the signed agreement commitment path. An unchanged sponsor permitted
the introduction. Simulating owner revocation and readmission at the
store boundary caused the older decision to be refused and its child
record to be revoked. The test used verified directory facts supplied
by a test double. The upstream subagent checker separately exercises
the real operator directory.
[Lineage generation output](phase-d-evidence/codex-java-lineage-generation.txt).

The first independent Java `make -j8 check-all` exited 0 on a fresh
stack. All 17 gates passed, including 92 mandatory PostgreSQL store
tests, 126 assertions across the Phase D checkers, and the full simulated
demo. The final rerun includes the subsequent lineage and operator
revocation fixes.

A separate live HTTP probe on the updated portal passed. The Java portal
served the pinned login page, JavaScript and CSS byte for byte. Alice's
Keycloak sign-in reached the byte-identical pinned portal page, and the
authenticated session could read policy, resource, vocabulary and
operator data through the Java proxy.
[Aggregate and portal output](phase-d-evidence/codex-java-first-aggregate.txt).

The repository's new Phase D vector generator produced byte-identical
outputs in two independent CPython 3.12.12 runs with the pinned
reference modules supplied directly. The three earlier vector files
remained byte-identical. The new output includes 11 introduction
verification cases and 1,242 policy decisions. The repository target
and its Java consumers still need the final integration run.
[Vector generation output](phase-d-evidence/codex-python-repository-vector-generation.txt).

The repository's own `make vectors` reproduced all four files byte
for byte, and `make vendor-verify` verified 47 blobs. On that exact
source snapshot, a full `mvn verify -Duma.store.requirePostgres=true`
passed 244 tests against PostgreSQL 17.12 with zero skips, including
all ten Java Phase D vector tests.
[Final Maven and vector output](phase-d-evidence/codex-java-final-maven-vectors.txt).

## Sign-off

The second independent fresh-stack run passed all 17 live gates on the
final production Java and Compose sources. It included the lineage and
operator revocation fixes. I ran the updated smoke target against the
same stack and confirmed it reached Alice's own operator. The latest
store suite ran separately against PostgreSQL 17.12 and passed all 114
tests with none skipped. Combined with the pinned Python controls and
the final Maven and vector results above, this satisfies Phase D's exit
criteria at upstream `7764928`.
[Final live output](phase-d-evidence/codex-java-final-live.txt).
