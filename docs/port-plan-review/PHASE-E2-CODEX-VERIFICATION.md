# Independent Phase E2 controls

The reference is `77649287dc883b75ef563c59f96de8613ecf10d0`. The
unchanged checks ran serially against the full pinned Python Compose
topology in an isolated project. The project was stopped after the run.

| Gate | Pinned input blob | Reference result |
| --- | --- | --- |
| `org-check` | `f6e96702028cc13b5fdc6b7f5d730f4f638488fa` | 104/104 on membership, charter ceilings, sharing, policy withdrawal, and owner boundaries |
| `clearance-check` | `56f3949f93d1973a862805eeb1cd0f591a0b0951` | 20/20 on attestation, requirements, and enforcement |
| `rego-test` | `1899b3e42356ff5b994d48826fec74af26e77298` | All shared pattern vectors matched through OPA 1.4.2 |

These results establish the reference side for E2. Java implementation
and verification follow the Phase D and E1 sign-offs.
[Reference output](phase-e2-evidence/codex-python-controls.txt).

## Java implementation and gate results

- `org-check` passed 104/104 against the Java organization authority, the
  pinned OPA module and both Java owner authorities. The live check exercised
  role-derived sharing, charter writes and custom Rego, independent owner
  policy, delegated administration, revocation and break-glass notices.
- `clearance-check` passed 20/20. It exercised invalid policy at write time,
  refusal before terms, attestation fetched with the membership credential,
  a digest in the issued RPT, private facts in the owner's ledger and refusal
  after withdrawal and expiry of the configured cache.
- `rego-test` passed all 14 shared pattern vectors on OPA 1.4.2. Maven
  ran the same pinned vectors against Java. The clearance vectors distinguish
  CPython's number encoding and supplementary Unicode key order from RFC 8785.
- The organization console served the pinned assets and completed an OIDC
  sign-in with Dana's Northwind realm. Its authenticated proxy reached the
  admin-only organization API.
- Full Maven verification against PostgreSQL 17.12 passed all 254 tests.
  The memory and JDBC contracts check that a stale credential cannot update
  or erase a new enrolment, and scoped blocks survive unrelated envelope writes.

The first aggregate exposed a race in the earlier embedded gate. Its
restoration waited for the internal gateway, and Envoy could still have a
stale upstream connection when the smoke probe arrived. The restore now
probes the actual TLS route through Envoy before returning.

The organization authority keeps its lab charter history and roster in
memory, like the pin. Each member's AS holds her membership and scoped blocks
in the owner store. Java retains the owner's narrowed terms on leaving.
The E4 gate covers federation and enterprise assertions separately.

[Java feature gates and console probe](phase-e2-evidence/codex-java-feature-gates.txt).
[Java Maven verification and Compose health](phase-e2-evidence/codex-java-unit-and-topology.txt).

## Final sign-off

The isolated stack rebuilt from the final sources passed all 22 serial gates
on a clean reset, including the previous A–E1 gates, 118 store tests on
PostgreSQL, organization 104/104, clearance 20/20 and the pinned Rego vectors.
The embedded gate verified restoration through the edge before smoke ran.

[Final clean aggregate](phase-e2-evidence/codex-java-final-aggregate.txt).
