# Independent Phase E1 controls

The reference is `77649287dc883b75ef563c59f96de8613ecf10d0`. This
preparatory run used the pinned Python stack while the Java worktree
was still in Phase D.

The full pinned default Compose topology started in an isolated
project without publishing host ports. All 25 services ran and every
defined health check became healthy. One Docker memory sample after
startup totaled 2.35 GiB across the containers. This is a reference
measurement for the planned Compose smoke.

| Gate | Pinned checker blob | Reference result |
| --- | --- | --- |
| `establishment-check` | `da6ae7e43af38b348443dac3dd8f0961c28cd15c` | 15/15, including signed introduction, withdrawal and owner reapproval |
| `multi-owner-check` | `b5b84a0839a8b37178419b3deae65eae06a819f3` | 20/20, including distinct authorities and signing keys, owner terms and grants, and separate negotiation records |

The two gates ran in that order on the same fresh reference topology.
[Reference output](phase-e1-evidence/codex-python-controls.txt).

## Java sign-off

Both Java runs passed all 19 live gates. The final run rebuilt the services
under project `codex-e1-final` with isolated ports and a fresh set of volumes.
`establishment-check` passed 15/15 and `multi-owner-check` passed 20/20 from
the unchanged pinned checkers. The store gate passed 116 tests with no skips on
PostgreSQL 17.12. Full Maven verification with PostgreSQL required passed 248
tests with none skipped. All 47 vendored blobs matched the pin.

| Requirement | Implementation and verification |
| --- | --- |
| Separate owner deployments | The same Java AS, vault and portal images serve Alice and Carol. Carol's pinned Keycloak realm and holdings fixture are byte-identical to upstream. The live checker verified separate grants, policies, keys, holdings and ledger entries. |
| Gateway owner routing | `PepConfig`, `CheckController` and `DiscoveryController` select one authority, resource namespace, PAT and signature-verification keyset per route. |
| Signed introduction and reapproval | `ResourceServerRegistration`, `ResourceServerSignatures` and `ProtectionClient` verify the pinned RFC 9421 profile and exercise the whole lifecycle over HTTPS. |
| Approval and revocation | Memory and JDBC implement the same state transitions. Carol's portal signed in through her realm and reached the authenticated decision API. |
| Ticket and policy isolation | The new regression covers owner marks on minted and rotated tickets, wrong-owner and malformed markers, and tickets created before this phase. |

The Java store keeps the resource URI of a pending registration until the owner
decides. A concurrent registration cannot overwrite what the owner is being
asked to approve. The pin updates a pending record on a repeat introduction.
The Java AS also retains its prior 2 MiB servlet form size limit when reading
the raw signed body.

The separate HTTPS verification exercised a Carol vault in embedded mode with
no shared secret. The vault introduced itself while blocking access and issued
a Carol-scoped ticket after approval. The gateway deployment's main Carol route
continues to use gateway enforcement.

[First Java run](phase-e1-evidence/codex-java-first-aggregate.txt).
[Final Java run](phase-e1-evidence/codex-java-final.txt).
[Portal and embedded checks](phase-e1-evidence/codex-java-supplemental.txt).
