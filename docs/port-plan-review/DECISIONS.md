# Port plan decisions

**Status** · Review complete. Both reviewers signed off on the same plan revision. Phase A implementation awaits the user's direction.

| Finding | Resolution | Plan location |
| --- | --- | --- |
| CX-1 | Establishment moves to E1. Consequence stays in D and clearance is delivered with organization support in E2. B uses thumbprint or issuer-qualified handles. XAA and ID-JAG get their own gate in E4. | A, B, D, E |
| CX-2 | C precedes D. Use an owner-scoped store with composite keys and atomic consumption. Test two AS instances against one database. Keep upstream's count-before-admission semantics for assurance. | C, D |
| CX-3 | Pin SDK 2.2.0 for the spike. Verify both shim transports and both enforcement paths. Record the SDK or fallback choice and evidence here during A. | A |
| CX-4 | Run the pinned scripts against Python and Java. Use `UMA4A_REPO` to put the Java exec stub in a separate runtime tree. Match timing inputs and serialize checks that mutate shared state. | Completion rules |
| CX-5 | Use the TypeScript check and separate decline assertion in A. Use the standalone fixture in B with local-key auth and TLS. Run full smoke in E4, once Carol and ID-JAG both exist. Use the spec register to map unit coverage and generate pinned vectors. | Completion rules, A, B, E |
| CX-6 | Use upstream DDL and plain JDBC, keep the memory default, and reset isolated durable test state explicitly. Gate AS rotation. Preserve clear refusal of obsolete schemas. Python↔Java database interchange and additional PEP signing-key rotation are outside this release scope. | C |
| CX-7 | Reuse the pinned Python demo. Keep a small Java client example. Ship Compose at `7764928`. Kubernetes, devcontainer, and a head refresh have separate scope. | Deliverable, Scope |
| CX-8 | Budget 19–26 sessions, with 4–5 for A and re-estimates after the A and C spikes and E2. Give joint and XAA independent gates. | E, Schedule |
| CL-1 | Reconcile the early Java cherry-picks with the pin before the protocol work. | A |
| CL-2 | Add Maven verification CI and phase-aware Make gates in A. Compose remains a local release gate. | Completion rules |
| CL-3 | Match CPython clearance bytes and add vectors distinguishing them from RFC 8785. The review records the discrepancy for any separately authorized upstream report. | Completion rules |
| CL-4 | Vendor scripts, Python support, and the TypeScript client under `conformance/upstream/` with a verified blob manifest. | Completion rules |
| CL-5 | Update Alice's realm and owner client configuration in A. Exercise the pinned pre-provisioned embedded path and deliver signed admission for unprovisioned resources in E1. | A, E1 |

## Sign-off

- Plan revision (SHA-256) `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f`.
- Codex signed off on this revision on 2026-11-19.
- Claude signed off on revision `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f` on 2026-11-19.
