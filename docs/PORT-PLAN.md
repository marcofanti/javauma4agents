# Full re-port plan

**Status** · Implementation plan, with reviewer sign-off recorded in the decision log  
**Upstream** · nickgamb/uma4agents `77649287dc883b75ef563c59f96de8613ecf10d0`  
**Java baseline** · `966e1db`, tracking upstream `f6e6068` plus the early single-use grant fixes  
**Review record** · [Decisions and sign-off](port-plan-review/DECISIONS.md)

## Deliverable

Produce a wire-compatible Java/Spring Boot twin of the pinned UMA 2.0 lab. The pinned Python checks and TypeScript agent must run against the relevant Java processes with unchanged check source and client code. Preserve public hostnames and paths, ports, configuration variables and defaults, status codes, JSON and JWT fields, and the two RFC 9421 profiles. Preserve the operation ordering and owner boundaries that the check suite and the implementation tests specify.

The supported release at completion is the pin above. Any later upstream refresh has its own scope and estimate.

## Scope

- Port the AS and PEP, shared authorization and agent libraries, vault and embedded enforcement, agent shim, operator service, portal backends, org authority and console backend, joint tally, and XAA broker. Use the same Java AS, vault, portal and operator images for the additional owner instances where upstream does. Reuse upstream SPA assets. Port the owner CLI in F.
- Use the upstream Python demo driver and helper library as independent clients. The driver is 529 lines at the pin. The directory also contains check programs and helper clients. Keep the existing Java demo only where it provides an example of the Java client library, outside the compatibility gates.
- Reuse pinned Keycloak realms, gateway and Envoy configuration, DNS and CA setup, fixture data, observability configuration, OPA policy, the AAuth person server, and the Postgres image. Match the relevant Compose service contracts and activate the corresponding configuration with each phase. Use gateway `v1.4.0`. Record the person-server pin used by both stacks and verify its behavior against upstream's `4e05247`. OPA's unchanged `rego-test` runs in E2. Keep Python client dependencies and container images reproducible across the reference and Java runs.
- Reuse the Kwaai abilities and n8n workflow and checker. The site, draft sources, Kubernetes deployment, devcontainer, and live external-tenant trials sit outside Compose release scope. Use upstream's [conformance register](https://github.com/nickgamb/uma4agents/blob/7764928/spec/conformance.yaml) as the coverage index.

## Completion rules

1. Vendor the checker scripts, the Python support library, and the TypeScript client under `conformance/upstream/`. Verify raw blobs against an upstream path/hash manifest with a Make target. Keep Java adaptations in the launcher or Compose wiring. Point `UMA4A_REPO` to a separate runtime tree with the pinned Python support and CA bundle. In that tree, the fixed `clients/agent-shim/shim.py` path is a thin launcher that execs Java. Verify the process under test. Move Python-based service probes and rotation key generation to the orchestration or a helper container. Preserve check inputs, exit codes, and restore behavior.
2. Establish runnable Python control results by the phase that uses each check. Run the Java gates against explicitly identified Java services, with isolated Compose projects and known seed state, key volumes, and CA bundles. Match TTL configuration on both sides of timing checks. Run policy mutations and service recreates serially. Record reference failures and resolve the cause before treating a Java run as evidence.
3. Each phase must pass `mvn verify`, its wire gates, and applicable earlier gates. Add a Maven verification workflow in A and Make targets for `check-unit`, `check-live`, and `check-all` that grow with the phases. Run Compose checks locally for phase sign-off. Port relevant Python implementation assertions into Java tests, with mandatory real-Postgres integration tests from C. For new signatures and hashes, commit reproducible CPython-generated vectors under `lib/uma4a-common/src/test/resources` and verify them in Java. For the clearance digest in E2, include vectors that distinguish the pinned compact sorted CPython serialization from RFC 8785, including numeric formatting and ordering of supplementary Unicode keys.
4. Phase-specific documentation and runnable gate commands land with the phase. A candidate feature that needs later services gets its end-to-end gate when those services exist, and targeted tests when its code lands. Keep all Java/HTTP compatibility evidence inspectable in the phase PR.

## Phase A · MCP transport and enforcement

**First deliverable** · A transport and harness spike before the shared PEP refactor. Compile MCP Java SDK 2.2.0 against this Spring Boot setup. Through the real Servlet paths, verify that a protected call is authorized before any tool side effect, using the exact received bytes and configured public target. Verify `server/discover` and the embedded extension advertisement, custom JSON-RPC challenge and denial with their status and data, Origin checks on all MCP requests, routing-header validation, and trace context. Check the gateway denial and remediation envelope separately. Capture the actual Python SDK handshake on shim stdio and HTTP, and prove that pend can hand back and resume. If these contracts need a transport fork or an invasive workaround, implement the affected transport in a thin Java adapter and reuse the enforcement core and tool code. Record the SDK/fallback choice and evidence in a short note in the [review folder](port-plan-review/README.md) and link it in the Phase A PR.

0. Reconcile the early cherry-picked behavior against the pin, including family-keyed negotiations, introspection reasons, burn-last and pending semantics. Copy the pinned Alice realm and update owner client configuration to `meridian-portal` before running the A controls.
1. Move lab-facing MCP resource and client paths to `2026-07-28` discovery, per-request metadata, routing headers, and sessionless operation. Preserve the shim-facing handshake and behavior exercised by the pinned stdio and HTTP clients. Remove superseded paths where the pin removed them. Extend the existing Java client plumbing for the lab.
2. Extract one `uma4a-pep` enforcement core for agentgateway ext_authz and vault-embedded hosts. Keep the two wire envelopes, signed resource metadata and owner-resource listing, TLS and origin rules, and original request-body handling. Include structured remediation and trace propagation. Keep single-use consumption after validation and before execution. Add the organization and joint branches, with their tests, in E.
3. Remove legacy RReg push and repair. Keep pull as the resource-registration mode. Use the same pre-provisioned Alice resource server as pinned Compose for its gateway and embedded shapes. Assert the seeded registry entry has the expected active status and resource URI. Signed introduction and owner approval for unprovisioned resource servers land in E1.
4. Port non-blocking shim pending decisions and continuation state with the pinned timing configuration. Wire the HTTP shim and its readiness probe alongside stdio. Ship the Alice portal paths that exercise discovery and approval. Publish the requesting operator's CIMD document and Web Bot Auth directory.

**Gates** · Run the unchanged `embedded-check`, `shim-test`, and `ts-agent-check`. Run an Alice-only smoke check covering discovery, resource metadata, challenge, health, and trace events. Use the pinned Python driver for `tier1`, `tier2`, `tier3`, and `revocation` with `--pseudonymous --simulate-alice`. The spike exercises HTTP shim behavior and F runs the named `adapter-check` gate. Add a supplemental decline assertion outside the vendored TypeScript client because its decline path is conditional. The full upstream `smoke-test` needs Carol's topology and ID-JAG discovery, and `demo-all SIM=1` needs first-party behavior. Require both full gates later.

## Phase B · Agent identity

Port AAuth token-shape compatibility and identify agents by issuer-qualified subject. Pseudonymous, CIMD-described, and Web Bot Auth-published agents stay keyed by the signing-key thumbprint. Verify descriptive metadata and key publication without changing the handle or grant binding. Verify identified-agent enrollment and withdrawal against the pinned person server. Add ID-JAG acceptance with the XAA vertical slice in E. Add local-key owner authentication and standalone vault TLS for the minimal fixture, keeping OIDC and local-key authority and credential handling distinct.

**Gates** · Run `flow-check` for the four regimes and two handle levels, `fixture` for standalone local-key authorization, and the identified Python demo acts. Add focused coverage for AAuth token variants outside the flow.

## Phase C · Owner-scoped state and hardening

1. Introduce an owner-scoped store interface with memory and JDBC implementations before D. Use the pinned Postgres DDL through plain JDBC, including composite owner keys, and preserve the negotiation family's identity across ticket rotation. Preserve atomic ticket consumption, RPT consumption, decisions, seeding, and revocations, and owner-scoped event delivery. Bring in feature-specific operations with their callers in D and E.
2. Keep memory as the Compose default and keep restart-based `make reset` for the memory demo. For durable tests, reset by replacing the isolated test database or volume. AS restarts and recreates preserve durable grants and owner state. Match upstream's clear startup refusal of obsolete single-owner schemas. Database interchange between runtimes is outside release scope. It would require Python-to-Java and Java-to-Python handoff tests even with shared DDL.
3. Port AS signing-key rotation, retired verification keys, and refresh on the PEP when the AS pull-signing key changes. Audit #38, #41, and #43 against the cherry-picked baseline. Land shared fail-closed, re-enrollment, route/hostname, and registry/surface safeguards here. Land safeguards tied to organization or joint flows with those features.

**Gates** · Run `rotation-check` and exercise the same store properties on memory and real Postgres. From C on, use Postgres 17 and require `UMA_AS_TEST_DSN` for the integration gate. Exercise single-use, competing owner decisions, and owner event isolation using two AS instances on the same database. Check restart, reseeding, and stale-schema startup behavior. Port the AS and PEP assertions the live checks bypass.

## Phase D · Intent, assurance, consequence, and agent relationships

Implement intent declarations and the owner record with drift reads. Port the assurance axes, onboarding and attention-budget lanes, owner configuration, and visibility through the portal. Keep the pinned count-and-admit semantics for this release and document the limit under concurrent admission. Port consequence declarations from the provider through policy, RPT, introspection, and enforcement. Include first-party operator claims and the activation and delegation behavior exercised by the subagent check. Wire Alice's operator as a second instance of the same service.

**Gates** · `intent-check`, `assurance-check`, `consequence-check`, `first-party-check`, `subagent-check`, and the full pinned `make demo-all SIM=1`.

## Phase E · Ownership models and XAA

Run an early Compose resource and configuration smoke across the planned topology. Deliver and gate four slices in dependency order.

| Slice | Work | Gates |
| --- | --- | --- |
| E1 · Multi-owner and BYOAS | Carol's AS, portal and vault; owner routing, signed resource-server introduction and separate policy | `establishment-check`, `multi-owner-check` |
| E2 · Organization and clearance | Org authority and OPA, admin console, northwind identity and vault, member enrollment and charter, attested clearance, invalidation and owner boundaries | `org-check`, `clearance-check`, `rego-test` |
| E3 · Joint ownership | Joint tally and vault, holder verdicts, mandate binding and grant validation | `joint-check` |
| E4 · Cross App Access | XAA broker, enterprise ID-JAG acceptance, membership and resource audience boundaries, advertised claim format | `xaa-check`, full upstream `smoke-test` |

## Phase F · Integrations and release verification

Finish the portal surfaces and owner CLI. Wire the pinned Kwaai abilities and n8n workflow using the Java deployments, including operator naming for the adapter. Run `adapter-check`, `kwaai-check`, `paios-check`, the standalone n8n Compose sidecar conformance script, and the full staged Compose matrix. The Kubernetes n8n lab is outside this gate. Verify that the default and embedded enforcement labs, standalone fixture, owner surfaces, and runnable examples are documented. Update the README to cite the supported pin.

## Schedule

Budget **19–26 focused sessions** for Compose. Start with A at 4–5, B at 2–3, C at 3–4, D at 3–4, E at 5–7, and F at 2–3. Re-estimate after the A transport and harness spike, the C store spike, and E2. The main schedule risks are the SDK's transport/custom error seam, semantic and concurrency fidelity across memory and Postgres, and authority/cache behavior across the organization and joint flows. Keep risks tied to hard gates. The total assumes the pinned Python demo driver stays in use and excludes Kubernetes and an upstream head refresh.
