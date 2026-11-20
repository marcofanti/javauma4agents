# Phase A transport and harness spike

Decision note required by the plan's Phase A first deliverable and by CX-3. It records which
boundary uses MCP Java SDK 2.2.0, which one is hand-rolled, and the evidence. Gate results
are in [PHASE-A-GATES.md](PHASE-A-GATES.md).

## Decision

| Boundary | Choice | Why |
| --- | --- | --- |
| Vault, 2026-07-28 (agents, gateway) | SDK 2.2.0 `modern` server: `McpServer` + `HttpServletMcpTransport` | Answers `server/discover`, is stateless, and validates `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` itself. |
| Vault, legacy (`initialize` + session) | SDK 2.2.0 `HttpServletStreamableServerTransportProvider` | The modern server rejects `initialize` ("this server does not support the initialize handshake"). The portal's client still uses it, as the pinned Python portal does. |
| Choosing between them | `McpDispatchServlet`, about 40 lines | One `/mcp` endpoint, routed by `MCP-Protocol-Version` (2026-07-28 or later goes to the modern transport). Both transports share `VaultTools`. |
| Embedded enforcement | Servlet filter ahead of both transports (`EmbeddedEnforcementFilter`) | It reads the exact request bytes once and decides with the shared `uma4a-pep` core before any tool can run. It renders the -32001 and -32002 JSON-RPC errors itself, and applies the Origin rule to POST, GET and DELETE. |
| Extension advertisement | A `McpFeature` with no methods whose `capabilities()` adds `dev.uma4agents/uma-enforcement` | The SDK merges feature capabilities into the `server/discover` result. |
| Gateway enforcement | `uma-pep` ext_authz host on the same core | It is not MCP-transport code. |
| Shim, stdio | SDK 2.2.0 legacy `StdioServerTransportProvider` | The pinned `test_shim.py` drives it with Python `mcp` 2.3.0 `ClientSession.initialize()`, which negotiates 2025-11-25 over stdio. Elicitation needs the session. |
| Shim, streamable HTTP | Hand-rolled stateless JSON-RPC on the JDK HTTP server (`ShimHttp`) | It is stateless with no session to elicit on, so terms fall to standing config and pends are handed back. The SDK's servlet transports would need a servlet container in a plain-jar client, which adds a dependency for about 150 lines of protocol. |
| Shim upstream client | Hand-rolled (`Upstream`) | The body must be serialized once and signed over those exact bytes, with a Content-Digest. The SDK client serializes internally. |

None of these needs a transport fork.

## Evidence

- **SDK release.** MCP Java SDK 2.2.0 is in Maven Central (published 2026-11-13).
  - `ProtocolVersions` in the legacy package ends at 2025-11-25.
  - The `modern` package carries `DiscoverResult`, `HttpServletMcpTransport` and the routing-header validation strings ("Mcp-Method header does not match request method").
- **What agentgateway v1.4.0 sends the vault.** Captured with tcpdump against the pinned Python reference stack, `--act tier1`:
  - `server/discover` followed by `tools/call`;
  - headers `mcp-protocol-version: 2026-07-28`, `mcp-method` and `mcp-name`;
  - per-request `_meta`;
  - no session id.
- **Local probes of the Java vault, gateway mode.**
  - `server/discover` returns `supportedVersions:["2026-07-28"]`.
  - A sessionless `tools/call` returns the fixture result.
  - A legacy `initialize` at 2025-03-26 returns `Mcp-Session-Id` and protocol 2025-03-26.
- **Local probes of the Java vault, embedded mode.**
  - `server/discover` advertises `dev.uma4agents/uma-enforcement` with `jsonrpc_error_code: -32001`.
  - With no AS reachable, a `tools/call` returns -32002 `temporarily_unavailable` with status 503.
  - Missing routing headers return -32002 `missing_routing_headers` with status 400.
  - `Origin: https://evil.example` gets 403 `{"error":"invalid_origin"}` on both POST and GET.
  - The signed metadata names `https://gateway.uma.lab/mcp`.
- **Python reference control** (completion rule 2) at upstream `7764928`, run on 2026-11-19. All eight passed:
  - `shim-test`, `ts-agent-check`, `embedded-check`;
  - driver acts `tier1`, `tier2`, `tier3` and `revocation` with `--pseudonymous --simulate-alice`;
  - full `smoke-test`.

## Reconciliation of the early cherry-picks (plan item 0)

| Behaviour | Java baseline | Pinned form | Phase A change |
| --- | --- | --- | --- |
| Waiting ticket | Spent and rotated on every poll | Peeked; the same ticket returned while undecided | `AsState.peekTicket`; `TokenController` returns the same ticket |
| Owner decision | Overwrites | Compare-and-set; a second decision gets 404 | `OwnerController.decision` |
| `PENDING_TTL` | 600, hard-coded | `UMA_AS_PENDING_TTL`, default 3600 | `AsConfig` |
| `revoked` reason | Missing: a re-admitted agent revived old reusable RPTs | A consumed reusable grant introspects as `revoked` | `ProtectionController.decodeRpt` |
| PEP inactive-reason map | Only `connection_revoked` is terminal | `RENEGOTIABLE` set; unknown reasons are terminal; `introspection_unavailable` gives 503 | `Enforcer.notLive` |
| Consume transport failure | 403 `already_consumed` | 503 `temporarily_unavailable` | `Enforcer.spendOnce` |
| Single-use trigger | Tool list only | Tool list or `info.single_use`; `operation_required` | `Enforcer.spendOnce` |
| `params_s256` | `json.dumps(sort_keys)` with default separators, ASCII | Compact, sorted, `ensure_ascii=False` | `PyJson.compactSortedUnicode`, with pinned CPython vectors |
| Deny-by-default | No `server/discover`, Origin, header/body or routing-header rules | All four, in the pinned order | `Enforcer.requestShape` |
| Agreement URNs | `urn:uma4agents:*` | `https://u4a.ai/spec/terms/1.0#…` | `AsConfig`, `GrantClient` |
| RPT | `typ aa-auth+jwt`; `sub` a constant; 3600 s cap | `typ at+jwt`; `sub` and `client_id` the handle; `owner`, `iat`; tier and agreement lifetime; scope intersection | `GrantService.issueRpt` |
| RFC 9421 verifier | Exact four components; parameters rebuilt | Superset of components; parameters echoed; `nonce`, `tag`, `expires`, `signature-agent`, `content-digest` | `HttpSignature`, with pinned CPython vectors |
| Revoke route | `/owner/connections/{handle}/revoke` | `POST /owner/connections/revoke` with `{"handle"}` | `OwnerController` |
| Push registration | `/rreg` and `REGISTRATION_MODE` | Removed; pull only | `ProtectionController`, `AsConfig`, `RegistrationPuller` |

## Deferred, by plan phase

- **Phase B:** identified-agent token renewal in the shim (`renew_identity`) and the `Ed25519` JWS alg.
- **Phase D:** tier rules and assurance (pinned tier 1 asks under low accountability; tier 2 asks on first contact at a tier). The A driver acts run with `--simulate-alice`, so a pend is approved either way.
- **Phase E:** consequence in `authorization_details` and discovery, organization and joint `Enforcer` branches, signed resource-server introduction (`/rs/register`, `/owner/resource-servers/decision`), ID-JAG.
- **AS metadata:** `uma_profiles_supported` lists only the profiles implemented now (core, terms, fedauthz). The rest are added with the phases that implement them.
