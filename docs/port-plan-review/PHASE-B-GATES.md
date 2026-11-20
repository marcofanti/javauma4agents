# Phase B gate results

Phase B of [the port plan](../PORT-PLAN.md): agent identity, local-key owner
authentication, and the standalone fixture. The live gates were run by Codex as the
independent verifier; its record is
[PHASE-B-CODEX-VERIFICATION.md](PHASE-B-CODEX-VERIFICATION.md), with command output in
[`phase-b-evidence/`](phase-b-evidence/). This file records the inputs, how each plan
requirement maps to a gate and to source, and the unit-level evidence. The work is
uncommitted on `phase-b-agent-identity`, on top of the verified Phase A worktree.

## Inputs

| Input | Value |
| --- | --- |
| Plan revision (SHA-256) | `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f` |
| Upstream | nickgamb/uma4agents `77649287dc883b75ef563c59f96de8613ecf10d0` |
| Person server, Python control | `christian-posta/aauth-person-server` `4e05247` (upstream's pin) |
| Person server, Java stack | `18d9558`, which is `4e05247` plus the LICENSE file and nothing else |
| Person-server dependencies | The pinned source's `uv.lock` (SHA-256 `649e0c3f…bb90a`), exported by `uv==0.9.5` and installed with `--require-hashes`: `aauth==0.3.2`, `aauth-signing==0.1.2` |
| Vendored checks (git blob) | `flow_check.py` `9f9749aa`, `fixture_check.py` `347fbadc`, `driver.py` `90412ce9`, `uma4a_aauth.py` `fbd00aae`, `uma4a_enroll.py` `fac7b708`, `uma4a_grant.py` `6c7a170e`; all 39 checked by `make vendor-verify` |
| Python clients | `python:3.12.12-slim`; `httpx==0.28.1`, `pyjwt[crypto]==2.15.1`, `cryptography==50.0.2`, `aauth==0.3.2`, `aauth-signing==0.1.3` (the version upstream's `aauth-test` and driver install) |
| Fixture | [`compose.fixture.yml`](../../compose.fixture.yml), derived from upstream blob `8944cde3`: the Java `uma-as` and vault images, pinned client versions, vendored check, curl health checks |
| CPython vectors | `lib/uma4a-common/src/test/resources/pinned/aauth-vectors.json` (SHA-256 `2327d7d9…6f9f`), from `make vectors` with `aauth==0.3.2`, `aauth-signing==0.1.3`, `pyjwt==2.15.1` |
| Owner key | `certs/owner-ed25519.{pem,pub}` from [`scripts/owner-key.sh`](../../scripts/owner-key.sh), run by `make up` and `make init` |

## Gates

| Plan gate | Java command | Pinned source | Python control | Java |
| --- | --- | --- | --- | --- |
| `flow-check`: four regimes, two handle levels | `make flow-check` | `flow_check.py` | Pass: four regimes, two levels, withdrawal | Pass |
| `fixture`: standalone local-key authorization | `make fixture` | `fixture_check.py` | Pass | Pass |
| Identified Python demo acts | `make demo-acts-b` (`tier1`, `tier2`, `tier3`, `revocation`, `--simulate-alice`, no `--pseudonymous`) | `driver.py` | Pass, all four | Pass, all four |
| Focused AAuth token variants | `make token-test` | `lib/test_aauth.py` (ported), CPython vectors | `make aauth-test`: 43 assertions | Pass |
| `mvn verify`, zero warnings | `make check-unit` | | n/a | Pass: 67 tests, 39 blobs |
| Phase A regressions | `make check-live` (also runs the gates above) | | n/a | Pass: shim 8/8, TypeScript 11/11, decline 4/4, four pseudonymous acts, embedded `check=0 switch=0 restore=0`, Alice smoke |

The Java aggregate was `make -j8 check-live FIXTURE_PROJECT=codex-phase-b-java-fixture`,
exit 0, on Compose project `codex-phase-b-java` with the edge on host port 14443. It ran
nine gates one at a time: `shim-test ts-agent-check decline-check demo-acts-a demo-acts-b
flow-check embedded-check smoke-alice fixture`. Output:
[`codex-java-gates.txt`](phase-b-evidence/codex-java-gates.txt). Python controls:
[`codex-python-controls.txt`](phase-b-evidence/codex-python-controls.txt).

After the last client and bootstrap changes, Codex recorded these final results in the
same output file:

- The latest `make check-unit` passed 67 tests, and `make token-test` passed.
- A wire probe compared each grant's subject and `cnf` key with the requesting identity
  on Java, for all four regimes. The three key-level regimes kept their thumbprint and
  key binding. The identified agent kept one issuer-qualified handle across two
  enrolled session keys, each grant bound to its own key.
- After a rebuild, the stdio shim passed 8/8 and the HTTP spike (`make shim-spike`) 7/7.
- Over the main stack's TLS, the AS accepted the new local-key signer and an OIDC token
  independently, and refused unsigned requests.
- The owner-key repair passed scratch fault and ordering tests.

### Running them

```bash
export COMPOSE_PROJECT_NAME=<project> UMA4A_EDGE_PORT=<port> UMA4A_DNS_PORT=<port>
make up && make reset
make -j8 check-live FIXTURE_PROJECT=<fixture-project>
make check-unit
```

`check-live` runs one gate at a time whatever `-j` is passed, and stops at the first
failure. The pinned driver approves the first pending item by design, so start from
`make reset`. The fixture runs in its own project and publishes no ports. The main
stack's edge and DNS host ports follow `UMA4A_EDGE_PORT` and `UMA4A_DNS_PORT`, and the
smoke probes use `curl --connect-to` so they follow the edge port.

## Requirements and where they are met

| Plan requirement | Source | Unit evidence |
| --- | --- | --- |
| AAuth token-shape compatibility: current `Ed25519` and earlier `EdDSA` shapes, the named-issuer list, discovery, `kid` and key-algorithm rules, subject and `parent_agent` rules, fetch floors | `lib/uma4a-common/.../AgentTokens.java`, `Jose.java`, `PyJwtClaims.java`, `PyRepr.java`; AS `TokenVerifiers.verifyAgentToken`, `PeerFetch` (https, no redirects, 5 s, 256 KiB); `UMA_AS_AGENT_ISSUERS` | `AgentTokensTest` (6): Java reaches the pinned module's verdict on all 34 CPython tokens, and the same refusal text where it refuses. The tokens include one minted by `aauth==0.3.2`. Further tests cover caching and kid refresh, issuers that were not named, the unreadable-issuer floor, and issuer validation |
| Contracts verified with the algorithm the signing key names | `CompactJws.verifyWith`; `GrantService.verifyContract` | `AgentKeysTest`: sign/verify round trip under `Ed25519` |
| Issuer-qualified identity | `GrantService.connectionHandle`: subject qualified by the whole issuer (host, port, path) | `ConnectionHandleTest` (3): tenants by path, port kept, an already-qualified subject unchanged |
| Pseudonymous, CIMD and Web Bot Auth agents keep the thumbprint handle and grant binding; descriptive metadata and key publication verified | `RequesterMetadata` (CIMD self-claim, same-origin directory, cached hits, failure floor); `GrantService.describeOperator`; identity record adds `client_metadata`, `operator_attested`, `operator_directory`, `operator_client_id`, `parent_agent`, `key_bound` | `ConnectionHandleTest`: described or published, with or without `alg`, gives the same `jkt:` handle; live `flow-check` and Codex's binding probe |
| Identified enrollment and withdrawal against the pinned person server | Person server built from its own lock ([`aauth/person-server.Dockerfile`](../../aauth/person-server.Dockerfile)); `UMA_AS_AGENT_ISSUERS=https://ps.uma.lab`. On the Java client side, `AgentKeys.jwsAlg`, `publicJwk` naming `Ed25519`, `connectionHandle`, and `GrantClient` signing with the key's algorithm | `AgentKeysTest` (3); live `flow-check` withdrawal and `demo-acts-b` |
| Local-key owner authentication, distinct from OIDC | `OwnerAuth` (modes from `UMA_AS_OWNER_AUTH`, RFC 9421 over the configured authority, digest required with a body, once-only changing requests, `UMA_AS_OWNER_KEY_OWNER`, most specific failure); `OwnerBodyFilter`; `TokenVerifiers.oidcOwner`; `OwnerController` on `OwnerAuth`; Compose `oidc,local-key` | `OwnerAuthTest` (10): accepted signature; refusals for no signature, wrong key, wrong path, a body without a matching digest, a replay, another owner's key (403); OIDC-only refuses a signature; missing key and unknown mode give 500 |
| Standalone vault TLS | `VaultApplication.tlsProperties` (`UMA_VAULT_TLS_CERT`, `UMA_VAULT_TLS_KEY`) | Live `fixture`; Codex's hostname and CA check of the vault alone |
| Owner key provisioning, including Phase A upgrades | `scripts/owner-key.sh`; `make up` depends on `owner-key` | Scratch cases: fresh pair (private 600), no rotation on rerun, a missing public key derived to the same bytes, directory at either path refused with a volume-preserving fix, public without private refused, mismatched pair refused, unwritable directory and corrupt private key fail with nothing left behind |
| Phase documentation and runnable gate commands | README (status, quick start, upgrade note, targets, conformance, troubleshooting); [PROTOCOL.md](../PROTOCOL.md) (Agent identity, Owner authentication, The standalone fixture) | |

## Decisions and deviations

- **Person server dependencies.** Upstream's Dockerfile installs from `pyproject.toml`
  ranges, which today resolve `aauth-signing` 0.2.0 and fail enrollment with a 500.
  Both stacks now build the pinned source from its own `uv.lock`; the source, the
  clients and the check scripts are unchanged. The clients keep `aauth-signing==0.1.3`,
  as upstream's driver and `aauth-test` install it.
- **Isolation.** Host ports are overridable. The defaults, 443 and 5053, are upstream's.
- **`make up` provisions the owner key.** Upstream's `make init` does it. A Phase A
  checkout never ran the new `init`, and Compose creates a directory at a missing bind
  source, so `up` provisions it too. `owner-key` never rotates a key, and it refuses a
  directory or an inconsistent pair rather than reporting success.
- **Fixture health checks** use curl (`https://localhost:9020/health` for the vault)
  because the Java images carry no Python.
- **PyJWT semantics** that the token verifier relies on are ported explicitly: required
  claims, `sub` and `jti` types, `nbf`, and `exp <= now` as expired. A mutation that
  changed the expiry boundary failed the vector test.

## Not in Phase B, by plan

ID-JAG acceptance comes with the XAA slice in E4. Owner-scoped store work starts in C.
`first-party` (driver act 4), `intent`, `assurance`, `consequence` and `subagent`
checks and the full `demo-all SIM=1` are D. The full upstream `smoke-test` is E4, and
`adapter-check` is F.

## Blocking failures

None.
