# Independent Phase F controls

The reference is `77649287dc883b75ef563c59f96de8613ecf10d0`.
The adapter passed 3/3. The personal AI binding gate passed after
the reference fixture supplied the public half of its device key as
a file. An earlier run used a directory left by Docker at the missing
public-key bind source. The rerun derived the public half from the
existing scratch key and mounted it at the expected container path
without changing the reference checker or code. The Java provisioning
fix verified in Phase B already handles this fixture condition.

[Selected reference output](phase-f-evidence/codex-python-controls.txt).

The corrected pAI-OS reference setup reached a reproducible checker
failure. The unchanged checker generates a fresh keystore for the
standing-consent tier. The pinned ability deliberately refuses first
contact even for a tier with standing consent. Its own log showed
`standing_approval: ["tier1"]`, a first-contact request, `cannot-ask`,
and a denied decision. The raw pinned checker therefore fails on the Python reference. The
Phase F gate supplies explicit owner approval before testing standing
consent and checks first-contact refusal with a separate agent.

A corrected pinned reference fixture now passes all three decisions
without changing the ability, its host, or the AS. Before starting
pAI-OS, a signed owner request approved the fixture agent's first
connection. The running ability then refused a different, unfamiliar
agent, approved a tier1 operation from the admitted agent, and refused
an ask-me operation from that same agent. The runtime log proved one
standing decision and two refusals. The probe reused the pinned checker
module's negotiation function and ran against unmodified Python services.

The final launcher also runs the pinned check's complete entry point
after the explicit owner approval. It controls only the first UUID,
which is used to name the temporary keystore file. The real UUID
generator is restored before the check negotiates or makes a key.
The full checker and two supplemental assertions passed against the
pinned Python services. The supplemental cases exercise an unfamiliar
agent on the standing tier and the admitted agent on the ask-me tier.

[Python pAI-OS control](phase-f-evidence/codex-python-paios.txt).

## n8n reference control

The same Compose workflow and client passed against the pinned Python
authority and standalone Python PEP. The extension reuses the pinned
workflow and supplies a distinct owner resource namespace for the test.
The first Python start required its lab CA in `SSL_CERT_FILE`, as in the
pinned n8n pod. The AS registers the canonical `/mcp/alice` resource
while the MCP client calls the `/mcp` alias. The published metadata,
owner approval, live signed call, withdrawal and the unchanged 15-case
integration probe passed on the corrected fixture.

[Python n8n control](phase-f-evidence/codex-python-n8n.txt).

## Java integration checks

- The unchanged adapter checker passed all three assertions with the
  adapter's key published under the configured lab operator. The client
  used plain MCP over streamable HTTP.
- The pinned Kwaai checker verified owner-key and OIDC access on one
  authority. The initial Java pAI-OS fixture used its real loader and
  the pinned negotiation code. The final launcher additionally runs the
  complete unchanged checker. Its dependencies are locked to the passing
  Python control image.
- The Java sidecar introduced itself, waited for signed owner approval,
  and put the pinned n8n workflow behind the same enforcement core as the
  gateway. It passed the unchanged 15-case integration probe and an
  actual workflow call. The proxy uses HTTP/1.1 on the n8n hop after
  an early h2c negotiation stalled the initialization response.
- The Java owner CLI generated a stable mode-0600 Ed25519 key with an
  X.509 public PEM. At the standalone fixture an unchanged Python grant
  client spent a grant the CLI approved, then saw it refused after CLI
  revocation.
- The portal probe matched pinned SPA bytes and completed three Keycloak
  sign-ins. It exercised Alice's organization and joint routes, Carol's
  separate resource listing, and Dana's organization console session.
  The probe handles Carol's fresh state by using her portal to accept the
  gateway introduction before asking for her protected resource records.

[Java focused results](phase-f-evidence/codex-java-focused.txt).

The initial portal event-stream probe received HTTP 200, then the edge
closed it at about 16 seconds before a heartbeat made it back. Envoy's
ordinary route timeout was still applied to SSE. The edge now disables
that timeout on the exact owner and portal event paths, for Alice and
Carol. A separate edge with the corrected configuration delivered two
heartbeats across 30 seconds. The release portal check now requires both
heartbeats and also exercises the revoke proxy's JSON request path.

[Idle portal event-stream probe](phase-f-evidence/codex-event-stream.txt).

## Release sign-off

`make -j8 check-all` exited 0 against the rebuilt, isolated Java
Compose project after a memory reset. PostgreSQL 17.12 was supplied
to Maven and the store gate. All 262 Maven tests passed with zero
skips. The 31 serial live gates passed, including rotation and restore,
122 store cases, the full staged matrix through XAA, the unchanged
adapter and Kwaai checks, the full pinned pAI-OS checker with its
explicit fixture approval, the 15-case n8n probe and real workflow,
Java CLI approval and revocation, and all three portal sign-ins.

The edge was refreshed during the independent CLI fixture gate to
load the SSE route change. The final portal gate observed Carol's
event feed for 30 seconds, including two keepalives. Full smoke passed
again through the refreshed edge.

All 67 vendored blobs were verified against the pin. A fresh export
reproduced the manifest. The verifier now rejects an unlisted file whose
name is a prefix of a listed path and rejects unlisted nested READMEs.
All six CPython vector files regenerated byte-for-byte. The signed port
plan still has SHA-256 `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f`.

[Full Java release matrix](phase-f-evidence/codex-java-release.txt).
[Smoke after the edge refresh](phase-f-evidence/codex-final-edge-smoke.txt).
