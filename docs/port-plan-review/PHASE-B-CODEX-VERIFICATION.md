# Independent Phase B verification

The agreed plan has SHA-256 `21267cdd56d5c5bdde0b5a765265d0717728f9eb32056b3a33fa8e8df3d3a89f`.
The Python control uses upstream `77649287dc883b75ef563c59f96de8613ecf10d0` and
its person-server source pin `4e05247134640433b4fb0736e548cc2b1c21a267`.
The Java repository's person-server pin `18d9558` adds only the upstream LICENSE.

## Pinned Python controls

- The unmodified standalone `fixture-check` passed in a disposable Compose project.
  The owner signature was accepted, the unsigned owner request returned 401, an
  embedded call completed over the fixture's TLS, and the other owner key was refused.
- The pinned `make aauth-test` passed all 43 token verification and discovery assertions.
- The reference gateway's configured organization and joint tally must be running for
  Alice's owner-resource pull to succeed. A gateway-only subset returned HTTP 503
  before any identity was negotiated. The full Python control retains those services.
- After the owner-resource pull succeeded, the unconstrained person-server Docker
  build returned HTTP 500 at token issuance. Its transitive `aauth-signing` resolved
  to 0.2.0. The error was `Missing or unsupported fully-specified alg`. The pinned
  person-server source locks 0.1.2 in `uv.lock`; the next control run constrains the
  build to that version and leaves the Python app and check scripts unchanged.
- With the person-server dependency constrained to its lockfile, the unchanged
  `flow-check` passed all four identity regimes, the two handle levels, and
  Bob's withdrawal check. The flow obtained an EdDSA-signed token from that
  person server. All four identified driver acts passed separately in sequence
  with `--simulate-alice` and without `--pseudonymous`.
- The controls used distinct Compose networks and volumes, no host-published
  ports, and the same lab CA as the Java stack. [Selected command output](phase-b-evidence/codex-python-controls.txt)
  is recorded locally.

## Java verification in progress

- The exact revised repository Dockerfile built successfully against person-server
  `18d9558`. The image contains `aauth-signing==0.1.2` from the frozen upstream lock.
  With that Dockerfile and source pin substituted for the person-server build in the
  isolated pinned Python lab, the unchanged `flow-check` again passed all four
  regimes and withdrawal. It received an EdDSA token from the rebuilt service.
- A separate Maven snapshot including the first Java token-verifier changes passed
  the common module's existing 17 tests. This precedes the focused Phase B Java
  token tests and is preliminary regression evidence.
- The later Maven snapshot passed all 51 tests and the 39-blob manifest check.
  Its six focused `AgentTokensTest` tests compare Java's results with 34 pinned
  CPython token vectors and cover issuer configuration, discovery caching and
  refresh, and malformed input. The CPython generator reproduced the checked-in
  token fixture byte-for-byte twice with its pinned dependencies.
- An independent wire probe first passed against the pinned Python control. It
  compared each grant's subject and confirmation key to the requesting identity.
  The three key-based regimes retained their exact thumbprint and signing-key
  binding. The identified agent retained its issuer-qualified subject across
  two different enrolled session keys, with each grant bound to its own key.
  The same probe is ready for the Java stack.
- The Java standalone vault was started with the fixture-generated certificate
  in an isolated Compose project. A client inside that project verified the
  fixture CA and the `alice-vault.local` hostname and received HTTP 200 over
  TLS. An earlier AS image snapshot was caught mid-wiring and did not compile.
  This TLS check precedes the full fixture's local-key authorization test.
- After the AS wiring landed, the next independent snapshot passed the full
  `make check-unit` with 64 tests. This includes 10 owner-authentication tests
  and 3 connection-handle tests in addition to the token-vector tests.
- The latest Java client unit snapshot passed all 67 tests, including the
  three new `AgentKeysTest` cases. The named `make token-test` also passed.
  In the independent live aggregate, the original Phase A shim, TypeScript,
  decline, and four pseudonymous acts passed. All four identified acts passed.
- The normal Phase A-to-B upgrade exposed an owner-key bootstrap issue:
  starting Compose before the new public key exists can create a directory at
  its bind-mount source. A focused reproduction showed `make owner-key`
  exiting 0 even though OpenSSL could not write the public key, followed by a
  second false success because the private key already existed. Opus is
  addressing this before sign-off.
- The independent `make -j8 check-live` run exited 0. The remaining gates
  passed, including the four-regime identity flow and withdrawal, embedded
  enforcement and gateway restoration, the scoped Alice smoke probe, and the
  full standalone Java fixture. [Selected Java output](phase-b-evidence/codex-java-gates.txt)
  records the initial aggregate. The Java shim is being rerun after the
  final client-library delta, and the owner-key bootstrap fix is still open.

## Independent Phase B sign-off

The signed plan and pinned Python controls were verified. The Java images built
from the measured snapshot passed all nine named `make -j8 check-live` gates in
order. Phase A passed the unchanged shim, TypeScript, embedded, and pseudonymous
driver checks, unconditional decline, gateway restoration, and Alice smoke
including trace context. Phase B passed the unchanged four-regime flow and
withdrawal, all four identified acts, and the standalone fixture with its own
TLS and local-key owner authentication. The final client library passed all 67
Maven tests, including the focused token target. The rebuilt stdio shim passed
8/8 and the HTTP spike 7/7 on that library.

A separate wire probe against Java confirmed the exact RPT subject and
confirmation key for the three thumbprint regimes, and unchanged
issuer-qualified subject with two different enrolled session keys. The fixed
owner-key bootstrap provisions before Compose, derives a missing public key
without rotating the private key, and fails clearly for a directory at the bind
path. On the main Java stack, OIDC and an enrolled local signer independently
returned the same owner policy over TLS, and the unsigned request got 401. The
AS bind contained the public key and did not contain the private key.

[Selected Java results](phase-b-evidence/codex-java-gates.txt) and [Python
controls](phase-b-evidence/codex-python-controls.txt) are saved locally. The
implementation and evidence remain uncommitted on `phase-b-agent-identity`.
