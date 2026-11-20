# PROTOCOL — the grant wire contract

The API of `services/uma-as`, which is both the demo's authorization server and
the reference implementation of the core grant semantics, plus the enforcement
`services/uma-pep` runs behind the gateway. Grounded in the UMA 2.0 Grant and
Federated Authorization specifications and the AAuth draft; see
[ARCHITECTURE.md](ARCHITECTURE.md) for the system view.

Design rule: **stay inside UMA 2.0's wire surface wherever it already fits**
(`WWW-Authenticate: UMA`, the `uma-ticket` grant, `need_info`,
`request_submitted`, introspection `permissions`), and mark every deviation as
an explicit extension. The deviations are the findings.

## Parties and endpoints

| Party | Host | Role |
|---|---|---|
| Requesting agent + agent-shim | (host machine) | Holds an Ed25519 signing key; optionally a PS-issued `aa-agent+jwt`, a CIMD URL and a Web Bot Auth directory. Default is pseudonymous (bare public key in the contract header) |
| person-server | `ps.uma.lab` | Bob's AAuth agent server (pinned upstream build): enrolls identified agents and issues their `aa-agent+jwt` |
| agent-operator | `agent.uma.lab` | The firm operating Bob's agent: its CIMD document and Web Bot Auth key directory |
| agentgateway + uma-pep | `gateway.uma.lab` | RS-side PEP; holds the PAT; carries the FedAuthz obligations |
| alice-vault-mcp | (internal) | The resource server's backend; never speaks UMA |
| uma-as | `alice-as.uma.lab` | Alice's authorization server (beside Keycloak) |
| alice-portal | `portal.uma.lab` | Alice's consent / policy / audit surface |

### uma-as endpoints

```
GET  /.well-known/uma4agents-configuration   discovery: issuer, endpoints, jwks_uri,
                                             claim formats accepted
GET  /jwks                                   uma-as signing keys (RPTs, receipts, PATs)
GET  /terms                                  the owner's terms roster (MyTerms pattern)
GET  /terms/{template_id}                    a proffered terms document; every version
                                             stays dereferenceable (persistent record).
                                             Three representations at one URI: JSON
                                             (default), plain-language HTML
                                             (Accept: text/html — IEEE 7012 4.4.1),
                                             JSON-LD/ODRL (?format=jsonld — 4.4.2)

# Protection API (resource servers only, PAT-authorized — FedAuthz shape).
# The PAT is an OAuth access token this AS issues (see /token below): signed,
# expiring, scope uma_protection, carrying the owner (sub) and the RS (azp).
# Registration is declarative (pull): there is no push endpoint. /perm
# re-pulls on an unknown resource id, then rejects unregistered resources
# (invalid_resource_id) and excess scopes (invalid_scope).
POST   /perm            register attempted permissions -> ticket
POST   /introspect      RPT introspection (permissions array). Never consumes by
                        default; an inactive answer carries an `error` reason
                        (invalid_signature | unknown_token | connection_revoked |
                        already_consumed | revoked | expired) so the PEP can tell
                        a re-negotiable failure from a settled one. `revoked` is a
                        reusable grant spent by revoking its connection, which
                        stays dead if the same agent is admitted again
POST   /consume         burn a single-use RPT — the atomic last step of
                        enforcement, called only after PoP and operation binding
                        have passed
POST   /audit/access    the PEP reports an allowed call (grounds the ledger's "touched")

# Token endpoint (agent-facing UMA 2.0 Grant shape, plus RS-facing PAT issuance)
POST /token         grant_type=uma-ticket            the four-beat negotiation loop
POST /token         grant_type=client_credentials    PAT for an owner-authorized RS
                    (scope=uma_protection; the owner can revoke the RS, which
                    kills issuance and verification at once)

# Owner API. Each credential the deployment names in UMA_AS_OWNER_AUTH is
# independently sufficient (see "Owner authentication" below):
#   oidc       the owner's own OIDC access token (the portal proxies it)
#   local-key  an RFC 9421 signature by her Ed25519 device key
# No static owner credential exists. The Compose stack accepts both.
GET  /owner/pending                        requests in awaiting-owner state
POST /owner/pending/{family}/decision      approve | deny (compare-and-set: a
                                           second decision on one pend is 404)
GET  /owner/policies                       tier policy
PUT  /owner/policies/{tier_id}             edit a tier's terms / ask-me
GET  /owner/resources                      registered resources joined with tiers
GET  /owner/resource-servers               RSs holding her protection access
POST /owner/resource-servers/{id}/revoke   cut an RS off from the Protection API
POST /owner/resource-servers/decision      approve or revoke an RS by the client_id in its JSON body
GET  /owner/connections                    standing agent relationships
POST /owner/connections/revoke             {"handle": …}: revoke a connection
                                           and its live RPTs
GET  /owner/ledger                         the activity ledger
GET  /owner/events                         SSE stream -> the portal notification
```

### uma-pep endpoints (behind the gateway)

```
GET  /.well-known/oauth-protected-resource[/mcp]   RFC 9728 metadata for the /mcp
                                                   alias: structural, signed,
                                                   jwks_uri + tool_surfaces +
                                                   owner_resources_endpoint
GET  /.well-known/oauth-protected-resource/mcp/{owner}
                                                   the same, for the owner's own path;
                                                   404 for an owner not served here
GET  /jwks                                         the resource's signing keys
GET  /owner-resources[/{owner}]                    owner-bound instances; served only
                                                   to an RFC 9421-signed query by the
                                                   owner's AS ("protected webfinger")
/check{path}                                       ext_authz decision endpoint
```

With `ENFORCEMENT_MODE=embedded` the vault serves the same documents itself (signed
under `alice-vault-1`), advertises `dev.uma4agents/uma-enforcement` in its
`server/discover` capabilities, and answers a challenge in-band as JSON-RPC error
-32001 carrying the ticket and the remediation object; other refusals are -32002.

```
```

## The four beats

### Beat 0 — Discovery (two layers, two audiences)

Discovery is split by who may ask:

**Public — structure.** The gateway serves RFC 9728 Protected Resource
Metadata at `GET /.well-known/oauth-protected-resource[/mcp]`: the resource
identifier, the owner's `authorization_servers`, `scopes_supported`,
`jwks_uri`, `signed_metadata` (the same claims as a JWT under the resource's
key, so a relayed copy stays attributable), and two extension members —
`tool_surfaces` (tool names + scopes, *structural only*) and
`owner_resources_endpoint` (below). What the public document deliberately
omits is whose instances sit behind the resource: publishing which resources
Alice owns at an unauthenticated URI would be a privacy leak the old push
registration never had.

**Protected — instance.** `GET /owner-resources/{owner}` (advertised by the
public document) returns the owner-bound resource
instances — ids, names, scopes, owner — only to a querier that proves
possession of the owner's AS signing key: RFC 9421 message signatures over the
same profile the agent uses for proof-of-possession, verified against the AS's
published JWKS. A "protected webfinger" for Alice's stuff: discoverable, but
only by the party her consent already connected. This instance layer, and the
permission ticket, are **binding-independent** — only the public encoding
changes.

Agents consume the public layer: both clients fetch it (the driver before
any call; the shim on first challenge), validate `resource` (RFC 9728
§3.3), and **corroborate every challenge's `as_uri` against the published
`authorization_servers`** — a challenge naming an AS the resource never
published is refused. The AS consumes both layers (see Registration below).
The challenge remains authoritative for the ticket.

### Registration — how the AS learns what the RS protects

Declarative (pull) only, as at the pinned upstream: the RS only publishes. The
AS fetches the public RFC 9728 document, verifies `signed_metadata` against the
resource's `jwks_uri`, then queries the advertised `owner_resources_endpoint`
with an RFC 9421-signed request and materializes its registry from the response.

### Separate owner authorities

The gateway routes `/mcp` and `/mcp/alice` to Alice and `/mcp/carol` to Carol.
Each route has its own tool namespace, PAT cache and RFC 9728 metadata. The
gateway verifies signed owner-resource queries against the keyset of the
authority configured for that route. `UMA_EXTRA_OWNERS` lists additional
owners and `UMA_OWNER_AUTHORITIES` maps each owner to the AS's `public` and
`internal` URLs. `UMA_PEP_RS_SECRETS` lists the relationships provisioned
with a shared secret.

For an unprovisioned relationship, the resource server presents its HTTPS
origin as `client_id` and signs `POST /rs/register` with a published key
covering the request's Content-Digest. The AS fetches the exact resource's RFC
9728 document and same-origin JWKS, and verifies the signature before
creating a pending record. The owner sends `{"client_id":"…","decision":"approved"}`
to her decision endpoint. The resource server uses the same signature profile
over its exact form body to obtain a PAT. A revoked resource server may ask
again and waits for a new approval. An embedded vault can use the same flow
with an explicitly empty `UMA_AS_RS_CLIENT_SECRET`.

Permission tickets carry a base64url owner marker before the opaque store
ticket. The authority checks that marker before accessing the negotiation.
Existing unmarked tickets still resolve against the same owner's store.

### Organization membership and clearance

The organization authority publishes its charter and enrolment endpoints at
`/.well-known/u4a-organization`. A member accepts one charter version
through her owner API. Her AS keeps its membership credential in her
owner-scoped store. The gateway derives each `/mcp/shared/{owner}` tool
surface from the role that the organization currently publishes for her.
The member's AS folds OPA's decision into her grant loop. OPA can require
additional approval or refuse a request. The gateway checks the charter's
scope and expiry limits against the grant before forwarding the call.

The organization can attest to clearance under `typ=u4a-clearance+jwt`, with
the member as subject and her AS as audience. Her AS fetches the attestation
using its membership credential, verifies it, and applies the intersection
of the owner's and charter's requirements. The ledger holds the verified
facts. The RPT carries their SHA-256 digest over compact sorted UTF-8
CPython JSON. The grant issuer checks current clearance before dictating
terms and again before redeeming an approved pending request.

The organization console can act over charter-scoped pending operations and
blocks. Signed notices identify the organization and expire, and the AS
records each notice once. A break-glass grant is bound to one agent key and
one operation, and issuance requires a successful notice to the member's AS.
Staleness repairs itself on the AS side: an unknown `resource_id` at `/perm`
triggers a re-pull, and her `/owner/resources` listing re-pulls when the last pull is
older than `UMA_AS_RESOURCE_REFRESH_S` (15 s).

What a pull believes (as at the pin, with the #38/#41/#43 safeguards):

- Only a resource server whose registration is `active` is pulled, at startup and on
  every re-pull; startup keeps retrying until every approved server has answered.
- `jwks_uri` and `owner_resources_endpoint` must be https on the resource's own origin;
  redirects are not followed; no document may exceed 1 MiB.
- `signed_metadata` must verify under a published key *and* pass a JWT decode's default
  claim checks (`iat`, `nbf`, `exp`, `sub`/`jti` types; audience aside), and its `iss`
  must be the resource.
- The listing must name no other owner, and every entry must carry a string `_id` and
  a `resource_scopes` array. A listing that fails any of these is refused whole and
  changes nothing.
- A listing replaces what that server published before: a resource it no longer lists
  is withdrawn. Each resource records every approved server publishing it (`sources`),
  and `/perm` issues tickets only to a source.

Deployment note (learned as a deadlock): in pull mode the pull and its
verification form a call cycle — the AS queries the RS while the RS
authenticates the AS against the AS's own JWKS. Signed-query verification
must either tolerate a live back-call (the AS must not block its service
loop on the pull) or verify against pre-cached keys.

### Beat 1 — Challenge

The agent calls a gateway-fronted MCP tool without (sufficient) authorization.
MCP session bootstrap and discovery (`initialize`, `tools/list`) pass
unauthenticated; only `tools/call` is protected. The PEP registers the attempt
at uma-as (`POST /perm` with `resource_id`, `resource_scopes`) and the gateway
answers:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: UMA realm="alice-vault",
  as_uri="https://alice-as.uma.lab",
  ticket="<ticket>",
  resource_metadata="https://gateway.uma.lab/.well-known/oauth-protected-resource/mcp"
```

`resource_metadata` is RFC 9728 §5.1: the challenge names the document that
lets the client corroborate `as_uri` instead of taking an unauthenticated
header's word for it.

The primary challenge is stock UMA 2.0. An `AAuth-Requirement:
requirement=grant; as_uri=…; ticket=…` form may be emitted alongside it as a
binding profile, so AAuth-native agents can discover the grant layer through
their own challenge header; this belongs in the AAuth binding document.

### Beat 2 — Attempt

The agent presents the ticket at the AS token endpoint:

```
POST /token
grant_type = urn:ietf:params:oauth:grant-type:uma-ticket
ticket     = <ticket>
```

uma-as answers `403 need_info` with a **rotated ticket** and the owner's
proffered terms. `required_claims` is standard UMA; the `terms_template` inside
the required claim is **extension #1** — UMA lets the AS name acceptable claim
formats; here it *proffers the content* the requesting side must accept. This
is the MyTerms exchange (IEEE 7012, extended from privacy terms to agentic
access terms): the terms are a **persistent, dereferenceable document** on the
owner's roster (`terms_uri`, served at `GET /terms/…` for the life of the AS,
every version retained), and the signed echo returned in Beat 3 is the
reciprocal agreement.

```json
{
  "error": "need_info",
  "ticket": "<rotated>",
  "required_claims": [{
    "claim_type": "urn:uma4agents:claim:myterms-agreement",
    "claim_token_format": ["urn:uma4agents:format:myterms-agreement-v1+jws"],
    "friendly_name": "Alice's terms: Holdings summary",
    "terms_template": {
      "template_id": "alice/advisor-tier1/v2",
      "terms_uri": "https://alice-as.uma.lab/terms/alice/advisor-tier1/v2",
      "proffered_by": "https://alice-as.uma.lab",
      "purpose": "Suitability review for advisory onboarding",
      "scope": ["positions:read"],
      "expires_in": 172800,
      "prohibited": ["retention-after-review", "marketing", "model-training"],
      "resource_id": "alice-vault/get_positions",
      "family": "<negotiation-family-id>",
      "nonce": "<nonce>"
    }
  }]
}
```

An AAuth mission reference (`approver` + `s256`) may be offered as an additional
acceptable `claim_token_format` — attestation demanded by the owner's side.

### Beat 3 — Commit

The shim surfaces the terms to the agent's human (MCP elicitation; fallback:
standing config), then re-presents the rotated ticket with the signed contract:

```
POST /token
grant_type         = urn:ietf:params:oauth:grant-type:uma-ticket
ticket             = <rotated>
claim_token        = <base64url(myterms-agreement JWS)>
claim_token_format = urn:uma4agents:format:myterms-agreement-v1+jws
```

The **agreement** is the terms template echoed and signed by the agent's key.
Its JWS protected header carries either `jwk` (the pseudonymous bare key) or an
`agent_token` (an `aa-agent+jwt` from the agent's server; see
[Agent identity](#agent-identity); its `cnf.jwk` is the signing key) — so the
same key both signs the agreement and, later, proves possession of the RPT.
The agreement is verified with the algorithm its signing key names, never the
one its header asks for: a key naming `Ed25519` requires `alg: Ed25519`, and a
key naming nothing (a bare pseudonymous key, or an earlier token's) requires
`EdDSA`. The header may also carry `client_id` (a CIMD URL) and
`signature_agent` (a Web Bot Auth directory); both are descriptive only.

```json
{
  "iss": "aauth:agent:<keyid>",
  "aud": "https://alice-as.uma.lab",
  "iat": 1751900000,
  "template_id": "alice/advisor-tier1/v2",
  "terms_uri": "https://alice-as.uma.lab/terms/alice/advisor-tier1/v2",
  "purpose": "Suitability review for advisory onboarding",
  "scope": ["positions:read"],
  "expires_in": 172800,
  "prohibited": ["retention-after-review", "marketing", "model-training"],
  "family": "<negotiation-family-id>",
  "nonce": "<nonce>"
}
```

If the tier governing the resource, or the terms it publishes, changed since they were
dictated, uma-as dictates the current terms again (`need_info` with a fresh template and
ticket) instead of reading the agreement. Otherwise it verifies the signature against the
header key and checks the echo matches the proffered template, in the pinned order:
nonce, family, template_id, `terms_uri` naming the proffered document, purpose; `scope`
and `prohibited` arrays of strings; prohibited not weakened; `expires_in` a positive
whole number of seconds and not extended; scope not widened beyond what was offered and
not empty when something was; for a per-operation tier, an operation naming a tool and
an object of params. All of this is checked before she is asked. It then evaluates
Alice's tier policy and stores the agreement (content-addressed by `s256`).
Then one of:

- **Known connection, non-ask-me tier** → Beat 4 immediately.
- **New agent (no standing connection), any tier** → `403 request_submitted`
  as a *connection request*: uma-as holds the rotated ticket and pushes the
  pending item to the portal (`owner.notified`, `kind=connection`).
- **Ask-me tier (e.g. trade execution)** → `403 request_submitted` as an
  *operation approval* (`kind=operation`).
- **Policy failure / weakened echo / bad signature** → `request_denied`.

For a held ticket the agent re-presents after `interval` (each poll rotates
it). Alice's decision resolves it: approve → grant (and, for a connection
request, the standing relationship is recorded); deny → `request_denied`;
expiry → `invalid_grant`.

### Beat 4 — Grant

```json
{
  "access_token": "<RPT: aa-auth+jwt, cnf-bound>",
  "token_type": "PoP",
  "expires_in": 3600,
  "receipt": "<myterms-receipt+jws>"
}
```

The `receipt` completes the MyTerms exchange: a JWS counter-signed by the
owner's AS that **embeds the complete agent-signed agreement JWS** alongside
the `terms_uri`, agreement hash, agent key thumbprint, and negotiation
family. Both sides therefore hold identical, dually-signed copies of the
record (IEEE 7012 5.2.2/5.4.4): the owner's AS retains it with her ledger;
the shim persists the agent's copy to its receipts directory.

A requesting side that does not accept the proffered terms may end the
negotiation with `decline=true` at the token endpoint; the refusal is a
record too (IEEE 7012 5.2.4) — the owner's ledger gains a `refused` entry
naming the terms that were declined.

The RPT is an `aa-auth+jwt` (**extension #2**: UMA's introspection
`permissions` array carried as a claim inside a proof-of-possession token):

```json
{
  "iss": "https://alice-as.uma.lab",
  "sub": "<agent id or aauth:pseudonymous-agent>",
  "aud": "https://gateway.uma.lab",
  "jti": "rpt_<id>",
  "exp": 1751910000,
  "cnf": { "jwk": { "…agent signing key…": "" } },
  "permissions": [
    { "resource_id": "alice-vault/get_positions",
      "resource_scopes": ["positions:read"], "exp": 1752072800 }
  ],
  "contract": "s256:<agreement-hash>"
}
```

**Ask-me (tier 3) RPTs** additionally carry the operation binding — authority
for *this trade*, not trading authority:

```json
  "single_use": true,
  "operation": { "tool": "execute_trade",
                 "params_s256": "<hash of the exact approved order>" }
```

The agent retries the original MCP call — RFC 9421-signed over
`@method @authority @path authorization`, with the RPT in the `Authorization:
PoP …` header. The PEP then enforces **in this order**, and the order is
normative:

1. `POST /introspect` (PAT-authorized, non-consuming) — is the token live, and
   does the connection behind it still stand?
2. The tool maps to a `resource_id` present in `permissions`.
3. The request signature verifies against the RPT's `cnf` key — this is what
   makes the RPT proof-of-possession rather than bearer.
4. For single-use RPTs, an exact `operation.params_s256` match.
5. `POST /consume` — only now is the grant spent.

Consuming earlier, at step 1, is the intuitive placement and it is a denial of
service: anyone who observes the token can replay it unsigned and destroy an
approval the owner personally gave, without ever passing a check. Because the
sequence is check-then-act, the burn has to be both last and atomic; a caller
that loses the race is told `consumed: false` and must deny.

An inactive introspection carries a reason. `connection_revoked` is terminal —
the PEP answers `403 access_revoked` rather than a fresh challenge, because
re-negotiating cannot change an outcome the owner has already settled.
Everything else re-challenges. The call then reaches alice-vault-mcp.


## Joint ownership

The tally at `https://joint-tally.uma.lab` publishes each account's resources,
holders and voting rule. Each holder accepts one mandate through her own owner
API and writes her own terms. The tally proffers the shortest expiry, the scope
intersection and the union of the holders' prohibitions. It asks each holder's
authority to sign a verdict about the agent's agreement.

The resulting proof-of-possession grant carries those signed verdicts. The
gateway reads the published mandate and checks the signatures, count, account,
resource, agreement digest, calling key, expiry and operation bound into the
verdicts. An organization cannot run its charter over an unrelated co-owner's
holdings. A changed mandate must be accepted before the holder will answer
under it. Her terms remain in her authority if she leaves.

`make joint-check` uses the unchanged pinned client against
`/mcp/joint/meridian-joint` (both holders) and `/mcp/joint/meridian-either`
(either holder).


## Cross App Access

For an organization's resource, a charter that names an identity provider
adds a `need_info` beat before terms. The AS advertises the ID-JAG format
and tells the agent which provider, token endpoint, audience, resource and
operation to request. The broker exchanges an ID token issued to the
requesting application only over an approved connection. The receiving
AS verifies the signature, issuer, audience, member, lifetime and operation,
then spends the assertion once in the owner store. Her own terms and the
organization's charter still govern the regular UMA negotiation.

Northwind's workforce realm is independent of the Meridian administration
realm. Workforce credentials can establish eligibility for membership.
Joining still requires explicit assent to the charter version. Personal
resources and jointly held resources outside the charter use the original
grant loop without a workforce assertion.

## Standing relationships (the day-1 handshake)

A **connection** is the standing relationship an owner has with a specific
agent, keyed by a **handle** whose shape follows the agent's identity level:

- *Pseudonymous* — the RFC 7638 JWK thumbprint (`jkt:…`). The key *is* the
  identity, so it must persist for the relationship to persist.
- *Identified* — the issuer-qualified subject of the verified `aa-agent+jwt`
  (e.g. `aauth:…@ps.uma.lab`). AAuth session keys rotate per run, so a
  thumbprint-keyed connection would forget an identified agent every session;
  continuity lives in the token's issuer+subject. The qualifier is the whole
  issuer — host, port and path — appended as `@…` unless the subject already
  ends with it, so two issuers, or two tenants of one host, never share a
  connection. (The AS verifies the agent token first; see
  [Agent identity](#agent-identity).)

These are the only two levels. A CIMD document or a Web Bot Auth directory
describes a key-level agent; it does not change its handle.

A connection is created when Alice approves a `kind=connection` request
(first contact), and it holds the identity level, a label,
first-seen/last-access timestamps, and status.

- While no active connection exists, first contact pends regardless of tier.
- Once active, non-ask-me tiers auto-grant for that agent; ask-me tiers still
  pend per operation.
- `POST /owner/connections/revoke` with `{"handle": …}` sets the connection
  inactive, counts the revocation, and marks every live RPT bound to that handle
  consumed, in one store step, so introspection fails immediately
  (`connection_revoked`, and `revoked` for a reusable grant after the agent is
  admitted again). Admitting the agent again starts a new connection that keeps
  the revocation count.
- An approval is collected by the agent's next poll. Before anything is issued the AS
  reads the connection again: if she revoked the agent after it asked, or an operation
  request's agent is no longer connected, the approval issues nothing
  (`request_denied`, with the reason, recorded as `refused`).

This is the standing-relationship handle discussed in
[FINDINGS.md](../FINDINGS.md); the PCT is its spec-native ancestor, here made
owner-visible and owner-revocable.

## Agent identity

Agent identity stays on the requesting side. Alice's tiers, the terms she
proffers and the shape of the grant are the same however the agent is
identified; only the connection handle differs, and only by level.
`make flow-check` runs the same negotiation four ways and asserts this.

| Regime | Contract header | Handle | What the AS checks |
|---|---|---|---|
| Pseudonymous | `jwk` | `jkt:` thumbprint | The signature, under the header key |
| Identified | `agent_token` | issuer-qualified subject | The agent token, then the signature under its `cnf.jwk` |
| Described | `jwk`, `client_id` | `jkt:` thumbprint | The CIMD document claims the URL it was fetched from |
| Published | `jwk`, `client_id`, `signature_agent` | `jkt:` thumbprint | The directory shares the `client_id`'s https origin and holds this key |

The owner's pending item and connection carry the identity record:
`level`, `iss`, `sub` and `parent_agent` for an identified agent, then
`client_metadata` (`verified`, and the document's display fields, or the
`error`), `operator_attested`, `operator_directory`, `operator_client_id`, and
`key_bound: true`. A CIMD or directory failure leaves the agent unattested; it
never refuses the contract.

### Accepting an AAuth agent token

The AS believes only the issuers named in `UMA_AS_AGENT_ISSUERS` (whitespace or
comma separated; the Compose stack names `https://ps.uma.lab`). An issuer not
named is never fetched, and with none named no agent token is accepted. Both
shapes in use are accepted:

| | Current (draft-hardt-oauth-aauth-protocol-10) | Earlier revisions |
|---|---|---|
| Header `alg` | `Ed25519` (RFC 9864) | `EdDSA` |
| Issuer key and `cnf.jwk` | must name `Ed25519` | may name `EdDSA` or nothing |
| `dwk`, `jti`, `iat` | required | optional |

Checked in order, each failure refusing the contract with a reason that names
the step:

1. `typ` is `aa-agent+jwt`, and `alg` is `Ed25519` or `EdDSA`.
2. `iss` is an https origin with a lowercase host and no credentials, query or
   fragment, and is one of the named issuers. `dwk`, if present, is
   `aauth-agent.json`.
3. `{iss}/.well-known/aauth-agent.json`, if it names an `issuer`, names `iss`.
4. The key at its `jwks_uri` with the header's `kid` — or, with no `kid`, the
   only key there — is an Ed25519 key, names the header's `alg` or nothing, and
   verifies the signature. `sub` and `exp` are present, `exp` is in the future,
   and `nbf`, if present, has passed.
5. A current-shape token carries `dwk`, `jti` and `iat`, under a key and a
   `cnf.jwk` that both name `Ed25519`.
6. A `sub` in AAuth's `aauth:local@domain` form names the issuer's own host.
7. `cnf.jwk` is an Ed25519 key.
8. `parent_agent`, if present, names another agent of the same issuer.

An issuer's keys are fetched at most once a minute and kept five minutes; a
`kid` not in the cached set is how a rotation is noticed, after the minute. An
issuer that cannot be read is not asked again for a minute. Every document an
agent names (issuer metadata and keys, CIMD, directory) is read over https
only, with no redirects, a five-second deadline and a 256 KiB cap.

### Enrollment and withdrawal

Identified agents enroll with Bob's person server (the pinned
`christian-posta/aauth-person-server`): a stable key registered by a request
the session key signs (`hwk`), pending until Bob approves, then an
`aa-agent+jwt` binding the session key. When Bob revokes an agent there, its
next enrollment is not issued a token without him. Both happen between the
agent and its issuer; the authorization server sees only the tokens.

## Owner authentication

`UMA_AS_OWNER_AUTH` lists the credentials the owner API accepts:

- **`oidc`** — `Authorization: Bearer <token>` from her realm
  (`UMA_AS_OWNER_ISSUER`), issued to an owner-surface client
  (`UMA_AS_OWNER_CLIENTS`). Her `preferred_username` is the owner.
- **`local-key`** — an RFC 9421 signature by the Ed25519 key at
  `UMA_AS_OWNER_KEY` (a public-key PEM), with the agents' profile: covering
  `@method`, `@authority`, `@path` and `authorization` (the empty string when
  there is no bearer), within 60 seconds of `created`. The authority is
  `UMA_AS_OWNER_AUTHORITY`, from configuration and never the request. A
  request with a body must also cover its RFC 9530 `content-digest`, so an
  approval cannot be turned into a refusal in transit. A request that changes
  something is accepted once; a replay inside two minutes is refused. A
  signature proves a holder, so `UMA_AS_OWNER_KEY_OWNER` names whose key it is.

Each listed credential is independently sufficient; neither is a fallback for
the other. When none verifies, the AS answers with the most specific failure:
a credential that authenticated but names another owner (`403`) over one that
was not presented (`401`), and a missing key file or unknown mode as `500`.
The Compose stack runs `oidc,local-key`. `make up` provisions the key pair with
`make owner-key` before Compose bind-mounts the public half; only that half
reaches the AS.

## The standalone fixture

[`compose.fixture.yml`](../compose.fixture.yml) runs the grant with nothing
standing behind it, in its own Compose project and with no published ports.
Its `uma-as` uses the memory store and `UMA_AS_OWNER_AUTH=local-key`. Its vault
runs `ENFORCEMENT_MODE=embedded` and serves its own TLS from
`UMA_VAULT_TLS_CERT` and `UMA_VAULT_TLS_KEY`. A one-shot container makes the
owner key and a throwaway CA and certificate for `alice-vault.local`. The AS
trusts only that CA (`UMA4A_CA_BUNDLE`) when it pulls the vault's metadata.
`make fixture` runs the pinned `fixture_check.py` against it: signed owner
requests accepted, unsigned or wrongly-keyed ones refused with `401`, and the
four beats through to an authorized call.

## Ticket lifecycle

```
issued ─present─▶ need_info(rotated) ─commit─▶ ┌─ known conn, open tier ─▶ granted (consumed)
                        │                       ├─ new agent (any tier) ──▶ awaiting-owner ┐
                        │                       └─ ask-me tier ───────────▶ awaiting-owner ┤
                        │                                                                   │
                        └─(weakened echo / bad sig / policy fail)─▶ request_denied          │
                                                                                            │
        awaiting-owner(same ticket per poll):  approved ─▶ granted  denied ─▶ request_denied│
                                           expired  ─▶ invalid_grant                        │
                                                       (connection recorded on approve) ◀───┘
```

Every presentation consumes the ticket and, if negotiation continues, issues a
fresh one (UMA 2.0 single-use rule). The negotiation **family** id (assigned at
`/perm`) is stable across rotations and is the correlation id for logging,
audit, and owner decisions.

## State, replicas and key rotation

`uma-as` keeps every negotiation, ticket, grant, connection, ledger entry, terms version,
tier, resource-server registration and owner event in an owner-scoped store:
`UMA_AS_STORE=memory` (the Compose default) or `postgres`, over upstream's pinned
`schema.sql`. Every single-use guarantee is one store step, so it holds across replicas
sharing one database: a ticket is spent by the step that reads it, a single-use RPT by
one `UPDATE … WHERE NOT consumed`, an owner decision by one guarded `UPDATE`, a signed
owner change by one `INSERT` into `spent`. A decision written while a poll held an older
copy of the negotiation survives the poll's write. Owner events travel as rows announced
by `NOTIFY`, routed to the owner's own subscribers on every replica; the listening
connection reconnects after a failover. A database whose primary keys predate
multi-owner is refused at startup, naming the tables.

Signing-key rotation: the new key is `UMA_AS_SIGNING_KEY` under a new `UMA_AS_KID`; the
retired one moves to `UMA_AS_PREVIOUS_KEYS` (kid in `UMA_AS_PREVIOUS_KIDS`). `/jwks`
publishes all of them, and the AS verifies its own PATs and RPTs with the key the token's
kid names, so grants issued before the rotation keep working. The registration pull is
signed with the new kid; a resource server whose cached key set lacks it refetches once
on the failed signature (floored at 5 s between forced reads).

A seeded resource-server registration follows the secret the deployment provisions: the
token endpoint updates the stored secret alone, in one step, and reads the status from
the record that step returns, so a revocation that lands at the same moment stays a
revocation.

## Structured protocol events

One JSON line per event to stdout → Loki. `corr` is the negotiation family id;
the Grafana dashboard, `make audit`, and the portal ledger are views over this
stream.

```json
{ "ts": "2026-07-07T18:21:27Z", "event": "need_info.terms_dictated",
  "corr": "fam_8f3a…", "actor": "uma-as",
  "details": { "tier": "tier1", "template_id": "alice/advisor-tier1/v2",
               "resource_id": "alice-vault/get_positions" } }
```

Emitted events: `resource.registered`, `resources.registered_at_startup`,
`terms.published`, `terms.declined`, `permission.registered`,
`challenge.issued`, `ticket.presented`, `need_info.terms_dictated`,
`contract.committed`, `contract.rejected`, `policy.evaluated`,
`policy.updated`, `ticket.awaiting_owner`, `owner.notified`,
`owner.decision`, `connection.approved`, `connection.revoked`, `rpt.issued`,
`receipt.issued`, `rpt.introspected`, `rpt.consumed`, `access.allowed`,
`access.denied`.

The activity ledger is a projection: **promised** = `contract.committed`,
**touched** = `access.allowed`, **connected** = `connection.approved`,
**personally approved / denied** = `owner.decision`, **revoked** =
`connection.revoked`.

## Extension register (deviations from UMA 2.0, each a finding)

| # | Extension | UMA 2.0 baseline | Why |
|---|---|---|---|
| 1 | `terms_template` inside `required_claims`; AS proffers claim *content*, dereferenceable at a persistent `terms_uri`, with a counter-signed receipt returned on grant | AS names acceptable claim formats | Owner-proffered terms — MyTerms / IEEE 7012 extended to agentic access; descends from the 2010 Requesting Party Policy claim. Dual-held records: owner's ledger + agent's receipt |
| 2 | RPT = `aa-auth+jwt`, `cnf`-bound, `token_type: PoP`, `permissions` claim | Bearer RPT; permissions visible only via introspection | "Genome stays, organs replaced" — AAuth binding |
| 3 | `operation` + `single_use` RPT claims | Per-permission scopes/expiry only | Ask-me per-operation grants — approval permits one action |
| 4 | Owner push notification on `request_submitted`, in two kinds (connection / operation) | RO intervention out of scope | The agent-era consent surface; the day-1 handshake |
| 5 | Standing connection keyed by an identity handle (JWK thumbprint when pseudonymous, verified issuer-qualified subject when identified); `contract` (s256) on the RPT | — | Owner-visible, revocable relationships; promise/action/consent in one ledger. Identified agents' session keys rotate, so the key cannot be the relationship key |
| 6 | Public structural discovery from one registry — RFC 9728 `tool_surfaces`, per owner path; `resource_metadata` on the UMA challenge; clients corroborate `as_uri` against published `authorization_servers` | PRM and AAuth resource metadata both predate this; UMA's challenge carries `as_uri` on faith | Declarative discovery of the AS and the surface, per binding; the challenge gains a TLS-anchored second witness. The encodings are stock (9728 §5.1, AAuth R3) — composing them with the UMA challenge, and sharing one protected instance layer beneath both, is the extension |
| 7 | `owner_resources_endpoint` PRM member + the protected owner-resources listing (RFC 9421-signed query by the owner's AS) | FedAuthz: RS pushes owner-bound registrations under the PAT | The privacy split: public metadata stays structural; whose instances sit behind the resource is served only to the owner's AS — "protected webfinger." Enables declarative (pull) registration), with push remaining conformant |

Everything not listed here is intended to be stock UMA 2.0 / stock AAuth.
