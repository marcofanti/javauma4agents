# agent-shim

Lets an **unmodified agent** (Claude Code, Claude Desktop, any MCP client) act
as Bob's requesting agent against Alice's vault. The shim is to UMA-for-agents
what `mcp-remote` is to MCP OAuth: it holds the agent's signing key, signs
requests (RFC 9421), and runs the four-beat grant dance when the gateway
challenges — surfacing Alice's dictated terms to Bob *inside his agent* via
MCP elicitation, with his standing config as the fallback for clients that
don't render elicitation yet.

## Build and connect Claude Code

From the repo root (so the cert path resolves):

```bash
mvn -q -pl clients/agent-shim -am package -DskipTests
claude mcp add alice-vault -- \
  env UMA4A_CACERT=certs/rootCA.pem \
  java -jar clients/agent-shim/target/shim.jar
```

Then ask Claude something like *"what's in Alice's portfolio?"* — the first
tool call triggers the challenge, and Alice's terms appear as an elicitation
form for you to approve. `execute_trade` pends until Alice approves it in
[her portal](https://portal.uma.lab).

Environment (same names as the reference implementation): `UMA4A_GATEWAY`,
`UMA4A_CACERT`, `UMA4A_KEYSTORE`, `UMA4A_RECEIPTS`,
`UMA4A_STANDING_MAX_EXPIRES`, `UMA4A_AGENT_ISSUER` (set to e.g.
`https://ps.uma.lab` to enroll and run identified), `UMA4A_PERSON_TOKEN`.

## Verify headlessly

`make shim-test` runs the Java shim under a scripted stdio MCP client
(`test_shim.py`, kept in Python as a cross-language conformance harness) that
exercises both approval paths (elicitation and standing config).
