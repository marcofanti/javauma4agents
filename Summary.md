# javauma4agents

**Source:** Java port of https://github.com/nickgamb/uma4agents.git
**Stack:** Java 25 / Spring Boot 4 multi-module Maven, in the original Docker Compose lab
(Keycloak, Envoy, agentgateway, hickory-dns, Grafana/Loki, upstream AAuth person-server)

A Java implementation of the UMA-for-Agents proof-of-concept: a resource owner sets access
policy once, and other people's AI agents negotiate access against it — auto-granted for
permissive tiers, pending her approval for sensitive ones, with AAuth agent identity and
RFC 9421 proof-of-possession. The four custom services (uma-as authorization server, uma-pep
enforcement point, alice-portal, alice-vault MCP server) and the agent-side clients (grant
loop library, demo driver, stdio agent shim) are ported to Java and are wire-compatible with
the Python reference — the original Python demo driver and shim-test harness pass unchanged
against the Java servers, including the byte-exact `params_s256` canonicalization.

## Running it

```bash
make init        # local CA, TLS certs, signing keys, DNS for *.uma.lab
make up          # start the whole stack (Docker builds the Java services)
make smoke-test  # verify every service end to end
make demo-all SIM=1   # walk the demo acts; SIM auto-approves Alice's taps
make shim-test   # scripted MCP client drives the Java agent-shim
make audit       # print Alice's activity ledger
```

Requires Docker Desktop (or Engine + Compose v2) and `mkcert`. Portal at
`https://portal.uma.lab` (login `alice` / `alice-demo`), observability at
`https://grafana.uma.lab`. Local builds need JDK 25 + Maven (`mvn test`).
See `README.md`, `docs/ARCHITECTURE.md`, and `docs/PROTOCOL.md`.
