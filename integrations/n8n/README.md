# Put the Java sidecar in front of n8n

The lab runs n8n 2.38.6 with the pinned workflow and header-auth fixture. The
Java enforcement point serves the agent-facing MCP endpoint, and the n8n
server stays on the Compose network.

```sh
make up
make n8n-check
```

The check verifies resource-server introduction, owner approval, metadata,
grant negotiation, execution in n8n, and withdrawal. It also runs the
unchanged upstream integration checker against the sidecar and the upstream
endpoint. The lab serves the sidecar through Envoy at
`https://n8n.uma.lab/mcp`.

To run a sidecar for your own workflow, import the
[pinned starter workflow](../../conformance/upstream/integrations/n8n/workflow-template.json)
into n8n and publish it. Configure **Header auth** on its MCP Server Trigger.
Copy [.env.example](.env.example) to `.env` and set the workflow's production
endpoint and the header credential. Fill [tools.json](tools.json) with one
resource ID and scope list per tool. Set `single_use` for a one-operation
grant or declare the tool's `consequence`. The sidecar validates this
file on startup.

Run `docker compose up -d --build` from this directory. Put your TLS proxy
in front of the published loopback port `8443`. Set
`UMA_EXPECTED_AUTHORITY` and `UMA_PEP_SCHEME` to the agent-facing address.
The owner approves the sidecar under **Resource servers** in her portal
and writes terms over the tools it publishes.

The sidecar forwards the body, MCP session and transport headers, and the
agreement digest. It strips the caller's authorization and proof headers.
It authenticates upstream with the workflow's own header credential.
