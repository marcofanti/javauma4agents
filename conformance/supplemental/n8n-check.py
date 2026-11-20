"""Compose end-to-end check of the n8n workflow behind the Java enforcement point."""
import json
import runpy
import time
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from uma4a_grant import AgentKeys, parse_challenge, run_grant, signed_headers
from uma4a_http_sig import sign

AUTHORITY = "alice-as.uma.lab"
AS = f"https://{AUTHORITY}"
ORIGIN = "n8n.uma.lab"
MCP = f"https://{ORIGIN}/mcp"
UPSTREAM = "http://n8n:5678/mcp/u4a-protected"
RESOURCE = "n8n-book/get_positions"
CA = "/driver/rootCA.pem"


def wait_for(action, description):
    for _ in range(40):
        try:
            if answer := action():
                return answer
        except httpx.TransportError:
            pass
        time.sleep(1)
    raise AssertionError(description)


def check_stack():
    key = load_pem_private_key(Path("/owner/owner-ed25519.pem").read_bytes(), password=None)
    with httpx.Client(verify=CA, timeout=10) as client:
        def owner(method, path, data=None):
            body = None if data is None else json.dumps(data).encode()
            headers = sign(method, AUTHORITY, path, "", key, keyid="owner", body=body)
            if body is not None:
                headers["Content-Type"] = "application/json"
            response = client.request(method, AS + path, content=body, headers=headers)
            response.raise_for_status()
            return response.json()

        headers = {"accept": "application/json, text/event-stream",
                   "content-type": "application/json",
                   "mcp-protocol-version": "2025-06-18"}

        def rpc(url, method, arguments, *, notification=False, extra=None):
            payload = {"jsonrpc": "2.0", "method": method, "params": arguments}
            if not notification:
                payload["id"] = 1
            return client.post(url, json=payload, headers={**headers, **(extra or {})})

        arguments = {"name": "get_positions", "arguments": {}}
        direct = rpc(UPSTREAM, "tools/call", arguments)
        assert direct.status_code in (401, 403), direct.status_code
        print("PASS: n8n independently requires the sidecar's credential")

        prm_url = f"https://{ORIGIN}/.well-known/oauth-protected-resource/mcp"
        def published():
            response = client.get(prm_url)
            return response.json() if response.status_code == 200 else None

        doc = wait_for(published, "sidecar did not publish protected resource metadata")
        assert doc["resource"] == MCP and doc["authorization_servers"] == [AS]
        print("PASS: sidecar publishes its own resource and Alice's authority")

        def registration():
            refusal = rpc(MCP, "tools/call", arguments)
            matches = [rs for rs in owner("GET", "/owner/resource-servers")
                       if rs["client_id"] == f"https://{ORIGIN}"]
            if matches and matches[0]["status"] == "pending":
                assert refusal.status_code == 503 and refusal.json()["error"] == "authorization_pending"
                return matches[0]
            return None

        pending = wait_for(registration, "the owner did not receive the sidecar's introduction")
        assert pending["resource_uri"] == MCP + "/alice"
        owner("POST", "/owner/resource-servers/decision",
              {"client_id": pending["client_id"], "decision": "approved"})

        def registered():
            return any(item.get("_id") == RESOURCE or item.get("resource_id") == RESOURCE
                       for item in owner("GET", "/owner/resources"))

        wait_for(registered, "the AS did not pull the approved sidecar's tool surface")
        owner("POST", "/owner/policies", {
            "id": "n8n-read", "name": "Read the n8n book", "ask_me": False,
            "resources": [RESOURCE],
            "terms": {"purpose": "Read holdings from the n8n lab", "expires_in": 900,
                      "scope": ["positions:read"], "prohibited": ["model-training"]},
        })
        print("PASS: the signed introduction required an owner decision before enforcing her terms")

        initial = rpc(MCP, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "u4a-compose-check", "version": "1"}})
        initial.raise_for_status()
        if session := initial.headers.get("mcp-session-id"):
            headers["mcp-session-id"] = session
        rpc(MCP, "notifications/initialized", {}, notification=True).raise_for_status()
        refusal = rpc(MCP, "tools/call", arguments)
        assert refusal.status_code == 401
        challenge = parse_challenge(refusal.headers["www-authenticate"])
        assert challenge and challenge.as_uri == AS and challenge.ticket
        assert prm_url in refusal.headers["www-authenticate"]
        keys = AgentKeys()
        handle = keys.connection_handle()

        def approve(status):
            if "has been asked" in status:
                pending = [item for item in owner("GET", "/owner/pending")
                           if item.get("handle") == handle]
                for item in pending:
                    owner("POST", f"/owner/pending/{item['family']}/decision", {"decision": "approved"})

        grant = run_grant(client, AS, challenge.ticket, keys, lambda _terms: True,
                          on_status=approve, max_wait_s=40)
        unsigned = rpc(MCP, "tools/call", arguments, extra={"Authorization": f"PoP {grant}"})
        assert unsigned.status_code in (401, 403), unsigned.status_code
        body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": arguments}).encode()
        proof = signed_headers("POST", ORIGIN, "/mcp", grant, keys, body)
        result = client.post(MCP, content=body, headers={**headers, **proof})
        result.raise_for_status()
        assert "served_by" in result.text and "n8n" in result.text and "VTI" in result.text
        print("PASS: a signed call spent its grant through the sidecar and ran the pinned n8n workflow")

        unchanged = runpy.run_path("/driver/upstream-conformance.py")
        assert unchanged["main"](MCP, UPSTREAM) == 0
        print("PASS: the unchanged upstream integration conformance probe passed")

        owner("POST", "/owner/resource-servers/decision",
              {"client_id": pending["client_id"], "decision": "revoked"})
        result = client.post(MCP, content=body, headers={**headers,
                             **signed_headers("POST", ORIGIN, "/mcp", grant, keys, body)})
        assert result.status_code in (401, 403, 503), result.status_code
        print("PASS: withdrawal stopped the established sidecar from using that grant")


if __name__ == "__main__":
    check_stack()
