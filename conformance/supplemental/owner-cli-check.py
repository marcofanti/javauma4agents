"""The Java owner CLI's actions observed by a pinned protocol client."""
import json
import os
from pathlib import Path
import runpy
import sys

import httpx
from uma4a_grant import AGREEMENT_FORMAT, AgentKeys, GRANT_TYPE, sign_contract, signed_headers

fixture = runpy.run_path("/driver/fixture_check.py")
run = os.environ["U4A_CLI_CHECK_RUN"]
phase = sys.argv[1]
record = Path(f"/driver/keys/owner-cli-{run}.json")
keypath = Path(f"/driver/keys/owner-cli-{run}.pem")
as_uri = fixture["AS"]
call = {"name": "get_positions", "arguments": {}}
rpc = fixture["rpc"]


def send(client, **fields):
    return client.post(as_uri + "/token", data={"grant_type": GRANT_TYPE, **fields}).json()


with httpx.Client(verify=os.environ["UMA4A_CACERT"], timeout=20) as client:
    if phase == "prepare":
        keys = AgentKeys.load_or_create(str(keypath))
        challenge = rpc(client, "tools/call", call)["error"]["data"]
        assert challenge["as_uri"] == as_uri
        offer = send(client, ticket=challenge["ticket"])
        terms = offer["required_claims"][0]["terms_template"]
        committed = send(client, ticket=offer["ticket"], claim_token=sign_contract(terms, keys, as_uri),
                         claim_token_format=AGREEMENT_FORMAT)
        assert committed["error"] == "request_submitted", committed.get("error")
        record.write_text(json.dumps({"ticket": committed["ticket"]}))
        print(terms["family"], keys.connection_handle())
    else:
        keys = AgentKeys.load_or_create(str(keypath))
        current = json.loads(record.read_text())
        if phase == "approved":
            grant = send(client, ticket=current["ticket"])
            assert grant.get("access_token"), grant.get("error")
            current["grant"] = grant["access_token"]
            record.write_text(json.dumps(current))
        result = rpc(client, "tools/call", call,
                     signed_headers("POST", fixture["AUTHORITY"], "/mcp", current["grant"], keys))
        if phase == "approved":
            assert "result" in result, result.get("error")
            print("PASS: the agent used the grant approved through the Java CLI")
        elif phase == "revoked":
            assert "error" in result
            record.unlink()
            keypath.unlink()
            print("PASS: the same grant stopped working after Java CLI revocation")
        else:
            raise ValueError(phase)
