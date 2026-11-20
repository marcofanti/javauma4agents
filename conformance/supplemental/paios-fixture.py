"""Supply owner consent before the pinned pAI-OS negotiation probes."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import runpy
import sys
import time
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import load_pem_private_key
import httpx

sys.path.insert(0, os.environ.get("U4A_LIB", "/opt/u4a/lib"))
from uma4a_grant import AgentKeys, GrantDenied
from uma4a_http_sig import sign

ft = runpy.run_path("/opt/u4a/paios_check.py")
authority = "alice-as.uma.lab"
run = os.environ["U4A_CHECK_RUN"]
keyfile = f"/driver/keys/paios-t1-{run[:8]}.pem"
fresh = f"/driver/keys/paios-fresh-{run}.pem"
pinned_trade = f"/driver/keys/paios-t3-{run[:8]}.pem"
ca = os.environ["U4A_CA_BUNDLE"]

def negotiate(tool, key, operation=None):
    with httpx.Client(verify=ca) as client:
        return ft["negotiate"](client, tool, key, operation)

def owner_call(method, path, body=None):
    key = load_pem_private_key(Path("/owner/owner-ed25519.pem").read_bytes(), password=None)
    raw = None if body is None else json.dumps(body).encode()
    headers = sign(method, authority, path, "", key, keyid="owner", body=raw)
    if raw is not None:
        headers["Content-Type"] = "application/json"
    result = httpx.request(method, "https://" + authority + path, headers=headers,
                           content=raw, verify=ca, timeout=10)
    result.raise_for_status()
    return result.json()

def refuse(tool, key, operation=None):
    try:
        negotiate(tool, key, operation)
    except GrantDenied as error:
        assert "request_denied" in str(error), str(error)
        return
    raise AssertionError("an agent received a grant without the needed consent")

phase = sys.argv[1]
if phase == "seed":
    handle = AgentKeys.load_or_create(keyfile).connection_handle()
    with ThreadPoolExecutor(max_workers=1) as executor:
        grant = executor.submit(negotiate, "get_positions", keyfile)
        for _ in range(45):
            found = [p for p in owner_call("GET", "/owner/pending") if p.get("handle") == handle]
            if found:
                assert len(found) == 1 and found[0]["kind"] == "connection", found
                owner_call("POST", f"/owner/pending/{found[0]['family']}/decision",
                           {"decision": "approved"})
                break
            assert not grant.done(), "expected a first-contact request"
            time.sleep(1)
        else:
            raise AssertionError("the owner's test agent never appeared pending")
        assert grant.result(timeout=25)
    print("PASS: the owner's signed fixture approval admitted its named test agent")
elif phase == "verify":
    log = Path(os.environ["U4A_ABILITY_LOG"])
    offset = log.stat().st_size
    original_uuid4 = uuid.uuid4

    def choose_prepared_run():
        # The checker's first UUID only names the two disposable keystore files.
        # Restore the generator before it makes a request or creates an agent.
        uuid.uuid4 = original_uuid4
        return uuid.UUID(hex=run)

    try:
        with patch.object(uuid, "uuid4", side_effect=choose_prepared_run):
            assert ft["main"]() == 0, "the unchanged pAI-OS entry point failed"
        refuse("get_positions", fresh)
        print("PASS: pAI-OS refused an unfamiliar agent despite tier1 standing consent")
        refuse("execute_trade", keyfile, ft["ORDER"])
        print("PASS: pAI-OS refused an ask-me operation by the established agent")
        with log.open("rb") as stream:
            stream.seek(offset)
            entries = [json.loads(line) for line in stream if line.strip()]
        assert sum(e.get("event") == "decided.standing" for e in entries) == 1
        assert sum(e.get("event") == "cannot-ask" for e in entries) == 3
        print("PASS: the ability logged one standing authorization and all three refusals")
    finally:
        for fixture in (keyfile, fresh, pinned_trade):
            Path(fixture).unlink(missing_ok=True)
else:
    raise ValueError(phase)
