"""Leave one pending owner decision from an unrelated key, then print its family."""
import sys
import httpx
from uma4a_grant import AgentKeys, GrantDenied, mcp_call, mcp_meta, parse_challenge, run_grant

client = httpx.Client(verify="/driver/rootCA.pem", timeout=30.0)
r = mcp_call(client, "https://gateway.uma.lab/mcp", "tools/call",
             {"name": "get_positions", "arguments": {}}, mcp_meta("synthetic-pend"))
challenge = parse_challenge(r.headers.get("www-authenticate", ""))
keys = AgentKeys.load_or_create("/tmp/synthetic-other-key.pem")
try:
    run_grant(client, challenge.as_uri, challenge.ticket, keys, lambda t: True, max_wait_s=1)
except GrantDenied:
    pass
token = client.post("https://keycloak.uma.lab/realms/alice/protocol/openid-connect/token",
                    data={"grant_type": "password", "client_id": "meridian-portal",
                          "username": "alice", "password": "alice-demo"}).json()["access_token"]
pending = client.get("https://alice-as.uma.lab/owner/pending",
                     headers={"Authorization": f"Bearer {token}"}).json()
mine = [p["family"] for p in pending if p.get("handle") == keys.thumbprint()]
print("SYNTHETIC", mine[0] if mine else "none", "handle", keys.thumbprint())
sys.exit(0 if mine else 1)
