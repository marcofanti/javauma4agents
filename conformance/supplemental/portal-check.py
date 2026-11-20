"""Exercise the pinned SPA's owner and organization routes with real OIDC sessions."""
from html.parser import HTMLParser
import os
from pathlib import Path
import time
from urllib.parse import urljoin

import httpx

CA = "/driver/rootCA.pem"


class LoginForm(HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs.get("action")


def sign_in(client, base, user, password, assets):
    anonymous = client.get(base + "/")
    anonymous.raise_for_status()
    assert anonymous.url.path == "/login"
    assert anonymous.content == (assets / "login.html").read_bytes()
    for asset in ("app.js", "styles.css"):
        response = client.get(f"{base}/static/{asset}")
        response.raise_for_status()
        assert response.content == (assets / asset).read_bytes()
    login = client.get(base + "/auth/login")
    login.raise_for_status()
    form = LoginForm()
    form.feed(login.text)
    assert form.action, "Keycloak did not serve its login form"
    complete = client.post(urljoin(str(login.url), form.action),
                           data={"username": user, "password": password})
    complete.raise_for_status()
    assert str(complete.url) == base + "/"
    assert complete.content == (assets / "index.html").read_bytes()


def json_api(client, base, path, method="GET", body=None):
    response = client.request(method, base + path, json=body)
    response.raise_for_status()
    return response.json()


with httpx.Client(verify=CA, follow_redirects=True, timeout=20) as client:
    base = "https://portal.uma.lab"
    sign_in(client, base, "alice", "alice-demo", Path("/assets/owner"))
    api = "/api/agent"
    for path, expected in (("/pending", list), ("/operators", list), ("/resource-servers", list),
                           ("/resources", list), ("/policies", dict), ("/connections", list),
                           ("/ledger", list)):
        assert isinstance(json_api(client, base, api + path), expected), path

    invalid_revoke = client.post(base + api + "/connections/revoke", json={})
    assert invalid_revoke.status_code == 400 and "name the connection" in invalid_revoke.text

    charter = json_api(client, base, api + "/organization")
    if not charter["enrolled"]:
        code = os.environ["ORG_JOIN_CODE"]
        preview = json_api(client, base, api + "/organization/preview", "POST", {"code": code})
        version = preview["envelope"]["charter_version"]
        joined = json_api(client, base, api + "/organization", "POST",
                          {"code": code, "agreed": True, "charter_version": version})
        assert joined["joined"] == "northwind"
        assert json_api(client, base, api + "/organization")["enrolled"]
        assert json_api(client, base, api + "/organization", "DELETE")["left"]
    else:
        assert charter["org"] == "northwind"

    joint = {"account": "meridian-joint", "tally": "https://joint-tally.uma.lab"}
    preview = json_api(client, base, api + "/joint/preview", "POST", joint)
    assert preview["mandate"]["account"] == joint["account"]
    review = json_api(client, base, api + "/joint", "POST", {**joint, "agreed": True})
    assert review["joined"] == joint["account"]
    assert any(account["account"] == joint["account"]
               for account in json_api(client, base, api + "/joint"))
    assert json_api(client, base, api + "/joint/" + joint["account"], "DELETE")["left"] == joint["account"]
    print("PASS: Alice signed in through the edge and used the organization and joint owner controls")


with httpx.Client(verify=CA, follow_redirects=True, timeout=20) as client:
    base = "https://carol-portal.uma.lab"
    sign_in(client, base, "carol", "carol-demo", Path("/assets/owner"))
    registry = "/api/agent/resource-servers"
    registered = next((entry for entry in json_api(client, base, registry)
                       if entry["client_id"] == "https://gateway.uma.lab"), None)
    if registered is None or registered["status"] != "active":
        challenge = client.post("https://gateway.uma.lab/mcp/carol",
                                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "get_positions", "arguments": {}}})
        assert challenge.status_code == 503 and challenge.json()["error"] == "authorization_pending"
        assert any(entry["status"] == "pending"
                   and entry["client_id"] == "https://gateway.uma.lab"
                   for entry in json_api(client, base, registry))
        decision = json_api(client, base, registry + "/decision", "POST",
                            {"client_id": "https://gateway.uma.lab", "decision": "approved"})
        assert decision["status"] == "active"
    for _ in range(25):
        resources = json_api(client, base, "/api/agent/resources")
        if any(str(row["_id"]).startswith("carol-vault/") for row in resources):
            break
        time.sleep(1)
    else:
        raise AssertionError("Carol's approved gateway did not publish her resources")
    assert all(not str(r["_id"]).startswith("alice-vault/") for r in resources)
    print("PASS: Carol used her own portal, session, and resource authority")
    started = time.monotonic()
    with client.stream("GET", base + "/api/agent/events", timeout=22) as events:
        events.raise_for_status()
        assert events.headers["content-type"].startswith("text/event-stream")
        comments = (line for line in events.iter_lines() if line.startswith(":"))
        assert "keepalive" in next(comments)
        assert "keepalive" in next(comments)
    elapsed = time.monotonic() - started
    assert elapsed >= 24, elapsed
    print(f"PASS: Carol's idle owner event feed stayed open for {elapsed:.1f}s")


with httpx.Client(verify=CA, follow_redirects=True, timeout=20) as client:
    base = "https://org-console.uma.lab"
    sign_in(client, base, "dana", "dana-demo", Path("/assets/console"))
    assert json_api(client, base, "/api/org/org")["name"] == "Northwind Capital"
    print("PASS: Dana's separate administrative session reached the organization console")
