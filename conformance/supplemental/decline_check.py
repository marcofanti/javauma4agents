"""Supplemental decline assertion for Phase A (port plan CX-5).

The pinned TypeScript check exercises a decline only when its second challenge arrives,
so a run can pass without it. This check drives the decline unconditionally, using only
the vendored upstream client library, against whichever stack is running:

  1. an unauthorized tools/call is challenged at the gateway;
  2. the ticket draws Alice's dictated terms (need_info);
  3. declining them is answered 403 request_denied;
  4. the negotiation is over: its ticket is no longer accepted.
"""

import os
import sys

import httpx

from uma4a_grant import GRANT_TYPE, mcp_call, mcp_meta, parse_challenge

GATEWAY = os.environ.get("UMA4A_GATEWAY", "https://gateway.uma.lab/mcp")
CACERT = os.environ.get("UMA4A_CA_BUNDLE", "/driver/rootCA.pem")
FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(
        ("ok   " if ok else "FAIL ") + name + ("" if ok else f" — {detail}"), flush=True
    )
    if not ok:
        FAILURES.append(name)


def main() -> int:
    client = httpx.Client(verify=CACERT, timeout=30.0)
    r = mcp_call(
        client,
        GATEWAY,
        "tools/call",
        {"name": "get_transactions", "arguments": {"account": "brokerage-main"}},
        mcp_meta("u4a-decline-check"),
    )
    challenge = parse_challenge(r.headers.get("www-authenticate", ""))
    check(
        "an unauthorized call is challenged",
        r.status_code == 401 and challenge is not None,
        f"{r.status_code} {r.text[:160]}",
    )
    if challenge is None:
        return 1
    token_url = f"{challenge.as_uri}/token"
    body = client.post(
        token_url, data={"grant_type": GRANT_TYPE, "ticket": challenge.ticket}
    ).json()
    check(
        "the ticket draws the owner's dictated terms",
        body.get("error") == "need_info",
        str(body)[:160],
    )
    held = body.get("ticket", "")
    declined = client.post(
        token_url, data={"grant_type": GRANT_TYPE, "ticket": held, "decline": "true"}
    )
    check(
        "a decline is answered 403 request_denied",
        declined.status_code == 403
        and declined.json().get("error") == "request_denied",
        f"{declined.status_code} {declined.text[:160]}",
    )
    again = client.post(token_url, data={"grant_type": GRANT_TYPE, "ticket": held})
    check(
        "and the declined negotiation's ticket is no longer accepted",
        again.status_code == 400 and again.json().get("error") == "invalid_grant",
        f"{again.status_code} {again.text[:160]}",
    )
    print(f"\n{4 - len(FAILURES)} passed, {len(FAILURES)} failed", flush=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
