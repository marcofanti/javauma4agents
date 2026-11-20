"""Phase A spike evidence for the agent-shim's two client-facing boundaries.

Drives the Java shim with the pinned Python MCP SDK (ClientSession.initialize), records
what the handshake negotiates on stdio and on stateless streamable HTTP, and proves a pend
is handed back to a client that cannot be asked and then resumed by calling again:

  stdio   initialize → negotiated version and capabilities
  http    initialize → negotiated version; tools/list
  http    get_positions with a fresh key → PENDING (first contact, nobody to ask)
          approve only that key's one new pend → the same call again → resumed → data

Readiness is bounded and checks the process is alive. Nothing else in Alice's queue is
approved: the run snapshots the queue first and decides only its own new family.
"""

import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import time

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from uma4a_grant import AgentKeys

REPO = os.environ["UMA4A_REPO"]
SHIM = os.path.join(REPO, "clients/agent-shim/shim.py")
CACERT = os.path.join(REPO, "certs/rootCA.pem")
OIDC = "https://keycloak.uma.lab/realms/alice/protocol/openid-connect/token"
AS = "https://alice-as.uma.lab"
PORT = 9031
RESULTS: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(
        ("PASS: " if ok else "FAIL: ") + name + ("" if ok else f" — {detail}"),
        flush=True,
    )
    RESULTS.append((name, ok))


def shim_env(keystore: str, extra: dict | None = None) -> dict:
    return {
        **os.environ,
        "UMA4A_CACERT": CACERT,
        "UMA4A_KEYSTORE": keystore,
        "UMA4A_PEND_HANDBACK": "2",
        **(extra or {}),
    }


async def stdio_handshake() -> None:
    params = StdioServerParameters(
        command=sys.executable, args=[SHIM], env=shim_env("/tmp/spike-stdio.pem")
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(
                f"   stdio negotiated {init.protocol_version}; server "
                f"{init.server_info.name}; tools capability "
                f"{init.capabilities.tools is not None}",
                flush=True,
            )
            check(
                "stdio: the Python SDK's initialize is answered",
                bool(init.protocol_version),
            )


def owner_client() -> tuple[httpx.Client, dict]:
    client = httpx.Client(verify=CACERT, timeout=10.0)
    token = client.post(
        OIDC,
        data={
            "grant_type": "password",
            "client_id": "meridian-portal",
            "username": "alice",
            "password": "alice-demo",
        },
    ).json()["access_token"]
    return client, {"Authorization": f"Bearer {token}"}


def pending_families() -> set[str]:
    client, headers = owner_client()
    return {
        item["family"]
        for item in client.get(f"{AS}/owner/pending", headers=headers).json()
    }


def approve_own_pend(handle: str, before: set[str]) -> str:
    """Approve exactly the one pend this run created: new since `before`, filed under
    this run's own key. Anything else in Alice's queue is left as it was."""
    client, headers = owner_client()
    ours = [
        item
        for item in client.get(f"{AS}/owner/pending", headers=headers).json()
        if item.get("handle") == handle and item["family"] not in before
    ]
    if len(ours) != 1:
        return f"expected one new pend for {handle}, found {len(ours)}"
    r = client.post(
        f"{AS}/owner/pending/{ours[0]['family']}/decision",
        json={"decision": "approved"},
        headers=headers,
    )
    return "" if r.status_code == 200 else f"decision returned {r.status_code}"


async def http_session(keystore: str) -> None:
    url = f"http://127.0.0.1:{PORT}/mcp"
    async with streamable_http_client(url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"   http negotiated {init.protocol_version}", flush=True)
            check(
                "http: the Python SDK's initialize is answered",
                bool(init.protocol_version),
            )
            tools = {t.name for t in (await session.list_tools()).tools}
            check(
                "http: the three tools are listed",
                tools == {"get_positions", "get_transactions", "execute_trade"},
                str(tools),
            )
            if not os.path.exists(keystore):
                check("http: the shim wrote its fresh key", False, keystore)
                return
            handle = AgentKeys.load_or_create(keystore).thumbprint()
            before = pending_families()
            first = (await session.call_tool("get_positions", {})).content[0].text
            check(
                "http: a pend with nobody to ask is handed back, not held open",
                first.startswith("PENDING"),
                first[:120],
            )
            problem = approve_own_pend(handle, before)
            check(
                "http: exactly this run's pend is approved, nothing else",
                not problem,
                problem,
            )
            second = (await session.call_tool("get_positions", {})).content[0].text
            check(
                "http: calling again resumes the held request",
                "VTI" in second,
                second[:160],
            )


def wait_listening(shim: subprocess.Popen, attempts: int = 60) -> str:
    """Bounded readiness: the port accepts a connection, and the process is still alive.
    Returns an empty string when ready, else why not."""
    for _ in range(attempts):
        if shim.poll() is not None:
            return f"the shim exited with status {shim.returncode} before listening"
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1):
                return ""
        except OSError:
            time.sleep(1)
    return f"the shim was not listening on {PORT} after {attempts} attempts"


async def main() -> int:
    await stdio_handshake()
    keystore = f"/tmp/spike-http-{secrets.token_hex(6)}.pem"
    with open("/tmp/spike-http-shim.log", "w") as shim_log:
        shim = subprocess.Popen(
            [sys.executable, SHIM],
            stdout=subprocess.DEVNULL,
            stderr=shim_log,
            env=shim_env(
                keystore,
                {
                    "UMA4A_SHIM_TRANSPORT": "streamable-http",
                    "UMA4A_SHIM_HOST": "127.0.0.1",
                    "UMA4A_SHIM_PORT": str(PORT),
                },
            ),
        )
        try:
            problem = wait_listening(shim)
            check("http: the shim is listening within the bound", not problem, problem)
            if not problem:
                await http_session(keystore)
        finally:
            shim.terminate()
            shim.wait(timeout=10)
    if any(not ok for _, ok in RESULTS):
        with open("/tmp/spike-http-shim.log") as f:
            print(f.read()[-2000:], flush=True)
    print(
        json.dumps(
            {
                "passed": sum(ok for _, ok in RESULTS),
                "failed": sum(not ok for _, ok in RESULTS),
            }
        ),
        flush=True,
    )
    return 0 if all(ok for _, ok in RESULTS) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
