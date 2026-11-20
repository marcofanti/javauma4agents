"""Generate CPython ground-truth vectors from the pinned upstream modules.

Run through `make vectors`, which mounts conformance/upstream/lib on PYTHONPATH in a
pinned python image. Output is deterministic: keys come from fixed seeds and the clock is
fixed, so regenerating from the same pin reproduces the committed files byte for byte.
"""

import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import uma4a_http_sig
from aauth_vectors import aauth_vectors
from d_vectors import d_vectors
from clearance_digest import vectors as clearance_digest_vectors
from joint_vectors import vectors as joint_vectors

FIXED_NOW = 1_800_000_000
SEED = bytes(range(32))


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def httpsig_vectors() -> dict:
    """Signatures exactly as the pinned clients produce them, one per profile shape."""
    uma4a_http_sig.time.time = lambda: FIXED_NOW
    uma4a_http_sig.secrets.token_urlsafe = lambda n: "fixed-default-nonce"
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    raw_pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "get_positions", "arguments": {}},
        },
        separators=(",", ":"),
    ).encode()
    cases = {
        "required_only": {},
        "driver_nonce_tag": {"nonce": "n0nce-fixed", "tag": "web-bot-auth"},
        "signature_agent": {
            "nonce": "n0nce-agent",
            "tag": "web-bot-auth",
            "signature_agent": "https://agent.uma.lab/.well-known/"
            "http-message-signatures-directory",
        },
        "content_digest": {"nonce": "n0nce-digest", "body": body},
        "expires": {"nonce": "n0nce-exp", "expires_in": 30},
    }
    out = []
    for name, kw in cases.items():
        headers = uma4a_http_sig.sign(
            "POST",
            "gateway.uma.lab",
            "/mcp",
            "PoP rpt.value",
            key,
            "agent-vectors",
            **kw,
        )
        out.append(
            {
                "name": name,
                "method": "POST",
                "authority": "gateway.uma.lab",
                "path": "/mcp",
                "authorization": "PoP rpt.value",
                "signature_input": headers["Signature-Input"],
                "signature": headers["Signature"],
                "signature_agent": headers.get("Signature-Agent"),
                "content_digest": headers.get("Content-Digest"),
                "body_b64": base64.b64encode(body).decode() if "body" in kw else None,
            }
        )
    return {
        "now": FIXED_NOW,
        "keyid": "agent-vectors",
        "raw_public_b64url": b64url(raw_pub),
        "cases": out,
    }


JSON_VALUES = [
    {"symbol": "VTI", "side": "sell", "quantity": 40},
    {"note": "café ☕", "z": [1, 2.5, None, True], "a": {"nested": "ü"}},
    {"\U0001f600": 1, "￿": 2, "a": 3},
    {"price": 0.1, "big": 1e21, "small": 1.5e-7, "neg": -0.0, "int": 10},
    {"ctrl": "tab\tnew\nline\u007f\u0001", "quote": '"\\'},
    [{"b": 1, "a": 2}, "√2"],
]


def json_vectors() -> list:
    """The ensure_ascii=False compact sorted form, and the compact insertion-order form."""
    return [
        {
            "value": v,
            "compact_sorted_unicode": json.dumps(
                v, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
            "compact_ordered": json.dumps(v, separators=(",", ":")),
        }
        for v in JSON_VALUES
    ]


def main() -> None:
    dest = Path(sys.argv[1])
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "httpsig-vectors.json").write_text(
        json.dumps(httpsig_vectors(), indent=2, ensure_ascii=False) + "\n"
    )
    (dest / "pyjson-unicode-vectors.json").write_text(
        json.dumps(json_vectors(), indent=2, ensure_ascii=False) + "\n"
    )
    (dest / "phase-d-vectors.json").write_text(
        json.dumps(d_vectors(FIXED_NOW), indent=2, ensure_ascii=False) + "\n"
    )
    (dest / "aauth-vectors.json").write_text(
        json.dumps(aauth_vectors(FIXED_NOW), indent=2, ensure_ascii=False) + "\n"
    )
    (dest / "clearance-digest-vectors.json").write_text(
        json.dumps(list(clearance_digest_vectors()), indent=2, ensure_ascii=True) + "\n"
    )
    (dest / "joint-vectors.json").write_text(
        json.dumps(joint_vectors(), indent=2, ensure_ascii=True) + "\n"
    )


if __name__ == "__main__":
    main()
