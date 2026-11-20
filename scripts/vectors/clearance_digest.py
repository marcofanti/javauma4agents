"""CPython oracle for the Phase E2 RPT clearance digest."""
import base64
import hashlib
import json
import sys


def vectors():
    inputs = [
        {},
        {"state": "NY", "broker": True, "registration": ["SEC", "FINRA"]},
        {"\ue000": "BMP private use", "\U00010000": "supplementary", "z": "last ASCII"},
        {"small": 1e-7, "threshold": 1e-6, "decimal": 1.0, "zero": -0.0,
         "long": 1e20, "tiny": 1e-29, "large": 9007199254740993},
        {"\U0001f512": "\u00e9\n\t", "nested": {"\u2028": "\\path", "x": [1, 1.0, False]}},
    ]
    for facts in inputs:
        canonical = json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode()).digest()
        yield {"facts": facts, "canonical": canonical,
               "digest": "s256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")}


if __name__ == "__main__":
    json.dump(list(vectors()), sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")
