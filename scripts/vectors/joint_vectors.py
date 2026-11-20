"""The pinned mandate, fold and count vectors used by each Java participant."""
import uma4a_joint as joint


def vectors():
    holders = [
        {"owner": "alice", "issuer": "https://alice-as.uma.lab"},
        {"owner": "carol", "issuer": "https://carol-as.uma.lab"},
    ]
    weighted = [
        {**holders[0], "weight": 3},
        {**holders[1], "weight": 2},
        {"owner": "dana", "issuer": "https://dana-as.uma.lab", "weight": 1},
    ]
    unicode_holders = [
        {"owner": "\U00010000", "issuer": "https://a.example"},
        {"owner": "\ue000", "issuer": "https://b.example"},
    ]
    inputs = [
        {"resources": ["book/get", "book/write"], "holders": holders, "rule": {"kind": "all"}},
        {"resources": "book/*", "holders": weighted, "rule": {"kind": "any"}},
        {"resources": "book/*", "holders": weighted, "rule": {"kind": "threshold", "threshold": 4}},
        {"resources": ["\U00010000/read", "\ue000/read"], "holders": unicode_holders},
        {"resources": ["\ue000/read", "\U00010000/read"], "holders": list(reversed(unicode_holders))},
    ]
    mandates = []
    for doc in inputs:
        normal = joint.validate_mandate(doc)
        votes = [
            {},
            {"alice": "allow"},
            {"carol": "refuse"},
            {"alice": "allow", "carol": "allow"},
            {"alice": "refuse", "carol": "allow", "dana": "refuse"},
        ]
        mandates.append({"input": doc, "normal": normal, "digest": joint.mandate_digest(doc),
                         "summary": joint.describe(normal),
                         "counts": [{"votes": v, "result": joint.tally(normal, v)} for v in votes]})
    quotes = [
        ("alice", {"name": "book", "resources": ["book/*"], "ask_me": False,
                   "terms": {"expires_in": 3600, "scope": ["read", "write"], "prohibited": ["keep"]}}),
        ("carol", {"name": "book", "resources": ["book/*"], "ask_me": True,
                   "terms": {"expires_in": 120, "scope": ["read"], "prohibited": ["share"]}}),
    ]
    folded, _ = joint.fold(quotes, ["book/*"])
    invalid = []
    for doc, floor in [
        (inputs[1], 2),
        (inputs[2], 3),
        ({**inputs[0], "holders": [holders[0], holders[0]]}, 0),
        ({**inputs[0], "holders": [{**holders[0], "weight": True}, holders[1]]}, 0),
        ({**inputs[0], "rule": {"kind": "threshold", "threshold": 3}}, 0),
    ]:
        try:
            joint.validate_mandate(doc, floor)
        except ValueError as refused:
            invalid.append({"input": doc, "floor": floor, "error": str(refused)})
    return {"mandates": mandates, "invalid": invalid,
            "fold": {"quotes": [q for _, q in quotes], "resources": ["book/*"], "result": folded}}
