"""Phase D ground truth from the pinned modules: her rules, assurance, consequence and
sub-agent introductions.

Imported by generate.py, which runs with conformance/upstream/lib and
conformance/upstream/services/uma-as on PYTHONPATH. Deterministic: keys come from fixed
seeds and PyJWT's clock is frozen at FIXED_NOW.
"""

import copy
import datetime as _dt
import itertools

import jwt.api_jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import assurance
import introduction
import policy
import uma4a_consequence
import uma4a_grant

AS_URI = "https://alice-as.uma.lab"


def outcome(fn, *args):
    """What the pinned function returns, or the exception it raises."""
    try:
        return {"ok": fn(*args)}
    except Exception as exc:  # noqa: BLE001 - the type is part of the vector
        return {"error": str(exc), "type": type(exc).__name__}


# --- rules ----------------------------------------------------------------------

VALIDATE_CASES = [
    [],
    [{"when": ["assurance.accountability_below:1"], "then": "ask"}],
    [{"when": "standing.first_at_tier", "then": "ask"}],
    [{"when": ["standing.approved_at_tier", "standing.age_above:90d",
               "standing.never_revoked"], "then": "auto"}],
    [{"when": ["standing.first_party"], "then": "auto"}],
    [{"when": ["assurance.accountability_below:2"], "then": "auto"}],
    [{"when": ["standing.denials_above:1"], "then": "auto"}],
    [{"when": ["request.mission_absent"], "then": "auto"}],
    [{"when": ["request.consequence_at_or_above:irreversible"], "then": "auto"}],
    [{"when": ["request.consequence_at_or_above:catastrophic"], "then": "ask"}],
    [{"when": ["request.consequence_at_or_above: Irreversible "], "then": "ask"}],
    [{"when": ["standing.none", "assurance.accountability_below:1"], "then": "refuse"}],
    [{"when": ["standing.age_above"], "then": "auto"}],
    [{"when": ["standing.age_above:"], "then": "auto"}],
    [{"when": ["standing.age_above:soon"], "then": "auto"}],
    [{"when": ["standing.age_above:1.5h"], "then": "auto"}],
    [{"when": ["standing.age_above: 2d "], "then": "auto"}],
    [{"when": ["standing.age_above:1_0s"], "then": "auto"}],
    [{"when": ["standing.age_above:1__0s"], "then": "auto"}],
    [{"when": ["standing.age_above:١٢d"], "then": "auto"}],
    [{"when": ["standing.age_below:-3d"], "then": "ask"}],
    [{"when": ["standing.calls_above:-1"], "then": "ask"}],
    [{"when": ["standing.calls_above:+2"], "then": "ask"}],
    [{"when": ["standing.calls_above:2.0"], "then": "ask"}],
    [{"when": ["assurance.binding_below:-1"], "then": "ask"}],
    [{"when": ["assurance.binding_below:x"], "then": "ask"}],
    [{"when": ["standing.none:yes"], "then": "ask"}],
    [{"when": ["standing.bogus"], "then": "ask"}],
    [{"when": [""], "then": "ask"}],
    [{"when": "", "then": "ask"}],
    [{"when": [], "then": "ask"}],
    [{"then": "ask"}],
    [{"when": ["standing.none"], "then": "sometimes"}],
    [{"when": ["standing.none"]}],
    [{"when": ["standing.none"], "then": None}],
    [{"when": ["standing.none"], "then": "ask"},
     {"when": ["standing.introduced"], "then": "auto"}],
    [{"when": ["standing.lineage_new_at_tier", "standing.first_at_tier"], "then": "ask"}],
    [{"when": ["request.reason_absent", "request.max_expiry"], "then": "refuse"}],
]


def standing(active=True, age=10 * 86400, first_at_tier=False, first_party=False,
             introduced=False, lineage_new=False, approved=("tier1",), revocations=0,
             denials=0, tiers=("tier1",), calls=0):
    return {"active": active, "age_seconds": age, "first_at_tier": first_at_tier,
            "first_party": first_party, "introduced": introduced,
            "lineage_new_at_tier": lineage_new, "approved_tiers": list(approved),
            "revocations": revocations,
            "trajectory": {"denials": denials, "tiers": list(tiers), "calls": calls}}


def facts(st=None, axes=(1, 0, 0), expires_in=60, max_expires=900, reason="why",
          mission=None, consequence=None, tier="tier1"):
    return {"assurance": {"binding": axes[0], "provenance": axes[1],
                          "accountability": axes[2]},
            "standing": st if st is not None else standing(),
            "request": {"expires_in": expires_in, "max_expires_in": max_expires,
                        "reason": reason, "mission": mission, "consequence": consequence},
            "tier": tier}


TIER_RULES = [
    [],
    [{"when": ["assurance.accountability_below:1"], "then": "ask"}],
    [{"when": ["standing.first_at_tier"], "then": "ask"}],
    [{"when": ["standing.first_party"], "then": "auto"}],
    [{"when": ["standing.approved_at_tier", "standing.never_revoked"], "then": "auto"},
     {"when": ["standing.denials_above:2"], "then": "refuse"}],
    [{"when": ["standing.none", "assurance.accountability_below:1"], "then": "refuse"}],
    [{"when": ["request.consequence_at_or_above:irreversible"], "then": "ask"}],
    [{"when": ["request.consequence_unknown"], "then": "ask"}],
    [{"when": ["request.reason_absent"], "then": "ask"}],
    [{"when": ["request.mission_absent"], "then": "ask"}],
    [{"when": ["request.max_expiry"], "then": "ask"}],
    [{"when": ["standing.age_above:7d"], "then": "auto"}],
    [{"when": ["standing.age_below:10d"], "then": "ask"}],
    [{"when": ["standing.tiers_above:1"], "then": "ask"},
     {"when": ["standing.calls_above:2"], "then": "refuse"}],
    [{"when": ["standing.introduced"], "then": "ask"}],
    [{"when": ["standing.lineage_new_at_tier", "standing.first_at_tier"], "then": "ask"}],
    [{"when": ["standing.revoked_before"], "then": "refuse"}],
    # Stored before validation, or edited directly: each fails towards her.
    [{"when": ["standing.renamed"], "then": "ask"}],
    [{"when": ["standing.renamed"], "then": "auto"}],
    [{"when": ["standing.age_above"], "then": "auto"}],
    [{"when": ["standing.age_below"], "then": "ask"}],
    [{"then": "refuse"}],
    [{"when": ["standing.none"], "then": "sometimes"}],
    [{"when": ["standing.none", 5], "then": "ask"}],
    [{"when": [5, "standing.none"], "then": "ask"}],
    "not-a-list",
    [{"when": ["assurance.bogus_below:1"], "then": "ask"}],
]

FACT_ROWS = [
    facts(),
    facts(standing(active=False, age=None, first_at_tier=True, lineage_new=True,
                   approved=())),
    facts(axes=(1, 1, 2)),
    facts(standing(first_party=True), axes=(1, 0, 2)),
    facts(standing(age=7 * 86400)),
    facts(standing(age=7 * 86400 + 1)),
    facts(standing(age=10 * 86400 - 1)),
    facts(standing(denials=2, tiers=("tier1", "tier2"), calls=2)),
    facts(standing(denials=3, tiers=("tier1", "tier2", "tier3"), calls=3)),
    facts(standing(revocations=1, first_at_tier=True, introduced=True, lineage_new=True)),
    facts(expires_in=900),
    facts(reason=None),
    facts(reason=""),
    facts(reason="   "),
    facts(reason="\u00a0\u2003"),
    facts(reason="\u00a0 x \u2003"),
    facts(reason="\u200b"),
    facts(reason="\x1c\x85"),
    facts(mission={"approver": "https://ps.example", "s256": "a" * 43}),
    facts(consequence="irreversible"),
    facts(consequence="reversible"),
    facts(consequence="catastrophic"),
    facts(consequence=" Irreversible\n"),
]


def evaluate_cases() -> list:
    out = []
    for rules, ask_me, row in itertools.product(TIER_RULES, (False, True), FACT_ROWS):
        tier = {"ask_me": ask_me, "rules": copy.deepcopy(rules)}
        result = outcome(policy.evaluate, tier, copy.deepcopy(row))
        if "ok" in result:
            result = {"ok": list(result["ok"])}
        out.append({"tier": tier, "facts": row, **result})
    return out


DURATIONS = ["90d", "12h", "45m", "30s", "60", " 2d ", "1.5h", "0.5d", "1e1m", ".5h",
             "5.", "1_0s", "-3d", "+4h", "١٢d", "soon", "", "d", "1__0s",
             "nan", "1e400d", "inf"]

TIERS_FOR_NEW = {"tier1": {"resources": ["alice-vault/get_positions"]}}
REGISTERED = ["alice-vault/get_positions", "alice-vault/get_transactions",
              "alice-vault/execute_trade"]

NEW_TIER_CASES = [
    ("fresh", {"resources": ["alice-vault/get_transactions"],
               "terms": {"purpose": "p", "expires_in": 900}}),
    ("full", {"name": "Full", "resources": [], "ask_me": 1,
              "rules": [{"when": ["standing.first_party"], "then": "auto"}],
              "terms": {"purpose": "p", "expires_in": "3600", "scope": ["s"],
                        "prohibited": ["x"], "per_operation": "yes",
                        "constraints": {"accounts": ["a"]}}, "clearance": None}),
    ("floaty", {"terms": {"purpose": "p", "expires_in": 3600.9}}),
    ("emptyclear", {"terms": {"purpose": "p", "expires_in": 9}, "clearance": {}}),
    ("bad id!", {"terms": {"purpose": "p", "expires_in": 9}}),
    ("", {"terms": {"purpose": "p", "expires_in": 9}}),
    ("café-Ⅷ_1", {"terms": {"purpose": "p", "expires_in": 9}}),
    ("tier1", {"terms": {"purpose": "p", "expires_in": 9}}),
    ("unreg", {"resources": ["alice-vault/nope"], "terms": {"purpose": "p", "expires_in": 9}}),
    ("taken", {"resources": ["alice-vault/get_positions"],
               "terms": {"purpose": "p", "expires_in": 9}}),
    ("nopurpose", {"terms": {"expires_in": 9}}),
    ("zero", {"terms": {"purpose": "p", "expires_in": 0}}),
    ("words", {"terms": {"purpose": "p", "expires_in": "soon"}}),
    ("relax", {"terms": {"purpose": "p", "expires_in": 9},
               "rules": [{"when": ["standing.denials_above:1"], "then": "auto"}]}),
    ("chars", {"resources": "alice-vault/get_positions",
               "terms": {"purpose": "p", "expires_in": 9}}),
]

PATCH_CASES = [
    {"ask_me": True},
    {"ask_me": ""},
    {"rules": [{"when": ["standing.introduced"], "then": "ask"}]},
    {"rules": [{"when": ["standing.introduced"], "then": "auto"}]},
    {"terms": {"purpose": "changed", "scope": ["x"], "constraints": {"a": 1},
               "template_id": "ignored"}},
    {"clearance": None},
    {"clearance": {}},
    {"clearance": "licensed"},
    {"resources": ["ignored"]},
]


def policy_vectors() -> dict:
    validate = []
    for rules in VALIDATE_CASES:
        result = outcome(policy.validate_rules, copy.deepcopy(rules))
        validate.append({"rules": rules, **({"ok": True} if "ok" in result else result)})
    new_tier = []
    for tier_id, spec in NEW_TIER_CASES:
        new_tier.append({"id": tier_id, "spec": spec,
                         **outcome(policy.new_tier, tier_id, copy.deepcopy(spec),
                                   TIERS_FOR_NEW, set(REGISTERED), set(), "alice")})
    patch = []
    base = policy.defaults()["tier2"]
    for p in PATCH_CASES:
        patch.append({"tier": base, "patch": p,
                      **outcome(policy.apply_patch, copy.deepcopy(base), copy.deepcopy(p))})
    return {
        "defaults": policy.defaults(),
        "vocabulary": policy.vocabulary(),
        "enforced": {tid: policy.enforced_prohibitions(t)
                     for tid, t in policy.defaults().items()},
        "durations": [{"text": d, **outcome(policy.parse_duration, d)} for d in DURATIONS],
        "lanes": [{"axes": a, "lane": policy.pend_lane(a)}
                  for a in ({}, {"accountability": 1}, {"accountability": 2},
                            {"accountability": 3})],
        "validate": validate,
        "evaluate": evaluate_cases(),
        "new_tier": new_tier,
        "apply_patch": patch,
    }


# --- assurance and consequence ---------------------------------------------------

IDENTITIES = [
    {},
    {"level": "pseudonymous", "key_bound": True},
    {"level": "identified", "iss": "https://ps.uma.lab", "sub": "a", "key_bound": True},
    {"key_bound": True, "client_metadata": {"client_id": "https://x/agent.json",
                                            "verified": False}},
    {"key_bound": True, "client_metadata": {"client_id": "https://x/agent.json",
                                            "verified": True}},
    {"key_bound": True, "operator_attested": True,
     "client_metadata": {"client_id": "https://x/agent.json", "verified": True,
                         "client_name": "Sterling & Vance"}},
    {"key_bound": True, "operator_attested": True,
     "client_metadata": {"client_id": "https://x/agent.json", "verified": False}},
    {"level": "identified", "iss": "", "client_metadata": {"client_name": "",
                                                           "client_id": ""}},
    {"iss": "https://{operator}.example",
     "client_metadata": {"client_name": "Evil {issuer} {0} Ltd", "verified": True}},
]


def assurance_vectors() -> dict:
    assessed = []
    for identity in IDENTITIES:
        axes = assurance.assess(identity)
        assessed.append({"identity": identity, "axes": axes,
                         "notes": assurance.describe(axes, identity)})
    described = [{"identity": IDENTITIES[-1], "axes": axes,
                  "notes": assurance.describe(axes, IDENTITIES[-1])}
                 for axes in ({"binding": 0, "provenance": 0, "accountability": 0},
                              {"accountability": 2}, {"accountability": 7})]
    return {"assess": assessed, "describe": described}


CLASS_VALUES = ["reversible", "compensatable", "forward_recoverable", "irreversible",
                " Irreversible\n", "IRREVERSIBLE", "catastrophic", "", None, 3,
                " reversible "]
ANNOTATIONS = [None, {}, {"readOnlyHint": True}, {"destructiveHint": True},
               {"destructiveHint": False}, {"reversibleHint": True},
               {"reversibleHint": False, "readOnlyHint": True},
               {"reversibleHint": "yes", "destructiveHint": True}, "not-a-dict"]


def consequence_vectors() -> dict:
    return {
        "normalise": [{"value": v, "class": uma4a_consequence.normalise(v)}
                      for v in CLASS_VALUES],
        "at_or_above": [{"actual": a, "floor": f,
                         "result": uma4a_consequence.at_or_above(a, f)}
                        for a in CLASS_VALUES for f in CLASS_VALUES],
        "annotations": [{"annotations": a,
                         "class": uma4a_consequence.from_mcp_annotations(a)}
                        for a in ANNOTATIONS],
        "single_use": [{"value": v, "single_use": uma4a_consequence.single_use(v)}
                       for v in CLASS_VALUES],
    }


# --- introductions ----------------------------------------------------------------

class _FrozenDatetime(_dt.datetime):
    now_value = 0

    @classmethod
    def now(cls, tz=None):  # noqa: D102 - PyJWT's only use of the clock
        return _dt.datetime.fromtimestamp(cls.now_value, tz=tz)


def _keys(seed: int) -> uma4a_grant.AgentKeys:
    return uma4a_grant.AgentKeys(
        key=Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32))


def introduction_vectors(now: int) -> dict:
    _FrozenDatetime.now_value = now
    jwt.api_jwt.datetime = _FrozenDatetime
    uma4a_grant.time.time = lambda: now
    parent, child, other = _keys(1), _keys(2), _keys(3)
    child_jkt = child.thumbprint()

    def signed(keys, sub, aud=AS_URI, ttl=300, at=now, **headers):
        uma4a_grant.time.time = lambda: at
        token = uma4a_grant.sign_introduction(keys, sub, aud, ttl)
        uma4a_grant.time.time = lambda: now
        if headers:
            h = jwt.get_unverified_header(token)
            h.update(headers)
            claims = jwt.decode(token, options={"verify_signature": False})
            token = jwt.encode(claims, keys.key, algorithm="EdDSA",
                               headers={k: v for k, v in h.items() if k != "alg"})
        return token

    good = signed(parent, child_jkt)
    tampered = good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB")
    cases = {
        "good": good,
        "other_child": signed(parent, other.thumbprint()),
        "other_audience": signed(parent, child_jkt, aud="https://carol-as.uma.lab"),
        "expired": signed(parent, child_jkt, ttl=-1),
        "issued_later": signed(parent, child_jkt, at=now + 120),
        "wrong_typ": signed(parent, child_jkt, typ="JWT"),
        "no_jwk": signed(parent, child_jkt, jwk="not-a-key"),
        "tampered": tampered,
        "not_a_jws": "not.a.jws.at.all",
        "empty": "",
        "too_big": "a" * 4097,
    }
    verify = []
    for name, token in cases.items():
        result = outcome(introduction.verify_claim, token, child_jkt, AS_URI)
        if "ok" in result:
            result = {"ok": {"parent_jwk": result["ok"]["parent_jwk"],
                             "agent_token": result["ok"]["agent_token"],
                             "jti": result["ok"]["jti"], "exp": result["ok"]["exp"]}}
        verify.append({"name": name, "token": token, **result})

    active = {"status": "active", "tiers_approved": ["tier2"]}
    admit_cases = [
        (None, None, True, 0, 3),
        ({"status": "revoked", "tiers_approved": ["tier2"]}, None, True, 0, 3),
        ({"status": "active", "tiers_approved": []}, None, True, 0, 3),
        ({**active, "parent_handle": "jkt:grandparent"}, None, True, 0, 3),
        (active, {"status": "revoked"}, True, 0, 3),
        (active, None, False, 0, 3),
        (active, None, True, 3, 3),
        (active, None, True, 2, 3),
        (active, {"status": "active"}, True, 0, 3),
    ]
    admit = [{"parent": p, "child_prior": c, "same_operator": s, "live_children": n,
              "fanout": f, **({"ok": True} if "ok" in (r := outcome(
                  introduction.admit, p, c, s, n, f)) else r)}
             for p, c, s, n, f in admit_cases]
    return {"now": now, "audience": AS_URI, "child_jkt": child_jkt,
            "verify": verify, "admit": admit}


def d_vectors(now: int) -> dict:
    return {
        "policy": policy_vectors(),
        "assurance": assurance_vectors(),
        "consequence": consequence_vectors(),
        "introduction": introduction_vectors(now),
    }
