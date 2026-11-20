"""AAuth agent-token vectors: tokens minted by CPython and the verdict the pinned
`uma4a_aauth` reaches on each, at a fixed clock, against an issuer served from a dict.

Includes tokens minted by `aauth==0.3.2`, the package the pinned person server uses.
Deterministic: keys come from fixed seeds, and every clock read is fixed.
"""

import datetime
import uuid

import jwt
import jwt.api_jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import uma4a_aauth
import uma4a_jose

ISS = "https://ap.example"
AP_SEED = bytes(range(1, 33))
AGENT_SEED = bytes(range(33, 65))
OTHER_SEED = bytes(range(65, 97))


class _FixedDatetime(datetime.datetime):
    now_s = 0

    @classmethod
    def now(cls, tz=None):
        return datetime.datetime.fromtimestamp(cls.now_s, tz)


def _jwk(key, alg="Ed25519", **extra) -> dict:
    out = {k: v for k, v in uma4a_jose.ed25519_jwk(key).items() if k != "alg"}
    return {**out, **({"alg": alg} if alg else {}), **extra}


def _docs(keys, issuer=ISS) -> dict:
    meta = {"jwks_uri": f"{ISS}/jwks.json"}
    if issuer is not None:
        meta["issuer"] = issuer
    return {f"{ISS}/.well-known/aauth-agent.json": meta, f"{ISS}/jwks.json": {"keys": keys}}


def aauth_vectors(fixed_now: int) -> dict:
    _FixedDatetime.now_s = fixed_now
    jwt.api_jwt.datetime = _FixedDatetime
    ap = Ed25519PrivateKey.from_private_bytes(AP_SEED)
    agent = Ed25519PrivateKey.from_private_bytes(AGENT_SEED)
    other = Ed25519PrivateKey.from_private_bytes(OTHER_SEED)

    def mint(key=ap, alg="Ed25519", kid="ap-1", typ="aa-agent+jwt", drop=(), **over):
        claims = {"iss": ISS, "dwk": "aauth-agent.json", "sub": "aauth:planner@ap.example",
                  "jti": "at-1", "iat": fixed_now, "exp": fixed_now + 3600,
                  "cnf": {"jwk": _jwk(agent, "Ed25519" if alg == "Ed25519" else None)},
                  **over}
        for name in drop:
            claims.pop(name, None)
        header = {"typ": typ, **({"kid": kid} if kid else {})}
        return jwt.encode(claims, key, algorithm=alg, headers=header)

    def older(**over):
        return mint(alg="EdDSA", **over)

    current_keys = [_jwk(ap, kid="ap-1")]
    eddsa_keys = [_jwk(ap, "EdDSA", kid="ap-1")]
    bare_keys = [_jwk(ap, None, kid="ap-1")]
    cases = [
        ("current shape", mint(), current_keys, ISS),
        ("current without jti", mint(drop=("jti",)), current_keys, ISS),
        ("current without dwk and iat", mint(drop=("dwk", "iat")), current_keys, ISS),
        ("current, cnf.jwk names nothing", mint(cnf={"jwk": _jwk(agent, None)}),
         current_keys, ISS),
        ("current under a bare key", mint(), bare_keys, ISS),
        ("current under an EdDSA key", mint(), eddsa_keys, ISS),
        ("earlier shape", older(), eddsa_keys, ISS),
        ("earlier under a bare key", older(), bare_keys, ISS),
        ("earlier without dwk, jti, iat", older(drop=("dwk", "jti", "iat")), eddsa_keys, ISS),
        ("earlier under an Ed25519 key", older(), current_keys, ISS),
        ("another typ", mint(typ="aa-auth+jwt"), current_keys, ISS),
        ("an http issuer", mint(iss="http://ap.example"), current_keys, ISS),
        ("another dwk", mint(dwk="aauth-person.json"), current_keys, ISS),
        ("metadata naming another issuer", mint(), current_keys, "https://elsewhere.example"),
        ("metadata naming no issuer", older(), eddsa_keys, None),
        ("unknown kid", mint(kid="ap-2"), current_keys, ISS),
        ("no kid, one key", older(kid=None), [_jwk(ap, "EdDSA")], ISS),
        ("no kid, two keys", older(kid=None), [_jwk(ap, "EdDSA"), _jwk(other, "EdDSA")], ISS),
        ("an Ed448 key", older(), [{**_jwk(ap, "EdDSA", kid="ap-1"), "crv": "Ed448"}], ISS),
        ("signed by another key", mint(key=other), current_keys, ISS),
        ("no sub", mint(drop=("sub",)), current_keys, ISS),
        ("expired", mint(exp=fixed_now - 1), current_keys, ISS),
        ("expires now", mint(exp=fixed_now), current_keys, ISS),
        ("not yet valid", mint(nbf=fixed_now + 10), current_keys, ISS),
        ("subject under another domain", mint(sub="aauth:planner@other.example"),
         current_keys, ISS),
        ("malformed aauth subject", mint(sub="aauth:planner"), current_keys, ISS),
        ("case kept", mint(sub="aauth:Planner@ap.example"), current_keys, ISS),
        ("another subject form", older(sub="delegate-7"), eddsa_keys, ISS),
        ("no cnf", older(drop=("cnf",)), eddsa_keys, ISS),
        ("cnf.jwk Ed448", older(cnf={"jwk": {**_jwk(agent, None), "crv": "Ed448"}}),
         eddsa_keys, ISS),
        ("sub-agent", mint(sub="aauth:planner+search1@ap.example",
                           parent_agent="aauth:planner@ap.example"), current_keys, ISS),
        ("parent under another domain", mint(parent_agent="aauth:planner@other.example"),
         current_keys, ISS),
        ("its own parent", mint(parent_agent="aauth:planner@ap.example"), current_keys, ISS),
    ]

    import aauth
    import aauth_signing.tokens.agent_token as agent_token_module

    agent_token_module.time.time = lambda: fixed_now
    agent_token_module.uuid.uuid4 = lambda: uuid.UUID(int=7)
    posta_keys = [{**aauth.public_key_to_jwk(ap.public_key()), "kid": "ap-1",
                   "alg": "EdDSA", "use": "sig"}]
    posta = aauth.create_agent_token(
        iss=ISS, sub="aauth:3f1c2e7a@ap.example",
        cnf_jwk=aauth.public_key_to_jwk(agent.public_key()),
        private_key=ap, kid="ap-1", ps="https://ps.example")
    cases.append(("minted by aauth 0.3.2", posta, posta_keys, ISS))

    out = []
    for name, token, keys, issuer in cases:
        docs = _docs(keys, issuer)
        tokens = uma4a_aauth.AgentTokens(lambda url, d=docs: d[url], [ISS],
                                         clock=lambda: fixed_now)
        try:
            verdict = {"claims": tokens.verify(token)}
        except uma4a_aauth.Refused as exc:
            verdict = {"refused": str(exc)}
        out.append({"name": name, "token": token, "docs": docs, **verdict})
    return {"now": fixed_now, "issuer": ISS, "cases": out}
