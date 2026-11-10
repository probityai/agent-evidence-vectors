"""Build the principal-action cases byte-identically.

Each case is the producer's Ed25519 public key, the verifier's pin set and one
DSSE envelope over an in-toto Statement v1 in RFC 8785 bytes whose predicate is
``principal-action/v1`` (``spec/predicates/principal-action.md``): one action
and up to four principals, each bound to its credential by digest and to its
issuer key by RFC 7638 thumbprint.

The baseline names all four roles with one key type each (user and approver
OKP Ed25519, agent EC P-256, sponsor RSA 2048), a user credential whose ``act``
names the agent, and an approval the approver signed, so it is ``strict``.
Every rejected case changes one thing in that baseline, re-signed by the
producer unless the change is to the signature itself, so exactly one check
refuses it.

Every key is derived from a published label, so anyone can rebuild every case.
They are test keys and protect nothing. No credential is carried: a principal
names its credential by the SHA-256 of a labelled placeholder.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import principalaction as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/principal-action/v1/"
AT = "2026-11-10T12:00:00Z"
ISSUED, EXPIRES = "2026-11-10T11:55:00Z", "2026-11-10T12:55:00Z"
WORKFORCE = "https://example-workforce.okta.com/oauth2/default"
AGENTS = "https://idp.example.com/realms/agents"
SPONSORS = "https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/v2.0"
RESOURCE = "https://tools.example.com/mcp"
CUSTOM_DOMAIN = "https://login.example.org/tenant"


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _scalar(seed: bytes) -> int:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8)
    return a | 1 << 254


def okp_key(label: str, kid: str) -> dict[str, str]:
    public = rail._pt_compress(rail._pt_mul(_scalar(_seed(label)), rail._B))
    return {"crv": "Ed25519", "kid": kid, "kty": "OKP", "x": reader.b64url(bytes(public))}


# P-256 (FIPS 186-4 D.1.2.3), affine arithmetic: enough to derive a public point.
_P256 = 2**256 - 2**224 + 2**192 + 2**96 - 1
_A = _P256 - 3
_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _ec_add(p: tuple[int, int] | None, q: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P256 == 0:
        return None
    if p == q:
        slope = (3 * p[0] * p[0] + _A) * pow(2 * p[1], -1, _P256) % _P256
    else:
        slope = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P256) % _P256
    x = (slope * slope - p[0] - q[0]) % _P256
    return x, (slope * (p[0] - x) - p[1]) % _P256


def ec_key(label: str, kid: str) -> dict[str, str]:
    k, point, acc = int.from_bytes(_seed(label), "big") % (_P256 - 1) + 1, _G, None
    while k:
        if k & 1:
            acc = _ec_add(acc, point)
        point, k = _ec_add(point, point), k >> 1
    assert acc is not None
    x, y = (reader.b64url(v.to_bytes(32, "big")) for v in acc)
    return {"crv": "P-256", "kid": kid, "kty": "EC", "x": x, "y": y}


def _probable_prime(n: int) -> bool:
    small = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    if any(n % p == 0 for p in small):
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(label: str) -> int:
    counter = 0
    while True:
        raw = b"".join(hashlib.sha256(_seed(label) + (counter * 4 + i).to_bytes(8, "big")).digest()
                       for i in range(4))
        candidate = int.from_bytes(raw, "big") | (3 << 1022) | 1
        if candidate % 65537 != 1 and _probable_prime(candidate):
            return candidate
        counter += 1


def rsa_key(label: str, kid: str) -> dict[str, str]:
    n = _prime(label + "/p") * _prime(label + "/q")
    return {"e": "AQAB", "kid": kid, "kty": "RSA", "n": reader.b64url(n.to_bytes(256, "big"))}


KEYS = {
    "user": okp_key("issuer/workforce", "workforce-2026-11"),
    "agent": ec_key("issuer/agents", "agents-2026-11"),
    "sponsor": rsa_key("issuer/sponsors", "sponsors-2026-11"),
    "approver": okp_key("issuer/workforce-approvals", "workforce-approvals-2026-11"),
}
ISSUERS = {"user": WORKFORCE, "agent": AGENTS, "sponsor": SPONSORS, "approver": WORKFORCE}
SUBJECTS = {
    "user": "00u1a2b3c4d5e6f7g8h9",
    "agent": "agent-invoice-reconciler",
    "sponsor": "a1b2c3d4-0000-4000-8000-00000000f00d",
    "approver": "00u9z8y7x6w5v4u3t2s1",
}
CLIENTS = {
    "user": "0oa-invoice-assistant",
    "agent": "agent-invoice-reconciler-client",
    "sponsor": "11111111-2222-4333-8444-555555555555",
    "approver": "0oa-approvals-console",
}
PROVIDERS = {"user": "okta", "agent": "keycloak", "sponsor": "entra", "approver": "okta"}
APPROVAL_DIGEST = hashlib.sha256(b"approval record: approve invoice batch 2026-11-10").hexdigest()
TOOL, ARGUMENTS = "invoices.approve_batch", {"batch": "2026-11-10", "count": 14, "currency": "EUR"}


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def principal(role: str) -> dict[str, Any]:
    key = dict(KEYS[role])
    p: dict[str, Any] = {
        "audience": [RESOURCE],
        "authMethod": "private_key_jwt" if role in ("agent", "sponsor") else "none",
        "clientId": CLIENTS[role],
        "expiresAt": EXPIRES,
        "identityProvider": PROVIDERS[role],
        "issuedAt": ISSUED,
        "issuer": ISSUERS[role],
        "jwksDigest": _hex(bytes(rail.jcs_dumps({"keys": [key]}))),
        "key": key,
        "keyThumbprint": reader.jwk_thumbprint(key),
        "kid": key["kid"],
        "source": "jwt-access-token",
        "subject": SUBJECTS[role],
        "tokenDigest": _hex(f"credential placeholder: {role}".encode()),
    }
    if role == "agent":
        p["pinnedThumbprint"] = p["keyThumbprint"]
    if role == "user":
        p["act"] = {"sub": SUBJECTS["agent"]}
    return p


def predicate() -> dict[str, Any]:
    return {
        "action": {"argumentsDigest": _hex(bytes(rail.jcs_dumps(ARGUMENTS))), "at": AT, "tool": TOOL},
        "approvals": [{"approvalDigest": APPROVAL_DIGEST, "subject": SUBJECTS["approver"]}],
        "principals": {role: principal(role) for role in reader.ROLES},
    }


def statement(pred: dict[str, Any]) -> dict[str, Any]:
    digest = _hex(bytes(rail.jcs_dumps(pred["action"]))) if isinstance(pred.get("action"), dict) else _hex(b"")
    return {
        "_type": reader.STATEMENT_TYPE,
        "predicate": pred,
        "predicateType": reader.PREDICATE_TYPE,
        "subject": [{"digest": {"sha256": digest}, "name": "action"}],
    }


def envelope(stmt: dict[str, Any], payload: bytes | None = None, served: bytes | None = None) -> bytes:
    """A DSSE envelope the producer signs over ``payload`` (the RFC 8785 bytes of
    ``stmt`` unless given). ``served`` replaces the payload after signing, as an
    edit made without the producer key must."""
    signed = payload if payload is not None else bytes(rail.jcs_dumps(stmt))
    sig = rail.ed25519_sign(_seed("producer"), rail.pae(reader.PAYLOAD_TYPE, signed))
    return _json(
        {
            "payload": base64.b64encode(served if served is not None else signed).decode(),
            "payloadType": reader.PAYLOAD_TYPE,
            "signatures": [{"keyid": "producer-0001", "sig": base64.b64encode(sig).decode()}],
        }
    )


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def pins() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for role in reader.ROLES:
        out.setdefault(ISSUERS[role], []).append(reader.jwk_thumbprint(KEYS[role]))
    # The custom-domain sponsor issuer the verifier also trusts, with the sponsor key.
    out[CUSTOM_DOMAIN] = [reader.jwk_thumbprint(KEYS["sponsor"])]
    return {issuer: sorted(set(thumbs)) for issuer, thumbs in sorted(out.items())}


Edit = Callable[[dict[str, Any]], None]


def _set(path: str, value: Any) -> Edit:
    def edit(pred: dict[str, Any]) -> None:
        *head, last = path.split(".")
        node = pred
        for part in head:
            node = node[part]
        node[last] = value

    return edit


def _drop(path: str) -> Edit:
    def edit(pred: dict[str, Any]) -> None:
        *head, last = path.split(".")
        node = pred
        for part in head:
            node = node[part]
        del node[last]

    return edit


def _rekey(role: str, key: dict[str, str]) -> Edit:
    """Give a principal another key, keeping its kid, thumbprint and pin consistent."""

    def edit(pred: dict[str, Any]) -> None:
        p = pred["principals"][role]
        p["key"], p["kid"], p["keyThumbprint"] = key, key["kid"], reader.jwk_thumbprint(key)
        p["jwksDigest"] = _hex(bytes(rail.jcs_dumps({"keys": [key]})))
        if "pinnedThumbprint" in p:
            p["pinnedThumbprint"] = p["keyThumbprint"]

    return edit


def _all(*edits: Edit) -> Edit:
    def edit(pred: dict[str, Any]) -> None:
        for e in edits:
            e(pred)

    return edit


def _verified(reason: str, delegation: str) -> dict[str, str]:
    return {"decision": "verified", "delegation": delegation, "reason": reason}


def _rejected(reason: str) -> dict[str, str]:
    return {"decision": "rejected", "reason": reason}


# id, the change to the baseline predicate, the expected answer, what the change is.
EDITS: list[tuple[str, Edit, dict[str, str], str]] = [
    ("strict-four-principals", lambda p: None, _verified("strict", "act-chain"),
     "the baseline: four principals, an act chain naming the agent, the approval counted"),
    ("basic-user-agent-act-absent",
     _all(_drop("principals.sponsor"), _drop("principals.approver"), _drop("approvals"),
          _drop("principals.user.act")),
     _verified("basic", "act-absent"), "only user and agent, and no act chain"),
    ("basic-user-agent-act-chain",
     _all(_drop("principals.sponsor"), _drop("principals.approver"), _drop("approvals")),
     _verified("basic", "act-chain"), "only user and agent, the act chain names the agent"),
    ("basic-four-principals-act-absent", _drop("principals.user.act"), _verified("basic", "act-absent"),
     "four principals but no act chain: strict needs both"),
    ("strict-nested-act-chain",
     _set("principals.user.act", {"act": {"sub": "orchestrator-0001"}, "sub": SUBJECTS["agent"]}),
     _verified("strict", "act-chain"), "the act chain has a prior actor behind the agent"),
    ("strict-act-names-client-id", _set("principals.user.act", {"sub": CLIENTS["agent"]}),
     _verified("strict", "act-chain"), "the act chain names the agent by its client identifier"),
    ("strict-id-jag-source", _set("principals.user.source", "id-jag"), _verified("strict", "act-chain"),
     "the user principal was established from an identity assertion grant"),
    ("strict-custom-domain-declared",
     _all(_set("principals.sponsor.issuer", CUSTOM_DOMAIN),
          _set("principals.sponsor.identityProvider", "entra")),
     _verified("strict", "act-chain"), "a custom-domain issuer whose declared provider is accepted as declared"),
    ("strict-no-optional-members",
     _all(*(_drop(f"principals.{r}.identityProvider") for r in reader.ROLES), _drop("principals.agent.pinnedThumbprint")),
     _verified("strict", "act-chain"), "no provider declared and no pin recorded"),
    ("principals-malformed", _set("principals.owner", {}), _rejected("principals_malformed"),
     "a role outside user, agent, sponsor and approver"),
    ("user-member-missing", _drop("principals.user.tokenDigest"), _rejected("principal_user:principal_member_missing"),
     "the user principal does not name its credential"),
    ("agent-member-unknown", _set("principals.agent.token", "eyJhbGciOi..."),
     _rejected("principal_agent:principal_member_unknown"), "the agent principal carries a member the type does not define"),
    ("user-issuer-invalid", _set("principals.user.issuer", "http://example-workforce.okta.com/oauth2/default"),
     _rejected("principal_user:principal_issuer_invalid"), "an issuer that is not an https URL"),
    ("user-audience-duplicate", _set("principals.user.audience", [RESOURCE, RESOURCE]),
     _rejected("principal_user:principal_malformed"), "an audience naming one value twice"),
    ("sponsor-private-key", _set("principals.sponsor.key.d", "AQAB"),
     _rejected("principal_sponsor:principal_key_invalid"), "the sponsor key carries a private member"),
    ("agent-thumbprint-mismatch", _set("principals.agent.keyThumbprint", reader.jwk_thumbprint(KEYS["user"])),
     _rejected("principal_agent:principal_thumbprint_mismatch"), "a thumbprint that does not recompute from the key"),
    ("user-kid-mismatch", _set("principals.user.kid", "workforce-2026-10"),
     _rejected("principal_user:principal_kid_mismatch"), "the header kid differs from the key's kid"),
    ("user-provider-mismatch", _set("principals.user.identityProvider", "auth0"),
     _rejected("principal_user:principal_provider_mismatch"), "an Okta issuer declared as Auth0"),
    ("agent-pin-mismatch", _set("principals.agent.pinnedThumbprint", reader.jwk_thumbprint(KEYS["approver"])),
     _rejected("principal_agent:principal_pin_mismatch"), "the key the client pinned is not the key the record names"),
    ("user-not-yet-valid", _set("principals.user.issuedAt", "2026-11-10T12:01:00Z"),
     _rejected("principal_user:principal_not_yet_valid"), "the credential was issued after the action"),
    ("user-expired", _set("principals.user.expiresAt", "2026-11-10T12:00:00Z"),
     _rejected("principal_user:principal_expired"), "the credential expired at the moment of the action"),
    ("approver-issuer-untrusted",
     _all(_set("principals.approver.issuer", "https://approvals.example.net"),
          _drop("principals.approver.identityProvider")),
     _rejected("principal_approver:principal_issuer_untrusted"), "an approver from an issuer the verifier does not trust"),
    ("agent-key-not-pinned", _rekey("agent", ec_key("issuer/agents/unpinned", "agents-2026-11")),
     _rejected("principal_agent:principal_key_not_pinned"), "a consistent key the verifier did not pin for that issuer"),
    ("user-act-malformed", _set("principals.user.act", {"client_id": SUBJECTS["agent"]}),
     _rejected("principal_user:principal_act_malformed"), "an act claim without a sub"),
    ("user-idjag-undefined", _set("principals.user.idJag", {"issuer": WORKFORCE}),
     _rejected("principal_user:principal_idjag_undefined"), "an idJag block before its definition is published"),
    ("agent-missing", _all(_drop("principals.agent"), _drop("principals.user.act")),
     _rejected("principals_need_user_and_agent"), "no agent principal"),
    ("act-names-another-agent", _set("principals.user.act", {"sub": "agent-payments-mover"}),
     _rejected("principal_act_names_another_agent"), "the user credential delegated to a different agent"),
    ("approver-not-an-approval-signer", _drop("approvals"),
     _rejected("principal_approver_not_an_approval_signer"), "an approver principal with no approval counted"),
]


def cases() -> list[tuple[str, bytes, dict[str, str], str]]:
    """Every case: id, the envelope, the expected answer, what the case changes."""
    out = []
    for name, edit, expected, what in EDITS:
        pred = predicate()
        edit(pred)
        out.append((name, envelope(statement(pred)), expected, what))
    base = statement(predicate())
    pretty = json.dumps(base, indent=1, sort_keys=True).encode()
    moved = copy.deepcopy(base)
    moved["predicate"]["action"]["tool"] = "invoices.delete_batch"
    stray = copy.deepcopy(base)
    stray["predicate"]["action"]["note"] = "approved by phone"
    stray["subject"][0]["digest"]["sha256"] = _hex(bytes(rail.jcs_dumps(stray["predicate"]["action"])))
    wrong_type = copy.deepcopy(base)
    wrong_type["predicateType"] = "https://w3id.org/agent-evidence/predicate/v1/principal-actions"
    out += [
        ("statement-malformed", envelope(wrong_type), _rejected("statement_malformed"),
         "a predicate type one character from this one"),
        ("recorder-signature-invalid", envelope(base, served=bytes(rail.jcs_dumps(moved))),
         _rejected("recorder_signature_invalid"), "the action edited after the producer signed"),
        ("statement-not-canonical", envelope(base, payload=pretty), _rejected("statement_not_canonical"),
         "a signed payload that is not RFC 8785 bytes"),
        ("action-malformed", envelope(stray), _rejected("action_malformed"),
         "an action carrying a member the type does not define"),
        ("action-digest-mismatch", envelope({**moved, "subject": base["subject"]}),
         _rejected("action_digest_mismatch"), "the subject digest names another action"),
    ]
    return out


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    producer = bytes(rail._pt_compress(rail._pt_mul(_scalar(_seed("producer")), rail._B)))
    for name, env, expected, what in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case = {
            "envelope": "envelope.json",
            "pins": pins(),
            "producerKey": base64.b64encode(producer).decode(),
            "schema_version": "principal-action-case/v1",
        }
        files = {"case.json": _json(case), "envelope.json": env}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append(
            {
                "edit": what,
                "expected": expected,
                "files": {key: hashlib.sha256(value).hexdigest() for key, value in sorted(files.items())},
                "id": name,
                "path": f"cases/{name}",
            }
        )
    manifest = {
        "corpusDigest": hashlib.sha256(_json(entries)).hexdigest(),
        "predicateType": reader.PREDICATE_TYPE,
        "specification": "spec/predicates/principal-action.md",
        "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 verified, 1 rejected",
        "vectors": entries,
    }
    words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: words.count(word) for word in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
