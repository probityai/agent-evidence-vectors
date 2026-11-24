"""Build the agent-identity-statement cases byte-identically.

Every case is an issuer's signed history of an agent's identity document, one DSSE-signed
in-toto Statement per version (spec/predicates/agent-identity-statement.md), the pins a
consumer holds (the issuer's keys, the agent, the head of the history) and one past
decision: the instant a relying party acted and the envelope the agent signed for it. Each
rejected case is built so the check it names is the first that fails; each accepted case
is a control.

Regenerate byte-identically:

    uv run --extra generators python corpora/vectors-agent-identity-statement/gen_vectors.py

TEST KEYS ONLY. Each Ed25519 seed is the SHA-256 of a public label, so anyone can
rebuild every key and signature here, and none of them protects anything.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import agentidentity as reader  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "agent_card_receipt_generator", ROOT.parent / "vectors-agent-card-receipt" / "gen_vectors.py")
assert _SPEC and _SPEC.loader
receipts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(receipts)
_DIGEST_SPEC = importlib.util.spec_from_file_location(
    "agent_identity_statement_digest", ROOT / "digest.py")
assert _DIGEST_SPEC and _DIGEST_SPEC.loader
_digest = importlib.util.module_from_spec(_DIGEST_SPEC)
_DIGEST_SPEC.loader.exec_module(_digest)
enc, sha = _digest.enc, _digest.sha

SUITE = reader.SUITE
AGENT = {"issuer": "https://idp.example.com/realms/agents", "subject": "travel-agent"}
DOCUMENT = "https://agents.example.com/travel-agent/identity.json"
T1 = "2026-11-01T00:00:00Z"
T2 = "2026-11-10T00:00:00Z"
T3 = "2026-11-20T00:00:00Z"
DECIDED = "2026-11-05T12:00:00Z"
LATE = "2026-11-25T12:00:00Z"


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"agent-evidence-vectors agent-identity-statement test {label}".encode())
        .digest())


def raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


ISSUER, OTHER_ISSUER = key("issuer"), key("other issuer")
K1, K2, K3 = key("agent key 1"), key("agent key 2"), key("agent key 3")


def listed(*keys: Ed25519PrivateKey) -> list[dict[str, str]]:
    return sorted(({"publicKey": raw(k).hex(), "type": "Ed25519"} for k in keys),
                  key=lambda entry: entry["publicKey"])


def payload(value: dict[str, Any] | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def signed(value: dict[str, Any] | bytes, signer: Ed25519PrivateKey = ISSUER,
           payload_type: str = reader.PAYLOAD_TYPE) -> dict[str, Any]:
    body = payload(value)
    pae = b"DSSEv1 %d %s %d " % (len(payload_type), payload_type.encode(), len(body)) + body
    return {"payload": base64.b64encode(body).decode(), "payloadType": payload_type,
            "signatures": [{"keyid": sha(raw(signer)),
                            "sig": base64.b64encode(signer.sign(pae)).decode()}]}


def digest_of(env: dict[str, Any]) -> str:
    return sha(base64.b64decode(env["payload"]))


def statement(version: int, previous: dict[str, Any] | None, *, status: str = "active",
              keys: list[dict[str, str]] | None = None, issued: str = T1,
              effective: str | None = None, **changes: Any) -> dict[str, Any]:
    """Version ``version`` of the document, chained to the envelope ``previous``."""
    predicate: dict[str, Any] = {
        "agent": dict(AGENT), "effectiveAt": effective or issued, "issuedAt": issued,
        "keys": listed(K1) if keys is None else keys, "status": status, "version": version,
    }
    if previous is not None:
        predicate["previous"] = {"sha256": digest_of(previous)}
    predicate.update(changes)
    document = sha(f"{DOCUMENT} version {version} {status}".encode())
    return {"_type": reader.STATEMENT_TYPE, "predicate": predicate,
            "predicateType": reader.PREDICATE_TYPE,
            "subject": [{"digest": {"sha256": document}, "name": DOCUMENT}]}


def chain(*specs: dict[str, Any]) -> list[dict[str, Any]]:
    """Signed versions 1, 2, ... each chained to the one before; a spec overrides fields."""
    out: list[dict[str, Any]] = []
    for number, spec in enumerate(specs, start=1):
        spec = dict(spec)
        signer = spec.pop("signer", ISSUER)
        edit = spec.pop("edit", None)
        stmt = statement(spec.pop("version", number), out[-1] if out else None, **spec)
        if edit is not None:
            edit(stmt)
        out.append(signed(stmt, signer))
    return out


def decision(at: str = DECIDED, signer: Ed25519PrivateKey = K1,
             keyid: Ed25519PrivateKey | None = None) -> dict[str, Any]:
    request = {"action": "bookings:hold", "agent": AGENT["subject"],
               "audience": "https://api.travel-bookings.example.com", "nonce": at}
    env = signed(request, signer, "application/json")
    env["signatures"][0]["keyid"] = sha(raw(keyid or signer))
    return {"at": at, "envelope": env}


Case = tuple[str, str, dict[str, bytes], str, str]
ROTATED = (
    {"issued": T1},
    {"issued": T2, "keys": listed(K2)},
)


def case(name: str, edit: str, *, history: list[dict[str, Any]] | bytes | None = None,
         decided: dict[str, Any] | bytes | None = None, head: str | None = None,
         issuers: list[Ed25519PrivateKey] | None = None, reason: str = reader.PASS_REASON) -> Case:
    held = chain({}) if history is None else history
    tip = head or (digest_of(held[-1]) if isinstance(held, list) and held else sha(b"none"))
    context = {"agent": dict(AGENT), "head": {"sha256": tip},
               "issuerKeys": [raw(k).hex() for k in (issuers or [ISSUER])]}
    files = {"context.json": enc(context),
             "decision.json": decided if isinstance(decided, bytes) else enc(decided or decision()),
             "history.json": held if isinstance(held, bytes) else enc(held)}
    verdict = reader.ACCEPT if reason == reader.PASS_REASON else reader.REJECT
    return name, edit, files, verdict, reason


def _one(**changes: Any) -> list[dict[str, Any]]:
    """A one-version history whose predicate carries ``changes``."""
    return chain({"edit": lambda s: s["predicate"].update(changes)})


def _edited(change: Callable[[dict[str, Any]], None]) -> list[dict[str, Any]]:
    return chain({"edit": change})


def accepted() -> list[Case]:
    reactivated = chain({"issued": T1}, {"issued": T2, "status": "suspended", "keys": []},
                        {"issued": T3, "keys": listed(K1)})
    backdated_later = chain({"issued": T1}, {"issued": T3, "effective": T2, "status": "revoked",
                                              "keys": [], "reason": "key compromise"})
    two_signers = chain({})
    other = signed(statement(1, None), OTHER_ISSUER)
    two_signers[0]["signatures"].insert(0, other["signatures"][0])
    return [
        case("accept-single-version", "control: one active version lists the key that signed "
             "the decision"),
        case("accept-at-effective-instant", "control: the decision is at the very second "
             "version 1 took effect", decided=decision(T1)),
        case("accept-old-key-before-rotation", "control: the decision was signed with the first "
             "key before the rotation took effect, and is re-verified after it",
             history=chain(*ROTATED)),
        case("accept-new-key-after-rotation", "control: the decision was signed with the "
             "rotated key after the rotation took effect", history=chain(*ROTATED),
             decided=decision("2026-11-12T00:00:00Z", K2)),
        case("accept-overlapping-keys", "control: version 2 lists both keys, and the old key "
             "signs after the rotation", history=chain({"issued": T1},
                                                        {"issued": T2, "keys": listed(K1, K2)}),
             decided=decision("2026-11-12T00:00:00Z", K1)),
        case("accept-reactivated-after-suspension", "control: suspended in version 2, active "
             "again in version 3, decision after version 3", history=reactivated,
             decided=decision(LATE)),
        case("accept-decision-before-revocation", "control: a revocation later backdated to "
             "version 2's effectiveAt leaves an earlier decision standing",
             history=backdated_later),
        case("accept-history-out-of-order", "control: the history lists the newest version "
             "first", history=list(reversed(chain(*ROTATED))),
             head=digest_of(chain(*ROTATED)[-1])),
        case("accept-second-signature-pinned", "control: the version carries a signature by an "
             "unpinned key before the pinned issuer's", history=two_signers),
    ]


def _shape_cases() -> list[Case]:
    unsorted = sorted(listed(K1, K2), key=lambda e: e["publicKey"], reverse=True)
    return [
        case("history-not-json", "the history is not JSON", history=b"[{\"payload\": \n",
             reason="history_malformed"),
        case("history-empty", "the history is an empty list", history=[],
             reason="history_malformed"),
        case("history-payload-type-other", "a version is carried as plain JSON, not in-toto",
             history=[signed(statement(1, None), payload_type="application/json")],
             reason="history_malformed"),
        case("statement-signed-by-other-key", "version 2 is signed by a key the consumer did "
             "not pin", history=chain({"issued": T1}, {"issued": T2, "signer": OTHER_ISSUER}),
             reason="statement_signature"),
        case("statement-extra-member", "the Statement carries a member outside the four",
             history=[signed({**statement(1, None), "note": "draft"})],
             reason="statement_malformed"),
        case("statement-type-v01", "_type names in-toto Statement v0.1", history=_edited(
            lambda s: s.update(_type="https://in-toto.io/Statement/v0.1")),
             reason="statement_type_wrong"),
        case("predicate-type-other", "predicateType names the credential-release predicate",
             history=_edited(lambda s: s.update(
                 predicateType="https://w3id.org/agent-evidence/predicate/v1/credential-release")),
             reason="predicate_type_wrong"),
        case("subject-two-members", "the Statement names two documents", history=_edited(
            lambda s: s["subject"].append(copy.deepcopy(s["subject"][0]))),
             reason="subject_malformed"),
        case("predicate-status-unknown", "the status is deleted, which the predicate does not "
             "define", history=_one(status="deleted"), reason="predicate_malformed"),
        case("predicate-keys-unsorted", "the key set is not sorted", history=_one(keys=unsorted),
             reason="predicate_malformed"),
        case("predicate-key-type-other", "a key's type is P-256", history=_one(
            keys=[{"publicKey": raw(K1).hex(), "type": "P-256"}]), reason="predicate_malformed"),
        case("predicate-version-one-with-previous", "version 1 names a previous version",
             history=_one(previous={"sha256": sha(b"before")}), reason="predicate_malformed"),
        case("predicate-version-zero", "the version is zero", history=_one(version=0),
             reason="predicate_malformed"),
        case("predicate-time-offset", "effectiveAt carries an offset instead of Z",
             history=_one(effectiveAt="2026-11-01T01:00:00+01:00"), reason="predicate_malformed"),
        case("active-without-keys", "the agent is active with an empty key set",
             history=_one(keys=[]), reason="active_without_keys"),
        case("effective-after-issued", "the version takes effect after it was issued",
             history=_one(effectiveAt=T2), reason="effective_after_issued"),
        case("agent-other-subject", "version 2 names another agent", history=chain(
            {"issued": T1}, {"issued": T2, "agent": {"issuer": AGENT["issuer"],
                                                      "subject": "another-agent"}}),
             reason="agent_mismatch"),
    ]


def _chain_cases() -> list[Case]:
    v1, v2 = chain(*ROTATED)
    fork = signed(statement(2, v1, issued=T2, keys=listed(K3)))
    second_genesis = signed(statement(1, None, keys=listed(K2)))
    v3_missing = chain(*ROTATED, {"issued": T3})[2]
    status_only = signed(statement(2, v2, issued=T3, status="suspended"))
    gap = signed(statement(3, v1, issued=T2, keys=listed(K2)))
    early = chain({"issued": T2}, {"issued": T3, "effective": T1})
    after_revoked = chain({"issued": T1}, {"issued": T2, "status": "revoked", "keys": []},
                          {"issued": T3})
    return [
        case("history-no-genesis", "the history holds version 2 alone", history=[v2],
             reason="history_no_genesis"),
        case("history-forked", "two versions 2 name the same version 1", history=[v1, v2, fork],
             reason="history_forked"),
        case("history-two-genesis", "two versions 1 begin two histories",
             history=[v1, second_genesis], reason="history_forked"),
        case("history-previous-missing", "version 3 names a version 2 the history omits",
             history=[v1, v3_missing], reason="history_previous_missing"),
        case("version-not-incremented", "a status change keeps the version of the statement it "
             "follows", history=[v1, v2, status_only], reason="version_not_incremented"),
        case("version-gap", "the version after 1 is 3", history=[v1, gap],
             reason="version_gap"),
        case("history-time-reversed", "version 2 takes effect before version 1",
             history=early, reason="history_time_reversed"),
        case("revoked-is-final", "an active version follows a revocation",
             history=after_revoked, reason="revoked_is_final"),
        case("history-stops-before-head", "the consumer pinned version 2 and the history "
             "stops at version 1", history=[v1], head=digest_of(v2),
             reason="history_head_mismatch"),
    ]


def _decision_cases() -> list[Case]:
    revoked = chain({"issued": T1}, {"issued": T2, "status": "revoked", "keys": [],
                                      "reason": "decommissioned"})
    backdated = chain({"issued": T1}, {"issued": T3, "effective": T2, "status": "revoked",
                                        "keys": [], "reason": "key compromise"})
    suspended = chain({"issued": T1}, {"issued": T2, "status": "suspended", "keys": listed(K1)})
    two = decision()
    two["envelope"]["signatures"].append(copy.deepcopy(two["envelope"]["signatures"][0]))
    return [
        case("decision-not-json", "the decision is not JSON", decided=b"{\"at\": \n",
             reason="decision_malformed"),
        case("decision-two-signatures", "the decision envelope carries two signatures",
             decided=two, reason="decision_malformed"),
        case("key-unknown", "the decision was signed with a key no version lists: the agent "
             "rotated without a new statement", decided=decision(signer=K3),
             reason="key_unknown"),
        case("decision-signature-wrong", "the decision names the listed key and was signed "
             "with another", decided=decision(signer=K3, keyid=K1),
             reason="decision_signature"),
        case("decision-before-history", "the decision predates version 1",
             decided=decision("2026-10-31T23:59:59Z"), reason="decision_before_history"),
        case("agent-suspended", "the decision falls inside a suspension", history=suspended,
             decided=decision("2026-11-12T00:00:00Z"), reason="agent_suspended"),
        case("agent-revoked", "the decision follows the revocation", history=revoked,
             decided=decision("2026-11-12T00:00:00Z"), reason="agent_revoked"),
        case("agent-revoked-at-effective-instant", "the decision is at the second the "
             "revocation took effect", history=revoked, decided=decision(T2),
             reason="agent_revoked"),
        case("agent-revoked-backdated", "the revocation was issued after the decision and "
             "backdated before it", history=backdated, decided=decision("2026-11-12T00:00:00Z"),
             reason="agent_revoked"),
        case("key-used-before-rotation", "the rotated key signed before version 2 took effect",
             history=chain(*ROTATED), decided=decision(DECIDED, K2), reason="key_not_in_force"),
        case("key-retired", "the first key signed after version 2 dropped it",
             history=chain(*ROTATED), decided=decision("2026-11-12T00:00:00Z", K1),
             reason="key_not_in_force"),
    ]


def cases() -> list[Case]:
    """Every case: id, what it shows, files, expected decision and reason."""
    return [*accepted(), *_shape_cases(), *_chain_cases(), *_decision_cases()]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    return dict(receipts.generate(root, cases, SUITE))


if __name__ == "__main__":
    generate()
