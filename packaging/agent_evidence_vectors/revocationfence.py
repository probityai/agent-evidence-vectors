"""Judge the revocation-fence cases: a revocation a target enforces at its own commit.

A revocation that only a gateway or a registry knows about does not stop a permit that is
already on its way to a target. The fence moves the decision to the target: an authority signs
an effect permit that names the subject's revocation epoch, the target commits the effect only
when the epoch it holds for that subject EQUALS the permit's epoch, and it signs what it did.
Revoking a subject is installing its next epoch, so a permit from a revoked epoch cannot commit.

Three signed records, each ``{"claims": {...}, "sig": "<base64>"}``, signed with Ed25519 over
``DOMAIN || 0x00 || JCS(claims)`` (RFC 8785), the domain being the type URI plus a fragment:
the effect permit (``#effect-permit``), the epoch update (``#epoch-update``) and the target's
outcome (``#target-outcome``). A verifier takes keys only from the case's pinned lists; a
record's ``kid`` (lowercase hex SHA-256 of the raw public key) only selects among them.

Seven kinds of case, each with a fixed check order in which the first failing check wins:
``permit``, ``epoch-update``, ``outcome``, ``commit`` (shapes a, b and c), ``propagation``,
``ledger`` and ``feed`` (a Security Event Token from a CAEP or RISC transmitter). Every case
about a revocation also states ``revocation_status``: ``live``, ``partial``, ``closed`` or
``unknown``. An open, unresolved or unreadable revocation never reads ``closed``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON
object equal to the case's expected object and exits with ``EXIT_FOR[decision]``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import shlex
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictb64, strictjson
from agent_evidence_vectors.anchoredchain import _fixture_error
from agent_evidence_vectors.monitorcoverage import _validated_entries, run_corpus

SUITE = "revocation-fence/v1"
TYPE_URI = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-fence"
PERMIT_DOMAIN = TYPE_URI + "#effect-permit"
EPOCH_DOMAIN = TYPE_URI + "#epoch-update"
OUTCOME_DOMAIN = TYPE_URI + "#target-outcome"

PERMIT_MEMBERS = (
    "v",
    "permit_id",
    "subject",
    "epoch",
    "idempotency_key",
    "audience",
    "operation_digest",
    "not_before_ns",
    "not_after_ns",
    "kid",
)
EPOCH_MEMBERS = ("v", "subject", "epoch", "audience", "kid")
OUTCOME_MEMBERS = (
    "v",
    "target_id",
    "permit_id",
    "subject",
    "epoch",
    "idempotency_key",
    "stage",
    "outcome",
    "reason",
    "shape",
    "signed_at_ns",
    "kid",
)
STAGES = ("accept", "execute", "settle", "final")
OUTCOMES = ("committed", "refused")
KINDS = ("permit", "epoch-update", "outcome", "commit", "propagation", "ledger", "feed")
STATUSES = ("live", "partial", "closed", "unknown")

CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
RISC = "https://schemas.openid.net/secevent/risc/event-type/"
SESSION_REVOKED = CAEP + "session-revoked"
CREDENTIAL_CHANGE = CAEP + "credential-change"
RISK_LEVEL_CHANGE = CAEP + "risk-level-change"
ACCOUNT_DISABLED = RISC + "account-disabled"
ACCOUNT_PURGED = RISC + "account-purged"
ACCOUNT_ENABLED = RISC + "account-enabled"
SET_HEADER_TYP = "secevent+jwt"

PENDING_LABEL = "pending"
REVOKED_LABEL = "revoked for new admissions"
IN_FLIGHT, UNKNOWN, UNRESOLVED = "in flight", "unknown", "unresolved, revoked"
COMMITTED, NOT_COMMITTED = "committed", "not committed"

EXIT_FOR = {
    "valid": 0,
    "installed": 0,
    "unchanged": 0,
    "committed": 0,
    "replayed": 0,
    "done": 0,
    "revoked_for_new_admissions": 0,
    "delivered": 0,
    "session_ended": 0,
    "rotated": 0,
    "journalled": 0,
    "revoked": 0,
    "refused": 1,
    "pending": 2,
    "no_outcome": 3,
    "outcome_mismatch": 4,
}

#: Every rule a case can force, grouped by kind, in the order the reader applies them.
CHECKS = (
    "permit_shape",
    "permit_types",
    "permit_ranges",
    "permit_authority",
    "permit_signature",
    "permit_audience",
    "permit_not_before",
    "permit_not_after",
    "update_shape",
    "update_types",
    "update_range",
    "update_source",
    "update_signature",
    "update_audience",
    "update_rollback",
    "update_unchanged",
    "outcome_shape",
    "outcome_values",
    "outcome_key",
    "outcome_signature",
    "outcome_types",
    "commit_replay",
    "commit_key_reuse",
    "commit_epoch_unavailable",
    "commit_epoch_unknown",
    "commit_revocation_pending",
    "commit_epoch_equal",
    "commit_lease",
    "commit_hold",
    "commit_outcome_honest",
    "propagation_live_at_commit",
    "propagation_ack_live",
    "propagation_ack",
    "propagation_skew",
    "ledger_submit_revoked",
    "ledger_revoke_moves_unknown",
    "ledger_retry_refused",
    "ledger_read_only",
    "ledger_reservation",
    "set_compact",
    "set_header",
    "set_payload",
    "set_issuer_key",
    "set_signature",
    "set_audience",
    "set_shape",
    "set_subject_issuer",
    "set_jti",
    "set_session_binding",
    "set_credential_change",
    "set_account",
    "set_unknown_event",
    "set_not_before",
)

_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-revocation-fence"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-revocation-fence"
)

Skip = frozenset[str]


class Refused(Exception):
    """A record or request the fence refuses, with its stable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _rail() -> Any:
    """The rail's Ed25519 and RFC 8785, resolved at call time (the rail imports this module)."""
    for name in ("run_vectors", "agent_evidence_vectors.run_vectors"):
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "ed25519_verify"):
            return module
    return importlib.import_module("run_vectors")


def _load(path: Path) -> Any:
    return strictjson.loads(path.read_text(encoding="utf-8"))


def key_id(raw_public: bytes) -> str:
    """The lowercase hex SHA-256 of a raw public key."""
    return hashlib.sha256(raw_public).hexdigest()


def pinned(keys: list[str]) -> dict[str, bytes]:
    """The pinned keys of a case, by key id."""
    raws = [strictb64.std(key) for key in keys]
    return {key_id(raw): raw for raw in raws}


def message(domain: str, claims: Mapping[str, Any]) -> bytes:
    """The bytes a record's signature covers: the domain, one zero byte, then JCS of the claims."""
    return domain.encode("ascii") + b"\x00" + _rail().jcs_dumps(dict(claims))


def _signed(
    pins: Mapping[str, bytes], kid: Any, domain: str, claims: Mapping[str, Any], sig: Any
) -> bool:
    raw = pins.get(kid) if isinstance(kid, str) else None
    if raw is None or not isinstance(sig, str):
        return False
    try:
        signature = strictb64.std(sig)
    except ValueError:
        return False
    return len(signature) == 64 and bool(
        _rail().ed25519_verify(raw, message(domain, claims), signature)
    )


def _is_int(value: Any) -> bool:
    return type(value) is int


def read_ns(value: Any) -> int | None:
    """A nanosecond instant in its one canonical decimal spelling, or None."""
    if (
        isinstance(value, str)
        and value.isascii()
        and value.isdigit()
        and (value == "0" or value[0] != "0")
    ):
        return int(value)
    return None


def _text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _wire(raw: Any, members: tuple[str, ...], rule: str, skip: Skip) -> tuple[dict[str, Any], Any]:
    """The claims and signature of a record with exactly the declared members and version 1."""
    if rule in skip:
        return dict(raw["claims"]), raw["sig"]
    if not isinstance(raw, dict) or set(raw) != {"claims", "sig"}:
        raise Refused("malformed")
    claims = raw["claims"]
    if (
        not isinstance(claims, dict)
        or set(claims) != set(members)
        or not (_is_int(claims["v"]) and claims["v"] == 1)
    ):
        raise Refused("malformed")
    return dict(claims), raw["sig"]


def _record(directory: Path, name: str) -> Any:
    """A stored record; bytes that are not strict JSON are not a record of this protocol."""
    try:
        return _load(directory / name)
    except ValueError as exc:
        raise Refused("malformed") from exc


# --- the three records --------------------------------------------------------------------------


def read_permit(
    raw: Any, pins: Mapping[str, bytes], audience: str, now_ns: int, skip: Skip = frozenset()
) -> dict[str, Any]:
    """The permit's claims, with its window as integers, once every check passes."""
    claims, sig = _wire(raw, PERMIT_MEMBERS, "permit_shape", skip)
    texts = ("permit_id", "subject", "idempotency_key", "audience", "operation_digest", "kid")
    begin, end = read_ns(claims["not_before_ns"]), read_ns(claims["not_after_ns"])
    if "permit_types" not in skip and (
        not all(_text(claims[k]) for k in texts)
        or not _is_int(claims["epoch"])
        or begin is None
        or end is None
    ):
        raise Refused("malformed")
    epoch = claims["epoch"]
    ranged = "permit_ranges" in skip or (epoch >= 0 and end > begin)  # type: ignore[operator]
    if not ranged:
        raise Refused("malformed")
    if "permit_authority" not in skip and claims["kid"] not in pins:
        raise Refused("unknown_authority")
    if "permit_signature" not in skip and not _signed(
        pins, claims["kid"], PERMIT_DOMAIN, claims, sig
    ):
        raise Refused("bad_signature")
    if "permit_audience" not in skip and claims["audience"] != audience:
        raise Refused("wrong_audience")
    if "permit_not_before" not in skip and now_ns < begin:  # type: ignore[operator]
        raise Refused("not_yet_valid")
    if "permit_not_after" not in skip and now_ns >= end:  # type: ignore[operator]
        raise Refused("expired")
    return claims


def read_update(
    raw: Any, pins: Mapping[str, bytes], audience: str, skip: Skip = frozenset()
) -> dict[str, Any]:
    """The epoch update's claims once its shape, pinned signature and audience pass."""
    claims, sig = _wire(raw, EPOCH_MEMBERS, "update_shape", skip)
    if "update_types" not in skip and (
        not all(_text(claims[k]) for k in ("subject", "audience", "kid"))
        or not _is_int(claims["epoch"])
    ):
        raise Refused("malformed")
    if "update_range" not in skip and claims["epoch"] < 0:
        raise Refused("malformed")
    if "update_source" not in skip and claims["kid"] not in pins:
        raise Refused("unknown_epoch_source")
    if "update_signature" not in skip and not _signed(
        pins, claims["kid"], EPOCH_DOMAIN, claims, sig
    ):
        raise Refused("bad_signature")
    if "update_audience" not in skip and claims["audience"] != audience:
        raise Refused("wrong_audience")
    return claims


def read_outcome(raw: Any, pins: Mapping[str, bytes], skip: Skip = frozenset()) -> dict[str, Any]:
    """The outcome's claims if a pinned target key signed them.

    The stage and outcome values and the key are checked before the member types, so an
    outcome naming an unknown stage is malformed whoever signed it.
    """
    claims, sig = _wire(raw, OUTCOME_MEMBERS, "outcome_shape", skip)
    if "outcome_values" not in skip and (
        claims["stage"] not in STAGES or claims["outcome"] not in OUTCOMES
    ):
        raise Refused("malformed")
    if "outcome_key" not in skip and not (isinstance(claims["kid"], str) and claims["kid"] in pins):
        raise Refused("unknown_target_key")
    if "outcome_signature" not in skip and not _signed(
        pins, claims["kid"], OUTCOME_DOMAIN, claims, sig
    ):
        raise Refused("bad_signature")
    texts = ("target_id", "permit_id", "subject", "idempotency_key", "shape", "kid")
    if "outcome_types" not in skip and (
        not all(_text(claims[k]) for k in texts)
        or not isinstance(claims["reason"], str)
        or read_ns(claims["signed_at_ns"]) is None
        or not _is_int(claims["epoch"])
    ):
        raise Refused("malformed")
    return claims


# --- the kinds ----------------------------------------------------------------------------------


def _permit_kind(case: dict[str, Any], directory: Path, skip: Skip) -> dict[str, Any]:
    pins = pinned(case["keys"]["authority"])
    try:
        read_permit(
            _record(directory, case["permit"]), pins, case["audience"], int(case["now_ns"]), skip
        )
    except Refused as exc:
        return {"decision": "refused", "reason": exc.code}
    return {"decision": "valid", "reason": "permit_valid"}


def _update_kind(case: dict[str, Any], directory: Path, skip: Skip) -> dict[str, Any]:
    pins = pinned(case["keys"]["epoch_source"])
    before = dict(case["held"])
    held = dict(before)
    results: list[dict[str, str]] = []
    rolled_back: set[str] = set()
    for name in case["updates"]:
        try:
            claims = read_update(_record(directory, name), pins, case["audience"], skip)
        except Refused as exc:
            results.append({"decision": "refused", "reason": exc.code})
            continue
        subject, epoch = claims["subject"], claims["epoch"]
        current = held.get(subject)
        if current is None:
            held[subject] = epoch
            results.append({"decision": "installed", "reason": "epoch_installed"})
        elif epoch < current and "update_rollback" not in skip:
            rolled_back.add(subject)
            results.append({"decision": "refused", "reason": "epoch_rollback"})
        elif epoch == current and "update_unchanged" not in skip:
            results.append({"decision": "unchanged", "reason": "epoch_unchanged"})
        else:
            held[subject] = epoch
            results.append({"decision": "installed", "reason": "epoch_installed"})
    answer: dict[str, Any] = {**results[-1], "held_after": held, "results": results}
    raised = {s for s in before if held[s] > before[s]}
    if raised or rolled_back:
        answer["revocation_status"] = "closed"
    return answer


def _outcome_kind(case: dict[str, Any], directory: Path, skip: Skip) -> dict[str, Any]:
    pins = pinned(case["keys"]["target"])
    try:
        read_outcome(_record(directory, case["outcome"]), pins, skip)
    except Refused as exc:
        return {"decision": "refused", "reason": exc.code}
    return {"decision": "valid", "reason": "outcome_valid"}


def _replay(state: dict[str, Any], permit: dict[str, Any], skip: Skip) -> str | None:
    """``replayed`` or ``key_reused`` when the idempotency key already names an effect."""
    prior = state["effects"].get(permit["idempotency_key"])
    if prior is None or "commit_replay" in skip:
        return None
    if prior == {"permit_id": permit["permit_id"], "operation_digest": permit["operation_digest"]}:
        return "replayed"
    return None if "commit_key_reuse" in skip else "key_reused"


def fence(
    shape: str, state: dict[str, Any], permit: dict[str, Any], skip: Skip = frozenset()
) -> str:
    """What the target does: ``commit_done``, ``replay_done`` or a refusal code."""
    replay = _replay(state, permit, skip)
    if replay == "replayed":
        return "replay_done"
    if replay is not None:
        return replay
    held, epoch = state["epoch"], permit["epoch"]
    if shape == "a" and held == "unavailable" and "commit_epoch_unavailable" not in skip:
        return "epoch_unavailable"
    if held is None and "commit_epoch_unknown" not in skip:
        return "epoch_unknown"
    if shape == "b" and state["revocation_pending"] and "commit_revocation_pending" not in skip:
        return "revocation_pending"
    if held != epoch and "commit_epoch_equal" not in skip:
        return "epoch_mismatch"
    if shape == "b" and state["lease_expired"] and "commit_lease" not in skip:
        return "lease_expired"
    if shape == "c" and state["hold"] != "prepared" and "commit_hold" not in skip:
        return "revoked_before_commit"
    return "commit_done"


def commit_status(shape: str, state: dict[str, Any], permit_epoch: int) -> str:
    """What this target's state says about a revocation of the permit's epoch.

    An epoch the target cannot read, has never heard, or that is older than the permit's says
    nothing settled (``unknown``). A later epoch is a revocation in force here (``closed``). At
    the permit's epoch, a revocation waiting on leases or a void not yet confirmed is ``partial``,
    a voided hold is ``closed``, and otherwise the permit's epoch is ``live``.
    """
    held = state["epoch"]
    if held is None or held == "unavailable" or held < permit_epoch:
        return "unknown"
    if held > permit_epoch:
        return "closed"
    if shape == "b" and state["revocation_pending"]:
        return "partial"
    if shape == "c" and state["hold"] == "void_pending":
        return "partial"
    if shape == "c" and state["hold"] == "voided":
        return "closed"
    return "live"


def _honest(
    case: dict[str, Any], directory: Path, permit: dict[str, Any], reason: str, skip: Skip
) -> bool:
    """Whether the stored outcome is the target's signed statement of what it did."""
    if case["outcome"] is None:
        return False
    try:
        claims = read_outcome(_record(directory, case["outcome"]), pinned(case["keys"]["target"]))
    except Refused:
        return False
    committed = reason in ("commit_done", "replay_done")
    want = {
        "target_id": case["audience"],
        "permit_id": permit["permit_id"],
        "subject": permit["subject"],
        "epoch": permit["epoch"],
        "idempotency_key": permit["idempotency_key"],
        "stage": case["stage"],
        "outcome": "committed" if committed else "refused",
        "reason": "" if committed else reason,
        "shape": case["shape"],
    }
    return all(claims[k] == v and type(claims[k]) is type(v) for k, v in want.items())


def _commit_kind(case: dict[str, Any], directory: Path, skip: Skip) -> dict[str, Any]:
    pins = pinned(case["keys"]["authority"])
    try:
        permit = read_permit(
            _record(directory, case["permit"]), pins, case["audience"], int(case["now_ns"]), skip
        )
    except Refused as exc:
        return {"decision": "no_outcome", "reason": exc.code}
    shape, state = case["shape"], case["state"]
    reason = fence(shape, state, permit, skip)
    decision = {"commit_done": "committed", "replay_done": "replayed"}.get(reason, "refused")
    if "commit_outcome_honest" not in skip and not _honest(case, directory, permit, reason, skip):
        decision = "outcome_mismatch"
    return {
        "decision": decision,
        "reason": reason,
        "revocation_status": commit_status(shape, state, permit["epoch"]),
    }


def _propagation_kind(case: dict[str, Any], skip: Skip) -> dict[str, Any]:
    commit, now = int(case["commit_ns"]), int(case["now_ns"])
    leases = {
        gateway: (int(lease["granted_ns"]), int(lease["length_ns"]), int(lease["skew_ns"]))
        for gateway, lease in case["leases"].items()
    }
    live = {
        g: lease
        for g, lease in leases.items()
        if "propagation_live_at_commit" in skip or lease[0] <= commit < lease[0] + lease[1]
    }
    acked: set[str] = set()
    for gateway in case["acks"]:
        if gateway not in live and "propagation_ack_live" not in skip:
            return {"decision": "refused", "reason": "malformed", "revocation_status": "unknown"}
        acked.add(gateway)
    if "propagation_ack" in skip:
        acked = set()
    ends = {
        g: granted + length + (0 if "propagation_skew" in skip else skew)
        for g, (granted, length, skew) in live.items()
    }
    waiting = sorted(g for g in live if g not in acked and now < ends[g])
    if waiting:
        return {
            "decision": "pending",
            "label": PENDING_LABEL,
            "reason": "propagation_pending",
            "revocation_status": "partial",
            "waiting_on": waiting,
            "worst_case_ends_ns": str(max(ends[g] for g in waiting)),
        }
    return {
        "decision": "revoked_for_new_admissions",
        "label": REVOKED_LABEL,
        "reason": "propagation_done",
        "revocation_status": "closed",
        "waiting_on": [],
        "worst_case_ends_ns": str(commit),
    }


def _ledger_retry(
    step: dict[str, Any], request: list[Any], revoked: set[str], skip: Skip
) -> dict[str, Any]:
    """A retry of a request: refused when it is a new admission of an open, revoked outcome."""
    read_only = step["read_only"] and "ledger_read_only" not in skip
    refused = (
        request[0] in revoked
        and request[2] in (UNKNOWN, UNRESOLVED)
        and not read_only
        and "ledger_retry_refused" not in skip
    )
    if refused:
        return {"decision": "refused", "reason": "retry_after_revoke", "state": request[2]}
    reason = "read_only_status" if read_only else "retry_allowed"
    return {"decision": "done", "reason": reason, "state": request[2]}


def _ledger_revoke(
    subject: str, requests: dict[str, list[Any]], revoked: set[str], skip: Skip
) -> dict[str, Any]:
    revoked.add(subject)
    if "ledger_revoke_moves_unknown" not in skip:
        for request in requests.values():
            if request[0] == subject and request[2] == UNKNOWN:
                request[2] = UNRESOLVED
    return {"decision": "done", "reason": "revoked", "state": None}


def _ledger_step(
    step: dict[str, Any], requests: dict[str, list[Any]], revoked: set[str], skip: Skip
) -> dict[str, Any]:
    op = step["op"]
    if op == "submit":
        if step["subject"] in revoked and "ledger_submit_revoked" not in skip:
            return {"decision": "refused", "reason": "retry_after_revoke", "state": None}
        requests[step["permit_id"]] = [step["subject"], step["reservation"], IN_FLIGHT]
        return {"decision": "done", "reason": "submitted", "state": IN_FLIGHT}
    if op == "revoke":
        return _ledger_revoke(step["subject"], requests, revoked, skip)
    request = requests[step["permit_id"]]
    if op == "mark_unknown":
        request[2] = UNRESOLVED if request[0] in revoked else UNKNOWN
        return {"decision": "done", "reason": "marked_unknown", "state": request[2]}
    if op == "retry":
        return _ledger_retry(step, request, revoked, skip)
    if op == "resolve":
        request[2] = COMMITTED if step["committed"] else NOT_COMMITTED
        return {"decision": "done", "reason": "resolved", "state": request[2]}
    raise ValueError(f"unknown ledger op {op!r}")


def _ledger_kind(case: dict[str, Any], skip: Skip) -> dict[str, Any]:
    requests: dict[str, list[Any]] = {}
    revoked: set[str] = set()
    steps = [_ledger_step(step, requests, revoked, skip) for step in case["steps"]]
    settled = (COMMITTED, NOT_COMMITTED)
    open_states = (IN_FLIGHT,) if "ledger_reservation" in skip else (IN_FLIGHT, UNKNOWN, UNRESOLVED)
    reserved = sum(r[1] for r in requests.values() if r[2] in open_states)
    subjects = {
        s: "unknown"
        if any(r[0] == s and r[2] not in settled for r in requests.values())
        else "closed"
        for s in sorted(revoked)
    }
    if not subjects:
        status = "live"
    else:
        status = "unknown" if "unknown" in subjects.values() else "closed"
    return {
        "decision": steps[-1]["decision"],
        "reason": steps[-1]["reason"],
        "reserved": reserved,
        "revocation_status": status,
        "states": {p: r[2] for p, r in sorted(requests.items())},
        "steps": steps,
        "subjects": subjects,
    }


# --- the feed -----------------------------------------------------------------------------------


def _set_refused(code: str) -> dict[str, Any]:
    return {
        "decision": "refused",
        "entry": None,
        "not_before_s": None,
        "reason": code,
        "revocation_status": "unknown",
        "session_id": None,
    }


def _iss_sub(value: Any) -> tuple[str, str] | None:
    if (
        isinstance(value, dict)
        and value.get("format") == "iss_sub"
        and _text(value.get("iss"))
        and _text(value.get("sub"))
    ):
        return value["iss"], value["sub"]
    return None


def _subject(sub_id: Any) -> tuple[str, str, str | None] | None:
    """(issuer, subject, session id or None) of an iss_sub or complex subject identifier."""
    simple = _iss_sub(sub_id)
    if simple is not None:
        return simple[0], simple[1], None
    if not isinstance(sub_id, dict) or sub_id.get("format") != "complex":
        return None
    user = _iss_sub(sub_id.get("user"))
    if user is None:
        return None
    if "session" not in sub_id:
        return user[0], user[1], None
    session = sub_id["session"]
    if not (
        isinstance(session, dict) and session.get("format") == "opaque" and _text(session.get("id"))
    ):
        return None
    return user[0], user[1], session["id"]


def _number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _decode_set(token: bytes, skip: Skip) -> tuple[str, str, dict[str, Any], dict[str, Any], bytes]:
    """The header and payload of a compact JWS, refusing any other spelling (``set_malformed``)."""
    try:
        text = token.decode("ascii")
        parts = text.split(".")
        if len(parts) != 3 and "set_compact" not in skip:
            raise Refused("set_malformed")
        header = strictjson.loads(strictb64.url(parts[0]))
        payload = strictjson.loads(strictb64.url(parts[1]))
        signature = strictb64.url(parts[2])
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refused("set_malformed") from exc
    if "set_header" not in skip and not (
        isinstance(header, dict)
        and set(header) == {"alg", "kid", "typ"}
        and header["alg"] == "EdDSA"
        and header["typ"] == SET_HEADER_TYP
        and _text(header["kid"])
    ):
        raise Refused("set_malformed")
    if "set_payload" not in skip and not (
        isinstance(payload, dict) and isinstance(payload.get("iss"), str)
    ):
        raise Refused("set_malformed")
    return parts[0], parts[1], header, payload, signature


def _shape_ok(payload: dict[str, Any]) -> bool:
    events = payload.get("events")
    return (
        "sub" not in payload
        and "exp" not in payload
        and _text(payload.get("jti"))
        and _number(payload.get("iat"))
        and isinstance(events, dict)
        and len(events) == 1
        and isinstance(next(iter(events.values())), dict)
    )


def _not_before(body: dict[str, Any], iat: float, skip: Skip) -> int:
    stamp = body.get("event_timestamp")
    if "set_not_before" not in skip and _number(stamp) and stamp <= iat:
        return math.floor(stamp)
    return math.floor(iat)


def _issuer_refusal(
    case: dict[str, Any], parts: tuple[str, str, dict[str, Any], dict[str, Any], bytes], skip: Skip
) -> str | None:
    """The first of the key, signature and audience checks the token fails."""
    head, body64, header, payload, signature = parts
    pins = pinned(case["issuer_keys"].get(payload["iss"], []))
    if "set_issuer_key" not in skip and header["kid"] not in pins:
        return "unknown_issuer_key"
    raw = pins.get(header["kid"])
    signed = (
        raw is not None
        and len(signature) == 64
        and _rail().ed25519_verify(raw, f"{head}.{body64}".encode("ascii"), signature)
    )
    if "set_signature" not in skip and not signed:
        return "bad_signature"
    aud = payload.get("aud")
    audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
    if "set_audience" not in skip and case["receiver_audience"] not in audiences:
        return "wrong_audience"
    return None


def _journalled(case: dict[str, Any], payload: dict[str, Any], token: bytes, skip: Skip) -> Any:
    """``delivered`` or a ``jti_reused`` refusal when the jti is journalled, else None."""
    if "set_jti" in skip:
        return None
    digest = hashlib.sha256(token).hexdigest()
    for entry in case["journal"]:
        if entry["jti"] == payload["jti"]:
            if entry["sha256"] != digest:
                return _set_refused("jti_reused")
            return {
                "decision": "delivered",
                "entry": None,
                "not_before_s": None,
                "reason": "jti_delivered",
                "session_id": None,
            }
    return None


def _feed_kind(case: dict[str, Any], directory: Path, skip: Skip) -> dict[str, Any]:
    token = (directory / case["set"]).read_bytes()
    try:
        parts = _decode_set(token, skip)
    except Refused as exc:
        return _set_refused(exc.code)
    payload = parts[3]
    refusal = _issuer_refusal(case, parts, skip)
    if refusal is not None:
        return _set_refused(refusal)
    if "set_shape" not in skip and not _shape_ok(payload):
        return _set_refused("set_shape")
    subject = _subject(payload.get("sub_id"))
    if subject is None:
        return _set_refused("set_shape")
    if "set_subject_issuer" not in skip and subject[0] != payload["iss"]:
        return _set_refused("subject_issuer_mismatch")
    journalled = _journalled(case, payload, token, skip)
    if journalled is not None:
        return dict(journalled)
    ((event, event_body),) = payload["events"].items()
    iat = payload["iat"]
    return _apply_event(case, payload["iss"], subject, event, event_body, iat, skip)


def _apply_event(
    case: dict[str, Any],
    iss: str,
    subject: tuple[str, str, str | None],
    event: str,
    body: dict[str, Any],
    iat: float,
    skip: Skip,
) -> dict[str, Any]:
    answer: dict[str, Any] = {"entry": None, "not_before_s": None, "session_id": None}
    short = event.rsplit("/", 1)[-1].replace("-", "_")
    rotated = {
        **answer,
        "decision": "rotated",
        "not_before_s": _not_before(body, iat, skip),
        "reason": short,
        "revocation_status": "partial",
    }
    if event == SESSION_REVOKED:
        bound = case["session_binding"].get(iss) is True
        if bound and subject[2] is not None and "set_session_binding" not in skip:
            return {
                **answer,
                "decision": "session_ended",
                "reason": short,
                "revocation_status": "partial",
                "session_id": subject[2],
            }
        return rotated
    if event == CREDENTIAL_CHANGE:
        change = body.get("change_type")
        if change == "create" and "set_credential_change" not in skip:
            return {**answer, "decision": "journalled", "reason": short}
        if change in ("create", "revoke", "delete", "update"):
            return rotated
        return _set_refused("set_shape")
    if event in (ACCOUNT_DISABLED, ACCOUNT_PURGED) and "set_account" not in skip:
        return {
            **answer,
            "decision": "revoked",
            "entry": f"{iss}#{subject[1]}",
            "reason": short,
            "revocation_status": "closed",
        }
    if event in (RISK_LEVEL_CHANGE, ACCOUNT_ENABLED, ACCOUNT_DISABLED, ACCOUNT_PURGED) or (
        "set_unknown_event" in skip
    ):
        return {**answer, "decision": "journalled", "reason": short}
    return _set_refused("event_unknown")


# --- running ------------------------------------------------------------------------------------


def verify(case_path: Path, skip: Skip = frozenset()) -> dict[str, Any]:
    """The reference reader's expected object for one case."""
    case = _load(case_path)
    directory, kind = case_path.parent, case["kind"]
    if kind == "permit":
        return _permit_kind(case, directory, skip)
    if kind == "epoch-update":
        return _update_kind(case, directory, skip)
    if kind == "outcome":
        return _outcome_kind(case, directory, skip)
    if kind == "commit":
        return _commit_kind(case, directory, skip)
    if kind == "propagation":
        return _propagation_kind(case, skip)
    if kind == "ledger":
        return _ledger_kind(case, skip)
    if kind == "feed":
        return _feed_kind(case, directory, skip)
    raise ValueError(f"unknown kind {kind!r}")


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(case_path), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        decision = str(answer["decision"])
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(decision) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {decision}"
    return True, answer


def check(
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
    skip: Skip = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case, through the named verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, SUITE)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        case_path = directory / "case.json"
        observed: dict[str, Any] | str
        if command is None:
            try:
                ran, observed = True, verify(case_path, skip)
            except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
                ran, observed = True, f"reader raised {type(exc).__name__}"
        else:
            ran, observed = _external_answer(command, case_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the answer as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(_load(ROOT / "MANIFEST.json")["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
