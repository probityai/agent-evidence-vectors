"""Build the revocation-fence cases byte-identically.

Every case is one directory: ``case.json`` (the reader's pinned keys, clock and state) and the
records it judges. The generator signs every record with Ed25519 seeds derived from published
labels, asks the reference reader for each case's expected object, and stops when the reader's
decision, reason or revocation status differs from the one the case table below states, so a
reader defect fails generation instead of landing in the corpus.

The keys are test keys and protect nothing.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import revocationfence as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/revocation-fence/v1/"
SOURCE = {
    "note": (
        "Synthetic records and keys. The check order and refusal codes restate a target-side "
        "revocation fence; the feed kind reads Security Event Tokens of the OpenID CAEP 1.0 and "
        "RISC 1.0 event types."
    ),
    "source": "https://openid.net/specs/openid-caep-1_0-final.html",
}

SECOND = 1_000_000_000
T0 = 1_767_225_600 * SECOND  # 2026-01-01T00:00:00Z
NB, NA = T0, T0 + 300 * SECOND
NOW = T0 + 60 * SECOND
TARGET = "target:ledger"
SUBJECT = "agent:alpha"
OPERATION = hashlib.sha256(b"operation:transfer 100 to acct-7").hexdigest()
ISSUER, OTHER_ISSUER = "https://idp.example", "https://other-idp.example"
RECEIVER = "https://receiver.example"
IAT = 1_767_225_600


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def public(label: str) -> bytes:
    return bytes(rail.ed25519_public_key(_seed(label)))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def kid(label: str) -> str:
    return reader.key_id(public(label))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _record_bytes(value: object) -> bytes:
    """A record keeps its member order (``v`` first); RFC 8785 sorts for the signature."""
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def sign(claims: dict[str, Any], domain: str, label: str) -> dict[str, Any]:
    signature = rail.ed25519_sign(_seed(label), reader.message(domain, claims))
    return {"claims": claims, "sig": b64(signature)}


KEYS = {
    "authority": [b64(public("authority"))],
    "epoch_source": [b64(public("epoch-source"))],
    "target": [b64(public("target"))],
}

# --- records ------------------------------------------------------------------------------------


def permit_claims(**edit: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "v": 1,
        "permit_id": "permit-1",
        "subject": SUBJECT,
        "epoch": 3,
        "idempotency_key": "idem-1",
        "audience": TARGET,
        "operation_digest": OPERATION,
        "not_before_ns": str(NB),
        "not_after_ns": str(NA),
        "kid": kid("authority"),
    }
    return _edited(claims, edit)


def update_claims(**edit: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "v": 1,
        "subject": SUBJECT,
        "epoch": 4,
        "audience": TARGET,
        "kid": kid("epoch-source"),
    }
    return _edited(claims, edit)


def outcome_claims(**edit: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "v": 1,
        "target_id": TARGET,
        "permit_id": "permit-1",
        "subject": SUBJECT,
        "epoch": 3,
        "idempotency_key": "idem-1",
        "stage": "execute",
        "outcome": "committed",
        "reason": "",
        "shape": "a",
        "signed_at_ns": str(NOW + SECOND),
        "kid": kid("target"),
    }
    return _edited(claims, edit)


_DROP = object()


def _edited(claims: dict[str, Any], edit: dict[str, Any]) -> dict[str, Any]:
    out = dict(claims)
    for key, value in edit.items():
        if value is _DROP:
            del out[key]
        else:
            out[key] = value
    return out


def permit(label: str = "authority", **edit: Any) -> dict[str, Any]:
    return sign(permit_claims(**edit), reader.PERMIT_DOMAIN, label)


def update(label: str = "epoch-source", **edit: Any) -> dict[str, Any]:
    return sign(update_claims(**edit), reader.EPOCH_DOMAIN, label)


def outcome(label: str = "target", **edit: Any) -> dict[str, Any]:
    return sign(outcome_claims(**edit), reader.OUTCOME_DOMAIN, label)


def tampered(record: dict[str, Any], **edit: Any) -> dict[str, Any]:
    """A record whose claims changed after it was signed."""
    out = copy.deepcopy(record)
    out["claims"].update(edit)
    return out


def respelled(record: dict[str, Any]) -> dict[str, Any]:
    """The same signature in a non-canonical base64 spelling: one unused low bit set."""
    out = copy.deepcopy(record)
    sig = out["sig"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = sig[-3]
    out["sig"] = sig[:-3] + alphabet[alphabet.index(last) | 1] + sig[-2:]
    if out["sig"] == sig:
        out["sig"] = sig[:-3] + alphabet[alphabet.index(last) | 2] + sig[-2:]
    return out


# --- case files ---------------------------------------------------------------------------------

Files = dict[str, bytes]
Case = tuple[str, dict[str, Any], Files, str, str, str | None, str]


def _base(kind: str) -> dict[str, Any]:
    return {"audience": TARGET, "keys": copy.deepcopy(KEYS), "kind": kind, "v": 1}


def permit_case(
    name: str,
    record: Any,
    decision: str,
    reason: str,
    shows: str,
    now: int = NOW,
    raw: bytes | None = None,
) -> Case:
    case = {**_base("permit"), "now_ns": str(now), "permit": "permit.json"}
    files = {"permit.json": raw if raw is not None else _record_bytes(record)}
    return (name, case, files, decision, reason, None, shows)


def update_case(
    name: str,
    held: dict[str, int],
    records: list[dict[str, Any]],
    decision: str,
    reason: str,
    status: str | None,
    shows: str,
) -> Case:
    names = [f"update-{i + 1}.json" for i in range(len(records))]
    case = {**_base("epoch-update"), "held": held, "updates": names}
    files = {n: _record_bytes(r) for n, r in zip(names, records, strict=True)}
    return (name, case, files, decision, reason, status, shows)


def outcome_case(name: str, record: dict[str, Any], decision: str, reason: str, shows: str) -> Case:
    case = {**_base("outcome"), "outcome": "outcome.json"}
    return (name, case, {"outcome.json": _record_bytes(record)}, decision, reason, None, shows)


def state(
    shape: str, epoch: Any = 3, effects: dict[str, Any] | None = None, **extra: Any
) -> dict[str, Any]:
    out: dict[str, Any] = {"effects": effects or {}, "epoch": epoch}
    if shape == "b":
        out.update({"lease_expired": False, "revocation_pending": False})
    if shape == "c":
        out["hold"] = "prepared"
    out.update(extra)
    return out


SAME_EFFECT = {"idem-1": {"operation_digest": OPERATION, "permit_id": "permit-1"}}
OTHER_EFFECT = {"idem-1": {"operation_digest": OPERATION, "permit_id": "permit-0"}}


def honest_outcome(
    shape: str, stage: str, code: str, held: dict[str, Any], edit: dict[str, Any]
) -> dict[str, Any]:
    """The outcome an honest target signs for the permit whose claims are ``held``."""
    committed = code in ("commit_done", "replay_done")
    claims = {
        "outcome": "committed" if committed else "refused",
        "reason": "" if committed else code,
        "shape": shape,
        "stage": stage,
    }
    claims.update({k: held[k] for k in ("permit_id", "subject", "epoch", "idempotency_key")})
    claims.update(edit)
    label = claims.pop("label", "target")
    return outcome(str(label), **claims)


def commit_case(
    name: str,
    shape: str,
    st: dict[str, Any],
    decision: str,
    reason: str,
    status: str | None,
    shows: str,
    *,
    record: dict[str, Any] | None = None,
    stage: str = "execute",
    now: int = NOW,
    said: dict[str, Any] | None = None,
) -> Case:
    """A commit case; ``said`` overrides what the stored outcome claims (a dishonest target)."""
    record = record or permit()
    files: Files = {"permit.json": _record_bytes(record)}
    stored: str | None = None
    if decision != "no_outcome":
        signed = honest_outcome(shape, stage, reason, record["claims"], said or {})
        files["outcome.json"] = _record_bytes(signed)
        stored = "outcome.json"
    case = {
        **_base("commit"),
        "now_ns": str(now),
        "outcome": stored,
        "permit": "permit.json",
        "shape": shape,
        "stage": stage,
        "state": st,
    }
    return (name, case, files, decision, reason, status, shows)


def lease(granted_s: int, length_s: int = 30, skew_s: int = 2) -> dict[str, str]:
    return {
        "granted_ns": str(COMMIT + granted_s * SECOND),
        "length_ns": str(length_s * SECOND),
        "skew_ns": str(skew_s * SECOND),
    }


COMMIT = T0 + 120 * SECOND
LEASES = {"gw-east": lease(-10), "gw-west": lease(-5)}


def propagation_case(
    name: str,
    leases: dict[str, Any],
    acks: list[str],
    now_s: float,
    decision: str,
    reason: str,
    status: str,
    shows: str,
) -> Case:
    case = {
        "acks": acks,
        "commit_ns": str(COMMIT),
        "kind": "propagation",
        "leases": leases,
        "now_ns": str(COMMIT + int(now_s * SECOND)),
        "v": 1,
    }
    return (name, case, {}, decision, reason, status, shows)


def submit(pid: str, subject: str = SUBJECT, reservation: int = 100) -> dict[str, Any]:
    return {"op": "submit", "permit_id": pid, "reservation": reservation, "subject": subject}


def mark(pid: str) -> dict[str, Any]:
    return {"op": "mark_unknown", "permit_id": pid}


def revoke(subject: str = SUBJECT) -> dict[str, Any]:
    return {"op": "revoke", "subject": subject}


def retry(pid: str, read_only: bool = False) -> dict[str, Any]:
    return {"op": "retry", "permit_id": pid, "read_only": read_only}


def resolve(pid: str, committed: bool) -> dict[str, Any]:
    return {"committed": committed, "op": "resolve", "permit_id": pid}


def ledger_case(
    name: str, steps: list[dict[str, Any]], decision: str, reason: str, status: str, shows: str
) -> Case:
    return (name, {"kind": "ledger", "steps": steps, "v": 1}, {}, decision, reason, status, shows)


# --- Security Event Tokens ----------------------------------------------------------------------


def iss_sub(sub: str = "user-42", iss: str = ISSUER) -> dict[str, str]:
    return {"format": "iss_sub", "iss": iss, "sub": sub}


def complex_sub(session: str | None = "sess-9", iss: str = ISSUER) -> dict[str, Any]:
    out: dict[str, Any] = {"format": "complex", "user": iss_sub(iss=iss)}
    if session is not None:
        out["session"] = {"format": "opaque", "id": session}
    return out


def set_payload(event: str, body: dict[str, Any] | None = None, **edit: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "jti": "set-1",
        "iat": IAT,
        "aud": RECEIVER,
        "sub_id": iss_sub(),
        "events": {event: body if body is not None else {}},
    }
    return _edited(payload, edit)


def set_header(label: str = "issuer", **edit: Any) -> dict[str, Any]:
    return _edited({"alg": "EdDSA", "kid": kid(label), "typ": "secevent+jwt"}, edit)


def compact(
    payload: dict[str, Any],
    label: str = "issuer",
    header: dict[str, Any] | None = None,
) -> str:
    head = b64url(json.dumps(header or set_header(label), separators=(",", ":")).encode())
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = rail.ed25519_sign(_seed(label), f"{head}.{body}".encode("ascii"))
    return f"{head}.{body}.{b64url(sig)}"


def feed_case(
    name: str,
    token: str,
    decision: str,
    reason: str,
    status: str | None,
    shows: str,
    *,
    binding: bool = True,
    journal: list[dict[str, str]] | None = None,
) -> Case:
    case = {
        "issuer_keys": {
            ISSUER: [b64(public("issuer"))],
            OTHER_ISSUER: [b64(public("other-issuer"))],
        },
        "journal": journal or [],
        "kind": "feed",
        "receiver_audience": RECEIVER,
        "session_binding": {ISSUER: binding, OTHER_ISSUER: False},
        "set": "set.jws",
        "v": 1,
    }
    return (name, case, {"set.jws": token.encode("ascii")}, decision, reason, status, shows)


# --- the cases ----------------------------------------------------------------------------------


def permit_cases() -> list[Case]:
    good = permit()
    repeated = _record_bytes(good).replace(b'"v": 1,', b'"v": 1,\n    "v": 1,', 1)
    m = "malformed"
    return [
        permit_case(
            "permit-valid",
            good,
            "valid",
            "permit_valid",
            "a permit signed by the pinned authority for this target, inside its window",
        ),
        permit_case(
            "permit-valid-at-not-before",
            good,
            "valid",
            "permit_valid",
            "the window is half-open: the first instant is inside",
            now=NB,
        ),
        permit_case(
            "permit-not-yet-valid-one-ns-early",
            good,
            "refused",
            "not_yet_valid",
            "one nanosecond before the window begins",
            now=NB - 1,
        ),
        permit_case(
            "permit-valid-one-ns-before-not-after",
            good,
            "valid",
            "permit_valid",
            "the last nanosecond inside the window",
            now=NA - 1,
        ),
        permit_case(
            "permit-expired-at-not-after",
            good,
            "refused",
            "expired",
            "the window is half-open: its end instant is outside",
            now=NA,
        ),
        permit_case(
            "permit-unknown-authority",
            permit("stranger", kid=kid("stranger")),
            "refused",
            "unknown_authority",
            "signed by a key this target does not pin, naming that key",
        ),
        permit_case(
            "permit-bad-signature-claims-edited",
            tampered(good, epoch=4),
            "refused",
            "bad_signature",
            "the epoch was raised after the authority signed",
        ),
        permit_case(
            "permit-bad-signature-pinned-kid-other-signer",
            permit("stranger"),
            "refused",
            "bad_signature",
            "names the pinned authority's key id and was signed by another key",
        ),
        permit_case(
            "permit-bad-signature-other-domain",
            sign(permit_claims(), reader.EPOCH_DOMAIN, "authority"),
            "refused",
            "bad_signature",
            "the authority's signature under the epoch-update domain does not sign a permit",
        ),
        permit_case(
            "permit-bad-signature-non-canonical-base64",
            respelled(good),
            "refused",
            "bad_signature",
            "the signature bytes are right and their base64 spelling is not the canonical one",
        ),
        permit_case(
            "permit-wrong-audience",
            permit(audience="target:other"),
            "refused",
            "wrong_audience",
            "a genuine permit for another target",
        ),
        permit_case(
            "permit-malformed-epoch-missing",
            permit(epoch=_DROP),
            "refused",
            m,
            "a permit with no epoch: there is no expiry-only mode to fall back to",
        ),
        permit_case(
            "permit-malformed-epoch-float",
            permit(epoch=3.0),
            "refused",
            m,
            "the epoch 3.0 is a JSON number with a fraction part, not an integer",
        ),
        permit_case(
            "permit-malformed-epoch-boolean",
            permit(epoch=True),
            "refused",
            m,
            "the epoch true is not an integer",
        ),
        permit_case(
            "permit-malformed-epoch-negative",
            permit(epoch=-1),
            "refused",
            m,
            "an epoch is never negative",
        ),
        permit_case(
            "permit-malformed-ns-json-number",
            permit(not_before_ns=NB),
            "refused",
            m,
            "a nanosecond time written as a JSON number instead of a decimal string",
        ),
        permit_case(
            "permit-malformed-ns-leading-zero",
            permit(not_after_ns="0" + str(NA)),
            "refused",
            m,
            "a nanosecond time with a leading zero has two spellings",
        ),
        permit_case(
            "permit-malformed-empty-window",
            permit(not_after_ns=str(NB)),
            "refused",
            m,
            "a window whose end equals its start contains no instant",
        ),
        permit_case(
            "permit-malformed-extra-member",
            permit(scope="all"),
            "refused",
            m,
            "a member the permit does not declare, signed along with the rest",
        ),
        permit_case(
            "permit-malformed-version-2",
            permit(v=2),
            "refused",
            m,
            "version 2 is not this protocol",
        ),
        permit_case(
            "permit-malformed-version-boolean",
            permit(v=True),
            "refused",
            m,
            "the version true is not the integer 1",
        ),
        permit_case(
            "permit-malformed-empty-subject",
            permit(subject=""),
            "refused",
            m,
            "an empty subject names nobody",
        ),
        permit_case(
            "permit-malformed-envelope-extra-member",
            {**good, "kid": kid("authority")},
            "refused",
            m,
            "the signed record carries a member beside claims and sig",
        ),
        permit_case(
            "permit-malformed-repeated-member",
            good,
            "refused",
            m,
            "the claims name v twice; two readers could read two records",
            raw=repeated,
        ),
    ]


def update_cases() -> list[Case]:
    held = {SUBJECT: 3}
    m = "malformed"
    return [
        update_case(
            "update-installs-next-epoch",
            held,
            [update()],
            "installed",
            "epoch_installed",
            "closed",
            "revoking a subject is installing its next epoch",
        ),
        update_case(
            "update-installs-first-epoch",
            {},
            [update(epoch=0)],
            "installed",
            "epoch_installed",
            None,
            "a target that held no epoch for the subject installs one",
        ),
        update_case(
            "update-unchanged-at-equal-epoch",
            held,
            [update(epoch=3)],
            "unchanged",
            "epoch_unchanged",
            None,
            "the update repeats the epoch already held",
        ),
        update_case(
            "update-rollback-refused",
            {SUBJECT: 4},
            [update(epoch=3)],
            "refused",
            "epoch_rollback",
            "closed",
            "a replayed older update is refused and the revocation stays",
        ),
        update_case(
            "update-revoke-then-replay-old",
            held,
            [update(), update(epoch=3)],
            "refused",
            "epoch_rollback",
            "closed",
            "the revocation installs, then the earlier update is replayed",
        ),
        update_case(
            "update-refusal-does-not-stop-later",
            held,
            [update("authority"), update()],
            "installed",
            "epoch_installed",
            "closed",
            "an update the epoch source did not sign is refused and the next genuine one installs",
        ),
        update_case(
            "update-unknown-epoch-source",
            held,
            [update("authority", kid=kid("authority"))],
            "refused",
            "unknown_epoch_source",
            None,
            "the authority's permit key is not an epoch source",
        ),
        update_case(
            "update-bad-signature",
            held,
            [tampered(update(), epoch=9)],
            "refused",
            "bad_signature",
            None,
            "the epoch was changed after the source signed",
        ),
        update_case(
            "update-wrong-audience",
            held,
            [update(audience="target:other")],
            "refused",
            "wrong_audience",
            None,
            "a genuine update for another target",
        ),
        update_case(
            "update-malformed-epoch-negative",
            held,
            [update(epoch=-1)],
            "refused",
            m,
            None,
            "an epoch is never negative",
        ),
        update_case(
            "update-malformed-epoch-float",
            held,
            [update(epoch=4.0)],
            "refused",
            m,
            None,
            "the epoch 4.0 is not an integer",
        ),
        update_case(
            "update-malformed-extra-member",
            held,
            [update(reason="compromise")],
            "refused",
            m,
            None,
            "a member the update does not declare",
        ),
        update_case(
            "update-malformed-empty-subject",
            held,
            [update(subject="")],
            "refused",
            m,
            None,
            "an empty subject names nobody",
        ),
        update_case(
            "update-malformed-version-2",
            held,
            [update(v=2)],
            "refused",
            m,
            None,
            "version 2 is not this protocol",
        ),
    ]


def outcome_cases() -> list[Case]:
    m = "malformed"
    return [
        outcome_case(
            "outcome-valid-committed",
            outcome(),
            "valid",
            "outcome_valid",
            "the target's signed statement that it committed",
        ),
        outcome_case(
            "outcome-valid-refused",
            outcome(outcome="refused", reason="epoch_mismatch"),
            "valid",
            "outcome_valid",
            "the target's signed statement that it refused, with the code",
        ),
        outcome_case(
            "outcome-malformed-stage-before-key",
            outcome("stranger", stage="prepare", kid=kid("stranger")),
            "refused",
            m,
            "an unknown stage is malformed before the key is looked at",
        ),
        outcome_case(
            "outcome-malformed-outcome-value",
            outcome(outcome="aborted"),
            "refused",
            m,
            "an outcome is committed or refused",
        ),
        outcome_case(
            "outcome-unknown-target-key",
            outcome("stranger", kid=kid("stranger")),
            "refused",
            "unknown_target_key",
            "signed by a key the reader does not pin",
        ),
        outcome_case(
            "outcome-key-before-types",
            outcome("stranger", kid=kid("stranger"), epoch="3"),
            "refused",
            "unknown_target_key",
            "an unpinned key is refused before the member types are read",
        ),
        outcome_case(
            "outcome-bad-signature",
            tampered(outcome(), outcome="refused"),
            "refused",
            "bad_signature",
            "a committed outcome edited to read refused",
        ),
        outcome_case(
            "outcome-malformed-signed-at-number",
            outcome(signed_at_ns=1_767_225_661),
            "refused",
            m,
            "a genuine signature over a time written as a JSON number",
        ),
        outcome_case(
            "outcome-malformed-reason-not-string",
            outcome(reason=None),
            "refused",
            m,
            "the reason is a string, empty when committed",
        ),
        outcome_case(
            "outcome-malformed-extra-member",
            outcome(note="x"),
            "refused",
            m,
            "a member the outcome does not declare",
        ),
    ]


def commit_cases() -> list[Case]:
    a, b, c = "a", "b", "c"
    return [
        commit_case(
            "commit-a-committed",
            a,
            state(a),
            "committed",
            "commit_done",
            "live",
            "the store's epoch equals the permit's: the effect commits",
        ),
        commit_case(
            "commit-a-revoked-effect-not-done",
            a,
            state(a, 4),
            "refused",
            "epoch_mismatch",
            "closed",
            "the subject was revoked before the commit and the effect was not done",
        ),
        commit_case(
            "commit-a-revoked-effect-done-replays",
            a,
            state(a, 4, SAME_EFFECT),
            "replayed",
            "replay_done",
            "closed",
            "the effect committed before the revocation; a retry returns it and runs nothing",
        ),
        commit_case(
            "commit-a-replayed",
            a,
            state(a, 3, SAME_EFFECT),
            "replayed",
            "replay_done",
            "live",
            "a retry under the same key and operation",
            stage="settle",
        ),
        commit_case(
            "commit-a-key-reused",
            a,
            state(a, 3, OTHER_EFFECT),
            "refused",
            "key_reused",
            "live",
            "the idempotency key already names another permit's effect",
        ),
        commit_case(
            "commit-a-epoch-unavailable",
            a,
            state(a, "unavailable"),
            "refused",
            "epoch_unavailable",
            "unknown",
            "the store could not give an epoch: fail closed",
        ),
        commit_case(
            "commit-a-replay-before-epoch-read",
            a,
            state(a, "unavailable", SAME_EFFECT),
            "replayed",
            "replay_done",
            "unknown",
            "a recorded effect is returned before the epoch is needed",
        ),
        commit_case(
            "commit-a-epoch-unknown",
            a,
            state(a, None),
            "refused",
            "epoch_unknown",
            "unknown",
            "the target holds no epoch for the subject: it has heard nothing",
        ),
        commit_case(
            "commit-a-permit-from-future-epoch",
            a,
            state(a, 3),
            "refused",
            "epoch_mismatch",
            "unknown",
            "the permit names epoch 5 and the target holds 3: the target is behind",
            record=permit(epoch=5),
        ),
        commit_case(
            "commit-a-no-outcome-expired",
            a,
            state(a),
            "no_outcome",
            "expired",
            None,
            "an expired permit is refused before any outcome can be attributed",
            now=NA,
        ),
        commit_case(
            "commit-a-no-outcome-unknown-authority",
            a,
            state(a, 4),
            "no_outcome",
            "unknown_authority",
            None,
            "a permit under an unpinned key gets no outcome",
            record=permit("stranger", kid=kid("stranger")),
        ),
        commit_case(
            "commit-a-outcome-says-committed-after-revocation",
            a,
            state(a, 4),
            "outcome_mismatch",
            "epoch_mismatch",
            "closed",
            "the target signed committed while its epoch says revoked",
            said={"outcome": "committed", "reason": ""},
        ),
        commit_case(
            "commit-a-outcome-wrong-code",
            a,
            state(a, 4),
            "outcome_mismatch",
            "epoch_mismatch",
            "closed",
            "the target signed a refusal with another code",
            said={"reason": "expired"},
        ),
        commit_case(
            "commit-a-outcome-unpinned-key",
            a,
            state(a),
            "outcome_mismatch",
            "commit_done",
            "live",
            "an honest-looking outcome signed by a key the reader does not pin",
            said={"label": "stranger", "kid": kid("stranger")},
        ),
        commit_case(
            "commit-a-outcome-other-permit",
            a,
            state(a),
            "outcome_mismatch",
            "commit_done",
            "live",
            "the target's outcome names another permit",
            said={"permit_id": "permit-2"},
        ),
        commit_case(
            "commit-b-committed",
            b,
            state(b),
            "committed",
            "commit_done",
            "live",
            "a commit lease at the permit's epoch, still live",
        ),
        commit_case(
            "commit-b-revocation-pending",
            b,
            state(b, revocation_pending=True),
            "refused",
            "revocation_pending",
            "partial",
            "a revocation waits on leases in force: no new lease is granted",
        ),
        commit_case(
            "commit-b-replayed-while-pending",
            b,
            state(b, 3, SAME_EFFECT, revocation_pending=True),
            "replayed",
            "replay_done",
            "partial",
            "a retry of a done effect is returned while the revocation waits",
        ),
        commit_case(
            "commit-b-epoch-unknown-before-pending",
            b,
            state(b, None, revocation_pending=True),
            "refused",
            "epoch_unknown",
            "unknown",
            "no epoch held is refused before the pending revocation is consulted",
        ),
        commit_case(
            "commit-b-lease-expired",
            b,
            state(b, lease_expired=True),
            "refused",
            "lease_expired",
            "live",
            "the commit lease ended before the commit began",
        ),
        commit_case(
            "commit-b-revoked",
            b,
            state(b, 4, lease_expired=True),
            "refused",
            "epoch_mismatch",
            "closed",
            "the revocation committed; the epoch is checked before the lease",
        ),
        commit_case(
            "commit-b-key-reused",
            b,
            state(b, 3, OTHER_EFFECT),
            "refused",
            "key_reused",
            "live",
            "the idempotency key already names another permit's effect",
        ),
        commit_case(
            "commit-c-committed",
            c,
            state(c),
            "committed",
            "commit_done",
            "live",
            "the coordinator's prepared hold commits",
            stage="final",
        ),
        commit_case(
            "commit-c-revoked-before-commit-voided",
            c,
            state(c, hold="voided"),
            "refused",
            "revoked_before_commit",
            "closed",
            "the revocation voided the prepared hold and the participant confirmed it",
        ),
        commit_case(
            "commit-c-revoked-before-commit-void-pending",
            c,
            state(c, hold="void_pending"),
            "refused",
            "revoked_before_commit",
            "partial",
            "the hold is void pending: the participant has not confirmed the release",
        ),
        commit_case(
            "commit-c-revoked",
            c,
            state(c, 4),
            "refused",
            "epoch_mismatch",
            "closed",
            "the subject's epoch moved before the prepare",
        ),
        commit_case(
            "commit-c-epoch-unknown",
            c,
            state(c, None),
            "refused",
            "epoch_unknown",
            "unknown",
            "the coordinator holds no epoch for the subject",
        ),
        commit_case(
            "commit-c-replayed-after-void",
            c,
            state(c, 3, SAME_EFFECT, hold="voided"),
            "replayed",
            "replay_done",
            "closed",
            "the first delivery committed; a retry's hold is voided and the effect is returned",
        ),
    ]


def propagation_cases() -> list[Case]:
    ended = {**LEASES, "gw-north": lease(-40), "gw-south": lease(-30)}
    return [
        propagation_case(
            "propagation-all-acknowledged",
            LEASES,
            ["gw-east", "gw-west"],
            1,
            "revoked_for_new_admissions",
            "propagation_done",
            "closed",
            "every gateway that held a live lease at the commit acknowledged",
        ),
        propagation_case(
            "propagation-pending-on-both",
            LEASES,
            [],
            1,
            "pending",
            "propagation_pending",
            "partial",
            "no gateway acknowledged: both still admit on the old list until lease plus skew",
        ),
        propagation_case(
            "propagation-pending-on-one",
            LEASES,
            ["gw-east"],
            1,
            "pending",
            "propagation_pending",
            "partial",
            "one gateway acknowledged and one is waited on",
        ),
        propagation_case(
            "propagation-skew-keeps-pending",
            LEASES,
            ["gw-east"],
            26,
            "pending",
            "propagation_pending",
            "partial",
            "the lease ended at 25 s and the skew bound keeps it waited on to 27 s",
        ),
        propagation_case(
            "propagation-ends-at-lease-plus-skew",
            LEASES,
            ["gw-east"],
            27,
            "revoked_for_new_admissions",
            "propagation_done",
            "closed",
            "at lease plus skew the last gateway no longer admits on the old list",
        ),
        propagation_case(
            "propagation-unacknowledged-leases-end",
            LEASES,
            [],
            40,
            "revoked_for_new_admissions",
            "propagation_done",
            "closed",
            "no acknowledgement arrived and every lease plus skew has ended",
        ),
        propagation_case(
            "propagation-ended-leases-not-waited-on",
            ended,
            ["gw-east", "gw-west"],
            1,
            "revoked_for_new_admissions",
            "propagation_done",
            "closed",
            "leases that ended at or before the commit instant are not live at it",
        ),
        propagation_case(
            "propagation-ack-without-live-lease",
            ended,
            ["gw-east", "gw-north"],
            1,
            "refused",
            "malformed",
            "unknown",
            "an acknowledgement from a gateway that held no live lease at the commit",
        ),
    ]


def ledger_cases() -> list[Case]:
    beta = "agent:beta"
    return [
        ledger_case(
            "ledger-no-revocation",
            [submit("p1"), resolve("p1", True)],
            "done",
            "resolved",
            "live",
            "a request in flight resolves committed with no revocation",
        ),
        ledger_case(
            "ledger-resolved-after-revoke",
            [submit("p1"), mark("p1"), revoke(), retry("p1", read_only=True), resolve("p1", True)],
            "done",
            "resolved",
            "closed",
            "the unknown outcome is reconciled after the revocation and the reservation ends",
        ),
        ledger_case(
            "ledger-retry-after-revoke-refused",
            [submit("p1"), mark("p1"), revoke(), retry("p1")],
            "refused",
            "retry_after_revoke",
            "unknown",
            "a retry of an unknown outcome after the revocation is a new admission",
        ),
        ledger_case(
            "ledger-read-only-status-proceeds",
            [submit("p1"), mark("p1"), revoke(), retry("p1", read_only=True)],
            "done",
            "read_only_status",
            "unknown",
            "a read-only status query proceeds and the outcome stays unresolved",
        ),
        ledger_case(
            "ledger-submit-after-revoke-refused",
            [revoke(), submit("p2")],
            "refused",
            "retry_after_revoke",
            "closed",
            "a submit for a revoked subject is a new admission",
        ),
        ledger_case(
            "ledger-in-flight-at-revoke",
            [submit("p1"), revoke()],
            "done",
            "revoked",
            "unknown",
            "a request in flight at the revocation keeps it open",
        ),
        ledger_case(
            "ledger-unknown-after-revoke",
            [submit("p1"), revoke(), mark("p1")],
            "done",
            "marked_unknown",
            "unknown",
            "an outcome that turns unknown after the revocation is unresolved, revoked",
        ),
        ledger_case(
            "ledger-not-committed-closes",
            [submit("p1"), mark("p1"), revoke(), resolve("p1", False)],
            "done",
            "resolved",
            "closed",
            "reconciliation says the effect did not commit: the revocation is closed",
        ),
        ledger_case(
            "ledger-other-subject-retries",
            [submit("p1"), submit("p2", beta, 40), mark("p1"), mark("p2"), revoke(), retry("p2")],
            "done",
            "retry_allowed",
            "unknown",
            "another subject's unknown outcome may still be retried",
        ),
    ]


def feed_cases() -> list[Case]:
    disabled = reader.ACCOUNT_DISABLED
    session = reader.SESSION_REVOKED
    change = reader.CREDENTIAL_CHANGE
    good = compact(set_payload(disabled))
    head, body, sig = good.split(".")
    other_body = b64url(
        json.dumps(set_payload(disabled, jti="set-2"), separators=(",", ":")).encode()
    )
    return [
        feed_case(
            "feed-account-disabled-revoked",
            good,
            "revoked",
            "account_disabled",
            "closed",
            "a RISC account-disabled event writes a permanent entry for the subject",
        ),
        feed_case(
            "feed-account-purged-revoked",
            compact(set_payload(reader.ACCOUNT_PURGED)),
            "revoked",
            "account_purged",
            "closed",
            "a RISC account-purged event writes a permanent entry",
        ),
        feed_case(
            "feed-audience-list",
            compact(set_payload(disabled, aud=["https://a.example", RECEIVER])),
            "revoked",
            "account_disabled",
            "closed",
            "an aud list that includes the receiver",
        ),
        feed_case(
            "feed-account-enabled-journalled",
            compact(set_payload(reader.ACCOUNT_ENABLED)),
            "journalled",
            "account_enabled",
            None,
            "account-enabled is recorded and never un-revokes",
        ),
        feed_case(
            "feed-risk-level-change-journalled",
            compact(set_payload(reader.RISK_LEVEL_CHANGE, {"current_level": "high"})),
            "journalled",
            "risk_level_change",
            None,
            "a risk change is recorded and revokes nothing",
        ),
        feed_case(
            "feed-session-revoked-bound",
            compact(set_payload(session, sub_id=complex_sub())),
            "session_ended",
            "session_revoked",
            "partial",
            "the receiver binds session ids for this issuer and the token names one",
        ),
        feed_case(
            "feed-session-revoked-unbound",
            compact(set_payload(session, sub_id=complex_sub())),
            "rotated",
            "session_revoked",
            "partial",
            "the receiver binds no session ids for this issuer: rotation class",
            binding=False,
        ),
        feed_case(
            "feed-session-revoked-no-session",
            compact(set_payload(session)),
            "rotated",
            "session_revoked",
            "partial",
            "the token's subject carries no session",
        ),
        feed_case(
            "feed-session-revoked-complex-no-session",
            compact(set_payload(session, sub_id=complex_sub(None))),
            "rotated",
            "session_revoked",
            "partial",
            "a complex subject with a user and no session",
        ),
        feed_case(
            "feed-credential-change-create",
            compact(set_payload(change, {"change_type": "create", "credential_type": "password"})),
            "journalled",
            "credential_change",
            None,
            "a new credential revokes nothing",
        ),
        feed_case(
            "feed-credential-change-revoke",
            compact(set_payload(change, {"change_type": "revoke", "credential_type": "password"})),
            "rotated",
            "credential_change",
            "partial",
            "a revoked credential rotates the subject",
        ),
        feed_case(
            "feed-credential-change-delete",
            compact(
                set_payload(change, {"change_type": "delete", "credential_type": "fido2-roaming"})
            ),
            "rotated",
            "credential_change",
            "partial",
            "a deleted credential rotates the subject",
        ),
        feed_case(
            "feed-credential-change-update",
            compact(set_payload(change, {"change_type": "update", "credential_type": "password"})),
            "rotated",
            "credential_change",
            "partial",
            "an updated credential rotates the subject",
        ),
        feed_case(
            "feed-credential-change-unknown-type",
            compact(set_payload(change, {"change_type": "suspend"})),
            "refused",
            "set_shape",
            "unknown",
            "a change_type CAEP 1.0 does not define",
        ),
        feed_case(
            "feed-not-before-event-timestamp",
            compact(set_payload(session, {"event_timestamp": IAT - 30})),
            "rotated",
            "session_revoked",
            "partial",
            "rotation takes effect from the event time",
        ),
        feed_case(
            "feed-not-before-event-after-iat",
            compact(set_payload(session, {"event_timestamp": IAT + 30})),
            "rotated",
            "session_revoked",
            "partial",
            "an event time later than iat is not used",
        ),
        feed_case(
            "feed-not-before-fractional-iat",
            compact(set_payload(session, iat=IAT + 0.75)),
            "rotated",
            "session_revoked",
            "partial",
            "an iat with a fraction, as the CAEP 1.0 examples carry, is floored",
        ),
        feed_case(
            "feed-unknown-event",
            compact(set_payload(reader.CAEP + "assurance-level-change")),
            "refused",
            "event_unknown",
            "unknown",
            "an event type this receiver does not act on",
        ),
        feed_case(
            "feed-duplicate-delivered",
            good,
            "delivered",
            "jti_delivered",
            None,
            "the same token again: already journalled, nothing changes",
            journal=[{"jti": "set-1", "sha256": _sha(good.encode())}],
        ),
        feed_case(
            "feed-jti-reused",
            good,
            "refused",
            "jti_reused",
            "unknown",
            "the jti is journalled for different token bytes",
            journal=[{"jti": "set-1", "sha256": _sha(b"another token")}],
        ),
        feed_case(
            "feed-set-malformed-two-parts",
            f"{head}.{body}",
            "refused",
            "set_malformed",
            "unknown",
            "a compact JWS has three parts",
        ),
        feed_case(
            "feed-set-malformed-padded",
            f"{head}.{body}.{sig}==",
            "refused",
            "set_malformed",
            "unknown",
            "base64url in a JWS carries no padding",
        ),
        feed_case(
            "feed-set-malformed-alg",
            compact(set_payload(disabled), header=set_header(alg="ES256")),
            "refused",
            "set_malformed",
            "unknown",
            "the header names an algorithm other than EdDSA",
        ),
        feed_case(
            "feed-set-malformed-typ",
            compact(set_payload(disabled), header=set_header(typ="JWT")),
            "refused",
            "set_malformed",
            "unknown",
            "the header type is not secevent+jwt",
        ),
        feed_case(
            "feed-set-malformed-header-member",
            compact(set_payload(disabled), header=set_header(cty="json")),
            "refused",
            "set_malformed",
            "unknown",
            "the header carries a member beside alg, kid and typ",
        ),
        feed_case(
            "feed-set-malformed-no-iss",
            compact(set_payload(disabled, iss=_DROP)),
            "refused",
            "set_malformed",
            "unknown",
            "a payload with no string iss",
        ),
        feed_case(
            "feed-unknown-issuer-key",
            compact(set_payload(disabled), label="stranger"),
            "refused",
            "unknown_issuer_key",
            "unknown",
            "signed by a key pinned for no issuer",
        ),
        feed_case(
            "feed-key-of-another-issuer",
            compact(set_payload(disabled), label="other-issuer"),
            "refused",
            "unknown_issuer_key",
            "unknown",
            "signed by the key pinned for another issuer",
        ),
        feed_case(
            "feed-bad-signature",
            f"{head}.{other_body}.{sig}",
            "refused",
            "bad_signature",
            "unknown",
            "the payload was replaced after the issuer signed",
        ),
        feed_case(
            "feed-wrong-audience",
            compact(set_payload(disabled, aud="https://a.example")),
            "refused",
            "wrong_audience",
            "unknown",
            "a genuine token for another receiver",
        ),
        feed_case(
            "feed-shape-sub-present",
            compact(set_payload(disabled, sub="user-42")),
            "refused",
            "set_shape",
            "unknown",
            "a SET carries no sub claim",
        ),
        feed_case(
            "feed-shape-exp-present",
            compact(set_payload(disabled, exp=IAT + 60)),
            "refused",
            "set_shape",
            "unknown",
            "a SET carries no exp claim",
        ),
        feed_case(
            "feed-shape-two-events",
            compact(set_payload(disabled, events={disabled: {}, reader.ACCOUNT_PURGED: {}})),
            "refused",
            "set_shape",
            "unknown",
            "one event per token",
        ),
        feed_case(
            "feed-shape-empty-jti",
            compact(set_payload(disabled, jti="")),
            "refused",
            "set_shape",
            "unknown",
            "an empty jti identifies nothing",
        ),
        feed_case(
            "feed-shape-iat-string",
            compact(set_payload(disabled, iat=str(IAT))),
            "refused",
            "set_shape",
            "unknown",
            "iat is a JSON number",
        ),
        feed_case(
            "feed-shape-no-sub-id",
            compact(set_payload(disabled, sub_id=_DROP)),
            "refused",
            "set_shape",
            "unknown",
            "a token with no subject identifier",
        ),
        feed_case(
            "feed-subject-issuer-mismatch",
            compact(set_payload(disabled, sub_id=iss_sub(iss=OTHER_ISSUER))),
            "refused",
            "subject_issuer_mismatch",
            "unknown",
            "a transmitter states an account of another issuer",
        ),
        feed_case(
            "feed-subject-issuer-mismatch-complex",
            compact(set_payload(session, sub_id=complex_sub(iss=OTHER_ISSUER))),
            "refused",
            "subject_issuer_mismatch",
            "unknown",
            "the user inside a complex subject belongs to another issuer",
        ),
    ]


def cases() -> list[Case]:
    """Every case: id, case file, record files, decision, reason, status and what it shows."""
    return [
        *permit_cases(),
        *update_cases(),
        *outcome_cases(),
        *commit_cases(),
        *propagation_cases(),
        *ledger_cases(),
        *feed_cases(),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries: list[dict[str, Any]] = []
    kinds: list[str] = []
    for name, case, records, decision, reason, status, shows in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        files = {"case.json": _json(case), **records}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        expected = reader.verify(directory / "case.json")
        stated = (expected["decision"], expected["reason"], expected.get("revocation_status"))
        if stated != (decision, reason, status):
            raise SystemExit(
                f"{name}: the reader says {stated}, the case {(decision, reason, status)}"
            )
        kinds.append(case["kind"])
        entries.append(
            {
                "edit": shows,
                "expected": expected,
                "files": {filename: _sha(data) for filename, data in sorted(files.items())},
                "id": name,
                "path": f"cases/{name}",
            }
        )
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "kinds": {kind: kinds.count(kind) for kind in sorted(set(kinds))},
        "provenance": copy.deepcopy(SOURCE),
        "suite": SUITE,
        "synthetic": True,
        "typeUri": reader.TYPE_URI,
        "verifierContract": "verifier case.json --json prints the expected object; exit 0 for an "
        "accepting decision, 1 refused, 2 pending, 3 no_outcome, 4 outcome_mismatch",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
