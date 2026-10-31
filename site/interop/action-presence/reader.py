"""Read signed actions without treating two missing actions as a match.

This bounded profile reads one grant, one receipt, an optional intent, and
delegation observations. It checks supplied bytes. It makes no live lookup.
"""

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from agent_evidence_vectors import run_vectors

PROFILE = "probity.signed-action-presence/v1"
MISSING = object()
SAFE_INTEGER = 2**53 - 1
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PRIME = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
CURVE_D = -121665 * pow(121666, PRIME - 2, PRIME) % PRIME
IDENTITY = (0, 1)
TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z"
)
DERIVED = {
    "observation": {"evidence_id", "witness_sig", "edge_sig", "consent"},
    "grant": {"grant_ref", "caller_sig", "action_binding"},
    "receipt": {"receipt_id", "provider_sig", "action_binding"},
    "intent": {"intent_id", "intent_sig", "action_binding"},
}


class Unsupported(ValueError):
    """The supplied input is outside this selected offline profile."""


def _json_members(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise Unsupported("duplicate JSON member")
        result[name] = value
    return result


def _json_constant(value: str) -> None:
    raise Unsupported("non-JSON numeric constant: " + value)


def decode_json(raw: bytes):
    """Read UTF-8 JSON without discarding duplicate members at any depth."""
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_json_members,
        parse_constant=_json_constant,
    )


def _string(value: str) -> str:
    value = value.encode("utf-16-le", "surrogatepass").decode(
        "utf-16-le", "surrogatepass"
    )
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return re.sub(r"[\ud800-\udfff]", lambda match: f"\\u{ord(match[0]):04x}", encoded)


def _number(value: float) -> str:
    if type(value) is float and (not math.isfinite(value) or value != int(value)):
        raise Unsupported("non-integer number")
    if abs(value) > SAFE_INTEGER:
        raise Unsupported("unsafe number")
    return str(int(value))


def _object(value: dict, depth: int) -> str:
    if any(
        not isinstance(key, str) or any(not 32 <= ord(c) <= 126 for c in key)
        for key in value
    ):
        raise Unsupported("object key is not printable ASCII")
    return (
        "{"
        + ",".join(
            _string(k) + ":" + _canonical(value[k], depth + 1) for k in sorted(value)
        )
        + "}"
    )


def _canonical(value, depth: int) -> str:
    if depth > 64:
        raise Unsupported("canonical depth exceeds 64")
    if value is None or type(value) is bool:
        return json.dumps(value)
    if type(value) in (int, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        return _object(value, depth)
    raise Unsupported("not a JSON value")


def canonical(value) -> bytes:
    """Return printable-ASCII-key, safe-integer canonical JSON bytes."""
    return _canonical(value, 0).encode("utf-8")


def action_shape(value) -> str:
    """Keep absence distinct from every present JSON value."""
    if value is MISSING:
        return "missing"
    if value is None:
        return "null"
    if value is False:
        return "false"
    if type(value) in (int, float) and value == 0:
        return "zero"
    if value == "":
        return "empty_string"
    return "present"


def actions_equal(left, right) -> bool:
    """Compare canonical actions only when neither action is degenerate."""
    if action_shape(left) != "present" or action_shape(right) != "present":
        return False
    return canonical(left) == canonical(right)


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = CURVE_D * x1 * x2 * y1 * y2 % PRIME
    return (
        (x1 * y2 + y1 * x2) * pow((1 + product) % PRIME, PRIME - 2, PRIME) % PRIME,
        (y1 * y2 + x1 * x2) * pow((1 - product) % PRIME, PRIME - 2, PRIME) % PRIME,
    )


def _decode_point(key: bytes) -> tuple[int, int] | None:
    if len(key) != 32:
        return None
    encoded = int.from_bytes(key, "little")
    sign, y = encoded >> 255, encoded & (2**255 - 1)
    if y >= PRIME:
        return None
    squared = (y * y - 1) * pow((CURVE_D * y * y + 1) % PRIME, PRIME - 2, PRIME) % PRIME
    x = pow(squared, (PRIME + 3) // 8, PRIME)
    if x * x % PRIME != squared:
        x = x * pow(2, (PRIME - 1) // 4, PRIME) % PRIME
    if x * x % PRIME != squared or (x == 0 and sign):
        return None
    if x % 2 != sign:
        x = PRIME - x
    return x, y


@lru_cache(maxsize=128)
def prime_order_key(key: bytes) -> bool:
    """Reject identity, mixed-order and non-canonical Ed25519 public keys."""
    point = _decode_point(key)
    if point is None or point == IDENTITY:
        return False
    result, scalar = IDENTITY, ORDER
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result == IDENTITY


def _base58(digits: str) -> bytes | None:
    if not digits or len(digits) > 64 or any(char not in BASE58 for char in digits):
        return None
    number = 0
    for char in digits:
        number = number * 58 + BASE58.index(char)
    raw = b"\0" * (len(digits) - len(digits.lstrip("1")))
    raw += number.to_bytes((number.bit_length() + 7) // 8, "big")
    return raw


def public_key(identifier) -> bytes | None:
    """Resolve a canonical Ed25519 did:key without a network request."""
    if not isinstance(identifier, str) or not identifier.startswith("did:key:z"):
        return None
    raw = _base58(identifier[9:])
    if raw is None or len(raw) != 34 or raw[:2] != b"\xed\x01":
        return None
    if not prime_order_key(raw[2:]):
        return None
    return raw[2:]


def signature_valid(identifier, signature, preimage) -> bool:
    """Check standard canonical base64 and the pinned Vectors Ed25519 primitive."""
    key = public_key(identifier)
    if key is None or not isinstance(signature, str) or len(signature) > 128:
        return False
    try:
        raw = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != signature:
        return False
    return run_vectors.ed25519_verify(key, canonical(preimage), raw)


def preimage(record: dict, kind: str) -> dict:
    """Keep unknown signed fields and omit only that record's derived fields."""
    return {key: value for key, value in record.items() if key not in DERIVED[kind]}


def identifier(record: dict, kind: str) -> str:
    return hashlib.sha256(canonical(preimage(record, kind))).hexdigest()


def _timestamp(value) -> datetime | None:
    if not isinstance(value, str) or not TIME.fullmatch(value):
        return None
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return instant.replace(microsecond=(instant.microsecond // 1000) * 1000)


def _window(record: dict, field: str, grant: dict) -> str | None:
    instant = _timestamp(record.get(field))
    if instant is None:
        return "invalid_timestamp"
    for key, lower in (("not_before", True), ("not_after", False)):
        value = grant.get(key)
        if value is None:
            continue
        bound = _timestamp(value)
        if bound is None:
            return "invalid_timestamp"
        if (lower and instant < bound) or (not lower and instant > bound):
            return "outside_authorization_window"
    return None


def _binding_shape(binding) -> str | None:
    if (
        not isinstance(binding, dict)
        or binding.get("type") != "canonical_request_digest"
    ):
        return "action_binding_malformed"
    digest = binding.get("digest")
    if (
        not isinstance(digest, dict)
        or digest.get("alg") != "sha-256"
        or not isinstance(digest.get("value"), str)
    ):
        return "action_binding_malformed"
    if (
        binding.get("canonicalization") != "musubi-canonical-v0"
        or binding.get("preimage_profile") != "task-execution-bind-v0/action"
    ):
        return "action_binding_unknown_profile"
    return None


def _binding(record: dict, field: str) -> str | None:
    if "action_binding" not in record:
        return None
    binding = record["action_binding"]
    reason = _binding_shape(binding)
    if reason:
        return reason
    if (
        record.get(field) is None
        or binding["digest"]["value"]
        != hashlib.sha256(canonical(record[field])).hexdigest()
    ):
        return "action_binding_mismatch"
    return None


def _pair_identity(grant: dict, record: dict, kind: str) -> str | None:
    if grant.get("grant_ref") != identifier(grant, "grant"):
        return "grant_recompute_mismatch"
    field, id_field = (
        ("executed_action", "receipt_id")
        if kind == "receipt"
        else ("proposed_action", "intent_id")
    )
    if record.get(id_field) != identifier(record, kind):
        return kind + "_recompute_mismatch"
    bindings = ([(grant, "action")] if kind == "receipt" else []) + [(record, field)]
    for selected, action in bindings:
        reason = _binding(selected, action)
        if reason is not None:
            return reason
    if record.get("grant_ref") != identifier(grant, "grant"):
        return kind + "_unbound"
    return None


def _pair_context(grant: dict, record: dict, kind: str) -> str | None:
    reason = _pair_identity(grant, record, kind)
    if reason is not None:
        return reason
    time_field = "executed_at" if kind == "receipt" else "declared_at"
    reason = _window(record, time_field, grant)
    if reason == "invalid_timestamp":
        return reason
    if grant.get("provider_id") is not None and grant["provider_id"] != record.get(
        "provider_id"
    ):
        return "provider_not_authorized"
    if reason is not None:
        return reason
    return None


def _pair_reason(grant: dict, record: dict, kind: str) -> str | None:
    reason = _pair_context(grant, record, kind)
    if reason is not None:
        return reason
    field = "executed_action" if kind == "receipt" else "proposed_action"
    return (
        None
        if actions_equal(grant.get("action", MISSING), record.get(field, MISSING))
        else "action_diverged"
    )


def _records(bundle: dict) -> tuple[dict, dict, dict | None]:
    grant, receipt, intent = (bundle.get(key) for key in ("grant", "receipt", "intent"))
    if not isinstance(grant, dict) or not isinstance(receipt, dict):
        raise Unsupported("profile needs grant and receipt objects")
    if intent is not None and not isinstance(intent, dict):
        raise Unsupported("intent is not an object")
    schemas = [(grant, "grant"), (receipt, "receipt")] + (
        [(intent, "intent")] if intent is not None else []
    )
    if any(
        row.get("schema") != "task-execution-bind-v0/" + kind for row, kind in schemas
    ):
        raise Unsupported("record schema is outside the selected profile")
    return grant, receipt, intent


def _observation_objects(observations) -> list[dict]:
    if not isinstance(observations, list) or any(
        not isinstance(row, dict) for row in observations
    ):
        raise Unsupported("observations are not objects")
    if any(
        not isinstance(row.get("hop"), dict) or not isinstance(row.get("conduct"), dict)
        for row in observations
    ):
        raise Unsupported("observation hop or conduct is not an object")
    return observations


def _supported(bundle: dict) -> tuple[dict, dict, dict | None, list[dict]]:
    if not isinstance(bundle, dict):
        raise Unsupported("bundle is not an object")
    if "receipts" in bundle or bundle.get("require_signatures") is False:
        raise Unsupported("profile needs one receipt and required signatures")
    grant, receipt, intent = _records(bundle)
    observations = _observation_objects(bundle.get("observations", []))
    canonical(bundle)
    return grant, receipt, intent, observations


def _observation_reason(row: dict) -> str | None:
    hop = row["hop"]
    if row.get("witness_id") in (hop.get("from"), hop.get("to")):
        return "witness_not_independent"
    if row.get("evidence_id") != identifier(row, "observation"):
        return "recompute_mismatch"
    if not signature_valid(
        row.get("witness_id"), row.get("witness_sig"), preimage(row, "observation")
    ):
        return "witness_sig_invalid"
    if not signature_valid(
        hop.get("from"),
        row.get("edge_sig"),
        {"task_id": row.get("task_id"), "hop": hop},
    ):
        return "edge_sig_invalid"
    return None


def _observation_groups(rows: list[dict], refusals: dict) -> dict[int, list[dict]]:
    groups: dict[int, list[dict]] = {}
    for row in rows:
        reason = _observation_reason(row)
        if reason:
            refusals.setdefault("delegation_observation_invalid", []).append(reason)
        seq = row["hop"].get("seq")
        if type(seq) is not int or seq < 0:
            refusals.setdefault("delegation_chain_broken", []).append("seq_gap")
        else:
            groups.setdefault(seq, []).append(row)
    return groups


def _chain_reason(row: dict, seq: int, previous: set[str]) -> str | None:
    link = row.get("prev_evidence_id", MISSING)
    if seq == 0 and link is not None:
        return "root_prev_not_null"
    if seq > 0 and (not isinstance(link, str) or link not in previous):
        return "broken_link"
    return None


def _observations(rows: list[dict], refusals: dict, findings: set[str]) -> None:
    if not rows:
        findings.add("no_delegation_observations")
        return
    groups = _observation_groups(rows, refusals)
    if sorted(groups) != list(range(len(groups))):
        refusals.setdefault("delegation_chain_broken", []).append("seq_gap")
    for seq, group in groups.items():
        previous = {identifier(row, "observation") for row in groups.get(seq - 1, [])}
        for row in group:
            reason = _chain_reason(row, seq, previous)
            if reason:
                refusals.setdefault("delegation_chain_broken", []).append(reason)
        verdicts = {
            canonical(row.get("conduct", {}).get("verdict", {"missing": True}))
            for row in group
        }
        if len(verdicts) > 1:
            findings.add("witness_disagreement")


def _evidence(receipt: dict, refusals: dict, findings: set[str]) -> None:
    outcome = receipt.get("outcome")
    evidence = (
        outcome.get("evidence", MISSING) if isinstance(outcome, dict) else MISSING
    )
    if action_shape(evidence) != "present":
        findings.add("no_evidence_bound")
    elif (
        not isinstance(evidence, dict)
        or evidence.get("kind")
        not in ("bitcoin_tx", "ledger_record", "document_sha256", "url_sha256")
        or not re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("ref", "")))
        or not isinstance(evidence.get("system"), str)
        or not evidence["system"]
    ):
        refusals.setdefault("evidence_invalid", []).append("evidence_malformed")
    else:
        findings.add("evidence_bound_unchecked")


def _task_ids(bundle: dict, records: list[dict], refusals: dict) -> None:
    task_id = bundle.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        refusals["task_id_missing"] = ["task_id_missing"]
    if any(not task_id or row.get("task_id") != task_id for row in records):
        refusals["task_id_mismatch"] = ["task_id_mismatch"]


def _execution(grant: dict, receipt: dict, refusals: dict) -> tuple[dict, bool]:
    reason = _pair_reason(grant, receipt, "receipt")
    if reason is not None:
        refusals["execution_invalid"] = [reason]
    signatures = {
        "grant": signature_valid(
            grant.get("caller_id"), grant.get("caller_sig"), preimage(grant, "grant")
        ),
        "receipt": signature_valid(
            receipt.get("provider_id"),
            receipt.get("provider_sig"),
            preimage(receipt, "receipt"),
        ),
    }
    if not all(signatures.values()):
        refusals["execution_signature_invalid"] = [
            "caller_sig_invalid" if not signatures["grant"] else "provider_sig_invalid"
        ]
    if grant.get("provider_id") is None:
        reconciled = False
    else:
        reconciled = (
            receipt.get("grant_ref") == grant.get("grant_ref")
            and receipt.get("provider_id") == grant.get("provider_id")
            and receipt.get("receipt_id") == identifier(receipt, "receipt")
            and signatures["receipt"]
        )
    if not reconciled:
        refusals["execution_unreconciled"] = ["no_authentic_authorized_receipt"]
    return signatures, reconciled


def _preflight(
    grant: dict,
    receipt: dict,
    intent: dict,
    reconciled: bool,
    signatures: dict,
    refusals: dict,
    findings: set[str],
) -> None:
    reason = _pair_reason(grant, intent, "intent")
    if reason is not None:
        refusals["preflight_invalid"] = [reason]
    signatures["intent"] = signature_valid(
        intent.get("provider_id"), intent.get("intent_sig"), preimage(intent, "intent")
    )
    if not signatures["intent"]:
        refusals["preflight_signature_invalid"] = ["intent_sig_invalid"]
    if reconciled and not actions_equal(
        intent.get("proposed_action", MISSING), receipt.get("executed_action", MISSING)
    ):
        findings.add("declared_executed_divergence")


def _grant_findings(
    grant: dict, receipt: dict, intent: dict | None, findings: set[str]
) -> None:
    contexts = [receipt] + ([intent] if intent is not None else [])
    if any(
        _pair_context(grant, row, "receipt" if row is receipt else "intent") is None
        for row in contexts
    ):
        if grant.get("provider_id") is None:
            findings.add("open_grant")
        elif grant.get("provider_id") == grant.get("caller_id"):
            findings.add("self_authorized")


def _linkage(
    observations: list[dict], receipt: dict, refusals: dict, findings: set[str]
) -> None:
    links = [row["conduct"].get("detail_ref") for row in observations]
    links = [
        value
        for value in links
        if isinstance(value, str) and value.startswith("nenrin-exec://")
    ]
    if not links:
        findings.add("no_digest_link")
    elif any(value[14:] != identifier(receipt, "receipt") for value in links):
        refusals["linkage_receipt_mismatch"] = ["receipt_digest_differs"]


def _assess(bundle: dict) -> dict:
    grant, receipt, intent, observations = _supported(bundle)
    refusals: dict[str, list[str]] = {}
    findings: set[str] = set()
    records = observations + [grant, receipt] + ([intent] if intent is not None else [])
    _task_ids(bundle, records, refusals)
    _observations(observations, refusals, findings)
    signatures, reconciled = _execution(grant, receipt, refusals)
    if intent is not None:
        _preflight(grant, receipt, intent, reconciled, signatures, refusals, findings)
    _grant_findings(grant, receipt, intent, findings)
    _evidence(receipt, refusals, findings)
    if observations and reconciled:
        _linkage(observations, receipt, refusals, findings)
    return {
        "profile": PROFILE,
        "signature": {
            "verdict": "refused" if refusals else "accepted",
            "refusals": sorted(refusals),
            "findings": sorted(findings),
        },
        "reasons": refusals,
        "actionShapes": {
            "grant": action_shape(grant.get("action", MISSING)),
            "receipt": action_shape(receipt.get("executed_action", MISSING)),
            "intent": action_shape(intent.get("proposed_action", MISSING))
            if intent is not None
            else "not_presented",
        },
        "recordSignatures": signatures,
        "receiptReconciled": reconciled,
        "liveEvidenceLookupExecuted": False,
        "executionObserved": False,
    }


def assess(bundle) -> dict:
    """Return diagnostics or an explicit unsupported result without acceptance."""
    try:
        return _assess(bundle)
    except Unsupported as error:
        return {
            "profile": PROFILE,
            "signature": {"verdict": "unsupported", "refusals": [], "findings": []},
            "unsupported": str(error),
            "liveEvidenceLookupExecuted": False,
            "executionObserved": False,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    try:
        raw = args.bundle.read_bytes()
        if len(raw) > 1024 * 1024:
            raise Unsupported("bundle exceeds one MiB")
        result = assess(decode_json(raw))
    except (OSError, ValueError, RecursionError) as error:
        result = {
            "profile": PROFILE,
            "signature": {"verdict": "unsupported", "refusals": [], "findings": []},
            "unsupported": str(error),
            "liveEvidenceLookupExecuted": False,
            "executionObserved": False,
        }
    print(json.dumps(result, sort_keys=True))
    return 2 if result["signature"]["verdict"] == "unsupported" else 0


if __name__ == "__main__":
    raise SystemExit(main())
