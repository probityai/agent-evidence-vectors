"""Judge a lifecycle-binding record set: does the authenticated execution report name the authorized
action?

Each case is one set of decision, control and execution records under the ``lifecycle_binding`` term
of agent-evidence-vocabulary, with the consumer's key bindings (``{producer: {public_key_hex,
suite}}``) and its revocation snapshot (``{producer: {state}}``). Records are grouped by (decision
record id, instruction id) and each group gets one of five states, in this order of rules: a shared
identity anywhere in the set (``indeterminate``), an execution no control covers
(``not_evaluated``), a missing control, execution or cited decision (``missing``), an artifact that
does not authenticate (``failure``), a binding the snapshot does not list as active
(``not_evaluated``), then every authorized digest against every executed digest (``satisfied`` or
``failure``).

The set's answer is ``failure`` when any group fails, else the first of ``indeterminate``,
``not_evaluated`` and ``missing`` any group holds, else ``satisfied``. A set the profile cannot
admit (strict I-JSON, a registered tag, the members of its type) is ``refused`` with the reason.
Absent evidence is never ``satisfied``.

Pre-images: the tag
``agent-evidence/lifecycle-binding/v1/{decision,control,execution}/{hash,signature}``, one LF, then
RFC 8785 bytes: of the record without ``integrity.current`` and ``integrity.signature`` for the
hash, and of ``{"current", "suite"}`` with the suite the producer's binding names for the signature.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json`` prints one JSON object
carrying ``decision`` and ``reason``; exit 0 for ``satisfied``, 1 for ``failure`` or ``refused``, 2
otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_evidence_vectors import a2ajcs
from agent_evidence_vectors.monitorcoverage import _fixture_error, _validated_entries, run_corpus

SUITE = "lifecycle-binding/v1"
TYPES = ("decision", "control", "execution")
TAGS = frozenset(
    f"agent-evidence/lifecycle-binding/v1/{t}/{p}" for t in TYPES for p in ("hash", "signature")
)
STATES = ("satisfied", "failure", "missing", "not_evaluated", "indeterminate")
EXIT_FOR = {
    "satisfied": 0,
    "failure": 1,
    "refused": 1,
    "missing": 2,
    "not_evaluated": 2,
    "indeterminate": 2,
}
MEMBERS = {
    "decision": {"lifecycle_version", "artifact_type", "record_id", "producer", "integrity"},
    "control": {
        "lifecycle_version",
        "artifact_type",
        "record_id",
        "producer",
        "integrity",
        "decision_ref",
        "instruction_id",
        "boundary_side",
        "authorized_action_digest",
    },
    "execution": {
        "lifecycle_version",
        "artifact_type",
        "record_id",
        "producer",
        "integrity",
        "decision_ref",
        "instruction_id",
        "executed_action_digest",
    },
}
_HEX = frozenset("0123456789abcdef")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-lifecycle-binding"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-lifecycle-binding"
)
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")


def _rail() -> Any:
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "ed25519_verify"):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if hasattr(module, "ed25519_verify"):
            return module
    raise ImportError("the reference rail's Ed25519 primitive is unavailable")


class Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Refused("no_duplicate_member")
        out[key] = value
    return out


def _safe_int(text: str) -> int:
    value = int(text)
    if abs(value) > 2**53 - 1:
        raise Refused("record_shape")
    return value


def _finite(text: str) -> float:
    value = float(text)
    if value in (float("inf"), float("-inf")) or value != value:
        raise Refused("record_shape")
    return value


def _no_lone_surrogate(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise Refused("record_shape")
    elif isinstance(value, list):
        for item in value:
            _no_lone_surrogate(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _no_lone_surrogate(key)
            _no_lone_surrogate(item)


def parse_records(text: str) -> list[Any]:
    """Strict I-JSON: a repeated member, an unsafe integer, a non-finite number or a lone
    surrogate is refused."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_safe_int,
            parse_float=_finite,
            parse_constant=lambda c: (_ for _ in ()).throw(Refused("record_shape")),
        )
    except Refused:
        raise
    except ValueError as exc:
        raise Refused("record_shape") from exc
    _no_lone_surrogate(value)
    if not isinstance(value, list):
        raise Refused("record_shape")
    return value


def _jcs(value: Any) -> bytes:
    return a2ajcs.canonicalize(value)


def _tag(kind: str, purpose: str, version: str = "v1") -> bytes:
    text = f"agent-evidence/lifecycle-binding/{version}/{kind}/{purpose}"
    if text not in TAGS:
        raise Refused("unregistered_tag")
    return text.encode("ascii")


def _sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and not set(value[7:]) - _HEX
    )


def _admit(record: Any) -> dict:
    if not isinstance(record, dict):
        raise Refused("record_shape")
    if record.get("lifecycle_version") != "v1" or record.get("artifact_type") not in TYPES:
        raise Refused("unregistered_tag")
    kind = record["artifact_type"]
    if not MEMBERS[kind] <= set(record):
        raise Refused("record_shape")
    names = ["record_id", "producer"] + ([] if kind == "decision" else ["instruction_id"])
    if any(not isinstance(record[n], str) or not record[n] for n in names):
        raise Refused("record_shape")
    integrity = record["integrity"]
    if (
        not isinstance(integrity, dict)
        or not _sha(integrity.get("current"))
        or not isinstance(integrity.get("signature"), dict)
        or not isinstance(integrity["signature"].get("value"), str)
    ):
        raise Refused("record_shape")
    if kind != "decision" and (
        not isinstance(record["decision_ref"], dict)
        or not isinstance(record["decision_ref"].get("record_id"), str)
    ):
        raise Refused("record_shape")
    if kind == "control" and record["boundary_side"] not in ("issuer", "receiver"):
        raise Refused("record_shape")
    for pointer in ("authorized_action_digest", "executed_action_digest"):
        if pointer in record and not _sha(record[pointer]):
            raise Refused("record_shape")
    return record


def _hash_input(record: dict) -> bytes:
    body = {k: v for k, v in record.items() if k != "integrity"}
    rest = {k: v for k, v in record["integrity"].items() if k not in ("current", "signature")}
    if rest:
        body["integrity"] = rest
    return _tag(record["artifact_type"], "hash") + b"\n" + _jcs(body)


def _authenticated(record: dict, bindings: dict) -> bool:
    binding = bindings.get(record["producer"])
    if binding is None or binding.get("suite") != "ed25519":
        return False
    if (
        "sha256:" + hashlib.sha256(_hash_input(record)).hexdigest()
        != record["integrity"]["current"]
    ):
        return False
    message = (
        _tag(record["artifact_type"], "signature")
        + b"\n"
        + _jcs({"current": record["integrity"]["current"], "suite": binding["suite"]})
    )
    try:
        return bool(
            _rail().ed25519_verify(
                bytes.fromhex(binding["public_key_hex"]),
                message,
                bytes.fromhex(record["integrity"]["signature"]["value"]),
            )
        )
    except ValueError:
        return False


def group_states(
    records: list[dict], bindings: dict, revocation: dict
) -> dict[tuple[str, str], str]:
    ids = [r["record_id"] for r in records]
    shared = {i for i in ids if ids.count(i) > 1}
    decisions = {r["record_id"]: r for r in records if r["artifact_type"] == "decision"}
    groups: dict[tuple[str, str], list[dict]] = {}
    for record in records:
        if record["artifact_type"] != "decision":
            groups.setdefault(
                (record["decision_ref"]["record_id"], record["instruction_id"]), []
            ).append(record)
    states = {}
    for key, members in groups.items():
        controls = [m for m in members if m["artifact_type"] == "control"]
        executions = [m for m in members if m["artifact_type"] == "execution"]
        if ({m["record_id"] for m in members} | {key[0]}) & shared:
            states[key] = "indeterminate"
        elif executions and not controls:
            states[key] = "not_evaluated"
        elif not controls or not executions or key[0] not in decisions:
            states[key] = "missing"
        elif not all(_authenticated(r, bindings) for r in [decisions[key[0]], *members]):
            states[key] = "failure"
        elif any(
            revocation.get(r["producer"], {}).get("state") != "active"
            for r in [decisions[key[0]], *members]
        ):
            states[key] = "not_evaluated"
        else:
            authorized = {c["authorized_action_digest"] for c in controls}
            executed = {e["executed_action_digest"] for e in executions}
            states[key] = (
                "satisfied" if len(authorized) == 1 and authorized == executed else "failure"
            )
    return states


def judge(case: dict[str, Any]) -> dict[str, str]:
    try:
        records = [_admit(r) for r in parse_records(case["records_text"])]
    except Refused as refused:
        return {"decision": "refused", "reason": refused.reason}
    states = set(group_states(records, case["bindings"], case["revocation"]).values())
    if not states:
        return {"decision": "missing", "reason": "missing" if records else "empty_denominator"}
    for state in ("failure", "indeterminate", "not_evaluated", "missing"):
        if state in states:
            return {"decision": state, "reason": state}
    return {"decision": "satisfied", "reason": "satisfied"}


def verify(record_path: Path) -> dict[str, str]:
    return judge(json.loads(record_path.read_text(encoding="utf-8")))


def _external(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(path), "--json"], capture_output=True, text=True, timeout=90, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(verifier: str | list[str] | None = None, root: Path = ROOT) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader."""
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
        path = directory / "record.json"
        ran, observed = (True, verify(path)) if command is None else _external(command, path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
