"""Build the deterministic Connector scope record cases.

    uv run python vectors-connector-scope/gen_vectors.py

Four accepted members (reads, changes and two recorded refusals) and nine rejected
twins, one per rule, each one mutation away from an accepted member.
Every case, the manifest, the index and the profile map are functions of this
file alone. The fixtures are synthetic.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "connector-scope-record/v1"
SCHEMA = "connector-scope-record/v1"
ACCEPT_REASON = "scope_respected"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _digest(value: object) -> str:
    return _sha(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    )


SPECIFICATION = {
    "status": "proposal of this repository, not a vendored upstream text",
    "scope": (
        "A connector scope record for a health-system integration: what the connector "
        "may read, what it may change, and what it refused. All fixtures are synthetic "
        "and carry no protected health information; a rule refuses a fixture that does."
    ),
}

PROFILE = {
    "suite": SUITE,
    "note": "Maps the three statements a connector owner makes to the record fields checked.",
    "map": {
        "can read": "connector.declared_scope.read",
        "can change": "connector.declared_scope.change",
        "refused an out-of-scope action": "action + outcome.result=refused + outcome.reason",
        "the scope the connector was granted, unchanged": "connector.grant_digest",
        "the action that ran or was refused": "record.action_digest",
    },
}

_SCOPE = {"read": ["Observation", "Condition", "Appointment"], "change": ["Appointment"]}


def _record(kind: str, resource: str, result: str, reason: str = "") -> dict[str, Any]:
    action = {"kind": kind, "resource": resource, "subject": "patient-synthetic-0001"}
    outcome: dict[str, Any] = {"result": result}
    if result == "refused":
        outcome["reason"] = reason
        outcome["refusal_recorded_by"] = "connector-runtime"
    return {
        "schema": SCHEMA,
        "fixture": {"phi_free": True},
        "connector": {
            "id": "ehr-sandbox-connector-1",
            "declared_scope": copy.deepcopy(_SCOPE),
            "grant_digest": _digest(_SCOPE),
        },
        "action": action,
        "outcome": outcome,
        "record": {"action_digest": _digest(action)},
    }


BASES: dict[str, Callable[[], dict[str, Any]]] = {
    "read": lambda: _record("read", "Observation", "performed"),
    "change": lambda: _record("change", "Appointment", "performed"),
    "refused": lambda: _record("change", "Observation", "refused", "out_of_scope"),
    "refused-unknown": lambda: _record("read", "MedicationRequest", "refused", "out_of_scope"),
}


def _drop_scope(r: dict[str, Any]) -> None:
    del r["connector"]["declared_scope"]["change"]


def _widened(r: dict[str, Any]) -> None:
    r["connector"]["declared_scope"]["change"].append("Condition")


def _phi_ssn(r: dict[str, Any]) -> None:
    r["action"]["subject"] = "123-45-6789"
    r["record"]["action_digest"] = _digest(r["action"])


def _phi_flag(r: dict[str, Any]) -> None:
    r["fixture"]["phi_free"] = False


def _change_on_read(r: dict[str, Any]) -> None:
    r["action"] = {"kind": "change", "resource": "Observation", "subject": r["action"]["subject"]}
    r["record"]["action_digest"] = _digest(r["action"])
    r["outcome"] = {"result": "performed"}


def _unlisted_performed(r: dict[str, Any]) -> None:
    r["action"] = {
        "kind": "read",
        "resource": "MedicationRequest",
        "subject": r["action"]["subject"],
    }
    r["record"]["action_digest"] = _digest(r["action"])


def _false_refusal(r: dict[str, Any]) -> None:
    r["outcome"] = {
        "result": "refused",
        "reason": "out_of_scope",
        "refusal_recorded_by": "connector-runtime",
    }


def _unrecorded(r: dict[str, Any]) -> None:
    r["outcome"] = {"result": "refused"}


def _stale_action(r: dict[str, Any]) -> None:
    r["action"]["resource"] = "Condition"


# (id, base, mutation or None for an accepted member, refusal code, description, twin)
MEMBERS: tuple[tuple[str, str, Callable[[dict[str, Any]], None] | None, str, str, str], ...] = (
    (
        "read-in-scope-performed",
        "read",
        None,
        "",
        "a read of a resource the connector may read",
        "",
    ),
    (
        "change-in-scope-performed",
        "change",
        None,
        "",
        "a change to a resource the connector may change",
        "",
    ),
    (
        "change-on-read-only-resource-refused",
        "refused",
        None,
        "",
        "a change to a read-only resource, refused and recorded",
        "",
    ),
    (
        "read-of-unlisted-resource-refused",
        "refused-unknown",
        None,
        "",
        "a read of a resource in neither list, refused and recorded",
        "",
    ),
    (
        "scope-declaration-missing",
        "read",
        _drop_scope,
        "scope_declaration_missing",
        "the change list is absent, so can-change is unstated",
        "read-in-scope-performed",
    ),
    (
        "scope-widened-after-grant",
        "change",
        _widened,
        "grant_digest_mismatch",
        "the declared scope no longer matches the digest granted",
        "change-in-scope-performed",
    ),
    (
        "fixture-carries-an-identifier",
        "read",
        _phi_ssn,
        "fixture_not_phi_free",
        "a fixture field holds a social security number pattern",
        "read-in-scope-performed",
    ),
    (
        "fixture-not-marked-phi-free",
        "read",
        _phi_flag,
        "fixture_not_phi_free",
        "the fixture does not assert it is PHI-free",
        "read-in-scope-performed",
    ),
    (
        "change-performed-under-read-grant",
        "read",
        _change_on_read,
        "change_performed_under_read_grant",
        "a change performed on a resource granted for reading only",
        "read-in-scope-performed",
    ),
    (
        "unlisted-read-performed",
        "read",
        _unlisted_performed,
        "out_of_scope_action_performed",
        "a read of a resource in neither list ran",
        "read-in-scope-performed",
    ),
    (
        "in-scope-read-refused-as-out-of-scope",
        "read",
        _false_refusal,
        "in_scope_action_refused_as_out_of_scope",
        "a permitted read refused for being out of scope",
        "read-in-scope-performed",
    ),
    (
        "refusal-without-record",
        "refused",
        _unrecorded,
        "refusal_not_recorded",
        "an out-of-scope action refused with no reason and no recorder",
        "change-on-read-only-resource-refused",
    ),
    (
        "action-changed-after-record",
        "read",
        _stale_action,
        "action_digest_mismatch",
        "the action differs from the one the record digest covers",
        "read-in-scope-performed",
    ),
)

_ACCEPT_IDS = {name for name, _b, mutate, *_ in MEMBERS if mutate is None}


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# Connector scope record vectors",
        "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
        "",
        f"Suite: `{SUITE}`. Record schema: `{SCHEMA}`.",
        "",
        f"Corpus digest: `{digest}`",
        "",
        "| id | decision | reason | twin | case |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        lines.append(
            f"| `{e['id']}` | {x['decision']} | `{x['reason']}` | "
            f"{e.get('twin', '')} | {e['description']} |"
        )
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest, the index and the profile map."""
    entries = []
    for name, base, mutate, reason, description, twin in MEMBERS:
        record = BASES[base]()
        if mutate is not None:
            mutate(record)
        record["case_id"] = f"vectors-connector-scope-{name}"
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
        (directory / "case.json").write_bytes(data)
        entry: dict[str, Any] = {
            "id": name,
            "path": f"cases/{name}",
            "files": {"case.json": _sha(data)},
            "description": description,
            "expected": {
                "decision": "accepted" if mutate is None else "rejected",
                "reason": reason if mutate is not None else ACCEPT_REASON,
            },
        }
        if mutate is not None:
            assert twin in _ACCEPT_IDS, (name, twin)
            entry["twin"] = twin
        entries.append(entry)
    digest = _sha(_json(entries))
    manifest = {
        "suite": SUITE,
        "schema": SCHEMA,
        "counts": {
            verdict: sum(e["expected"]["decision"] == verdict for e in entries)
            for verdict in ("accepted", "rejected")
        },
        "vectors": entries,
        "specification": SPECIFICATION,
        "verifierContract": "verifier case.json --json",
        "corpusDigest": digest,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    (root / "profile.json").write_bytes(_json(PROFILE))
    return manifest


if __name__ == "__main__":
    generate()
