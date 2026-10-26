"""Build the dispatch-fence cases byte-identically.

Every case is one record of an exclusive dispatch read under the contract at
``contractId``: the policy check, the fence taken to dispatch, the effect and
the commit. Each denied case is built so the check it names is the first that
fails and every earlier check passes, and each allowed case is a control that
keeps a verifier from denying everything.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import dispatchfence as reader  # noqa: E402

SUITE = reader.SUITE
T0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def at(offset: int) -> str:
    """The instant ``offset`` seconds after the fence is acquired."""
    return (T0 + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")


def base(name: str) -> dict[str, Any]:
    """The allowed record every case departs from."""
    return {
        "check": {"at": at(-5), "readSeq": 5, "verdict": "allow"},
        "commit": {"at": at(61)},
        "contextId": "context-1",
        "contractId": reader.CONTRACT_ID,
        "effect": {"endedAt": at(60), "startedAt": at(1)},
        "fence": {"acquiredAt": at(0), "appendSeq": 5, "expectedSeq": 5, "renewals": [],
                  "ttlSeconds": 120},
        "otherAttempts": [],
        "proposalId": f"proposal-{name}",
        "stateEvents": [{"at": at(-300), "kind": "label-set", "seq": 4},
                        {"at": at(-120), "kind": "comment", "seq": 5}],
    }


def variant(name: str, edit: Any = None, **top: Any) -> dict[str, Any]:
    """The base record with ``edit`` applied to a copy, then top-level keys replaced."""
    record = copy.deepcopy(base(name))
    if edit is not None:
        edit(record)
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


def _event(seq: int, offset: int) -> Any:
    return lambda r: r["stateEvents"].append({"at": at(offset), "kind": "label-raise", "seq": seq})


def _renewed(r: dict[str, Any]) -> None:
    r["fence"]["renewals"] = [{"at": at(100), "expiresAt": at(360)}]
    r["effect"].update(declaredMaxRuntimeSeconds=300, endedAt=at(300))
    r["commit"]["at"] = at(305)


def _second_hop(r: dict[str, Any]) -> None:
    r["otherAttempts"] = [{"admitted": True, "beganAt": at(30), "proposalId": r["proposalId"]}]


def _at_expiry(r: dict[str, Any]) -> None:
    r["effect"]["endedAt"] = at(120)
    r["commit"]["at"] = at(120)


def _unbound(r: dict[str, Any]) -> None:
    del r["fence"]["expectedSeq"]


def _raised_between(r: dict[str, Any]) -> None:
    _event(6, -2)(r)
    r["fence"]["appendSeq"] = 6


def _declared_too_long(r: dict[str, Any]) -> None:
    r["effect"].update(declaredMaxRuntimeSeconds=600, endedAt=at(100))
    r["commit"]["at"] = at(101)


def _outlives(r: dict[str, Any]) -> None:
    r["effect"]["endedAt"] = at(121)
    r["commit"]["at"] = at(122)


def _second_dispatch(r: dict[str, Any]) -> None:
    _renewed(r)
    r["fence"]["renewals"] = [{"at": at(110), "expiresAt": at(400)}]
    r["commit"]["at"] = at(301)
    r["otherAttempts"] = [{"admitted": True, "beganAt": at(150), "proposalId": "proposal-other"}]


def _late_commit(r: dict[str, Any]) -> None:
    r["effect"]["endedAt"] = at(100)
    r["commit"]["at"] = at(130)


Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, expected decision, expected reason, and what the case
    departs from."""
    unknown = reader.CONTRACT_ID.replace("/v1", "/v0")
    return [
        ("allow-single-read", variant("allow-single-read"), "allow", "exclusive",
         "control: the fence is bound to the state the check read and nothing changed"),
        ("allow-state-event-after-fence",
         variant("allow-state-event-after-fence", _event(6, 10)), "allow", "exclusive",
         "control: a label raised after the fence was appended does not reach back"),
        ("allow-renewed-hold-covers-effect",
         variant("allow-renewed-hold-covers-effect", _renewed), "allow", "exclusive",
         "control: a 300-second effect under a 120-second hold renewed to 360 seconds"),
        ("allow-same-proposal-second-hop",
         variant("allow-same-proposal-second-hop", _second_hop), "allow", "exclusive",
         "control: a second attempt carrying the same proposal identifier is re-entrant"),
        ("allow-effect-ends-at-expiry",
         variant("allow-effect-ends-at-expiry", _at_expiry), "allow", "exclusive",
         "control: the effect and the commit land exactly at the hold's expiry"),
        ("contract-id-missing", variant("contract-id-missing", contractId=None), "deny",
         "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown", variant("contract-id-unknown", contractId=unknown), "deny",
         "contract_id_unknown", "the record names a contract version that does not exist"),
        ("fence-rereads-state", variant("fence-rereads-state", _unbound), "deny",
         "fence_not_bound_to_check",
         "the fence names no sequence number, so it re-read state itself and nothing "
         "shows it acted on the state the check saw; no state changed"),
        ("label-raised-between-check-and-fence",
         variant("label-raised-between-check-and-fence", _raised_between), "deny",
         "state_changed_between_check_and_fence",
         "a label was raised after the check read sequence 5 and before the fence appended"),
        ("declared-runtime-exceeds-ttl",
         variant("declared-runtime-exceeds-ttl", _declared_too_long), "deny",
         "runtime_exceeds_hold",
         "the tool declares 600 seconds under a 120-second hold with no renewal"),
        ("tool-outlives-hold", variant("tool-outlives-hold", _outlives), "deny",
         "hold_expired_before_effect_ended",
         "the effect ran 121 seconds under a 120-second hold"),
        ("second-dispatch-after-expiry",
         variant("second-dispatch-after-expiry", _second_dispatch), "deny",
         "concurrent_dispatch_admitted",
         "the hold was renewed to cover the effect, and another proposal was admitted "
         "150 seconds in, after the initial hold would have lapsed"),
        ("commit-after-own-hold-expired",
         variant("commit-after-own-hold-expired", _late_commit), "deny",
         "commit_after_hold_expired",
         "the effect ended in time and the commit landed ten seconds after the hold expired"),
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
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"record.json": _sha(data)},
            "holdCoversCommit": reader.hold_covers_commit(body),
            "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
