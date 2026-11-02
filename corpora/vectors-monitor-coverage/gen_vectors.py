"""Build the monitor-coverage cases byte-identically.

Every case is one monitor's verdict over one window. Each denied case changes
the accepting control so the check it names is the first that fails and every
earlier check passes; each allowed case is a control that keeps a verifier
from denying everything. Every member is synthetic.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import monitorcoverage as reader  # noqa: E402

SUITE = reader.SUITE
T0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=UTC)
CHANNELS = ["message", "tool_call"]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def ts(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(name: str, *, result: str = "clean", expected: int = 400, collected: int = 400,
          dropped: int = 0, basis: str = "collector_count", channels: list[str] | None = None,
          vantage: str = "collector_side", kind: str = "detector",
          effect: dict[str, Any] | None = None, decisions: int = 12, actions: int = 0,
          claim: str | None = None, end: float = 3600, **top: Any) -> dict[str, Any]:
    """One monitor verdict over a one-hour window."""
    record: dict[str, Any] = {
        "contractId": reader.CONTRACT_ID,
        "coverage": {"basis": basis, "collected": collected, "collector": "collector-1",
                     "dropped": dropped, "expected": expected},
        "monitor": {"channels": sorted(channels if channels is not None else CHANNELS),
                    "id": f"monitor-{kind}", "kind": kind, "vantage": vantage},
        "recordId": f"record-{name}",
        "verdict": {"decisions": decisions, "effectiveActions": actions, "result": result},
        "window": {"end": ts(end), "start": ts(0)},
    }
    if effect is not None:
        record["effect"] = effect
    if claim is not None:
        record["claim"] = {"kind": claim}
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


def effect(channel: str, at: float = 1800) -> dict[str, Any]:
    """An effect another source observed: the channel it used and when."""
    return {"at": ts(at), "channel": channel, "observedBy": "sink-side ledger"}


Case = tuple[str, dict[str, Any], str, str, str]


def _controls() -> list[Case]:
    ok = reader.ALLOWED_REASON
    return [
        ("allow-clean-complete-coverage", build("allow-clean-complete-coverage"), "allow", ok,
         "control: a clean verdict with every expected event collected by the collector"),
        ("allow-not-established-incomplete",
         build("allow-not-established-incomplete", result="not_established", collected=310,
               dropped=40),
         "allow", ok, "control: the collector dropped 40 events and the monitor leaves the "
         "window not established"),
        ("allow-flagged-partial-coverage",
         build("allow-flagged-partial-coverage", result="flagged", collected=310, dropped=40,
               effect=effect("tool_call"), actions=3),
         "allow", ok, "control: a flag stands on partial coverage"),
        ("allow-not-established-outside-vantage",
         build("allow-not-established-outside-vantage", result="not_established",
               effect=effect("network_egress")),
         "allow", ok, "control: the effect used a channel the monitor does not read, and the "
         "monitor says the window is not established"),
        ("allow-clean-effect-outside-window",
         build("allow-clean-effect-outside-window", effect=effect("tool_call", at=3700)),
         "allow", ok, "control: the observed effect lands after the window closes"),
        ("allow-defence-effect-with-actions",
         build("allow-defence-effect-with-actions", kind="defence", result="flagged",
               actions=4, claim="defence_reduced_harm"),
         "allow", ok, "control: a defence credited with reducing harm took four effective "
         "actions"),
        ("allow-defence-zero-actions-no-claim",
         build("allow-defence-zero-actions-no-claim", kind="defence", result="flagged"),
         "allow", ok, "control: a defence that took no effective action, with no claim "
         "drawn from it"),
    ]


def _denied() -> list[Case]:
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    return [
        ("reject-contract-id-missing", build("reject-contract-id-missing", contractId=None),
         "deny", "contract_id_missing", "the record names no contract"),
        ("reject-contract-id-unknown", build("reject-contract-id-unknown", contractId=unknown),
         "deny", "contract_id_unknown", "the record names a contract version that does not "
         "exist"),
        ("reject-window-ends-before-start", build("reject-window-ends-before-start", end=-60),
         "deny", "window_invalid", "the window ends a minute before it starts"),
        ("reject-collected-exceeds-expected",
         build("reject-collected-exceeds-expected", collected=420),
         "deny", "coverage_counts_invalid", "the collector reports more events than it "
         "expected"),
        ("reject-actions-exceed-decisions",
         build("reject-actions-exceed-decisions", result="flagged", actions=13),
         "deny", "coverage_counts_invalid", "more effective actions than decisions"),
        ("reject-clean-on-producer-count",
         build("reject-clean-on-producer-count", basis="producer_count"),
         "deny", "coverage_self_reported", "the clean verdict rests on a count the watched "
         "agent reported about itself"),
        ("reject-clean-with-dropped-events",
         build("reject-clean-with-dropped-events", collected=360, dropped=40),
         "deny", "clean_with_incomplete_coverage", "the collector dropped 40 events and the "
         "verdict is clean"),
        ("reject-clean-with-uncollected-events",
         build("reject-clean-with-uncollected-events", collected=310),
         "deny", "clean_with_incomplete_coverage", "90 expected events never reached the "
         "collector and the verdict is clean"),
        ("reject-clean-outside-vantage",
         build("reject-clean-outside-vantage", effect=effect("network_egress")),
         "deny", "clean_outside_vantage", "the effect left by network egress, which the "
         "monitor does not read, and the verdict is clean"),
        ("reject-clean-contradicts-observed-effect",
         build("reject-clean-contradicts-observed-effect", effect=effect("tool_call")),
         "deny", "clean_contradicts_observed_effect", "a sink-side ledger saw an effect by tool "
         "call inside the window, and the monitor that read every tool call says clean"),
        ("reject-defence-effect-with-zero-effective-actions",
         build("reject-defence-effect-with-zero-effective-actions", kind="defence",
               result="flagged", decisions=2592, claim="defence_reduced_harm"),
         "deny", "defence_effect_without_effective_actions", "a defence is credited with "
         "reducing harm after 2,592 decisions in which it took no effective action"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, and what it shows."""
    return [*_controls(), *_denied()]


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
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append({"edit": edit, "expected": expected,
                        "files": {"record.json": _sha(data)}, "id": name,
                        "path": f"cases/{name}", "retained": reader.retained(copy.deepcopy(body))})
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
