#!/usr/bin/env python3
"""Build the ACS outage posture corpus from one recorded replay.

The four supported cases are the four steps the ACS reference host took while
its Guardian was unreachable, in a replay of the outage bundle posted on
GenAI-Security-Project/agent-control-standard#92, run at ACS commit
8a459524530b with Bun 1.3.11 (the recorded inputs are in corpus/source/). Every
other case changes one thing in one of those steps and states the answer it
expects. The expected answers are written here by hand, never read back from
the reader.

    python scripts/acs-outage-build.py           # write the corpus
    python scripts/acs-outage-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
CORPUS = PACKAGING / "agent_evidence_vectors/acs_outage/corpus"
SOURCE = CORPUS / "source"
SUITE = "acs-outage-posture/8a459524530b"
ORIGIN = {
    "report": "https://github.com/GenAI-Security-Project/agent-control-standard/issues/92",
    "bundle_sha256": "eec4b2d39683740dac5742c53ac3c7cb17f1f70a6698d8bf3419ae8eeff9b737",
    "acs_commit": "8a459524530b320c70c68d1d0b85bbcabb3771e6",
    "runtime": "bun 1.3.11",
    "host": "the bundle's synthetic host driving hosts/claude-code/acs-hook.ts",
    "guardian": "a loopback Guardian shut down cleanly before the unreachable steps",
}


def _jsonl(path: Path) -> list[Any]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _real_steps() -> dict[str, dict[str, Any]]:
    """The four recorded outage steps, as reader input."""
    steps: dict[str, dict[str, Any]] = {}
    for posture in ("proceed", "deny"):
        root = SOURCE / posture
        audit = _jsonl(root / "audit.jsonl")
        otlp = _jsonl(root / "audit.otlp.jsonl")
        for row in _jsonl(root / "steps.jsonl"):
            cache_file = root / "sessions" / f"{row['session_id']}.json"
            cached = row["phase"] == "unreachable-cached-session"
            steps[f"{posture}-{'cached' if cached else 'fresh'}"] = {
                "guardian": "unreachable",
                "session_id": row["session_id"],
                "session_cache": (json.loads(cache_file.read_text(encoding="utf-8"))
                                  if cache_file.exists() else None),
                "hook_env": {} if cached else {"ACS_ON_DECISION_FAILURE": posture},
                "hook_decision": row["decision"]["permissionDecision"],
                "marker_delta": row["effectDelta"],
                "audit": [r for r in audit if r["session_id"] == row["session_id"]],
                "otlp": otlp,
            }
    return steps


def _record(step: dict[str, Any]) -> dict[str, Any]:
    return step["audit"][0]


def _event(step: dict[str, Any]) -> dict[str, Any]:
    rpc = _record(step)["rpc_id"]
    for batch in step["otlp"]:
        for rs in batch["resourceSpans"]:
            for ss in rs["scopeSpans"]:
                for span in ss["spans"]:
                    ids = [a["value"]["stringValue"] for a in span["attributes"]
                           if a["key"] == "acs.request_id"]
                    if ids == [rpc]:
                        return span["events"][0]
    raise SystemExit(f"no exported event for {rpc}")


def _set_event_attr(key: str, value: str) -> Callable[[dict[str, Any]], None]:
    def change(step: dict[str, Any]) -> None:
        for attr in _event(step)["attributes"]:
            if attr["key"] == key:
                attr["value"] = {"stringValue": value}
    return change


def _drop_export(step: dict[str, Any]) -> None:
    rpc = _record(step)["rpc_id"]
    step["otlp"] = [b for b in step["otlp"]
                    if rpc not in json.dumps(b)]


def _set(path: tuple[str, ...], value: Any) -> Callable[[dict[str, Any]], None]:
    def change(step: dict[str, Any]) -> None:
        target: Any = step
        for key in path[:-1]:
            target = target[key] if not isinstance(target, list) else target[int(key)]
        target[path[-1]] = value
    return change


def _drop(path: tuple[str, ...]) -> Callable[[dict[str, Any]], None]:
    def change(step: dict[str, Any]) -> None:
        target: Any = step
        for key in path[:-1]:
            target = target[key] if not isinstance(target, list) else target[int(key)]
        del target[path[-1]]
    return change


S, C, N, X = "supported", "contradicted", "not_established", "no_verdict"
SUPPORTED_CASES = (
    ("accept-cached-proceed", "proceed-cached", "cached_proceed_applied_and_audited",
     "warm session with on_decision_failure=proceed: the step proceeds and is audited"),
    ("accept-cached-deny", "deny-cached", "cached_deny_applied_and_audited",
     "warm session with on_decision_failure=deny: the step is blocked and audited"),
    ("accept-fresh-default-proceed", "proceed-fresh", "startup_default_proceed_audited",
     "no session was negotiated: the default posture proceeds and the failed handshake is audited"),
    ("accept-fresh-default-despite-env-deny", "deny-fresh", "startup_default_proceed_audited",
     "no session was negotiated and the hook's environment says deny: the default still applies"),
)
# (id, twin, expected decision, reason, control, change)
REFUSED_CASES: tuple[tuple[str, str, str, str, str, Callable[[dict[str, Any]], None]], ...] = (
    ("reject-cached-deny-allowed", "accept-cached-deny", C, "posture_not_applied",
     "the host allows a step its cached deny posture should block",
     _set(("hook_decision",), "allow")),
    ("reject-fresh-env-deny-applied", "accept-fresh-default-despite-env-deny", C,
     "unnegotiated_posture_applied",
     "the host applies a deny read from its own environment to a session that never negotiated",
     _set(("hook_decision",), "deny")),
    ("reject-cached-proceed-denied", "accept-cached-proceed", C, "posture_not_applied",
     "the host blocks a step its cached proceed posture should allow",
     _set(("hook_decision",), "deny")),
    ("reject-blocked-step-executed", "accept-cached-deny", C, "blocked_step_executed",
     "the hook says deny but the marker shows the command ran",
     _set(("marker_delta",), 1)),
    ("reject-allowed-step-not-executed", "accept-cached-proceed", N, "allowed_step_not_executed",
     "the hook says allow but the marker shows nothing ran",
     _set(("marker_delta",), 0)),
    ("reject-step-not-audited", "accept-cached-proceed", C, "outage_step_not_audited",
     "the step proceeded without a decision and left no audit record",
     _set(("audit",), [])),
    ("reject-audit-posture-edited", "accept-cached-deny", C, "audit_posture_mismatch",
     "the audit record names a posture the session did not negotiate",
     _set(("audit", "0", "posture"), "proceed")),
    ("reject-fresh-source-claimed-negotiated", "accept-fresh-default-proceed", C,
     "posture_source_misreported",
     "the audit record says negotiated for a session whose handshake never succeeded",
     _set(("audit", "0", "posture_source"), "negotiated")),
    ("reject-audit-outcome-edited", "accept-cached-deny", C, "audit_outcome_mismatch",
     "the audit record says proceeded for a step the hook blocked",
     _set(("audit", "0", "outcome"), "proceeded")),
    ("reject-fresh-handshake-not-audited", "accept-fresh-default-proceed", C,
     "unguarded_startup_not_audited",
     "the unguarded start is audited without the failed handshake",
     _drop(("audit", "0", "session_failure"))),
    ("reject-audit-not-exported", "accept-cached-deny", C, "audit_not_exported",
     "the audit record has no acs.decision.failure event in the OTLP export",
     _drop_export),
    ("reject-export-class-edited", "accept-cached-deny", C, "failure_class_mismatch",
     "the exported failure class is not unreachable",
     _set_event_attr("acs.failure.class", "timeout")),
    ("reject-export-posture-edited", "accept-cached-deny", C, "failure_posture_mismatch",
     "a blocked step is exported as fail_open",
     _set_event_attr("acs.failure.posture", "fail_open")),
    ("reject-export-reporter-edited", "accept-fresh-default-proceed", C, "reporter_mismatch",
     "the export says the Guardian reported a failure only the host could observe",
     _set_event_attr("acs.failure.reported_by", "guardian")),
    ("reject-guardian-reachable", "accept-cached-proceed", X, "malformed_step",
     "a step taken with the Guardian reachable is not an outage step",
     _set(("guardian",), "reachable")),
)


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(out: Path) -> None:
    """Write cases/ and MANIFEST.json under ``out``, next to the source records."""
    steps = _real_steps()
    if sorted(steps) != ["deny-cached", "deny-fresh", "proceed-cached", "proceed-fresh"]:
        raise SystemExit(f"replay did not record four outage steps: {sorted(steps)}")
    built: dict[str, dict[str, Any]] = {}
    cases: list[dict[str, Any]] = []
    for case_id, key, reason, control in SUPPORTED_CASES:
        built[case_id] = steps[key]
        cases.append({"id": case_id, "control": control, "source": f"replay:{key}",
                      "expected": {"decision": S, "reason": reason}})
    for case_id, twin, decision, reason, control, change in REFUSED_CASES:
        step = copy.deepcopy(built[twin])
        change(step)
        if step == built[twin]:
            raise SystemExit(f"{case_id}: the change left the step unchanged")
        built[case_id] = step
        cases.append({"id": case_id, "control": control, "twin": twin,
                      "expected": {"decision": decision, "reason": reason}})
    for case in cases:
        data = _dump({"suite": SUITE, "step": built[case["id"]]})
        directory = out / "cases" / case["id"]
        directory.mkdir(parents=True)
        (directory / "case.json").write_bytes(data)
        case["files"] = {"case.json": _sha(data)}
    sources = {str(p.relative_to(SOURCE)): _sha(p.read_bytes())
               for p in sorted(SOURCE.rglob("*")) if p.is_file()}
    manifest = {"suite": SUITE, "origin": ORIGIN, "sources": sources, "cases": cases,
                "corpusDigest": _sha(json.dumps(cases, sort_keys=True).encode())}
    (out / "MANIFEST.json").write_bytes(_dump(manifest))


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and "source" not in p.relative_to(root).parts}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the corpus differs")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        build(fresh)
        if args.check:
            if _tree(fresh) != _tree(CORPUS):
                print("acs-outage corpus differs from what the builder writes", file=sys.stderr)
                return 1
            print(f"acs-outage corpus matches: {len(_tree(fresh)) - 1} cases")
            return 0
        shutil.rmtree(CORPUS / "cases", ignore_errors=True)
        (CORPUS / "MANIFEST.json").unlink(missing_ok=True)
        shutil.copytree(fresh / "cases", CORPUS / "cases")
        shutil.copy2(fresh / "MANIFEST.json", CORPUS / "MANIFEST.json")
    print(f"wrote {len(SUPPORTED_CASES) + len(REFUSED_CASES)} cases to {CORPUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
