#!/usr/bin/env python3
"""Replay the responsibility-escalation cases through agent-evidence-verify and compare.

A receiver that reads the record without this repository's reader still has to answer two
questions, and agent-evidence-verify has a claim type for each:

* what the authority reference resolved to at the instant the authority is read:
  ``authority_anchor/v1`` over a ``probity-http-capture/v1`` capture of the resolution, with
  the version and its standing (``v1:holds``) as the field the consumer pins;
* whether an escalation event is present or absent in a bounded interval:
  ``event_absence/v1`` over an observation record and a capabilities record, one run per
  slot of the escalation.

For each member the script builds that evidence from the record into a temporary directory,
runs ``agent_evidence_verify.adjudicate`` and compares each verdict with the one this corpus's
rules predict. It does not compare the final outcome token: the verifier does not know the
designated role, the escalation order or the closure window, so the role checks, the order
and the lateness of a step are not checked here. The authority half also does not see the
narrowing between the referral and the acknowledgement;
``authority_narrowed_before_acknowledgement`` is this corpus's rule over the version history.

    uv run --group crosscheck python \\
        corpora/vectors-responsibility-escalation/crosscheck_probity_verify.py \\
        corpora/vectors-responsibility-escalation [--table]

Exit 0 when every verdict agrees, 1 on a disagreement, 2 when nothing was compared.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path
from typing import Any

from agent_evidence_verify import adjudicate  # pyright: ignore[reportMissingImports]
from agent_evidence_verify.common import CaseError  # pyright: ignore[reportMissingImports]

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packaging"))

from agent_evidence_vectors import responsibilityescalation as reader  # noqa: E402

AUTHORITY_CHECKS = (
    "reference_unavailable",
    "reference_inconsistent",
    "current_record_resolved_not_decision_time",
    "authority_not_held_at_read_instant",
)
SCOPE_ID = "escalation-window"


def _bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _bind(root: Path, name: str, value: object) -> dict[str, Any]:
    data = _bytes(value)
    (root / name).write_bytes(data)
    return {"length": len(data), "path": name, "sha256": hashlib.sha256(data).hexdigest()}


def _standing(version_row: dict[str, Any] | None) -> str:
    if version_row is None:
        return "none"
    return f"{version_row['id']}:{'holds' if version_row['holds'] else 'narrowed'}"


def authority_verdict(record: dict[str, Any], root: Path, case_id: str) -> dict[str, str]:
    """agent-evidence-verify's verdict on what the authority reference resolved to."""
    authority = record["authority"]
    held = reader.version_in_force(record, reader.read_instant(record))
    resolution = authority["resolution"]
    by_id = {row["id"]: row for row in authority["versions"]}
    if resolution["status"] == "resolved":
        capture = {"body": {"standing": _standing(by_id.get(resolution.get("returned")))},
                   "captured_at": record["evaluatedAt"], "request_url": authority["reference"],
                   "schema_version": "probity-http-capture/v1", "status": 200}
    else:
        capture = {"body": {}, "captured_at": record["evaluatedAt"],
                   "request_url": authority["reference"],
                   "schema_version": "probity-http-capture/v1", "status": 503}
    binding = _bind(root, "capture.json", capture)
    case = {"artifacts": {"capture": binding}, "case_id": case_id,
            "schema_version": "probity-case/v1"}
    policy = {"assessments": {case_id: {
        "capture_window": {"end": record["evaluatedAt"], "start": record["decision"]["at"]},
        "capture_witness": "w-capture", "claim_type": "authority_anchor/v1",
        "expected_value": f"{held['id']}:holds" if held else "none",
        "json_pointer": "/standing", "request_url": authority["reference"]},
    }, "schema_version": "probity-policy/v1",
        "witnesses": {"w-capture": {"artifact": "capture", "authority": "authority.example",
                                    "sha256": binding["sha256"]}}}
    result = adjudicate(case, policy, root)
    return {"decision": result["decision"], "reason": result["reason"]}


def expected_authority(record: dict[str, Any]) -> dict[str, str]:
    """The verdict this corpus's authority checks predict for the same evidence."""
    failures = reader._failures(record)
    if failures["reference_unavailable"]():
        return {"decision": "not_established", "reason": "authority_response_unavailable"}
    if any(failures[name]() for name in AUTHORITY_CHECKS[1:]):
        return {"decision": "contradicted", "reason": "anchor_mismatch"}
    return {"decision": "supported", "reason": "anchor_matches"}


def slot_verdict(record: dict[str, Any], root: Path, case_id: str, slot: str) -> dict[str, str]:
    """agent-evidence-verify's verdict on the claim that one slot has no event."""
    row = record["escalation"]["slots"].get(slot, {})
    start, end = record["decision"]["at"], record["evaluatedAt"]
    observation: dict[str, Any] = {
        "claim_id": case_id, "coverage": "complete", "invocation_id": "escalation-1",
        "producer": "receiver-observer", "schema_version": "probity-observation/v1",
        "scope": {"end": end, "id": SCOPE_ID, "start": start}}
    if row.get("evidenced"):
        observation["events"] = [{"id": slot, "time": row["at"], "type": slot}]
    elif row.get("coverage") == "incomplete":
        observation["coverage"] = "incomplete"
        observation["gaps"] = [{"end": end, "start": start}]
    capabilities = {"claim_id": case_id, "invocation_id": "escalation-1",
                    "producer": "receiver-observer", "schema_version": "probity-capabilities/v1",
                    "visible_event_types": list(reader.SLOTS)}
    obs_binding = _bind(root, "observation.json", observation)
    cap_binding = _bind(root, "capabilities.json", capabilities)
    case = {"artifacts": {"capabilities": cap_binding, "observation": obs_binding},
            "case_id": case_id, "schema_version": "probity-case/v1"}
    policy = {"assessments": {case_id: {
        "capability_witness": "w-capabilities", "claim_type": "event_absence/v1",
        "event_type": slot, "invocation_id": "escalation-1",
        "observation_witness": "w-observation",
        "scope": {"end": end, "id": SCOPE_ID, "start": start}}},
        "schema_version": "probity-policy/v1",
        "witnesses": {
            "w-capabilities": {"artifact": "capabilities", "authority": "receiver-observer",
                               "sha256": cap_binding["sha256"]},
            "w-observation": {"artifact": "observation", "authority": "receiver-observer",
                              "sha256": obs_binding["sha256"]}}}
    result = adjudicate(case, policy, root)
    return {"decision": result["decision"], "reason": result["reason"]}


def expected_slot(record: dict[str, Any], slot: str) -> dict[str, str]:
    """The verdict the record's own slot state predicts for the claim that the slot is empty."""
    row = record["escalation"]["slots"].get(slot, {})
    if row.get("evidenced"):
        return {"decision": "contradicted", "reason": "event_observed"}
    if row.get("coverage") == "incomplete":
        return {"decision": "not_established", "reason": "observation_coverage_unestablished"}
    return {"decision": "supported", "reason": "absence_within_covered_scope"}


def slots_of(record: dict[str, Any]) -> list[str]:
    """The slots the record carries: closure only where the record requires it."""
    required = record["escalation"]["closure"]["required"]
    return [slot for slot in reader.SLOTS if slot != "closure" or required]


def compare_member(entry: dict[str, Any], member: Path) -> tuple[int, list[str], dict[str, Any]]:
    record = json.loads((member / "record.json").read_text(encoding="utf-8"))
    problems: list[str] = []
    seen: dict[str, Any] = {"slots": {}}
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        try:
            got = authority_verdict(record, root, entry["id"])
        except CaseError as exc:
            got = {"refused": str(exc)}
        want = expected_authority(record)
        seen["authority"] = got
        compared = 1
        if got != want:
            problems.append(
                f"{entry['id']} authority: expected {want}, agent-evidence-verify {got}"
            )
        for slot in slots_of(record):
            got = slot_verdict(record, root, entry["id"], slot)
            want = expected_slot(record, slot)
            seen["slots"][slot] = got
            compared += 1
            if got != want:
                problems.append(
                    f"{entry['id']} {slot}: expected {want}, agent-evidence-verify {got}"
                )
    return compared, problems, seen


def table_row(entry: dict[str, Any], seen: dict[str, Any]) -> str:
    """One README row: the case, our outcome, then the verifier's verdicts."""
    outcome = f"{entry['expected']['decision']} / {entry['expected']['reason']}"
    authority = f"{seen['authority']['decision']} / {seen['authority']['reason']}"
    short = {"contradicted": "event", "supported": "absent", "not_established": "unknown"}
    slots = ", ".join(f"{slot} {short[v['decision']]}" for slot, v in seen["slots"].items())
    return f"| {entry['case']} | `{entry['id']}` | {outcome} | {authority} | {slots} |"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--table", action="store_true", help="print the README rows")
    args = parser.parse_args(argv)
    manifest = json.loads((args.corpus / "MANIFEST.json").read_text(encoding="utf-8"))
    compared = 0
    problems: list[str] = []
    rows: list[str] = []
    for entry in manifest["vectors"]:
        count, found, seen = compare_member(entry, args.corpus / entry["path"])
        compared, problems = compared + count, problems + found
        rows.append(table_row(entry, seen))
    print(f"agent-evidence-verify {version('agent-evidence-verify')}: compared {compared}, "
          f"{len(problems)} disagreements")
    if args.table:
        print("\n".join(rows))
    for line in problems:
        print(line)
    if not compared:
        return 2
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
