#!/usr/bin/env python3
"""Read fixtures/cases.json under docs/INPUT-CONTRACT.md and report each case.

    python3 run_contract.py            # one line per case, then the expected comparison
    python3 run_contract.py --json     # the report as JSON
    python3 run_contract.py --check    # exit 1 when any case diverges from expected.json

Exit codes: 0 every case matches expected.json, 1 a divergence, 2 the corpus or
a manifest digest is unreadable.

This reader was written by the same author as the contract and the fixtures, so
it is answer-exposed: it shows the contract is implementable and internally
consistent. It is not an independent implementation and does not establish that
another party's reader agrees.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
#: jcs-rfc8785-v1 is accepted under its published alias or its content address.
SUPPORTED_PROFILES = frozenset({
    "jcs-rfc8785-v1",
    "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d",
})
CLASSIFICATIONS = ("established", "refused", "not_established", "invalid_input")
FINDINGS = frozenset({
    "join_established",
    "join_not_established",
    "effective_call_not_covered",
    "covering_decision_not_permit",
    "digest_mismatch",
    "unsupported_canonical_profile",
    "join_chain_broken",
    "result_not_completed",
    "refusal_observed",
    "store_mutation_not_established",
    "later_state_not_supplied",
    "later_state_unchanged",
    "later_state_differs",
    "later_state_not_comparable",
    "original_result_preserved",
})
#: Every top-level key is required. ``later_observation`` may be null but may
#: not be absent: an absent key and a null key mean different things here.
REQUIRED_KEYS = (
    "case_id",
    "contract",
    "source",
    "approved",
    "effective",
    "decision",
    "covering_decision",
    "attempt",
    "result",
    "later_observation",
)
CHAINED = ("approved", "effective", "decision", "covering_decision", "attempt", "result")


class InvalidInput(Exception):
    """The record is not well formed under the contract and must not be scored."""

    def __init__(self, findings: list[str] | None = None) -> None:
        """Carry the findings that name why the record is unreadable."""
        super().__init__("invalid input")
        self.findings = sorted(findings or [])


def jcs(value: object) -> bytes:
    """RFC 8785 canonical JSON for the value shapes this corpus uses."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def computed_ref(preimage: dict) -> str:
    """Return the ``sha256:<hex>`` a supplied preimage recomputes to."""
    return "sha256:" + hashlib.sha256(jcs(preimage)).hexdigest()


def shaped(case: object) -> dict:
    """Refuse anything that is not a record with exactly the declared key set."""
    if not isinstance(case, dict):
        raise InvalidInput
    if set(case) != set(REQUIRED_KEYS):
        raise InvalidInput
    if case["contract"] != "request-effect-join-fixture/v1":
        raise InvalidInput
    source = case["source"]
    if not isinstance(source, dict) or set(source) != {"producer_vector", "frequency_row", "note"}:
        raise InvalidInput
    if not isinstance(source["note"], str):
        raise InvalidInput
    for name in ("producer_vector", "frequency_row"):
        if source[name] is not None and not isinstance(source[name], str):
            raise InvalidInput
    for name in CHAINED:
        node = case[name]
        if node is None:
            if name in ("approved", "effective", "decision"):
                raise InvalidInput
            continue
        if not isinstance(node, dict) or set(node) != {"ref", "preimage"}:
            raise InvalidInput
        if not isinstance(node["preimage"], dict) or not isinstance(node["ref"], str):
            raise InvalidInput
    later = case["later_observation"]
    if later is not None:
        if not isinstance(later, dict) or set(later) != {
            "target_scope", "content_sha256", "observed_at_ms", "observer_id",
        }:
            raise InvalidInput
        if any(not isinstance(later[name], str)
               for name in ("target_scope", "content_sha256", "observer_id")):
            raise InvalidInput
        if later["observed_at_ms"] is not None and type(later["observed_at_ms"]) is not int:
            raise InvalidInput
    if (case["attempt"] is None) != (case["result"] is None):
        raise InvalidInput
    return case


def supported_profiles(case: dict) -> None:
    """Refuse a record that names a canonicalization profile we do not implement."""
    for name in ("decision", "covering_decision"):
        node = case[name]
        if node is None:
            continue
        declared = node["preimage"].get("canonicalization_profile_id")
        if declared is None or declared not in SUPPORTED_PROFILES:
            raise InvalidInput(["unsupported_canonical_profile"])


def digests_agree(case: dict) -> bool:
    """Return whether every supplied ref recomputes from its own preimage."""
    for name in CHAINED:
        node = case[name]
        if node is not None and computed_ref(node["preimage"]) != node["ref"]:
            return False
    return True


def classify(case: dict) -> dict:
    """Return the classification and findings for one record.

    Raises
    ------
    InvalidInput
        When the record is not well formed under the contract. A caller must
        report the error; it must not score the record as any join result.
    """
    record = shaped(case)
    supported_profiles(record)
    if not digests_agree(record):
        return outcome(record, "refused", ["digest_mismatch"])

    attempt, result = record["attempt"], record["result"]
    approved, effective = record["approved"], record["effective"]
    if attempt is None:
        # Nothing was dispatched, so the join question is not answered either
        # way. This is the branch a refusal lands in, and the mutation of the
        # store is exactly what stays unestablished here.
        findings = ["join_not_established", "store_mutation_not_established"]
        if record["decision"]["preimage"].get("outcome") != "permit":
            findings.append("refusal_observed")
        return outcome(record, "not_established", findings)

    if effective["ref"] != approved["ref"]:
        covering = record["covering_decision"]
        if covering is None or covering["preimage"].get("action_ref") != effective["ref"]:
            return outcome(record, "refused", ["effective_call_not_covered"])
        if covering["preimage"].get("outcome") != "permit":
            return outcome(record, "refused", ["covering_decision_not_permit"])
    elif record["decision"]["preimage"].get("outcome") != "permit":
        return outcome(record, "refused", ["covering_decision_not_permit"])

    if record["decision"]["preimage"].get("action_ref") != approved["ref"]:
        return outcome(record, "refused", ["join_chain_broken"])
    if attempt["preimage"].get("action_ref") != effective["ref"]:
        return outcome(record, "refused", ["join_chain_broken"])
    if result["preimage"].get("attempt_id") != attempt["ref"]:
        return outcome(record, "refused", ["join_chain_broken"])
    if result["preimage"].get("outcome") != "completed":
        return outcome(record, "not_established", ["result_not_completed"])

    return outcome(record, "established", ["join_established", *later_findings(record)])


def later_findings(record: dict) -> list[str]:
    """Return the later-state findings for an established join."""
    later = record["later_observation"]
    if later is None:
        return ["later_state_not_supplied"]
    if later.get("target_scope") != record["effective"]["preimage"].get("scope"):
        return ["later_state_not_comparable"]
    if later.get("content_sha256") == record["result"]["preimage"].get("output_hash"):
        return ["later_state_unchanged"]
    return ["later_state_differs", "original_result_preserved"]


def outcome(record: dict, classification: str, findings: list[str]) -> dict:
    """Return one case's report line."""
    return {"case_id": record["case_id"], "classification": classification,
            "findings": sorted(findings)}


def report_for(case: dict) -> dict:
    """Return the report line for a case, converting invalid input into its line."""
    try:
        return classify(case)
    except InvalidInput as invalid:
        return {"case_id": case.get("case_id"), "classification": "invalid_input",
                "findings": invalid.findings}


def load() -> tuple[dict, dict]:
    """Return the corpus and its expected results, refusing a stale manifest."""
    corpus = json.loads((ROOT / "fixtures" / "cases.json").read_text())
    expected = json.loads((ROOT / "expected.json").read_text())
    manifest = json.loads((ROOT / "fixtures" / "MANIFEST.json").read_text())
    for name, digest in manifest["sha256"].items():
        path = ROOT / "fixtures" / name if name == "cases.json" else ROOT / name
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise SystemExit(f"MANIFEST.json: {name} is {actual}, not the pinned {digest}")
    return corpus, expected


def main(argv: list[str]) -> int:
    """Report every case, and compare it with expected.json when asked."""
    corpus, expected = load()
    reports = [report_for(case) for case in corpus["cases"]]
    wanted = {case["case_id"]: case for case in expected["cases"]}
    diverged = [line for line in reports
                if line["case_id"] not in wanted
                or line["classification"] != wanted[line["case_id"]]["classification"]
                or sorted(line["findings"]) != sorted(wanted[line["case_id"]]["findings"])]
    if "--json" in argv:
        print(json.dumps({"cases": reports,
                          "divergences": [line["case_id"] for line in diverged]}, indent=2))
    else:
        for line in reports:
            print(f"{line['case_id']}  {line['classification']:<16} {', '.join(line['findings']) or '-'}")
        print(f"\n{len(reports) - len(diverged)}/{len(reports)} cases match expected.json")
        for line in diverged:
            print(f"  divergence: {line['case_id']}")
    return 1 if diverged else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
