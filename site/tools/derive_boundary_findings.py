"""Rederive finite boundary findings from the unmodified 384-call original.

Run ``python3 tools/derive_boundary_findings.py`` to write the public readout or
append ``--check`` to require the retained readout to be byte-identical. This
uses only original retained outputs; no inference or score adjustment occurs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "experiments/model-boundary-cpu-2026-10-02"
POLICY_VOCABULARY = ("admit", "dispatch", "hold", "inspect", "publish", "reject", "retry")


def encode(value: Any) -> bytes:
    """Encode a deterministic UTF-8 JSON readout with no nonfinite values."""
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _cap_comparison(attempts: list[dict[str, Any]], decoder: str) -> dict[str, Any]:
    """Count exact cap pairs without estimating performance beyond this run."""
    selected = [attempt for attempt in attempts if attempt["decoder"] == decoder]
    by_identity = {attempt["id"]: attempt for attempt in selected}
    short = [attempt for attempt in selected if attempt["configuration"] == "short24"]
    pairs = [(attempt, by_identity[attempt["id"].replace("--short24--", "--long96--")])
             for attempt in short]
    return {
        "decoder": decoder, "comparedCaseIdentities": len(pairs),
        "identicalOutputText": sum(left["output"] == right["output"] for left, right in pairs),
        "identicalPublishedVerdicts": sum(
            tuple(left[field] for field in ("correct", "formatValid", "schemaValid")) ==
            tuple(right[field] for field in ("correct", "formatValid", "schemaValid"))
            for left, right in pairs),
        "scope": "Descriptive paired original outputs. Cap identity does not establish causal invariance, future output stability or a benchmark effect.",
    }


def _policy_vocabulary(attempts: list[dict[str, Any]], model: str,
                       configuration: str) -> dict[str, Any]:
    """Separate wrong decision labels from wrong decisions using valid labels.

    This is a disclosed post hoc diagnostic over published schema-valid outputs.
    The seven labels occur in the frozen policy targets. Membership never
    changes the original typed-exact score and never authorizes an action.
    """
    selected = [attempt for attempt in attempts if
                (attempt["model"], attempt["configuration"], attempt["decoder"], attempt["family"]) ==
                (model, configuration, "schema", "policy-boundary")]
    labels = [json.loads(attempt["output"])["decision"] for attempt in selected]
    return {
        "model": model, "configuration": configuration,
        "decoder": "schema", "family": "policy-boundary", "planned": len(selected),
        "outsideFrozenActionVocabulary": sum(label not in POLICY_VOCABULARY for label in labels),
        "inVocabularyButWrong": sum(label in POLICY_VOCABULARY and not attempt["correct"]
                                    for label, attempt in zip(labels, selected)),
        "publishedStrictCorrect": sum(attempt["correct"] for attempt in selected),
        "originalAttemptIds": [attempt["id"] for attempt in selected],
        "scope": "Post hoc case-sensitive label diagnosis, not a replacement rubric or new inference result.",
    }


def _pair_row(row: dict[str, Any], attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """Retain every pair and both original attempt references for one quality row."""
    fields = ("model", "configuration", "decoder", "family")
    selected = [attempt for attempt in attempts if all(attempt[field] == row[field] for field in fields)]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for attempt in selected:
        groups[attempt["pair"]].append(attempt)
    return {**{field: row[field] for field in fields}, "pairs": [
        {"pair": name, "bothStrictlyCorrect": all(attempt["correct"] for attempt in pair),
         "attempts": [{"id": attempt["id"], "pairRole": attempt["pairRole"],
                       "correct": attempt["correct"], "schemaValid": attempt["schemaValid"]}
                      for attempt in sorted(pair, key=lambda item: item["pairRole"])]}
        for name, pair in sorted(groups.items())]}


def _typed_failures(report: dict[str, Any], cases: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Show all constrained typed failures with untouched output/target references."""
    failures = []
    for index, attempt in enumerate(report["attempts"]):
        if (attempt["decoder"], attempt["family"], attempt["correct"]) != ("schema", "typed-boundary", False):
            continue
        case = cases[attempt["id"].split("--")[-1]]
        failures.append({"attemptId": attempt["id"], "originalReportPointer": f"/attempts/{index}",
                         "output": attempt["output"], "frozenTarget": case["target"],
                         "schemaValid": attempt["schemaValid"], "publishedStrictCorrect": attempt["correct"]})
    return failures


def derive_findings(report: dict[str, Any], protocol: dict[str, Any],
                    report_sha256: str) -> dict[str, Any]:
    """Build a finite comparative release finding from authenticated originals.

    Parameters
    ----------
    report : dict of str to Any
        Unmodified native report containing all 384 attempts and 24 quality
        rows. The caller must authenticate it against the retained archive.
    protocol : dict of str to Any
        Frozen pre-inference protocol containing 48 case identities and their
        original targets. Two positive-control literal inputs are repeated.
    report_sha256 : str
        Separately authenticated digest of the original report bytes. This
        function is pure; it does not guess a digest from mutable local files.

    Returns
    -------
    dict of str to Any
        Source-bound original rows, cap comparisons, every pair, all constrained
        typed failures and a disclosed post hoc policy vocabulary diagnosis.
        Findings preserve original scores and shared resource scopes.

    Notes
    -----
    :func:`main` checks the immutable archive/report/protocol pins before calling
    this function. Atlas retention, installed acceptance, outside adoption and
    independently operated custody remain separate records and outcomes.
    """
    attempts = report["attempts"]
    cases = {case["id"]: case for case in protocol["cases"]}
    return {
        "schema": "probity-atlas-finite-boundary-findings-v1",
        "nativeRun": 37060702246,
        "originalReportSHA256": report_sha256,
        "population": report["population"], "authoredCaseIdentities": len(cases),
        "uniqueLiteralInputs": len({case["input"] for case in cases.values()}),
        "qualityRowsUnpooled": report["quality"],
        "capComparisons": [_cap_comparison(attempts, decoder) for decoder in ("unconstrained", "schema")],
        "policyVocabulary": list(POLICY_VOCABULARY),
        "policyVocabularyDiagnostic": [_policy_vocabulary(attempts, model, configuration)
            for model in ("smol135-q4", "smol360-q4") for configuration in ("short24", "long96")],
        "pairRows": [_pair_row(row, attempts) for row in report["quality"]],
        "allConstrainedTypedFailures": _typed_failures(report, cases),
        "resources": {
            "originalWallNs": report["elapsed_ns"], "originalTotalProcessCpuNs": report["process_cpu_ns"],
            "returnedCallProcessCpuNs": sum(row["processCpuNs"] for row in report["quality"]),
            "sharedProcessLifetimePeakRssKiB": max(row["processLifetimePeakRssKiB"] for row in report["quality"]),
            "originalNativeTokens": report["nativeTokens"],
            "currentPreparationResponseBodyBytes": report["preparation"]["selectedPayloadBytes"],
            "scope": "Total CPU includes initialization; row CPU sums returned-call deltas. RSS is shared lifetime peak, not per-model/task memory. Acquisition is one of five separately budgeted attempts.",
        },
        "interpretation": "Schema constraints remove selected format/type failures while decision logic and grounding remain unresolved. All96 constrained cap comparisons have identical text in this original run; neither policy nor grounded pairs are fully correct. These finite authored findings do not imply general benchmark performance or action acceptance.",
        "limits": ["Author-selected exposed cases and targets; selection informed by earlier public failures.",
                   "Published strict rubric and scores unchanged; vocabulary diagnosis is post hoc.",
                   "No new inference, protected effect, blind custody or outside recurring adoption."],
    }


def _retain_findings(target: Path, result: bytes, check: bool) -> None:
    """Write a deterministic readout or require exact retained-byte equality.

    Parameters
    ----------
    target : Path
        Fixed public readout destination selected by :func:`main`.
    result : bytes
        Derived JSON bytes produced by :func:`encode` from authenticated inputs.
    check : bool
        If true, compare without modifying the retained destination.

    Raises
    ------
    ValueError
        When check mode detects any difference from the original-byte finding.
    """
    if not check:
        target.write_bytes(result)
        return
    if target.read_bytes() != result:
        raise ValueError("finite findings differ from original-byte rederivation")


def main() -> None:
    """Authenticate original inputs and write/check the deterministic readout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if __package__:
        from .check_boundary_retention import ARCHIVE_SHA256, PROTOCOL_SHA256, REPORT_SHA256
    else:
        from check_boundary_retention import ARCHIVE_SHA256, PROTOCOL_SHA256, REPORT_SHA256
    archive = FOLDER / "original-artifact.zip"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("findings require selected original archive")
    with zipfile.ZipFile(archive) as bundle:
        report_raw, protocol_raw = bundle.read("report.json"), bundle.read("protocol.json")
    if (hashlib.sha256(report_raw).hexdigest(), hashlib.sha256(protocol_raw).hexdigest()) != (
            REPORT_SHA256, PROTOCOL_SHA256):
        raise ValueError("findings require frozen original report and protocol")
    result = encode(derive_findings(json.loads(report_raw), json.loads(protocol_raw), REPORT_SHA256))
    target = FOLDER / "finite-findings.json"
    _retain_findings(target, result, args.check)
    print("finite boundary findings: original24 rows,192 pairs and separate cap/vocabulary/resource axes retained")


if __name__ == "__main__":
    main()
