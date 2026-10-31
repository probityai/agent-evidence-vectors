"""Keep scripted SDK outcomes and installed gate decisions on distinct axes."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

if __package__:
    from .check_lab import artifact_path, require
else:
    from check_lab import artifact_path, require


def validate_execution_retention(record: dict, report: dict, provenance: dict) -> None:
    """Refuse selected outcome promotion even after artifact hash reselection."""
    require(provenance["roles"]["independentEffectCustody"] == "not-established",
            "retention cannot invent independent effect custody")
    require(record["roles"] == provenance["roles"], "retention roles rebound")
    require(record["sourceRevision"] == provenance["sourceCommit"] and
            record["readerRevision"] == provenance["readerCommit"], "retention source revisions rebound")
    if record["id"] == "google-adk-ticket-2026-10-02":
        rows = report["records"]
        require(report["modelQuality"] == "not-evaluated", "scripted SDK is not model quality")
        require(len(rows) == report["plannedAttempts"] == 12 and
                len({r["case"] for r in rows}) == 12, "ADK selected case population changed")
        measured = [c for c in record["claimResults"] if c.get("recordedField", "").startswith("/records/")]
        require(len(measured) == 24, "ADK task/effect axes incomplete")
        for i, row in enumerate(rows):
            require(type(row["nativeRevision"]) is int and row["nativeRevision"] in {0, 1},
                    "ADK native revision must be an integer zero or one")
            require(type(row["taskStatus"]) is str and row["taskStatus"] in {"complete", "error", "incomplete"},
                    "ADK task status must preserve selected outcome")
            for field, label, passed in (("taskStatus", "task-completion", row["taskStatus"] == "complete"),
                                         ("nativeRevision", "native-revision-one", row["nativeRevision"] == 1)):
                matches = [c for c in measured if c["recordedField"] == f"/records/{i}/{field}"]
                require(len(matches) == 1 and matches[0]["claim"] == row["case"] + "-" + label and
                        matches[0]["result"] == ("pass" if passed else "fail"),
                        "ADK task completion cannot be inferred from committed effect")
    else:
        require(report["baseline-installation"]["version"] == "0.0.2" and
                report["candidate-installation"]["version"] == "0.0.3", "installed upgrade versions changed")
        for prefix in ("baseline", "candidate"):
            require(all(v is False for v in report[prefix + "-installation"]["frameworkModules"].values()),
                    "installed no-framework boundary changed")
        require(report["baseline-format"]["gate"]["evidenceDecision"] == "not-verified" and
                report["baseline-format"]["gate"]["publicationDecision"] == "hold" and
                report["baseline-reader"]["exit"] == 1, "old unsupported reader must refuse")
        require(report["candidate-format"]["gate"]["evidenceDecision"] == "verified" and
                report["candidate-format"]["gate"]["publicationDecision"] == "publish",
                "upgraded bounded evidence publication changed")
        quality = report["candidate-format-quality"]["gate"]
        require(quality["evidenceDecision"] == "verified" and
                quality["publicationDecision"] == "hold-selected-score-or-resource",
                "verified evidence cannot promote failed selected quality")
        failures = quality["policyFailures"]
        require(len(failures) == 2 and {f["row"]["configuration"] for f in failures} == {"short24", "long96"},
                "selected policy failure rows changed")
        for failure in failures:
            require(type(failure["measured"]) is int and type(failure["minimum"]) is int,
                    "selected policy counts must be integers")
            require(failure["row"]["decoder"] == "schema" and
                    failure["row"]["model"] == "smol360-q4" and
                    failure["row"]["family"] == "policy-decision" and
                    failure["field"] == "correct" and failure["measured"] == 1 and failure["minimum"] == 3,
                    "schema validity cannot replace selected policy correctness")
        require(provenance["newInferenceExecuted"] is False and provenance["omissions"] == [],
                "installed gate is not new native inference or selected omission")


def check_selected_execution_register(register: dict, root: Path) -> None:
    """Bind selected execution report bytes to the complete original provider ZIP."""
    for record in register["records"]:
        if record["id"] not in {"google-adk-ticket-2026-10-02", "installed-format-policy-2026-10-02"}:
            continue
        report = json.loads(artifact_path(root, record["report"]).read_bytes())
        provenance = json.loads(artifact_path(root, record["provenance"]).read_bytes())
        validate_execution_retention(record, report, provenance)
        archive = artifact_path(root, next(a["path"] for a in record["artifacts"]
                                         if a["path"].endswith("original-artifact.zip")))
        with zipfile.ZipFile(archive) as bundle:
            require(bundle.read(provenance["reportMember"]) == artifact_path(root, record["report"]).read_bytes(),
                    "selected execution report differs from original member")
