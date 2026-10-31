#!/usr/bin/env python3
"""Bind the REMORA execution-boundary run records to their retained originals."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSUMED = "fe324dd734734d9227aa894330ac52c2bb916b94"
EXECUTED = "308c5b4401b18d42ed73dea80459375932e6b8e8"
RUN = "https://github.com/probityai/agent-evidence-vectors/actions/runs/37232420650"
PACKAGES = {
    "exact-call-binding-v1": "sha256:48dd143c4e4f50d69063df8e2a2993a5d240a50d81dc4330b225015ea432c77c",
    "fresh-authority-v1": "sha256:234c57d0ed79b0cd87e702b2efbc52e99af1c619bd7fed2aef7be5c14964b691",
    "effect-evidence-v1": "sha256:26c437c65a5c3890a0672845dd9e1e54b03c38ae5f05a6fbe7131402b952034c",
}
CLAIMS = {
    "exact-call-binding-v1": ["exact_call_binding", "single_use_authorization"],
    "fresh-authority-v1": ["fresh_authority_at_dispatch"],
    "effect-evidence-v1": ["effect_state_distinction"],
}
QUALIFICATION = ".build/remora-boundary-records/qualification/"
RESULTS = ("ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED")


def require(value, reason):
    """Refuse altered retained inputs or projections."""
    if not value:
        raise ValueError(reason)


def sha(raw):
    """Hash the original bytes."""
    return hashlib.sha256(raw).hexdigest()


def get(packet, name):
    """Read one authenticated JSON member."""
    return json.loads(packet.read(name))


def archive_check(source):
    """Check every original archive member before reading outcomes."""
    raw = (HERE / source["archive"]).read_bytes()
    require(len(raw) == source["bytes"] and sha(raw) == source["sha256"], "original archive differs")
    require(source["githubDigest"] == "sha256:" + source["sha256"], "provider digest differs")
    with zipfile.ZipFile(HERE / source["archive"]) as packet:
        names = [i.filename for i in packet.infolist() if not i.is_dir()]
        require(len(names) == len(set(names)) == len(source["members"]), "original member population differs")
        require(set(names) == {m["path"] for m in source["members"]}, "original members differ")
        for member in source["members"]:
            data = packet.read(member["path"])
            require(len(data) == member["bytes"] and sha(data) == member["sha256"], "original member bytes differ")


def producer_package(packet, contract):
    """Recompute the frozen package digest from the retained producer bytes."""
    root = QUALIFICATION + "producer-inputs/"
    manifest = get(packet, root + "artifacts/interop/" + contract + "/manifest.json")
    lines = "".join(f"{row['path']} {row['sha256']}\n" for row in sorted(manifest["package_files"], key=lambda row: row["path"]))
    digest = "sha256:" + sha(lines.encode())
    require(digest == manifest["package_digest"] == PACKAGES[contract], "package digest differs")
    checked = []
    for row in manifest["package_files"]:
        if row["path"].endswith("/reference_verifier.py"):
            require(root + row["path"] not in packet.namelist(), "reference verifier bytes were retained as input")
            continue
        require(sha(packet.read(root + row["path"])) == row["sha256"], "producer input differs from its manifest")
        checked.append(row["path"])
    return digest, checked


def contract_projection(packet, report):
    """Derive one contract's claim table and run record from native output."""
    contract = report["contract_id"]
    digest, checked = producer_package(packet, contract)
    require(report["package_digest"] == digest and report["case_count"] == report["passing_expectations"], "native contract result differs")
    claims = []
    for claim in CLAIMS[contract]:
        record = next(row for row in report["claims"] if row["claim"] == claim)
        cases = [row for row in report["cases"] if row["claim_id"] == claim]
        require([row["result"] for row in record["cases"]] == [row["result"] for row in cases], "claim record cases differ")
        require(all(row["result"] == row["expected"]["claim_result"] for row in cases), "a case differs from its fixture")
        counts = {result: sum(row["result"] == result for row in cases) for result in RESULTS}
        require(record["independence_level"] == "L2_SECOND_IMPLEMENTATION" and record["operator"] == "EXTERNAL", "claim classification differs")
        claims.append({"claim": claim, "status": record["status"], "cases": len(cases), "caseResults": counts})
    require([c["claim"] for c in claims] == [r["claim"] for r in report["claims"]], "claim population differs")
    run_record = report["run_record"]
    require(run_record["consumed_revision"] == CONSUMED and run_record["package_digest"] == digest, "run record identity differs")
    require(run_record["verifier"]["implementation_revision"] == EXECUTED and run_record["run_ref"] == RUN, "run record revision differs")
    require([(r["claim_id"], r["case_id"], r["result"]) for r in run_record["results"]] == [(r["claim_id"], r["case_id"], r["result"]) for r in report["cases"]], "run record results differ")
    require(run_record["imports"] == {"remora_runtime": False, "reference_verifier": False}, "run record imports differ")
    return {
        "contract": contract,
        "packageDigest": digest,
        "producerInputsChecked": checked,
        "cases": report["case_count"],
        "passingExpectations": report["passing_expectations"],
        "claims": claims,
        "runRecord": {
            "file": contract + ".external-run-record-v1.json",
            "implementationDiversity": run_record["implementation_diversity"],
            "operator": run_record["operator"],
            "maintainedBy": run_record["verifier"]["maintained_by"],
            "independence": run_record["independence"],
            "results": len(run_record["results"]),
        },
    }


def case_results(native):
    """Project per-case outcomes without the callback event timestamps."""
    rows = []
    for report in native["contracts"]:
        for row in report["cases"]:
            observed = {k: v for k, v in row["observed"].items() if k != "events"}
            events = [{k: v for k, v in event.items() if k != "at"} for event in row["observed"].get("events", [])]
            rows.append([report["contract_id"], row["case_id"], row["result"], observed, events])
    return rows


def project(source):
    """Derive one qualified execution from its original archive."""
    with zipfile.ZipFile(HERE / source["archive"]) as packet:
        log = json.loads(packet.read(".build/remora-boundary-records/qualification.log").decode().strip().splitlines()[-1])
        summary = get(packet, QUALIFICATION + "summary.json")
        native = get(packet, QUALIFICATION + "baseline-result/native-decisions.json")
        require(log["status"] == summary["status"] == native["status"] == "passed", "qualification did not pass")
        require(summary["revision"] == native["implementation_revision"] == EXECUTED, "executed revision differs")
        require(native["consumed_revision"] == CONSUMED and native["producer_runtime_imported"] is False and native["reference_evaluator_imported"] is False, "native scope differs")
        require(summary["python"] == source["python"], "interpreter differs")
        require(all(row["exit_status"] == 0 for row in summary["own_cases"]), "an additional case failed")
        require(all(row["matches_expected"] for row in summary["malformed_controls"]), "a malformed-input control differs")
        require(all(row["caught"] for row in summary["source_faults"]), "a source mutation survived")
        require(all(row["matches_expected"] for row in summary["verify_bridge"]), "a Verify decision differs")
        contracts = [contract_projection(packet, report) for report in native["contracts"]]
        require([c["contract"] for c in contracts] == list(PACKAGES), "contract population differs")
        records = {report["contract_id"]: report["run_record"] for report in native["contracts"]}
        return {
            "python": source["python"],
            "archive": source["archive"],
            "artifactId": source["artifactId"],
            "nativeDecisionsSHA256": sha(packet.read(QUALIFICATION + "baseline-result/native-decisions.json")),
            "status": "passed",
            "nativeCases": log["native_cases"],
            "additionalCases": len(summary["own_cases"]),
            "malformedControls": len(summary["malformed_controls"]),
            "sourceFaults": len(summary["source_faults"]),
            "verifyDecisions": len(summary["verify_bridge"]),
            "contracts": contracts,
        }, records, case_results(native)


def derive():
    """Check both originals, the three extracted records and their repeat."""
    provenance = json.loads((HERE / "provenance.json").read_bytes())
    sources = provenance["archives"]
    require([s["python"] for s in sources] == ["3.13.15", "3.14.7"], "archive selection differs")
    runs, records, cases = [], [], []
    for source in sources:
        archive_check(source)
        run, record, case = project(source)
        runs.append(run)
        records.append(record)
        cases.append(case)
    require(cases[0] == cases[1], "the two interpreters disagree on a case")
    for contract in PACKAGES:
        extracted = json.loads((HERE / (contract + ".external-run-record-v1.json")).read_bytes())
        require(extracted == records[0][contract], "extracted run record differs from the original")
    return {
        "schema": "probity.lab.remora-boundary.v1",
        "consumedRevision": CONSUMED,
        "readerRevision": EXECUTED,
        "workflowRun": RUN,
        "operator": "Probity-operated GitHub Actions",
        "implementationDiversity": "SECOND_IMPLEMENTATION",
        "independence": "NOT_INDEPENDENT",
        "interpretersAgreeOnEveryCase": True,
        "qualifiedRuns": runs,
    }


def validate():
    """Bind the Lab report to both originals."""
    require(derive() == json.loads((HERE / "report.json").read_bytes()), "Lab projection differs")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-report"]:
        (HERE / "report.json").write_text(json.dumps(derive(), indent=2) + "\n")
    else:
        require(not sys.argv[1:], "unsupported arguments")
        validate()
    print("REMORA boundary originals, three run records and both interpreter runs match")
