"""Read retained report and diagnostic outputs without executing captured code.

The fixed source hashes authenticate the selected historical dataset. Accounting
is recomputed from original report/harness records and diagnostic per-case rows.
This check establishes retained-output consistency, not a fresh reader replay.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any

if __package__:
    from .check_lab import require, _same_json_value
else:
    from check_lab import require, _same_json_value

IDENTITY = "w3c-report-replay-2026-10-06"
HASHES = {'LICENSE': '8b506a9d145be0a6fbef3f0519996faf84c770f8ab8d32d120c8682f2ad6181f', 'SOURCE-ORIGIN.json': 'a2a4e58b3f54c2ae34f58e9259972e45e94ab50978568ef9079e7e8cc4c520bc', 'checker-and-configuration.mutant.py': '6c2541c985569a3cf3483efc8e121a2a615fef64ab490c7fde98161dc9b4775e', 'checker-and-configuration.per-case.json': '7cd4cd6575588a21b518fc70c3f39bc9672d7a79fee5dd20c22363517408147e', 'control-summary.json': '95839e879d12d942bf0ac3c67608971eb40ac6ac005625a260429e4be4946312', 'historical-summary.json': 'bda9105e4c040d8140f6ab42ca7b22929b1bef1adf0527c65380d39557aee3f2', 'logic-control-configuration.json': '736f640557727e9b524c6925b7b29efbfcec56f8b6258cf02be8bf0590bb3a0e', 'logic-control-evidence.json': '815adc01af215bda4d7b10edf1e9707c578667762234cf955cd04c192b3a3167', 'logic-mutation-summary.json': '24edc6eb36ce9bf06abaddbcadf12c2c9fb78b65c85e2a9f44f14de4b9327aea', 'negative-witness-state.mutant.py': 'a57f365c5046ab4e400ef215ca3beea93fd975239a92726eb2eb0618c127816d', 'negative-witness-state.per-case.json': 'bdc424f51334c17079dd41af3cf62919ec4a33bb351a3281c60f36adb2395992', 'original-RUN.json': '00007b271fd027a5c952c17a8100190b8af360929f906936be352bb806c97448', 'original-conformance-report.json': 'ee349e66697a2f4f95dd8223fd261810f99f5f2807e03bde03c9a9f57359529d', 'original-report.json': '37288d8dfc01f56cb5ef553232258dc596928bc962e2309e0c7dc09ae588baf2', 'per-case-outcomes.csv': '57ec77ae8e30cf56b0ec7c6c1300e382df3fd9cafafa6e12d86d195cb0965753', 'per-case-outcomes.json': '0c328d01013c28137507ca9460caa61642d023479fe9a9edded42f18499bf751', 'report-replay-configuration.json': 'edc9489a5415616762dd67d2d740c8f064f709643724ed2c1cf55db3b09c6ff9'}
BASE = "0f5d25ab4cb00337f332eb109ac0dbc8b5651e00"
PROVENANCE = {'schema': 'atlas.report-replay-retention.v1', 'sourceRevision': '2f3aee40a454df6de0f571d119f057d7dbb8dd67', 'diagnosticReaderRevision': 'e07cd52999204d7c0f6562a5098dc4784fe025a6', 'historicalPackage': 'agent-evidence-vectors==0.12.0', 'diagnosticPackage': 'agent-evidence-vectors==0.13.0', 'roles': {'verifierAuthor': 'Probity', 'historicalRunner': 'Probity, author-operated', 'diagnosticRunner': 'Probity, author-operated', 'retentionAndAccounting': 'Probity', 'independentOperator': 'not-established'}, 'answerExposure': 'Published expected answers and author-selected predicates were exposed; not answer-blind.', 'comparisonOrder': 'Historical harness outcomes and comparison grades emitted together. Diagnostic copies remove one predicate each; outputs are retained separately from the historical report.', 'limits': ['Synthetic conformance artifacts; the customer refund story is hypothetical.', 'Retained-output accounting executes no captured reader or mutant code and performs no new model inference.', 'Historical 272-case report and separate 232-fixture diagnostic population are not combined.', 'Report validity, evidence conclusion and actual action completion are distinct.', 'Reader binding check is a historical proposed rule; its draft normative status is not promoted.', 'No independent operation, effect custody, production workload, customer payment or outside maintained job is established.']}


def derive(root: Path) -> dict[str, Any]:
    """Authenticate all source files and recompute the finite recorded counts.

    No archive source is imported. Report and harness rows join by exact unique
    identifiers. Missing, duplicated, promoted or changed rows are refused.
    """
    directory = root / "experiments" / IDENTITY
    raw = {name: (directory / name).read_bytes() for name in HASHES}
    for name, digest in HASHES.items():
        require(hashlib.sha256(raw[name]).hexdigest() == digest,
                "historical report source bytes changed: " + name)
    document = {name: json.loads(value) for name, value in raw.items() if name.endswith(".json")}
    harness = document["original-conformance-report.json"]
    report = document["original-report.json"]
    rows = document["per-case-outcomes.json"]
    originals = harness["vectors"]
    checks = report["checks"]
    require(len(rows) == len(originals) == len(checks) == 272,
            "historical report population changed")
    hi = {row["id"]: row for row in originals}
    ci = {row["check"]: row for row in checks}
    require(len(hi) == len(ci) == 272 and {row["case_id"] for row in rows} == set(hi) == set(ci),
            "historical report identity join changed")
    cells: Counter[tuple[Any, ...]] = Counter()
    for row in rows:
        h, c = hi[row["case_id"]], ci[row["case_id"]]
        expected = {
            "harness_status": h["status"], "harness_conformance": h["conformance"],
            "kind": h["kind"], "observed_verdict": h["observed"].get("verdict"),
            "observed_result": h["observed"].get("result"), "observed_codes": h["observed"].get("codes"),
            "expected": h["expected"], "source_file": h["file"], "report_state": c["state"],
            "report_cause": c.get("cause"),
        }
        require(all(_same_json_value(row[key], value) for key, value in expected.items()),
                "historical per-case row differs from original")
        cells[(row["kind"], row["observed_verdict"], row["observed_result"], row["report_state"])] += 1
    summary = document["historical-summary.json"]
    crosswalk = [{"kind": k[0], "observed_verdict": k[1], "observed_result": k[2],
                  "report_state": k[3], "count": count} for k, count in sorted(cells.items())]
    require(_same_json_value(crosswalk, summary["crosswalk_cells"]), "historical crosswalk changed")
    states = dict(Counter(row["state"] for row in checks))
    require(states == {"pass": 31, "fail": 239, "inconclusive": 2} and
            _same_json_value(summary["report_rollup"], report["roll-up"]), "historical report rollup changed")
    require(all(row["status"] == row["conformance"] == "PASS" for row in originals),
            "historical harness comparison changed")
    require(summary["report_states"] == states and summary["harness_statuses"] == {"PASS": 272},
            "historical summary changed")
    csv_rows = list(csv.DictReader(io.StringIO(raw["per-case-outcomes.csv"].decode("utf-8"))))
    require(len(csv_rows) == 272 and [row["case_id"] for row in csv_rows] == [row["case_id"] for row in rows],
            "historical CSV population changed")
    diagnostic = []
    for index, mutation in enumerate(document["logic-mutation-summary.json"]):
        name = mutation["mutation"]
        cases = document[name + ".per-case.json"]
        require(len(cases) == len({row["id"] for row in cases}) == 232,
                "diagnostic population changed")
        require(Counter(row["kind"] for row in cases) == {"accept": 116, "reject": 116},
                "diagnostic control population changed")
        for row in cases:
            require(type(row["changed"]) is bool and row["changed"] ==
                    (row["baseline_rejections"] != row["mutant_rejections"]), "diagnostic change flag differs")
            require(row["kind"] != "accept" or (row["baseline_rejections"] == row["mutant_rejections"] == []),
                    "accepting diagnostic control changed")
        flipped = [row for row in cases if row["changed"]]
        require([row["id"] for row in flipped] == mutation["flipped_cases"] and
                len(flipped) == mutation["flipped_count"] and
                232 - len(flipped) == mutation["unchanged_count"], "diagnostic summary differs")
        evidence = document["logic-control-evidence.json"][index]
        require([row["id"] for row in evidence["flipped_cases"]] == mutation["flipped_cases"] and
                evidence["actual_flipped_count"] == len(flipped) and
                evidence["actual_unchanged_count"] == 232 - len(flipped), "diagnostic evidence differs")
        mutant = raw[name + ".mutant.py"]
        after, before = mutation["after"].encode(), mutation["before"].encode()
        # The approved source has one exact authored predicate change. Reconstruct
        # its baseline as bytes; never import or execute it.
        require(mutant.count(after) == 1 and hashlib.sha256(mutant.replace(after, before, 1)).hexdigest() ==
                mutation["original_reader_sha256"], "diagnostic reader change is not exact")
        diagnostic.append({"mutation": name, "cases": 232, "changedRejects": len(flipped),
                           "unchanged": 232 - len(flipped), "unchangedAccepts": 116})
    return {"historical": {"cases": 272, "harnessPassingComparisons": 272, "reportStates": states,
                           "crosswalk": crosswalk}, "diagnostic": diagnostic,
            "checkScope": "offline retained-output accounting; no captured code executed",
            "actionCompletion": "not-established", "independentOperation": "not-established"}


def claim_results(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Bind each measured accounting claim separately from unmeasured effects."""
    return [
        {"claim": "historical-harness-comparisons", "result": "pass", "recordedField": "/historical/harnessPassingComparisons", "expectedValue": 272},
        {"claim": "historical-report-state-accounting", "result": "pass", "recordedField": "/historical/reportStates", "expectedValue": {"pass": 31, "fail": 239, "inconclusive": 2}},
        {"claim": "historical-report-crosswalk", "result": "pass", "recordedField": "/historical/crosswalk", "expectedValue": report["historical"]["crosswalk"]},
        *[{"claim": row["mutation"] + "-recorded-control", "result": "pass", "recordedField": "/diagnostic/" + str(index), "expectedValue": row} for index, row in enumerate(report["diagnostic"])],
        *[{"claim": name, "result": "not-exercised"} for name in ("real-workload-action-completion", "independent-operation", "outside-maintained-host-adoption", "current-vectors-reader-replay")],
    ]


def check_selected_report_replay(register: dict[str, Any], root: Path) -> None:
    """Require the selected record to preserve all original bytes and scope."""
    selected = [record for record in register["records"] if record["id"] == IDENTITY]
    if not selected:
        return
    record = selected[0]
    report = derive(root)
    directory = root / "experiments" / IDENTITY
    require(_same_json_value(json.loads((directory / "report.json").read_text()), report),
            "retained report accounting differs")
    require(_same_json_value(record["claimResults"], claim_results(report)), "report replay claims changed")
    provenance = json.loads((directory / "provenance.json").read_text())
    require(_same_json_value(provenance, PROVENANCE), "report replay provenance changed")
    require(record["answerExposure"] == PROVENANCE["answerExposure"] and record["comparisonOrder"] == PROVENANCE["comparisonOrder"], "report replay exposure changed")
    require(record["roles"] == provenance["roles"] and record["limits"] == provenance["limits"] and
            record["sourceRevision"] == "2f3aee40a454df6de0f571d119f057d7dbb8dd67" and
            record["readerRevision"] == "e07cd52999204d7c0f6562a5098dc4784fe025a6" and
            record["atlasRevision"] == BASE and record["reviewState"] == "author-retained-measured-record",
            "report replay role, source or scope changed")
    prefix = "../experiments/" + IDENTITY + "/"
    require(record["report"] == prefix + "report.json" and record["provenance"] == prefix + "provenance.json" and
            record["contract"] == "https://github.com/probityai/agent-evidence-vectors/tree/2f3aee40a454df6de0f571d119f057d7dbb8dd67" and
            record["evidenceClaim"] == "historical-report-accounting-and-separate-diagnostic-control-dependencies",
            "report replay contract or scope changed")
    require({a["path"] for a in record["artifacts"]} ==
            {prefix + name for name in HASHES} | {prefix + name for name in
                ("report.json", "provenance.json", "source-manifest.json", "README.md")},
            "report replay artifact population changed")
    manifest = json.loads((directory / "source-manifest.json").read_text())
    require(manifest["schema"] == "atlas.retained-public-files.v1" and manifest["base_directory"] == "." and
            {row["path"]: row["sha256"] for row in manifest["files"]} == HASHES and
            len(manifest["files"]) == len(HASHES) and
            all(type(row["bytes"]) is int and row["bytes"] == (directory / row["path"]).stat().st_size
                for row in manifest["files"]), "report replay source manifest changed")
    require({Path(a["path"]).name: a["sha256"] for a in record["artifacts"] if Path(a["path"]).name in HASHES} == HASHES,
            "report replay original artifact selection changed")


if __name__ == "__main__":
    print(json.dumps(derive(Path(__file__).resolve().parent.parent), indent=2, sort_keys=True))
