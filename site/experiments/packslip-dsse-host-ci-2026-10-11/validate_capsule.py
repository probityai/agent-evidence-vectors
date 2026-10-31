#!/usr/bin/env python3
"""Read retained host metadata; do not rerun Packslip or infer a native exit."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SOURCE = "7b32cd29a9240927882ee18b3db1dcfd8e0328b4"
CAPTURE_TIME = "2026-10-14T08:39:20+00:00"
PINS = {
    "raw/host-job.json": "c31e6ac7a7869deb297c8bd948cd2809b0c3dc104ff4015a260d795137bc2c58",
    "raw/host-workflow.yml": "d9db488b991f4fe3c1fddd7fb0059e23ca40f7c7755213559fc58f0c4036c27c",
    "raw/regression.rs": "7995538720ea419544ffe75f0e8785162face6d9514a7779346717116f718135",
    "raw/contribution-pr.json": "71589c0b88fa34508e79bc2cecc9790cfc7a04f4d670944486b6b71f054c6a28",
    "raw/reverse-dependencies.json": "985a0fae093e325e4fa4b6180c56d67abd3c702346fc9a3f6c477b31232fde62",
}
URLS = {
    "raw/host-job.json": "https://api.github.com/repos/jdx/packslip/actions/jobs/114504640732",
    "raw/host-workflow.yml": f"https://raw.githubusercontent.com/jdx/packslip/{SOURCE}/.github/workflows/ci.yml",
    "raw/regression.rs": f"https://raw.githubusercontent.com/jdx/packslip/{SOURCE}/tests/dsse_regression.rs",
    "raw/contribution-pr.json": "https://api.github.com/repos/jdx/packslip/pulls/149",
    "raw/reverse-dependencies.json": "https://crates.io/api/v1/crates/dsse/reverse_dependencies?page=1&per_page=100",
}


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def derive(directory: Path) -> dict:
    """Derive only the two selected claims from the frozen public responses."""
    for path, digest in PINS.items():
        require(hashlib.sha256((directory / path).read_bytes()).hexdigest() == digest,
                "retained public source differs: " + path)
    job = json.loads((directory / "raw/host-job.json").read_text())
    require(job["id"] == 114504640732 and job["run_id"] == 38151127588 and job["head_sha"] == SOURCE,
            "host job identity differs")
    require(job["status"] == "completed" and job["conclusion"] == "success", "host job did not succeed")
    steps = [step for step in job["steps"] if step["number"] == 9]
    require(len(steps) == 1, "host test step is missing or repeated")
    step = steps[0]
    require(step["name"] == "Run cargo test --all-features" and step["status"] == "completed" and step["conclusion"] == "success",
            "selected host test step differs")
    workflow = (directory / "raw/host-workflow.yml").read_text()
    require("      - run: cargo test --all-features\n" in workflow, "workflow test command differs")
    regression = (directory / "raw/regression.rs").read_text()
    require("dsse::verify(&envelope, &[&verifier], 1)" in regression and
            "fn a_bad_entry_cannot_hide_a_valid_signature()" in regression and
            "fn a_key_id_hint_cannot_hide_a_valid_signature()" in regression,
            "retained regression source differs")
    contribution = json.loads((directory / "raw/contribution-pr.json").read_text())
    require(contribution["number"] == 149 and contribution["merged"] is True and
            contribution["base"]["repo"]["full_name"] == "jdx/packslip" and
            contribution["user"]["login"] == "astrogilda" and contribution["merged_by"]["login"] == "jdx",
            "contribution author or host attribution differs")
    reverse = json.loads((directory / "raw/reverse-dependencies.json").read_text())
    versions = [v for v in reverse["versions"] if v["crate"] == "packslip" and v["num"] == "1.7.0"]
    require(len(versions) == 1, "published host package version is missing or repeated")
    version = versions[0]
    require(version["trustpub_data"]["sha"] == SOURCE and version["trustpub_data"]["repository"] == "jdx/packslip",
            "published host package source differs")
    dependencies = [d for d in reverse["dependencies"] if d["version_id"] == version["id"] and d["crate_id"] == "dsse"]
    require(len(dependencies) == 1 and dependencies[0]["kind"] == "dev" and dependencies[0]["req"] == "^0.1.1",
            "published development dependency differs")
    provenance = json.loads((directory / "provenance.json").read_text())
    require(set(provenance) == {"captureTime", "sourceType", "sourceCommit", "sources", "numericNativeExit", "rawNativeOutputRetained", "limit"},
            "provenance fields differ")
    require(provenance["captureTime"] == CAPTURE_TIME and provenance["sourceCommit"] == SOURCE and
            provenance["sourceType"] == "retained-public-source-responses", "capture identity differs")
    require(provenance["sources"] == [{"path": path, "url": URLS[path], "sha256": digest} for path, digest in PINS.items()],
            "provenance source pins differ")
    require(provenance["limit"] == "Historical provider step conclusion and published development dependency only; this reader repeats no host test and establishes no independent authorship, recurrence, production effect or payment.",
            "provenance scope differs")
    require(provenance["numericNativeExit"] is None and provenance["rawNativeOutputRetained"] is False,
            "native output availability was changed")
    return {
        "question": "Did the pinned Packslip host CI execute its DSSE regression suite, and did published Packslip 1.7.0 declare dsse as a development dependency?",
        "evidenceClass": "host-project-ci-dependency",
        "captureTime": provenance["captureTime"],
        "hostCI": {"repository": "jdx/packslip", "source": job["head_sha"], "jobID": job["id"], "runID": job["run_id"],
                   "jobConclusion": job["conclusion"], "completedAt": job["completed_at"], "cargoTestAllFeatures": step,
                   "numericNativeExit": None,
                   "numericNativeExitLimit": "GitHub retained job/step metadata reports success; numeric native exit and raw process stdout/stderr are not retained by this packet."},
        "publishedDependency": {"hostPackage": version["crate"], "hostVersion": version["num"], "dependency": dependencies[0]["crate_id"],
                                "requirement": dependencies[0]["req"], "kind": dependencies[0]["kind"], "sourceCommit": version["trustpub_data"]["sha"]},
        "contribution": {"pullRequest": contribution["html_url"], "author": contribution["user"]["login"], "merged": contribution["merged"],
                         "mergedAt": contribution["merged_at"], "hostMaintainer": contribution["merged_by"]["login"]},
    }


def validate(directory: Path | None = None) -> None:
    """Refuse edited sources, provenance, reports or unsupported native results."""
    directory = Path(__file__).resolve().parent if directory is None else directory
    expected = derive(directory)
    actual = json.loads((directory / "report.json").read_text())
    require(actual == expected, "report differs from retained host metadata")


if __name__ == "__main__":
    validate()
    print("retained Packslip host-step/development-dependency metadata matches")
