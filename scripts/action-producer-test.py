#!/usr/bin/env python3
"""Producer mode reads what a project emits, holds it to its pins, and never
passes a run that checked nothing.

Why this file exists
--------------------
The corpus modes test a reader. A project that only writes records has no
reader to hand over, so producer mode reads its output with the pinned reader
for the record class and writes a receipt naming that reader. These cases build
records from the published corpora (a conforming and a rejected v0.1 report, a
re-checkable and a non-re-checkable run record), run the command line the
action runs, and check the exit code and the receipt. They also read action.yml
as YAML: producer mode's steps exist, are keyed on `records`, and the corpus
replay is switched off when `records` is named. The last case makes the reader
call every record conforming in a copy of the module and requires the
rejection case to go red against the copy.

Usage: python3 scripts/action-producer-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "packaging"
MODULE = PACKAGING / "agent_evidence_vectors" / "producer.py"
W3C = ROOT / "corpora" / "vectors-w3c-report"
MRC = ROOT / "corpora" / "vectors-mcp-record-contract"


def w3c_subjects() -> tuple[dict[str, Any], dict[str, Any]]:
    """A report the reader accepts with nothing to resolve against, and one it rejects.

    A producer's own report reaches the reader with no observation store, so
    the cases are chosen by what the reader says of the subject alone.
    """
    sys.path.insert(0, str(PACKAGING))
    from agent_evidence_vectors import w3creport

    manifest = json.loads((W3C / "MANIFEST.json").read_text(encoding="utf-8"))
    accept = reject = None
    for entry in manifest["vectors"]:
        if entry.get("subjectType") != "report":
            continue
        raw = (W3C / entry["file"]).read_bytes()
        subject = w3creport.load_json(raw)["subject"]
        lines = w3creport.verdict_lines(subject)
        if accept is None and entry["kind"] == "accept" and lines == ["conforms"]:
            accept = json.loads(raw)["subject"]
        if reject is None and entry["kind"] == "reject" and lines != ["conforms"]:
            reject = json.loads(raw)["subject"]
    assert accept is not None and reject is not None, "the corpus lost a case this test needs"
    return accept, reject


def run_records() -> tuple[Path, Path]:
    """A re-checkable run record and one the criterion refuses."""
    manifest = json.loads((MRC / "MANIFEST.json").read_text(encoding="utf-8"))
    good = bad = None
    for entry in manifest["vectors"]:
        exp = entry["expected"]
        declared = exp["independence"] != "undeclared"
        ok = exp["recheckable"] and exp["figureMeansWhatItSays"] and declared
        if ok and good is None:
            good = MRC / entry["record"]
        if not ok and bad is None:
            bad = MRC / entry["record"]
    assert good is not None and bad is not None, "the corpus lost a case this test needs"
    return good, bad


def produced(
    cwd: Path, *args: str, module: Path = MODULE
) -> tuple[int, dict[str, Any] | None, str]:
    receipt = cwd / "receipt.json"
    if receipt.exists():
        receipt.unlink()
    env = dict(os.environ, PYTHONPATH=str(module.parent.parent))
    env.pop("GITHUB_OUTPUT", None)
    env.pop("GITHUB_STEP_SUMMARY", None)
    proc = subprocess.run(
        [sys.executable, str(module), *args, "--receipt", str(receipt)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    data = json.loads(receipt.read_text(encoding="utf-8")) if receipt.exists() else None
    return proc.returncode, data, proc.stdout + proc.stderr


def write(path: Path, value: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path


def setup(work: Path) -> dict[str, Path]:
    accept, reject = w3c_subjects()
    good, bad = run_records()
    out = {
        "accept": write(work / "out" / "report.json", accept),
        "reject": write(work / "bad" / "report.json", reject),
        "good_run": work / "runs" / "good.json",
        "bad_run": work / "runs-bad" / "bad.json",
    }
    out["good_run"].parent.mkdir(parents=True)
    out["bad_run"].parent.mkdir(parents=True)
    shutil.copy(good, out["good_run"])
    shutil.copy(bad, out["bad_run"])
    (work / "junk").mkdir()
    (work / "junk" / "x.json").write_text("{not json", encoding="utf-8")
    return out


def pin_for(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    report = json.loads(raw)
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "count": len(report["checks"]),
        "checkSetRoot": report["check-set"]["sha256"],
    }


@dataclass(frozen=True)
class Ctx:
    """The scratch directory every case runs in, and the records set up there."""

    work: Path
    paths: dict[str, Path]


Case = Callable[[Ctx], str | None]


def case_conforming(ctx: Ctx) -> str | None:
    work, p = ctx.work, ctx.paths
    code, receipt, log = produced(work, "w3c-report", "out/*.json")
    if code != 0 or receipt is None or receipt["result"] != "pass":
        return f"a conforming report did not pass: exit {code}\n{log}"
    ref = receipt["reference"]["verifier"]["id"]
    prefix, suffix = "pkg:pypi/agent-evidence-vectors@", "#reader/w3c-report"
    if not ref.startswith(prefix) or not ref.endswith(suffix):
        return f"reference.verifier.id is {ref!r}"
    entry = receipt["records"][0]
    if entry["sha256"] != hashlib.sha256(p["accept"].read_bytes()).hexdigest():
        return "the receipt's digest is not the record's"
    return None


def case_rejected(ctx: Ctx, module: Path = MODULE) -> str | None:
    work = ctx.work
    code, receipt, log = produced(work, "w3c-report", "bad/report.json", module=module)
    if code != 1 or receipt is None or receipt["result"] != "fail":
        return f"a rejected report did not fail with exit 1: exit {code}\n{log}"
    findings = receipt["records"][0]["findings"]
    if not findings or not any(f.startswith(("W3C-R-", "shape:")) for f in findings):
        return f"the findings name no row: {findings}"
    return None


def case_nothing_matched(ctx: Ctx) -> str | None:
    work = ctx.work
    code, receipt, _ = produced(work, "w3c-report", "nowhere/*.json")
    if code != 2 or receipt is None or receipt["result"] != "no-verdict":
        return f"a run that read nothing exited {code}"
    return None


def case_unknown_class(ctx: Ctx) -> str | None:
    work = ctx.work
    code, _, _ = produced(work, "not-a-class", "out/*.json")
    return None if code == 2 else f"an unknown class exited {code}"


def case_unreadable(ctx: Ctx) -> str | None:
    work = ctx.work
    code, receipt, _ = produced(work, "w3c-report", "junk/x.json")
    if code != 2 or receipt is None or receipt["records"][0]["verdict"] != "no-verdict":
        return f"a file that is not JSON exited {code}, not a no-verdict"
    return None


def case_pins(ctx: Ctx) -> str | None:
    work, p = ctx.work, ctx.paths
    good = write(work / "pins.json", {"records": {"out/report.json": pin_for(p["accept"])}})
    code, _, log = produced(work, "w3c-report", "out/*.json", "--pins", str(good))
    if code != 0:
        return f"matching pins did not pass: exit {code}\n{log}"
    for label, pins in (
        ("a wrong digest", {"out/report.json": {**pin_for(p["accept"]), "sha256": "0" * 64}}),
        ("a wrong count", {"out/report.json": {**pin_for(p["accept"]), "count": -1}}),
        (
            "a pinned record never produced",
            {"out/report.json": pin_for(p["accept"]), "out/missing.json": {"size": 1}},
        ),
        ("a produced record never pinned", {}),
    ):
        path = write(work / "pins-bad.json", {"records": pins})
        code, receipt, _ = produced(work, "w3c-report", "out/*.json", "--pins", str(path))
        if code != 1 or receipt is None or not receipt["totals"]["pinMismatches"]:
            return f"{label} was not a mismatch: exit {code}"
    bad = work / "pins-broken.json"
    bad.write_text("[]", encoding="utf-8")
    code, _, _ = produced(work, "w3c-report", "out/*.json", "--pins", str(bad))
    return None if code == 2 else f"a malformed pins file exited {code}"


def case_flat_pins(ctx: Ctx) -> str | None:
    """A producer's own EXPECTED.json, handed over as it is, pins its one record."""
    work, p = ctx.work, ctx.paths
    raw = p["accept"].read_bytes()
    report = json.loads(raw)
    expected = {
        "check-set-sha256": report["check-set"]["sha256"],
        "declared": report["roll-up"]["declared"],
        "report-bytes": len(raw),
        "report-sha256": hashlib.sha256(raw).hexdigest(),
    }
    good = write(work / "EXPECTED.json", expected)
    code, _, log = produced(work, "w3c-report", "out/*.json", "--pins", str(good))
    if code != 0:
        return f"a matching EXPECTED.json did not pass: exit {code}\n{log}"
    for key, wrong in (
        ("report-sha256", "0" * 64),
        ("report-bytes", -1),
        ("declared", -1),
        ("check-set-sha256", "0" * 64),
    ):
        path = write(work / "EXPECTED-bad.json", {**expected, key: wrong})
        code, receipt, _ = produced(work, "w3c-report", "out/*.json", "--pins", str(path))
        if code != 1 or receipt is None or not receipt["totals"]["pinMismatches"]:
            return f"a wrong {key} in EXPECTED.json was not a mismatch: exit {code}"
    code, receipt, _ = produced(work, "w3c-report", "out/*.json", "bad/*.json", "--pins", str(good))
    if code != 1:
        return f"one flat pin over two records exited {code}, not a mismatch"
    return None


def case_run_records(ctx: Ctx) -> str | None:
    work = ctx.work
    code, receipt, log = produced(work, "run-record", "runs/*.json")
    if code != 0 or receipt is None:
        return f"a re-checkable run record did not pass: exit {code}\n{log}"
    code, _, log = produced(work, "run-record", "runs-bad/*.json")
    return None if code == 1 else f"a refused run record exited {code}\n{log}"


def case_action_yaml(ctx: Ctx) -> str | None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    for name in ("records", "record-class", "producer", "pins", "receipt-path"):
        if name not in action["inputs"]:
            return f"action.yml has no `{name}` input"
    steps = {s.get("name"): s for s in action["runs"]["steps"]}
    produced_step = steps.get("Check the produced records")
    if produced_step is None or "inputs.records != ''" not in produced_step["if"]:
        return "the produced-records step is missing or not keyed on `records`"
    if "agent-evidence-vectors produced" not in produced_step["run"]:
        return "the produced-records step does not run the package's command"
    fail = steps.get("Fail the job when a produced record did not pass")
    if fail is None or "steps.produced.outputs.result != 'pass'" not in fail["if"]:
        return "no step fails the job on a producer result other than pass"
    replay = steps.get("Replay the corpus")
    if replay is None or "inputs.records == ''" not in replay["if"]:
        return "the corpus replay still runs when `records` is named"
    for out in ("result", "reference-verifier-id", "report"):
        if "steps.produced.outputs" not in action["outputs"][out]["value"]:
            return f"the `{out}` output does not carry producer mode"
    return None


def case_goes_red(ctx: Ctx) -> str | None:
    work = ctx.work
    copy = work / "mutant" / "agent_evidence_vectors"
    shutil.copytree(MODULE.parent, copy)
    text = (copy / "producer.py").read_text(encoding="utf-8")
    needle = 'entry["verdict"] = CONFORMS if not findings else DOES_NOT_CONFORM'
    if needle not in text:
        return "the verdict line moved; update the mutation"
    (copy / "producer.py").write_text(
        text.replace(needle, 'entry["verdict"] = CONFORMS'), encoding="utf-8"
    )
    if case_rejected(ctx, module=copy / "producer.py") is None:
        return "the rejection case stayed green against a reader that passes everything"
    return None


CASES: dict[str, Case] = {
    "a conforming report passes and names its reader": case_conforming,
    "a rejected report fails with its row": case_rejected,
    "a run that read nothing is no verdict": case_nothing_matched,
    "an unknown record class is no verdict": case_unknown_class,
    "a file that is not JSON is no verdict": case_unreadable,
    "pins hold, and every kind of mismatch fails": case_pins,
    "an EXPECTED.json pins the one record it describes": case_flat_pins,
    "run records are read by the criterion": case_run_records,
    "action.yml wires producer mode": case_action_yaml,
    "the rejection case goes red against a mutant": case_goes_red,
}


def main() -> int:
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        paths = setup(work)
        for label, case in CASES.items():
            problem = case(Ctx(work, paths))
            print(f"{'ok  ' if problem is None else 'FAIL'} {label}")
            if problem is not None:
                failed += 1
                print(f"     {problem}")
    print(f"{len(CASES) - failed} of {len(CASES)} cases behave as described")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
