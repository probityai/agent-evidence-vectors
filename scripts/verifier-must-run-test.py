#!/usr/bin/env python3
"""A verifier named on the command line is the verifier that runs, or nothing passes.

Why this file exists
--------------------
Until this test existed, ``--verifier`` was a request the harness could decline
without saying so in any way a caller acted on. It probed the first token of the
command line for the predicate type URI, and when the probe failed it ran the
corpus on its own reference rail instead, printed ``272 vectors, 272 pass`` and
exited 0. The probe failed for a verifier that rejects everything, for a file
that is not executable, for a path that does not exist, and for every command
resolved through PATH, because it tested ``os.path.isfile`` on the bare name.
The composite action fails the job on the exit status alone, so a consumer's
workflow went green on a verifier that was never started.

So every case below names a verifier and then asks what the harness did with
it. A case that only checked the exit status would pass against a harness that
refused for an unrelated reason, so each also reads the report or the output for
the fact it is about: which rail ran, how many vectors the named verifier
answered, and the words that tell a reader it did not run.

The last case restores the fallback in a copy of the harness and requires this
file to go red against the copy. A test that stays green under the defect it was
written for is not evidence about that defect.

Usage: python3 scripts/verifier-must-run-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS = REPO_ROOT / "vectors"
SUMMARY = REPO_ROOT / "scripts" / "action-summary.py"
DID_NOT_RUN = "did NOT run"

# The harness under test. The mutation case points this at a copy.
HARNESS = Path(os.environ.get("AEV_HARNESS_UNDER_TEST", REPO_ROOT / "packaging" / "run_vectors.py"))

# The anchor the mutation case rewrites, and what it rewrites it to. The anchor
# is asserted present before the rewrite, so a refactor that moves it turns the
# mutation case red instead of letting it rewrite nothing and pass.
MUTATION_ANCHOR = "        raise VerifierNotRun(reason) from None\n"
MUTATION_FALLBACK = "        return None, f\"{reason}; using the reference rail\"\n"


def manifest_count() -> int:
    manifest = json.loads((VECTORS / "MANIFEST.json").read_text(encoding="utf-8"))
    return len(manifest["vectors"])


def write_script(work: Path, name: str, body: str, executable: bool = True) -> Path:
    """A verifier as a shell script that does NOT carry the predicate type URI."""
    path = work / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755 if executable else 0o644)
    return path


class Run:
    def __init__(self, code: int, out: str, report: dict[str, Any] | None) -> None:
        self.code = code
        self.out = out
        self.report = report


def harness(
    work: Path, verifier: str | None, *extra: str, env: dict[str, str] | None = None
) -> Run:
    report_path = work / "report.json"
    report_path.unlink(missing_ok=True)
    argv = [sys.executable, str(HARNESS), "--report", str(report_path), *extra]
    if "--corpus" not in extra:
        argv += ["--vectors", str(VECTORS)]
    if verifier is not None:
        argv += ["--verifier", verifier]
    child_env = dict(os.environ)
    child_env.pop("AEE_EXTERNAL_VERIFIER", None)
    child_env.update(env or {})
    proc = subprocess.run(
        argv, cwd=work, capture_output=True, text=True, timeout=1800, check=False, env=child_env
    )
    report = None
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    return Run(proc.returncode, proc.stdout + proc.stderr, report)


def refused(label: str, run: Run) -> list[str]:
    """The harness must say the verifier did not run, exit 2, and claim nothing."""
    errors: list[str] = []
    if run.code != 2:
        errors.append(f"{label}: exit {run.code}, expected 2 (the verifier did not run)")
    if DID_NOT_RUN not in run.out:
        errors.append(f"{label}: the output never says the verifier {DID_NOT_RUN}")
    if run.report is not None:
        errors.append(f"{label}: a report was written for a run whose verifier never started")
    if " pass, 0 fail" in run.out:
        errors.append(f"{label}: the output prints a clean pass: {run.out[-300:]!r}")
    return errors


def ran_external(label: str, run: Run, total: int) -> list[str]:
    """The named verifier ran on every vector, and the report says so."""
    if run.report is None:
        return [f"{label}: no report was written (exit {run.code}): {run.out[-400:]!r}"]
    errors: list[str] = []
    if run.report.get("rail") != "external":
        errors.append(f"{label}: rail {run.report.get('rail')!r}, expected 'external'")
    executed = (run.report.get("verifier") or {}).get("vectorsExecuted")
    if executed != total:
        errors.append(f"{label}: vectorsExecuted {executed!r}, expected {total}")
    if f"ran on {total} of {total} vectors" not in run.out:
        errors.append(f"{label}: the output does not state the executed count")
    return errors


def case_rejects_everything_without_the_uri(work: Path) -> list[str]:
    total = manifest_count()
    rail = write_script(work, "fail-all", "exit 1")
    run = harness(work, str(rail))
    errors = ran_external("rejects-everything", run, total)
    if run.code == 0:
        errors.append("rejects-everything: exit 0 for a verifier that rejects every vector")
    return errors


def case_not_executable(work: Path) -> list[str]:
    rail = write_script(work, "not-exec", "exit 0", executable=False)
    return refused("not-executable", harness(work, str(rail)))


def case_does_not_exist(work: Path) -> list[str]:
    return refused("does-not-exist", harness(work, str(work / "no-such-verifier")))


def case_not_on_path(work: Path) -> list[str]:
    return refused("not-on-path", harness(work, "no-such-verifier-on-path --json"))


def case_empty_setting(work: Path) -> list[str]:
    return refused("empty-setting", harness(work, ""))


def case_environment_variable(work: Path) -> list[str]:
    rail = write_script(work, "env-not-exec", "exit 0", executable=False)
    return refused(
        "environment-variable", harness(work, None, env={"AEE_EXTERNAL_VERIFIER": str(rail)})
    )


def case_path_command_runs(work: Path) -> list[str]:
    """A command resolved through PATH runs, and every vector reaches it twice."""
    total = manifest_count()
    log = work / "invocations.log"
    log.unlink(missing_ok=True)
    rail = write_script(work, "counting", f'echo "$1" >> "{log}"\nexit 1')
    run = harness(work, f"sh {rail}")
    errors = ran_external("path-command", run, total)
    calls = log.read_text(encoding="utf-8").splitlines() if log.is_file() else []
    if len(calls) != 2 * total:
        errors.append(
            f"path-command: the verifier was invoked {len(calls)} times, expected "
            f"{2 * total} (every vector under both key policies)"
        )
    return errors


def case_stops_running_partway(work: Path) -> list[str]:
    """A verifier that vanishes partway through is reported with its real count."""
    total = manifest_count()
    counter = work / "count"
    counter.write_text("0", encoding="utf-8")
    body = (
        f'n=$(cat "{counter}"); n=$((n+1)); echo "$n" > "{counter}"\n'
        f'if [ "$n" -ge 20 ]; then rm -f "$0"; fi\nexit 1'
    )
    rail = write_script(work, "vanishes", body)
    run = harness(work, str(rail))
    errors: list[str] = []
    if run.code == 0:
        errors.append("stops-partway: exit 0 for a verifier that ran on a handful of vectors")
    executed = ((run.report or {}).get("verifier") or {}).get("vectorsExecuted")
    if executed != 10:
        errors.append(f"stops-partway: vectorsExecuted {executed!r}, expected 10")
    if f"ran on 10 of {total} vectors" not in run.out:
        errors.append("stops-partway: the output does not state the short count")
    return errors


def case_own_reader_corpora(work: Path) -> list[str]:
    """Corpora judged only by a built-in reader refuse a named verifier."""
    rail = write_script(work, "any", "exit 0")
    errors: list[str] = []
    for corpus in ("vectors-w3c-report", "vectors-observed-effect"):
        errors += refused(f"own-reader {corpus}", harness(work, str(rail), "--corpus", corpus))
    return errors


def case_no_w3c_report_from_a_stale_file(work: Path) -> list[str]:
    """A refused run must not emit a v0.1 report from whatever report was there."""
    stale = work / "report.json"
    out = work / "w3c.json"
    out.unlink(missing_ok=True)
    rail = write_script(work, "not-exec-2", "exit 0", executable=False)
    report_path = work / "report.json"
    argv = [
        sys.executable, str(HARNESS), "--vectors", str(VECTORS), "--verifier", str(rail),
        "--report", str(report_path), "--emit-w3c-report", str(out),
    ]
    stale.write_text(json.dumps({"rail": "reference", "vectors": []}), encoding="utf-8")
    proc = subprocess.run(argv, cwd=work, capture_output=True, text=True, check=False)
    errors: list[str] = []
    if proc.returncode == 0:
        errors.append("w3c-stale: exit 0 for a refused run")
    if out.is_file():
        errors.append("w3c-stale: a v0.1 report was emitted for a run whose verifier never ran")
    return errors


def summarise(work: Path, report: dict[str, Any] | None, status: str) -> dict[str, str]:
    report_path = work / "summary-report.json"
    report_path.unlink(missing_ok=True)
    if report is not None:
        report_path.write_text(json.dumps(report), encoding="utf-8")
    summary = work / "summary.md"
    outputs = work / "outputs.txt"
    for f in (summary, outputs):
        f.write_text("", encoding="utf-8")
    env = dict(os.environ, REPORT=str(report_path), STATUS=status, CORPUS="vectors",
               GITHUB_STEP_SUMMARY=str(summary), GITHUB_OUTPUT=str(outputs))
    subprocess.run([sys.executable, str(SUMMARY)], env=env, check=True, capture_output=True)
    lines = outputs.read_text(encoding="utf-8").splitlines()
    pairs = [ln.split("=", 1) for ln in lines if "=" in ln]
    return dict(pairs)


def synthetic(rail: str, vectors: int, executed: int | None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "rail": rail,
        "railNote": "synthetic",
        "totals": {"vectors": vectors, "pass": vectors, "fail": 0, "conform": vectors,
                   "reasonParityMismatch": 0, "suiteRefusals": 0},
        "vectors": [],
    }
    if executed is not None:
        report["verifier"] = {"command": "x", "vectorsExecuted": executed}
    return report


def case_action_summary(work: Path) -> list[str]:
    """The action's verdict needs the named verifier to have run on every vector."""
    errors: list[str] = []
    checks = [
        ("reference rail, exit 0", synthetic("reference", 272, None), "fail"),
        ("zero executed, exit 0", synthetic("external", 272, 0), "fail"),
        ("short count, exit 0", synthetic("external", 272, 271), "fail"),
        ("zero vectors, exit 0", synthetic("external", 0, 0), "fail"),
        ("full count, exit 0", synthetic("external", 272, 272), "pass"),
        # A report from a harness older than the executed count: the rail field
        # is the only statement about which verifier ran, and it must say external.
        ("older harness, external", synthetic("external", 272, None), "pass"),
    ]
    for label, report, want in checks:
        got = summarise(work, report, "0").get("result")
        if got != want:
            errors.append(f"action-summary {label}: result {got!r}, expected {want!r}")
    if summarise(work, None, "2").get("result") != "fail":
        errors.append("action-summary: no report and exit 2 did not read as fail")
    return errors


def case_mutation_restores_fallback(work: Path) -> list[str]:
    """Restore the fallback in a copy of the harness; this file must go red."""
    if os.environ.get("AEV_HARNESS_UNDER_TEST"):
        return []  # this is the mutated run itself
    copy = work / "mutant"
    shutil.copytree(REPO_ROOT / "packaging", copy / "packaging")
    target = copy / "packaging" / "run_vectors.py"
    source = target.read_text(encoding="utf-8")
    if source.count(MUTATION_ANCHOR) != 1:
        return [
            "mutation: the anchor that raises VerifierNotRun is not present exactly once, "
            "so the mutation would rewrite nothing and prove nothing"
        ]
    target.write_text(source.replace(MUTATION_ANCHOR, MUTATION_FALLBACK), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, __file__, "--core"],
        env=dict(os.environ, AEV_HARNESS_UNDER_TEST=str(target)),
        capture_output=True, text=True, timeout=3600, check=False,
    )
    if proc.returncode == 0:
        return ["mutation: this test stayed GREEN with the silent fallback restored"]
    # Red for the reason under test: a refusal case saw exit 0 where the
    # verifier never started. Red for anything else would prove nothing.
    if "expected 2 (the verifier did not run)" not in proc.stderr:
        return [f"mutation: went red, but not on a refusal case: {proc.stderr[-400:]!r}"]
    return []


CORE: list[Callable[[Path], list[str]]] = [
    case_not_executable,
    case_does_not_exist,
    case_not_on_path,
    case_empty_setting,
    case_environment_variable,
    case_rejects_everything_without_the_uri,
]
FULL: list[Callable[[Path], list[str]]] = [
    *CORE,
    case_path_command_runs,
    case_stops_running_partway,
    case_own_reader_corpora,
    case_no_w3c_report_from_a_stale_file,
    case_action_summary,
    case_mutation_restores_fallback,
]


def main() -> int:
    cases = CORE if "--core" in sys.argv[1:] else FULL
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="aev-verifier-must-run-") as tmp:
        for case in cases:
            errors += case(Path(tmp))
    if errors:
        print(f"FAIL: a named verifier can be reported without running ({len(errors)}):",
              file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(
        "OK: a named verifier runs on every vector or the harness exits non-zero "
        "saying it did not; the report and the action's verdict carry the executed "
        "count; and restoring the fallback turns this test red."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
