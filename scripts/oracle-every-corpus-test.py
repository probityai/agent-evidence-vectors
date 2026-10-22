#!/usr/bin/env python3
"""A perfect verifier must score a perfect run on every corpus that runs one.

``scripts/oracle-verifier.py`` answers every member exactly as its MANIFEST
declares. Driven through ``packaging/run_vectors.py`` it must draw, on every
corpus with an external-verifier contract, exit 0, zero failures and zero
suite-level refusals, under each reading a family may take. On every corpus
without such a contract it must be refused by name with exit 2 and no report,
never scored. Anything else is a defect in the harness or in a corpus: before
this test, the AI Agent Action corpus failed this oracle on four refusals about
the harness's own bookkeeping, so every implementer wiring the Action to it got
``result: fail`` whatever their verifier did.

Three controls keep the green run meaningful. A verifier that answers nothing
useful must fail the same corpus. A member-named file dropped outside the
directory a MANIFEST replays must still be refused. And the reference suite
must still require every kind this rail scores.

Every corpus directory in the tree must be named below as one or the other, so
a new corpus fails this test until somebody decides which it is.

    python3 scripts/oracle-every-corpus-test.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "packaging" / "run_vectors.py"
ORACLE = f"{sys.executable} {ROOT / 'scripts' / 'oracle-verifier.py'}"

#: Corpora a named verifier runs over, through the generic contract or the
#: contract the corpus writes for itself.
RUNS_A_VERIFIER = (
    "vectors",
    "vectors-a2a-jcs-v01",
    "vectors-agent-change-admission",
    "vectors-agentic-process-evidence",
    "vectors-admission",
    "vectors-ai-agent-action",
    "vectors-anchored-chain",
    "vectors-approval-binding",
    "vectors-authority-at-dispatch",
    "vectors-chunked-export",
    "vectors-grade-floor",
    "vectors-identity-binding",
    "vectors-receipt-chain-end",
    "vectors-receipt-signature",
    "vectors-scitt-cose",
    "vectors-source-coverage",
    "vectors-trace-anchor",
)

#: Corpora judged only by a reader of their own (``aee-verify <dir>`` or this
#: package's), whose expectations the external contract cannot carry.
REFUSES_A_VERIFIER = (
    "vectors-aci",
    "vectors-acs-core",
    "vectors-agent-audit-record",
    "vectors-agent-decision",
    "vectors-ai-generation",
    "vectors-anchor-stream",
    "vectors-artifact-binding",
    "vectors-delegation-lifecycle",
    "vectors-dependency-selection",
    "vectors-done-contract",
    "vectors-done-receipt",
    "vectors-spoofed-tool-output",
    "vectors-test-tampering",
    "vectors-grader-isolation",
    "vectors-done-probes",

    "vectors-ietf-agent-record-drafts",
    "vectors-mcp-owasp",
    "vectors-mcp-record-contract",
    "vectors-mcp-response-phase",
    "vectors-observed-effect",
    "vectors-self-reported-record",
    "vectors-w3c-report",
    "vectors-w3c-intake",
)

READINGS = ("condition", "accept")


def harness(corpus_dir: Path, verifier: str, report: Path, reading: str) -> tuple[int, str]:
    env = dict(os.environ)
    env["ORACLE_READING"] = reading
    proc = subprocess.run(
        [
            sys.executable,
            str(HARNESS),
            "--vectors",
            str(corpus_dir),
            "--verifier",
            verifier,
            "--report",
            str(report),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=1800,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def totals(report: Path) -> dict[str, int]:
    data = json.loads(report.read_text(encoding="utf-8"))
    return dict(data.get("totals") or {})


def check_every_corpus_is_classified() -> list[str]:
    on_disk = sorted(
        p.name
        for p in ROOT.iterdir()
        if p.is_dir()
        and (p.name == "vectors" or p.name.startswith("vectors-"))
        and (p / "MANIFEST.json").is_file()
    )
    named = set(RUNS_A_VERIFIER) | set(REFUSES_A_VERIFIER)
    return [f"{name}: not classified in this test" for name in on_disk if name not in named] + [
        f"{name}: classified here and not in the tree" for name in sorted(named - set(on_disk))
    ]


def check_perfect_runs(work: Path) -> list[str]:
    failures: list[str] = []
    for name in RUNS_A_VERIFIER:
        for reading in READINGS:
            report = work / f"{name}-{reading}.json"
            code, out = harness(ROOT / name, ORACLE, report, reading)
            if code != 0:
                failures.append(f"{name} ({reading}): exit {code}, want 0\n{out[-1500:]}")
                continue
            t = totals(report)
            bad = {k: t.get(k) for k in ("fail", "suiteRefusals") if t.get(k)}
            if bad:
                failures.append(f"{name} ({reading}): {bad}")
            print(f"PASS {name} ({reading}): exit 0, {t.get('vectors')} vectors, no refusal")
    return failures


def check_refusals(work: Path) -> list[str]:
    failures: list[str] = []
    for name in REFUSES_A_VERIFIER:
        report = work / f"{name}.json"
        code, out = harness(ROOT / name, ORACLE, report, "condition")
        if code != 2 or "did NOT run" not in out or report.exists():
            failures.append(
                f"{name}: exit {code}, report written {report.exists()}; want exit 2, "
                f"a named refusal and no report\n{out[-800:]}"
            )
            continue
        print(f"PASS {name}: refused by name, exit 2, nothing scored")
    return failures


def check_controls(work: Path) -> list[str]:
    failures: list[str] = []
    aia = work / "aia"
    shutil.copytree(ROOT / "vectors-ai-agent-action", aia)

    silent = work / "silent.sh"
    silent.write_text("#!/bin/sh\necho '{\"codes\":[]}'\nexit 0\n", encoding="utf-8")
    silent.chmod(0o755)
    code, _ = harness(aia, str(silent), work / "silent.json", "condition")
    if code != 1:
        failures.append(
            f"a verifier answering nothing scored exit {code} on the AI Agent Action corpus"
        )
    else:
        print("PASS control: a verifier answering nothing fails")

    first = json.loads((aia / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"][0]["id"]
    stray = aia / "attacks" / f"{first}.cbor"
    shutil.copy(aia / "statements" / f"{first}.json", stray)
    code, out = harness(aia, ORACLE, work / "stray.json", "condition")
    if code != 1 or "attacks/ holds 1 file(s) named like a corpus member" not in out + (
        (work / "stray.json").read_text(encoding="utf-8") if (work / "stray.json").exists() else ""
    ):
        failures.append(
            f"a member file outside the replayed directory was not refused (exit {code})"
        )
    else:
        print("PASS control: a member file outside the replayed directory is refused")
    stray.unlink()

    sys.path.insert(0, str(HARNESS.parent))
    import run_vectors as rv  # noqa: PLC0415 -- the harness is loaded by path, as every gate here does

    refusals = rv._closure_kind_coverage({"accept": ["a"], "reject": ["b"]}, rv.REPLAYED_KINDS)
    if not any("'indeterminate'" in r for r in refusals):
        failures.append("the reference suite no longer requires every kind this rail scores")
    else:
        print("PASS control: the reference suite still requires every kind it scores")
    return failures


def main() -> int:
    failures = check_every_corpus_is_classified()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        failures += check_perfect_runs(work)
        failures += check_refusals(work)
        failures += check_controls(work)
    for f in failures:
        print(f"FAIL {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
