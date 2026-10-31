"""Retain complete qualification output and actual status on the ordinary shared runner."""

import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    """Run exact lock, source, code and per-file coverage checks once."""
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    results = root / "gate-results"
    results.mkdir(exist_ok=True)
    python = str(root / ".venv/bin/python")
    if Path(sys.executable).absolute() != Path(python).absolute():
        raise ValueError("qualification must use this repository's Python environment")
    env = os.environ.copy()
    env["PATH"] = str(root / ".venv/bin") + os.pathsep + env["PATH"]
    env["E030_INPUT_ROOT"] = str(root / ".inputs")
    env["TERM"] = "dumb"
    steps = [
        ("lock", ["uv", "lock", "--check"]),
        ("inputs", [python, "-m", "scripts.fetch_inputs"]),
        (
            "lint",
            [
                python,
                "-m",
                "ruff",
                "check",
                "e030_case",
                "tests",
                "scripts/qualify.py",
                "scripts/fetch_inputs.py",
            ],
        ),
        (
            "format",
            [
                python,
                "-m",
                "ruff",
                "format",
                "--check",
                "e030_case",
                "tests",
                "scripts/qualify.py",
                "scripts/fetch_inputs.py",
            ],
        ),
        ("readme", [python, "scripts/readme-lint.py"]),
        (
            "per-file-coverage",
            [
                python,
                "scripts/check_coverage.py",
                "--src-dir",
                "e030_case",
                "--test-path",
                "tests",
                "--json",
            ],
        ),
        ("coverage-json", [python, "-m", "coverage", "json", "-o", "gate-results/coverage.json"]),
        (
            "demonstration",
            [
                python,
                "-m",
                "e030_case.regression",
                "--operator",
                "Probity Codex / ordinary shared BoxPool author-run",
                str(root / ".inputs/review"),
                str(root / ".inputs/aps"),
                str(root / ".inputs/priorseal"),
                str(results / "demonstration"),
            ],
        ),
    ]
    records = []
    for name, argv in steps:
        print("STEP", name, flush=True)
        with (
            (results / (name + ".stdout")).open("wb") as out,
            (results / (name + ".stderr")).open("wb") as err,
        ):
            process = subprocess.run(
                argv, env=env, stdout=out, stderr=err, check=False, timeout=900
            )
        records.append({"step": name, "argv": argv, "actual_exit": process.returncode})
        (results / "steps.json").write_text(json.dumps(records, indent=2) + "\n")
        if process.returncode:
            return process.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
