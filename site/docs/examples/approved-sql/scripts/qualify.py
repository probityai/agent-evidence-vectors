"""Keep full gate receipts and actual exits for this finite illustration."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    """Run the checked tools in this repository's environment."""
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    results = root / "gate-results"
    results.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = str(root / ".venv/bin") + os.pathsep + env["PATH"]
    env["TERM"] = "dumb"
    python = str(root / ".venv/bin/python")
    steps = [
        ("lock", ["uv", "lock", "--check"]),
        (
            "lint",
            [python, "-m", "ruff", "check", "sql_illustration", "tests", "scripts/qualify.py"],
        ),
        (
            "format",
            [
                python,
                "-m",
                "ruff",
                "format",
                "--check",
                "sql_illustration",
                "tests",
                "scripts/qualify.py",
            ],
        ),
        ("readme", [python, "scripts/readme-lint.py"]),
        ("tests", [python, "-m", "pytest", "--junitxml=gate-results/tests.xml"]),
        (
            "per-file-coverage",
            [
                python,
                "scripts/check_coverage.py",
                "--src-dir",
                "sql_illustration",
                "--test-path",
                "tests",
                "--json",
            ],
        ),
        ("coverage-json", [python, "-m", "coverage", "json", "-o", "gate-results/coverage.json"]),
    ]
    rows = []
    for name, argv in steps:
        print(f"STEP {name}", flush=True)
        with (
            (results / (name + ".stdout")).open("wb") as out,
            (results / (name + ".stderr")).open("wb") as err,
        ):
            run = subprocess.run(argv, stdout=out, stderr=err, env=env, check=False)
        rows.append({"step": name, "argv": argv, "exit": run.returncode})
        (results / "steps.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"STEPRC {name} {run.returncode}", flush=True)
        if run.returncode:
            return run.returncode
    fixture_rows = json.loads((root / "fixtures/manifest.json").read_text())["cases"]
    for index, case in enumerate(fixture_rows):
        name = f"fixture-{index:02}"
        argv = [python, "-m", "sql_illustration.check", case["path"]]
        with (
            (results / (name + ".stdout")).open("wb") as out,
            (results / (name + ".stderr")).open("wb") as err,
        ):
            run = subprocess.run(argv, stdout=out, stderr=err, env=env, check=False)
        actual = json.loads((results / (name + ".stdout")).read_text())
        row = {
            "step": name,
            "fixture": case["path"],
            "exit": run.returncode,
            "expected_exit": case["expected_exit"],
            "result": actual["result"],
        }
        rows.append(row)
        if (
            run.returncode != case["expected_exit"]
            or actual["result"] != case["expected_result"]
            or actual["later_state"] != case["expected_later_state"]
        ):
            (results / "steps.json").write_text(json.dumps(rows, indent=2) + "\n")
            return 1
    (results / "steps.json").write_text(json.dumps(rows, indent=2) + "\n")
    source = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if (
            path.is_file()
            and not set(rel.parts)
            & {".git", ".venv", "__pycache__", "gate-results", ".pytest_cache", ".ruff_cache"}
            and not rel.name.startswith(".coverage")
        ):
            source.append(
                {
                    "path": str(rel),
                    "size": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    (results / "SOURCE-HASHES.json").write_text(json.dumps(source, indent=2) + "\n")
    print("ILLUSTRATION_GATE_PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
