"""Retain one locked source gate and actual-process reads of the external pair."""

import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    python = str(root / ".venv/bin/python")
    if Path(sys.executable).absolute() != Path(python).absolute():
        raise ValueError("qualification must use this project's Python environment")
    output = root / "gate-results"
    output.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = str(root / ".venv/bin") + os.pathsep + env["PATH"]
    env["TERM"] = "dumb"
    checks = [
        ("lock", ["uv", "lock", "--check"], 0),
        ("lint", [python, "-m", "ruff", "check", "witness_case", "tests", "scripts/qualify.py"], 0),
        (
            "format",
            [
                python,
                "-m",
                "ruff",
                "format",
                "--check",
                "witness_case",
                "tests",
                "scripts/qualify.py",
            ],
            0,
        ),
        ("readme", [python, "scripts/readme-lint.py"], 0),
        (
            "per-file-coverage",
            [
                python,
                "scripts/check_coverage.py",
                "--src-dir",
                "witness_case",
                "--test-path",
                "tests",
                "--json",
            ],
            0,
        ),
        (
            "coverage-json",
            [python, "-m", "coverage", "json", "-o", "gate-results/coverage.json"],
            0,
        ),
    ]
    pins = json.loads((root / "fixtures/pins.json").read_text())
    for name, target, expected in [
        ("a", "https://gate.horizonshield.dev/a2a", 0),
        ("b", "https://gate.horizonshield.dev/a2a", 1),
        ("a", "https://gate.horizonshield.dev/a2a/", 1),
        ("b", "https://gate.horizonshield.dev/a2a/", 1),
    ]:
        pin = pins[name]
        argv = [
            python,
            "-m",
            "witness_case.reader",
            str(root / "fixtures" / pin["envelope_file"]),
            str(root / "fixtures" / pin["key_file"]),
        ]
        for key in ("record_sha256", "key_document_sha256", "key_url"):
            argv += ["--" + key.replace("_", "-"), pin[key]]
        argv += [
            "--target",
            target,
            "--operator",
            "Probity Codex / ordinary shared BoxPool author-run",
        ]
        checks.append(
            ("pair-" + name + "-" + ("slash" if target.endswith("/") else "a2a"), argv, expected)
        )
    results = []
    for name, argv, expected in checks:
        print("STEP", name, flush=True)
        with (
            (output / (name + ".stdout")).open("wb") as stdout,
            (output / (name + ".stderr")).open("wb") as stderr,
        ):
            process = subprocess.run(
                argv, env=env, stdout=stdout, stderr=stderr, timeout=900, check=False
            )
        result = {
            "step": name,
            "argv": argv,
            "actual_exit": process.returncode,
            "expected_exit": expected,
            "matched": process.returncode == expected,
        }
        if name.startswith("pair-") and result["matched"]:
            comparison = json.loads((output / (name + ".stdout")).read_text())
            expected_outcome = "MATCHING_SIGNED_OBSERVATION" if expected == 0 else "TARGET_MISMATCH"
            result["matched"] = (
                comparison["outcome"] == expected_outcome
                and comparison["signature_verified_under_pinned_key"] is True
            )
        results.append(result)
        (output / "steps.json").write_text(json.dumps(results, indent=2) + "\n")
        if not result["matched"]:
            return (
                process.returncode if process.returncode and process.returncode != expected else 1
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
