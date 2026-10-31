"""Retain actual build, example and page checks on the shared runner."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    results = root / "approved-sql-site-results"
    results.mkdir()
    python = str(root / ".venv/bin/python")
    environment = os.environ.copy()
    environment["PATH"] = str(root / ".venv/bin") + os.pathsep + environment["PATH"]
    environment["ATLAS_LAYOUT_EVIDENCE"] = str(results / "public-layout")
    commands = [
        ("witness-tools", ["uv", "sync", "--project", "examples/nenrin-witness-pair", "--frozen", "--group", "dev", "--python", "3.14.7"]),
        ("witness-controls", [str(root / "examples/nenrin-witness-pair/.venv/bin/python"), "examples/nenrin-witness-pair/scripts/qualify.py"]),
        ("e030-tools", ["uv", "sync", "--project", "examples/e030-corrected-wrapper", "--frozen", "--group", "dev", "--python", "3.14.7"]),
        ("e030-controls", [str(root / "examples/e030-corrected-wrapper/.venv/bin/python"), "examples/e030-corrected-wrapper/scripts/qualify.py"]),
        ("example-tools", ["uv", "sync", "--project", "examples/approved-sql", "--frozen", "--group", "dev", "--python", "3.14.7"]),
        ("example-controls", [str(root / "examples/approved-sql/.venv/bin/python"), "examples/approved-sql/scripts/qualify.py"]),
        ("coverage-gate-controls", [python, "-m", "pytest", "-q", "tests/test_coverage_gate.py",
                                    "--junitxml=" + str(results / "coverage-gate-tests.xml")]),
        ("build", [python, "tools/build.py"]),
        ("build-check", [python, "tools/build.py", "--check"]),
        ("links", [python, "tools/check_links.py"]),
        ("lab", [python, "tools/check_lab.py"]),
        ("readme", [python, "scripts/readme-lint.py", "README.md"]),
        ("readme-controls", [python, "scripts/readme-lint-test.py"]),
        ("browser-install", [python, "-m", "playwright", "install", "chromium"]),
        ("site-controls", [python, "-m", "pytest", "-q", "--junitxml=" + str(results / "site-tests.xml"),
                           "tools/discoverability/test_catalog.py", "tests/test_discovery.py", "tests/test_markdown_mirrors.py",
                           "tests/test_run_browser.py", "tests/test_social_metadata.py", "tests/test_public_layout.py",
                           "tests/test_run_browser_layout.py", "tests/test_evidence_article_layout.py"]),
    ]
    rows = []
    for name, argv in commands:
        print(f"STEP {name}", flush=True)
        with (results / (name + ".stdout")).open("wb") as out, (results / (name + ".stderr")).open("wb") as err:
            run = subprocess.run(argv, env=environment, stdout=out, stderr=err, check=False)
        rows.append({"step": name, "argv": argv, "exit": run.returncode})
        (results / "steps.json").write_text(json.dumps(rows, indent=2) + "\n")
        print(f"STEP_EXIT {name} {run.returncode}", flush=True)
        if run.returncode:
            return run.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
