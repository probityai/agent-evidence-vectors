#!/usr/bin/env python3
"""The workflow concurrency gate passes the repository and fails each rule it states."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "workflow-concurrency-gate.py"
REPO_WORKFLOWS = HERE.parent / ".github" / "workflows"

GOOD = """name: x
on:
  pull_request:
  push:
    branches: [main]
concurrency:
  group: x-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  go:
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""


def jobs(*names: str) -> str:
    body = "".join(f"  {n}:\n    runs-on: x\n    steps: []\n" for n in names)
    return GOOD.split("jobs:")[0] + "jobs:\n" + body


AGGREGATOR = (
    "  ci-ok:\n    if: ${{ always() }}\n    needs: [go, python]\n    runs-on: x\n    steps: []\n"
)


def ci(extra: str = AGGREGATOR, merge_group: bool = True) -> str:
    head = GOOD.split("jobs:")[0]
    if merge_group:
        head = head.replace("  push:\n", "  merge_group:\n  push:\n")
    return head + "jobs:\n" + jobs("go", "python").split("jobs:\n")[1] + extra


def fixture(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="wf-conc-") as d:
        for name, text in files.items():
            (Path(d) / name).write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(GATE), "--workflows", d],
            capture_output=True,
            text=True,
            check=False,
        )


def base() -> dict[str, str]:
    return {"ci.yml": ci()}


def main() -> int:
    real = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True, check=False)
    assert real.returncode == 0, real.stdout + real.stderr
    assert fixture(base()).returncode == 0
    extra = "name: e\non: [push]\njobs:\n  a:\n    runs-on: x\n    steps: []\n"
    r = fixture({**base(), "extra.yml": extra})
    assert r.returncode == 1 and "extra.yml: no concurrency" in r.stdout, r.stdout
    cancel = GOOD.replace("${{ github.event_name == 'pull_request' }}", "true")
    r = fixture({**base(), "extra.yml": cancel})
    assert r.returncode == 1 and "unconditionally true" in r.stdout, r.stdout
    filtered = ci().replace("  pull_request:\n", "  pull_request:\n    paths: ['a']\n")
    r = fixture({"ci.yml": filtered})
    assert r.returncode == 1 and "path-filters pull_request" in r.stdout, r.stdout
    r = fixture({"ci.yml": ci().replace("  ci-ok:", "  other:")})
    assert r.returncode == 1 and "no job of that name" in r.stdout, r.stdout
    r = fixture({"ci.yml": ci(AGGREGATOR.replace("${{ always() }}", "${{ success() }}"))})
    assert r.returncode == 1 and "always()" in r.stdout, r.stdout
    r = fixture({"ci.yml": ci(AGGREGATOR.replace("[go, python]", "[go]"))})
    assert r.returncode == 1 and "does not need python" in r.stdout, r.stdout
    r = fixture({"ci.yml": ci(merge_group=False)})
    assert r.returncode == 1 and "does not run on merge_group" in r.stdout, r.stdout
    assert fixture({}).returncode == 2
    print("workflow-concurrency-gate-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
