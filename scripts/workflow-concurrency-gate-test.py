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
    # Rule 5, the 24 Nov 2026 batch: 3 systems x 8 row groups asked for 8 macOS jobs.
    fan = (
        "  m:\n    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n"
        "        os: [ubuntu-24.04, macos-15]\n        rows: [a, b, c, d, e, f]\n    steps: []\n"
    )
    r = fixture({**base(), "mac.yml": GOOD.split("jobs:")[0] + "jobs:\n" + fan})
    assert r.returncode == 1 and "mac.yml: 6 macOS jobs in one run" in r.stdout, r.stdout
    head = GOOD.split("jobs:")[0] + "jobs:\n"
    rows = "        rows: [a, b, c, d, e, f]\n"
    # One macOS leg that takes every row, added by include, is one job.
    one = fan.replace("[ubuntu-24.04, macos-15]", "[ubuntu-24.04]")
    one = one.replace(
        rows, rows + "        include:\n          - os: macos-15\n            rows: all\n"
    )
    assert fixture({**base(), "mac.yml": head + one}).returncode == 0
    # An exclude removes a leg: five macOS jobs is the whole free allowance and passes.
    cut = fan.replace(
        rows, rows + "        exclude:\n          - os: macos-15\n            rows: a\n"
    )
    assert fixture({**base(), "mac.yml": head + cut}).returncode == 0
    # An exclude or include that GitHub resolves at run time adds and removes nothing the gate
    # can count: the literal axes still decide, and nothing in the gate crashes on the text.
    lazy = fan.replace(
        rows,
        rows + "        exclude: ${{ fromJSON(needs.go.outputs.skip) }}\n"
        "        include: ${{ fromJSON(needs.go.outputs.extra) }}\n",
    )
    r = fixture({**base(), "mac.yml": head + lazy})
    assert r.returncode == 1 and "mac.yml: 6 macOS jobs in one run" in r.stdout, r.stdout
    assert (
        fixture({**base(), "mac.yml": head + lazy.replace("macos-15", "ubuntu-22.04")}).returncode
        == 0
    )
    # A list entry that is not a mapping is no leg either.
    bare = fan.replace(rows, rows + "        include: [skip]\n")
    r = fixture({**base(), "mac.yml": head + bare})
    assert r.returncode == 1 and "mac.yml: 6 macOS jobs in one run" in r.stdout, r.stdout
    assert fixture({}).returncode == 2
    print("workflow-concurrency-gate-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
