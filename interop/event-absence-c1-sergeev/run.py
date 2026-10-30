"""Run Mikhail Sergeev's three C1 absence cases through probity-verify and
compare the decisions with EXPECTED.json.

    uv run --no-project --with probity-verify==0.2.2 python interop/event-absence-c1-sergeev/run.py

Every input file is checked against MANIFEST.json (length and SHA-256) before
any case runs, and the expected decisions are read only after the verifier has
answered.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCOPES = ("PEER", "EXTERNAL")


def check_inputs() -> list[str]:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    problems = []
    for rel, pinned in manifest["files"].items():
        with open(os.path.join(HERE, "source", rel), "rb") as fh:
            body = fh.read()
        if len(body) != pinned["length"] or hashlib.sha256(body).hexdigest() != pinned["sha256"]:
            problems.append(f"{rel}: bytes differ from the pinned length or hash")
    return problems


def decide(case: str, scope: str) -> dict[str, str]:
    base = os.path.join(HERE, "source", "probity", "cases", case)
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "probity_verify.cli",
            os.path.join(base, "case.json"),
            "--policy",
            os.path.join(base, "policy.json"),
            "--require-witness-scope",
            scope,
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise SystemExit(f"{case} {scope}: the verifier exited {done.returncode}: {done.stderr}")
    out = json.loads(done.stdout)
    return {"decision": out["decision"], "reason": out["reason"]}


def _cases() -> list[str]:
    return sorted(os.listdir(os.path.join(HERE, "source", "probity", "cases")))


def main() -> int:
    problems = check_inputs()
    if problems:
        print("\n".join(problems))
        return 1
    got = {case: {scope: decide(case, scope) for scope in SCOPES} for case in _cases()}
    with open(os.path.join(HERE, "EXPECTED.json"), encoding="utf-8") as fh:
        expected = json.load(fh)["cases"]
    bad = [
        f"{case} {scope}: expected {expected[case][scope]}, got {got[case][scope]}"
        for case in got
        for scope in SCOPES
        if got[case][scope] != expected[case][scope]
    ]
    for line in bad:
        print("FAIL", line)
    print(f"cases: {len(got)} x {len(SCOPES)} scopes, {len(bad)} disagree")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
