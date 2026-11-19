"""Run the D1 and L1 cases through event_absence/v2 and compare with EXPECTED.json.

    uv run --no-project --python 3.13 --with agent-evidence-verify==0.5.1 \
        python interop/adjudication-disagreement-d1/run.py [--out DIR]

Every input is checked against MANIFEST.json before a case runs. With --out, each
decision is written in full to DIR/<case>/<scope>.json.
"""

from __future__ import annotations

import argparse
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
        with open(os.path.join(HERE, rel), "rb") as fh:
            body = fh.read()
        if len(body) != pinned["length"] or hashlib.sha256(body).hexdigest() != pinned["sha256"]:
            problems.append(f"{rel}: bytes differ from the pinned length or hash")
    return problems


def decide(case: str, scope: str) -> dict:
    base = os.path.join(HERE, "inputs", "probity", case)
    done = subprocess.run(
        [sys.executable, "-m", "agent_evidence_verify.cli", os.path.join(base, "case.json"),
         "--policy", os.path.join(base, "policy.json"), "--require-witness-scope", scope, "--json"],
        capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise SystemExit(f"{case} {scope}: the verifier exited {done.returncode}: {done.stderr}")
    return json.loads(done.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out")
    args = parser.parse_args()
    problems = check_inputs()
    if problems:
        print("\n".join(problems))
        return 1
    with open(os.path.join(HERE, "EXPECTED.json"), encoding="utf-8") as fh:
        expected = json.load(fh)["cases"]
    bad = []
    for case in sorted(expected):
        for scope in SCOPES:
            full = decide(case, scope)
            if args.out:
                os.makedirs(os.path.join(args.out, case), exist_ok=True)
                with open(os.path.join(args.out, case, f"{scope}.json"), "w", encoding="utf-8") as fh:
                    json.dump(full, fh, indent=2, sort_keys=True)
                    fh.write("\n")
            got = {"decision": full["decision"], "reason": full["reason"]}
            want = expected[case]["probity"][scope]
            print(f"{case} {scope}: {got['decision']} {got['reason']}")
            if got != want:
                bad.append(f"FAIL {case} {scope}: expected {want}, got {got}")
    print("\n".join(bad))
    print(f"cases: {len(expected)} x {len(SCOPES)} scopes, {len(bad)} differ from EXPECTED.json")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
