"""Run the D1 and L1 cases through the standalone finite checker and compare.

    git clone https://github.com/Witnessability/witnessability-research wr
    git -C wr checkout 719b243b6c8b1bcd4429cab6347bb3e77ead6a5e
    python3 interop/adjudication-disagreement-d1/run_checker.py --checker-root wr [--out DIR]

Python 3.12 or newer. The checker's modules are checked against CHECKER-PIN.json and
the inputs against MANIFEST.json before any case runs. Each case is one
``evaluate-record`` call with ``--scope raw``, the call the checker's own C1 runner
makes. With --out, each report is written in full to DIR/<case>.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def sha(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def check(root: str) -> list[str]:
    with open(os.path.join(HERE, "CHECKER-PIN.json"), encoding="utf-8") as fh:
        pin = json.load(fh)
    problems = [f"{f['path']}: differs from the pinned checker source"
                for f in pin["files"] if sha(os.path.join(root, f["path"])) != f["sha256"]]
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    problems += [f"{rel}: bytes differ from the pinned length or hash"
                 for rel, p in manifest["files"].items()
                 if sha(os.path.join(HERE, rel)) != p["sha256"]]
    return problems


def evaluate(root: str, case: str) -> tuple[int, dict]:
    inputs = os.path.join(HERE, "inputs", "checker")
    env = dict(os.environ, PYTHONPATH=os.path.join(root, "standalone", "src"))
    done = subprocess.run(
        [sys.executable, "-B", "-m", "witnessability_checker", "evaluate-record",
         "--model", os.path.join(inputs, "models", f"{case}.json"),
         "--policy", os.path.join(inputs, "checker-policy.json"),
         "--expected", os.path.join(inputs, "expected-pins", f"{case}.json"),
         "--record", os.path.join(inputs, "records", f"{case}.json"),
         "--scope", "raw", "--max-work", "2000000"],
        capture_output=True, text=True, check=False, env=env)
    parsed = json.loads(done.stdout) if done.stdout.strip() else {"stderr": done.stderr}
    return done.returncode, parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker-root", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    root = os.path.abspath(args.checker_root)
    problems = check(root)
    if problems:
        print("\n".join(problems))
        return 1
    with open(os.path.join(HERE, "EXPECTED.json"), encoding="utf-8") as fh:
        expected = json.load(fh)["cases"]
    bad = []
    for case in sorted(expected):
        code, report = evaluate(root, case)
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            with open(os.path.join(args.out, f"{case}.json"), "w", encoding="utf-8") as fh:
                json.dump({"exit_code": code, "report": report}, fh, indent=2, sort_keys=True)
                fh.write("\n")
        got = report.get("result") if code == 0 else None
        print(f"{case}: exit {code}, {got}")
        if got != expected[case]["checker"]:
            want = expected[case]["checker"]
            bad.append(f"FAIL {case}: expected {want}, got exit {code} {report}")
    print("\n".join(bad))
    print(f"cases: {len(expected)}, {len(bad)} differ from EXPECTED.json")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
