"""Run both checkers on the same pinned inputs and fail when either side flips.

    uv run --no-project --python 3.13 --with probity-verify==0.2.2 \
        python interop/event-absence-c1-sergeev/compare.py --checker-root <checkout>

Shared inputs: every file under source/ is checked against MANIFEST.json
(length and SHA-256) before anything runs. event_absence/v2 reads source/probity,
the standalone checker reads source/checker, and both are in this tree, so one
manifest covers every byte either side reads. The checker engine comes from a
checkout of the repository named in CHECKER-PIN.json; each of its modules is
checked against the hashes in that file before it runs, and the module set must
match exactly.

Comparison: the checker's status, verdict and compatible histories for a case
must equal its pinned expectation (source/checker/EXPECTED.json), event_absence/v2
must return its pinned decision (EXPECTED.json), and the checker verdict must map
to the same decision through PAIRING.json. A change on either side that flips a verdict fails the
run, and the failure line says which side moved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

import run as probity_side

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER_INPUTS = os.path.join(HERE, "source", "checker")
SCOPE = "PEER"
WRAPPER = (
    "import pathlib,sys,importlib\n"
    "sys.path.insert(0,str(pathlib.Path(sys.argv.pop(1)).resolve()))\n"
    "raise SystemExit(importlib.import_module('witnessability_checker.cli').main())\n"
)


def _load(*parts: str):
    with open(os.path.join(HERE, *parts), encoding="utf-8") as fh:
        return json.load(fh)


def check_engine(root: str) -> list[str]:
    pin = _load("CHECKER-PIN.json")
    problems = []
    for item in pin["files"]:
        path = os.path.join(root, item["path"])
        if not os.path.isfile(path):
            problems.append(f"{item['path']}: missing from the checker checkout")
            continue
        with open(path, "rb") as fh:
            body = fh.read()
        if len(body) != item["length"] or hashlib.sha256(body).hexdigest() != item["sha256"]:
            problems.append(f"{item['path']}: bytes differ from the pinned length or hash")
    pkg = os.path.join(root, "standalone", "src", "witnessability_checker")
    found = set()
    for dirpath, _dirs, names in os.walk(pkg):
        for name in names:
            if name.endswith(".py"):
                found.add(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
    extra = found - {item["path"] for item in pin["files"]}
    problems += [f"{p}: module not in the pin" for p in sorted(extra)]
    return problems


def checker_expectations() -> dict:
    """The checker's pinned verdict and compatible histories per case, from his EXPECTED.json."""
    cases = _load("source", "checker", "EXPECTED.json")["cases"]
    return {c["id"]: c["checker_expected"] for c in cases}


def run_checker(root: str, case: str) -> dict:
    inp = CHECKER_INPUTS
    argv = [
        sys.executable, "-I", "-B", "-c", WRAPPER, os.path.join(root, "standalone", "src"),
        "evaluate-record",
        "--model", os.path.join(inp, "checker-model.json"),
        "--policy", os.path.join(inp, "checker-policy.json"),
        "--expected", os.path.join(inp, "expected-pins", case + ".json"),
        "--record", os.path.join(inp, "records", case + ".json"),
        "--scope", "raw", "--max-work", "2000000",
    ]
    done = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)
    if done.returncode != 0 or done.stderr:
        raise SystemExit(f"{case}: the checker exited {done.returncode}: {done.stderr}")
    return json.loads(done.stdout)


def compare(
    cases, checker_out, probity_out, checker_expected, probity_expected, mapping
) -> list[str]:
    """Pure comparison; returns one line per disagreement."""
    bad = []
    for case in cases:
        got_c, got_p = checker_out[case], probity_out[case]
        want_c = checker_expected[case]
        have_c = {
            "verdict": got_c.get("result", {}).get("verdict"),
            "compatible_histories": got_c.get("result", {}).get("compatible_histories"),
        }
        if got_c.get("status") != "ok" or have_c != {
            "verdict": want_c["verdict"],
            "compatible_histories": want_c["compatible_histories"],
        }:
            bad.append(f"{case}: checker side moved: status {got_c.get('status')!r}, {have_c}, "
                       f"pinned {want_c['verdict']!r} {want_c['compatible_histories']}")
        if got_p != probity_expected[case][SCOPE]:
            bad.append(
                f"{case}: event_absence/v2 side moved: "
                f"expected {probity_expected[case][SCOPE]}, got {got_p}"
            )
        verdict = got_c.get("result", {}).get("verdict")
        if mapping.get(verdict) != got_p["decision"]:
            bad.append(f"{case}: the two sides disagree: checker {verdict!r} maps to "
                       f"{mapping.get(verdict)!r}, event_absence/v2 says {got_p['decision']!r}")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--checker-root", required=True)
    args = ap.parse_args()
    problems = probity_side.check_inputs() + check_engine(args.checker_root)
    if problems:
        print("\n".join(problems))
        return 1
    cases = probity_side._cases()
    checker_expected = checker_expectations()
    if sorted(checker_expected) != cases:
        print(f"case sets differ: {sorted(checker_expected)} vs {cases}")
        return 1
    checker_out = {c: run_checker(args.checker_root, c) for c in cases}
    probity_out = {c: probity_side.decide(c, SCOPE) for c in cases}
    bad = compare(cases, checker_out, probity_out, checker_expected,
                  _load("EXPECTED.json")["cases"], _load("PAIRING.json")["verdict_to_decision"])
    for line in bad:
        print("FAIL", line)
    print(f"cases: {len(cases)}, {len(bad)} disagree")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
