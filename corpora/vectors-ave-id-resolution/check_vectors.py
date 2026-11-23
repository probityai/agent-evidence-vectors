#!/usr/bin/env python3
"""Judge every AVE id resolution member and prove each rule is load-bearing.

1. Every snapshot's bytes match its release SHA256SUMS and its pin, and the
   corpus digest recomputes.
2. Every member reads back to the verdict and codes MANIFEST.json declares,
   from the reference checker or from a named verifier.
3. Every rule's code is produced by at least one member.

    python3 corpora/vectors-ave-id-resolution/check_vectors.py
    python3 corpora/vectors-ave-id-resolution/check_vectors.py --verifier './my-check'

A named verifier runs as ``<verifier> <output-file> <snapshot-file> <sha256>``.
Its last non-empty stdout line is one JSON object carrying ``verdict`` and
``codes``, and it exits 0 for resolves, 1 for fails and 3 for no-ids.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import resolve_ids  # noqa: E402
from gen_vectors import corpus_digest  # noqa: E402

sys.path.insert(0, str(HERE.parents[1] / "packaging"))
from agent_evidence_vectors import strictjson  # noqa: E402


def answer(verifier: str | None, output: Path, snapshot: Path, pin: str) -> tuple[str, list[str]]:
    if verifier is None:
        report = resolve_ids.run(output, snapshot, pin)
        return report["verdict"], report["codes"]
    done = subprocess.run(
        [*shlex.split(verifier), str(output), str(snapshot), pin],
        capture_output=True,
        text=True,
        timeout=60,
    )
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    try:
        report = strictjson.loads(lines[-1])
        verdict, codes = report["verdict"], sorted(report.get("codes", []))
    except (IndexError, ValueError, KeyError, TypeError):
        return "errored", []
    if done.returncode != resolve_ids.EXIT.get(verdict):
        return f"exit {done.returncode} with {verdict}", codes
    return verdict, codes


def check(
    verifier: str | None, root: Path = HERE, decision_only: bool = False
) -> tuple[int, list[str]]:
    manifest: dict[str, Any] = strictjson.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    failures, seen = [], set()
    try:
        if corpus_digest(manifest, str(root)) != manifest["corpusDigest"]:
            failures.append("corpus: corpusDigest does not recompute")
    except ValueError as error:
        failures.append(f"corpus: {error}")
    for entry in manifest["vectors"]:
        release = entry["snapshot"]
        pin = manifest["snapshots"][release]["recordsSha256"]
        snapshot = root / "snapshots" / release / "ave-records.json"
        verdict, codes = answer(verifier, root / entry["path"], snapshot, pin)
        want = entry["expected"]
        seen.update(codes)
        if verdict != want["verdict"] or (not decision_only and codes != want["codes"]):
            failures.append(
                f"{entry['id']}: answered {verdict} {codes}, "
                f"declared {want['verdict']} {want['codes']}"
            )
    if verifier is None:
        failures += [
            f"rule {rule}: produced by no member" for rule in manifest["rules"] if rule not in seen
        ]
    return len(manifest["vectors"]), failures


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--verifier", help="command judged instead of the reference checker")
    parser.add_argument("--decision-only", action="store_true", help="compare verdicts, not codes")
    args = parser.parse_args()
    answered, failures = check(args.verifier, HERE, args.decision_only)
    for line in failures:
        print(f"FAIL {line}")
    print(f"ave-id-resolution: {answered} members, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
