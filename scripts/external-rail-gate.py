#!/usr/bin/env python3
"""External-rail gate: the CLI this repository ships must clear the corpus it
ships, driven the way the README tells a third party to drive one.

The README advertises `cmd/aee-verify` as a consumer implementation and, a few
sections later, tells an outside implementer how to wire a rail into
`packaging/run_vectors.py`. Nothing ever ran the first against the second. When
somebody finally did, the shipped CLI scored 0 of 186: its `-json` mode wrote
`json.MarshalIndent`, and the harness reads the LAST line of stdout, which in an
indented object is `}`. Every vector fell back to the exit status alone, which
the README itself says fails every vector in the suite. Two documented
contracts, each internally consistent, each describing the other's counterpart
wrongly, for as long as both have existed.

So this gate does not assert a property of the output. It runs the real corpus
through the real harness against the real binary and requires a clean sweep,
because that is the claim the README makes and the only check that could have
caught what was there.

Four things are checked, each failing on a different regression:

1. the shipped CLI clears every vector as an external rail;
2. its machine-readable output is ONE line the harness's own parse function
   reads back, rather than valid JSON that arrives unreadable;
3. the no-pinned-key tier column is observed from outside this process AND
   binds -- the harness skips a column it was handed nothing for, so an
   expectation that no external rail can express is an expectation nothing can
   fail. Check 3 drives a TOFU'd answer through the evaluator and requires it
   to be rejected.
4. a rail whose exit status contradicts its own reported verdict is REFUSED,
   in the no-consumer-policy mode where the contract is unambiguous. The
   contract puts the verdict in the exit status; the harness used to let a JSON
   member overwrite it with nothing comparing the two, so a rail returning zero
   on every refusal swept the corpus on its JSON alone. Check 4 drives synthetic
   rails, including that one, because a check that only ever sees correct input
   cannot show that it discriminates. It is scoped because the shipped CLI
   deliberately binds its exit status to ADMISSION when a consumer policy is
   supplied, which contradicts the rail contract and is a decision this gate
   records rather than settles.

Usage: python3 scripts/external-rail-gate.py
Needs a Go toolchain. Exit 0 when the shipped CLI satisfies its own published
contract; 1 on any disagreement; a missing toolchain is a FAILURE, not a skip.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"
HARNESS = REPO_ROOT / "packaging" / "run_vectors.py"

sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402


def build_cli(dest_dir: str) -> str:
    """Build cmd/aee-verify, or fail. Never returns without a binary."""
    binary = os.path.join(dest_dir, "aee-verify")
    try:
        proc = subprocess.run(
            ["go", "build", "-o", binary, "./cmd/aee-verify"],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(
            f"FAIL: cmd/aee-verify could not be built ({e}). This gate needs a Go "
            "toolchain; it does not skip, because a skipped external-rail check is "
            "how the shipped CLI came to score 0 of 186 unnoticed.",
            file=sys.stderr,
        )
        raise SystemExit(1) from e
    if proc.returncode != 0:
        print(
            "FAIL: cmd/aee-verify does not build:\n"
            + proc.stderr.decode("utf-8", "replace"),
            file=sys.stderr,
        )
        raise SystemExit(1)
    return binary


def check_full_corpus(binary: str, work_dir: str) -> list[str]:
    """The claim itself: this CLI, driven as the README says, clears the suite."""
    report_path = os.path.join(work_dir, "external-rail-report.json")
    proc = subprocess.run(
        [
            sys.executable,
            str(HARNESS),
            "--verifier",
            f"{binary} -json",
            "--report",
            report_path,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=1800,
    )
    if not os.path.isfile(report_path):
        return [
            "the harness wrote no report driving the shipped CLI (exit "
            f"{proc.returncode}):\n{proc.stdout.decode('utf-8', 'replace')[-4000:]}"
        ]
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    errors: list[str] = []
    if report.get("rail") != "external":
        errors.append(
            "the harness fell back to the reference rail "
            f"({report.get('railNote')!r}), so nothing below tested "
            "the shipped CLI at all"
        )
    totals = report.get("totals") or {}
    if totals.get("fail") or proc.returncode != 0:
        failed = [r["id"] for r in report.get("vectors", []) if r.get("status") != "PASS"]
        errors.append(
            f"the shipped cmd/aee-verify does not clear its own corpus as an external "
            f"rail: {totals.get('pass')} of {totals.get('vectors')} pass, harness exit "
            f"{proc.returncode}; first failures {failed[:5]}"
        )
    return errors


def _manifest_file(vector_id: str) -> str:
    """The file the MANIFEST declares for a vector id."""
    manifest = json.loads(
        (REPO_ROOT / "vectors" / "MANIFEST.json").read_text(encoding="utf-8")
    )
    for entry in manifest["vectors"]:
        if entry["id"] == vector_id:
            return str(entry["file"])
    raise SystemExit(
        f"the MANIFEST declares no file for {vector_id}, which this gate reads."
    )


def check_single_line(binary: str) -> list[str]:
    """The harness's own parse function, against the shipped CLI's own output."""
    # Resolved through the MANIFEST rather than built from a kind directory:
    # a path spelling the verdict only exists while the layout spells it.
    vector = REPO_ROOT / "vectors" / _manifest_file("vcf5a4601dee5c2ee")
    parsed = run_vectors.run_external([binary, "-json"], str(vector), None, "gate")
    errors: list[str] = []
    if parsed["verdict"] != "valid" or parsed["result"] is None or parsed["tiers"] is None:
        errors.append(
            "run_external read no report back from `aee-verify -json`: got "
            f"{parsed!r}. The last stdout line has to BE the report; valid JSON "
            "spread over several lines arrives as nothing."
        )
    raw = subprocess.run(
        [binary, "-json", str(vector)], capture_output=True, timeout=120
    ).stdout.decode("utf-8", "replace")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if len(lines) != 1:
        errors.append(
            f"`aee-verify -json` wrote {len(lines)} non-blank lines; the harness reads "
            "only the last, so every earlier line is unreachable by construction"
        )
    return errors


def _tier_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Every vector that states a tier column, not the first one that does.

    This read the first match for as long as the corpus had exactly one such
    vector, which made the gate's subject an accident of MANIFEST order: adding
    a second pinned vector silently moved what was checked instead of adding to
    it, and the five other pinned columns would have been observed from outside
    by nothing.
    """
    out: list[dict[str, Any]] = []
    for entry in manifest["vectors"]:
        typed: dict[str, Any] = entry
        expected = typed.get("expected") or {}
        if expected.get("tierWithoutKey") or expected.get("tierWithPinnedKey"):
            out.append(typed)
    if not out:
        print(
            "FAIL: no vector declares tierWithoutKey, so the corpus states GATE 2's "
            "no-TOFU rule nowhere and this gate has nothing to hold to.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return out


def check_no_key_column_binds(binary: str, work_dir: str, manifest: dict[str, Any]) -> list[str]:
    """Observed from outside, and fatal when wrong.

    Both halves matter. The harness compares a tier column only when the rail
    reported one, so an external rail that could not report the no-key column --
    which, before the key policy got an environment channel, was every external
    rail -- passed the expectation by not answering it.
    """
    entries = _tier_entries(manifest)
    keys_path = run_vectors.write_pinned_key_policy(run_vectors.derive_test_keys(), work_dir)
    errors: list[str] = []
    falsifiable = 0
    for entry in entries:
        expected = entry["expected"]
        vector = REPO_ROOT / "vectors" / entry["file"]
        observed = run_vectors.observe_external([binary, "-json"], str(vector), keys_path)
        for field, key in (("tierWithoutKey", "tiers_without_key"),
                           ("tierWithPinnedKey", "tiers_with_key")):
            if field in expected and observed[key] != expected[field]:
                errors.append(
                    f"`{entry['id']}` {field}: the external rail reported "
                    f"{observed[key]!r}, expected {expected[field]!r}"
                )
        # And the expectation has to be capable of failing. A rail that trusted
        # the predicate's own substrate root on first sight would report the
        # pinned-key column for both passes; the evaluator must reject that.
        #
        # Only a vector whose two columns DIFFER can ask that question. On one
        # whose columns are equal -- an artifact-only row, or a substrate row
        # that verifies under no key -- the substitution below is the identity,
        # so the evaluator passes it for the same reason it passes the real
        # answer, and reading that as a finding would report a healthy rail as a
        # TOFU rail. The count is asserted afterwards so that a corpus which
        # somehow pinned only equal-column vectors fails here rather than
        # reporting a check it never ran.
        if observed["tiers_with_key"] == observed["tiers_without_key"]:
            continue
        falsifiable += 1
        tofu = dict(observed, tiers_without_key=observed["tiers_with_key"])
        passed, _gates, _reasons = run_vectors.evaluate_vector("accept", entry, tofu, None)
        if passed:
            errors.append(
                f"`{entry['id']}` accepted a rail that derived the pinned-key tiers with no "
                "pinned key (TOFU), so the no-TOFU rule is stated in the MANIFEST and "
                "enforced against nothing"
            )
    if falsifiable == 0:
        errors.append(
            "no pinned vector has a pinned-key column differing from its no-key column, so "
            "the no-TOFU substitution is the identity everywhere and this gate asserts nothing"
        )
    return errors


def check_exit_status_binds(work_dir: str) -> list[str]:
    """A rail whose exit status contradicts its own JSON verdict is refused.

    The contract puts the verdict in the exit status. The harness used to read
    that, then let a `verdict` member in the JSON overwrite it, and never
    compared the two -- so a rail whose exit status was meaningless, returning
    zero on every refusal, scored a clean sweep on the strength of its JSON
    alone. The suite would have reported a conformant checker having only ever
    exercised half of one.

    This drives three synthetic rails rather than the shipped CLI, because the
    shipped CLI is correct and a check that only ever sees correct input cannot
    show that it discriminates. The third rail is the defect itself.
    """
    errors: list[str] = []
    vector = Path(work_dir) / "exit-status-probe.json"
    vector.write_text("{}", encoding="utf-8")
    rails = {
        # exit status and JSON agree on a reject: the verdict stands.
        "agreeing": ('{"verdict":"invalid","codes":["c"],"result":"reject"}', 1, "invalid"),
        # JSON omits the verdict, which the contract permits: exit status stands.
        "silent": ('{"codes":["c"],"result":"reject"}', 1, "invalid"),
        # THE DEFECT: a refusal reported in JSON, success in the exit status.
        "contradicting": ('{"verdict":"invalid","codes":["c"],"result":"reject"}', 0, "error"),
    }
    for name, (line, code, expected) in rails.items():
        script = Path(work_dir) / f"rail-{name}.sh"
        script.write_text(f"#!/bin/sh\necho '{line}'\nexit {code}\n", encoding="utf-8")
        script.chmod(0o755)
        got = run_vectors.run_external([str(script)], str(vector), None, name)
        if got["verdict"] != expected:
            errors.append(
                f"a {name} rail (exit {code}) produced verdict {got['verdict']!r}, "
                f"expected {expected!r}: the harness is not comparing the exit "
                f"status against the reported verdict"
            )
    return errors


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="aee-external-rail-gate-") as work_dir:
        binary = build_cli(work_dir)
        errors = (
            check_single_line(binary)
            + check_no_key_column_binds(binary, work_dir, manifest)
            + check_full_corpus(binary, work_dir)
            + check_exit_status_binds(work_dir)
        )
    if errors:
        print(
            f"FAIL: the shipped CLI and the external-rail contract it is published "
            f"under disagree ({len(errors)} disagreement(s)):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(
        "OK: cmd/aee-verify clears the published corpus as an external rail, its "
        "machine-readable output is one line the harness reads back, and the "
        "no-pinned-key tier column is both observable from outside and fatal when "
        "wrong. A rail whose exit status contradicts its reported verdict is refused."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
