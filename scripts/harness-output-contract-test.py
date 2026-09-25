#!/usr/bin/env python3
"""The external-rail OUTPUT CONTRACT, held against rails that break it.

Why this file exists
--------------------
The harness compares what a rail reported against what the MANIFEST declares.
Until this test existed it compared only what the rail HAD reported: a column
the rail never emitted was skipped, and a skipped comparison reads exactly like
a satisfied one. Four separate sites carried that shape at once.

  * ``_eval_accept_tiers`` compared a tier column only when the rail reported
    one, so a rail that emits no ``tiers`` member passed every tier expectation
    in the corpus by not answering it.
  * the same function's behaviour assertion -- that deriving a tier never alters
    the result -- read ``result_without_key not in (None, result)``, so a rail
    that omitted the result on its no-key pass satisfied the assertion
    vacuously.
  * ``run_external`` parsed the rail's last stdout line inside a
    ``try/except ValueError: pass``. Unparseable output left the verdict
    standing on the exit status alone and the invocation fault was gone.
  * ``observe_external`` kept the no-key pass's tier column and discarded
    everything else about that invocation, including the fact that it had
    failed.

Each of those made an ABSENCE indistinguishable from an ANSWER, which is the
one thing a conformance harness may never do. So the rails below are synthetic
and each is broken in exactly one way; every case requires the harness to
refuse it, and to say WHY in a reason a reader can act on. A case that only
asserted FAIL would be satisfied by the harness failing the vector for an
unrelated reason -- which is what several of these did before the repair, and
is how the defect survived: the vector went red for the wrong cause and the
report attributed the fault to the rail's result rather than to its silence.

The last two rails are harness CONTROLS rather than defect fixtures. One
accepts everything and one rejects everything; both must fail the census. A
harness that passed either would be measuring nothing, and a corpus census is
only evidence while that is checked rather than assumed.

Usage: python3 scripts/harness-output-contract-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import json
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

# An accept vector whose two tier columns DIFFER, so a rail that answers one
# pass and stays silent on the other is distinguishable from a correct one.
# Resolved through the MANIFEST rather than built from a path, because a path
# that spells the verdict only exists while the layout spells it.
TIER_VECTOR = "vcf5a4601dee5c2ee"
TIER_WITH_KEY = '["attested","unattested","declared"]'
TIER_WITHOUT_KEY = '["unattested","unattested","declared"]'
TIER_RESULT = "fail"


def manifest_entry(vector_id: str) -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for entry in manifest["vectors"]:
        if entry["id"] == vector_id:
            typed: dict[str, Any] = entry
            return typed
    raise SystemExit(f"the MANIFEST carries no vector {vector_id}, which this test reads.")


def write_rail(work: Path, name: str, body: str) -> str:
    """A synthetic rail as a shell script.

    The predicate type URI sits in a comment. The harness no longer probes a
    verifier's bytes for it (a named verifier always runs), so nothing depends
    on it; it stays so the rails read as what they stand in for.
    """
    path = work / f"rail-{name}.sh"
    path.write_text(
        f"#!/bin/sh\n# {run_vectors.AEE_PREDICATE_TYPE}\n{body}\n", encoding="utf-8"
    )
    path.chmod(0o755)
    return str(path)


def pass_split(with_key: str, without_key: str) -> str:
    """A rail body that answers the two key policies differently.

    The two passes are told apart by the PRESENCE of the environment variable,
    which is the only thing the harness varies between them.
    """
    return (
        'if [ -n "${AEE_SUBSTRATE_KEYS:-}" ]; then\n'
        f"{with_key}\n"
        "else\n"
        f"{without_key}\n"
        "fi"
    )


def echo_json(body: str, exit_code: int = 0) -> str:
    return f"printf '%s\\n' '{body}'\nexit {exit_code}"


def observe(rail: str, vector_id: str, keys_path: str) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = manifest_entry(vector_id)
    path = str(REPO_ROOT / "vectors" / entry["file"])
    return entry, run_vectors.observe_external([rail], path, keys_path)


def expect_refusal(
    label: str, entry: dict[str, Any], observed: dict[str, Any], needles: list[str]
) -> list[str]:
    """The harness must refuse this rail, and must say why in these words."""
    ok, _gates, reasons = run_vectors.evaluate_vector(entry["kind"], entry, observed, None)
    errors: list[str] = []
    if ok:
        errors.append(
            f"{label}: the harness PASSED a rail that broke the output contract. "
            f"Observed: {observed!r}"
        )
    for needle in needles:
        if not any(needle in reason for reason in reasons):
            errors.append(
                f"{label}: no reason names {needle!r}, so the refusal does not "
                f"attribute the fault to the rail's output. Reasons: {reasons}"
            )
    return errors


def expect_absence_not_claimed(
    label: str, entry: dict[str, Any], observed: dict[str, Any], forbidden: str
) -> list[str]:
    """An EMPTY answer is an answer. It must not be reported as an absence."""
    _ok, _gates, reasons = run_vectors.evaluate_vector(entry["kind"], entry, observed, None)
    if any(forbidden in reason for reason in reasons):
        return [
            f"{label}: the harness reported a PRESENT but empty member as absent "
            f"({forbidden!r} in {reasons}). Empty and absent are different answers "
            "and a rail that says [] has answered."
        ]
    return []


def case_emits_nothing(work: Path, keys: str) -> list[str]:
    """A rail that writes no report at all, and exits successfully."""
    rail = write_rail(work, "emits-nothing", "exit 0")
    entry, observed = observe(rail, TIER_VECTOR, keys)
    return expect_refusal("emits-nothing", entry, observed, ["external-output-absent"])


def case_malformed_json(work: Path, keys: str) -> list[str]:
    """A rail whose report is not JSON. The parse error is preserved."""
    rail = write_rail(work, "malformed-json", echo_json('{"verdict":"valid","result":'))
    entry, observed = observe(rail, TIER_VECTOR, keys)
    return expect_refusal(
        "malformed-json", entry, observed, ["external-output-malformed-json"]
    )


def case_omits_tiers(work: Path, keys: str) -> list[str]:
    """Correct verdict and result, no tier column. The headline defect."""
    rail = write_rail(
        work,
        "omits-tiers",
        echo_json(f'{{"verdict":"valid","result":"{TIER_RESULT}"}}'),
    )
    entry, observed = observe(rail, TIER_VECTOR, keys)
    return expect_refusal(
        "omits-tiers", entry, observed, ["tierWithPinnedKey", "tierWithoutKey"]
    )


def case_null_result_without_key(work: Path, keys: str) -> list[str]:
    """Both tier columns answered; the no-key pass reports a null result."""
    rail = write_rail(
        work,
        "null-result-without-key",
        pass_split(
            echo_json(
                f'{{"verdict":"valid","result":"{TIER_RESULT}","tiers":{TIER_WITH_KEY}}}'
            ),
            echo_json(f'{{"verdict":"valid","result":null,"tiers":{TIER_WITHOUT_KEY}}}'),
        ),
    )
    entry, observed = observe(rail, TIER_VECTOR, keys)
    return expect_refusal(
        "null-result-without-key", entry, observed, ["resultWithoutKey"]
    )


def case_no_key_pass_fails(work: Path, keys: str) -> list[str]:
    """The pinned-key pass is correct; the no-key invocation is broken.

    The no-key pass here contradicts itself -- a refusal in its JSON, success in
    its exit status -- which ``run_external`` already refuses on its own. The
    defect was that ``observe_external`` then kept only that pass's tier column,
    so the refusal arrived as a missing column and the missing column was
    skipped.
    """
    rail = write_rail(
        work,
        "no-key-pass-fails",
        pass_split(
            echo_json(
                f'{{"verdict":"valid","result":"{TIER_RESULT}","tiers":{TIER_WITH_KEY}}}'
            ),
            echo_json('{"verdict":"invalid","codes":["x"]}', exit_code=0),
        ),
    )
    entry, observed = observe(rail, TIER_VECTOR, keys)
    return expect_refusal("no-key-pass-fails", entry, observed, ["no-key"])


def case_no_key_verdict_differs(work: Path, keys: str) -> list[str]:
    """Validity is byte-pure. A rail whose validity turns on the consumer's
    key policy has answered a different question, and both of its answers are
    now compared rather than one of them being discarded."""
    rail = write_rail(
        work,
        "no-key-verdict-differs",
        pass_split(
            echo_json(
                f'{{"verdict":"valid","result":"{TIER_RESULT}","tiers":{TIER_WITH_KEY}}}'
            ),
            echo_json(
                f'{{"verdict":"invalid","codes":["x"],"tiers":{TIER_WITHOUT_KEY},'
                f'"result":"{TIER_RESULT}"}}',
                exit_code=1,
            ),
        ),
    )
    entry, observed = observe(rail, TIER_VECTOR, keys)
    return expect_refusal(
        "no-key-verdict-differs", entry, observed, ["verdictWithoutKey"]
    )


def case_empty_is_not_absent(work: Path, keys: str) -> list[str]:
    """A rail that reports an EMPTY tier column has answered, wrongly.

    The refusal must be a MISMATCH and never an absence: conflating the two
    would hide a rail that derives no tiers at all behind the same words as a
    rail that never spoke.
    """
    rail = write_rail(
        work,
        "empty-tiers",
        echo_json(f'{{"verdict":"valid","result":"{TIER_RESULT}","tiers":[]}}'),
    )
    entry, observed = observe(rail, TIER_VECTOR, keys)
    errors = expect_refusal("empty-tiers", entry, observed, ["tierWithPinnedKey"])
    errors += expect_absence_not_claimed("empty-tiers", entry, observed, "not established")
    return errors


def census(rail: str, work: Path, label: str) -> tuple[int, dict[str, Any]]:
    """Drive the whole corpus through the harness against one rail."""
    report_path = work / f"census-{label}.json"
    proc = subprocess.run(
        [sys.executable, str(HARNESS), "--verifier", rail, "--report", str(report_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=3600,
        check=False,
    )
    if not report_path.is_file():
        return proc.returncode, {}
    report: dict[str, Any] = json.loads(report_path.read_text(encoding="utf-8"))
    return proc.returncode, report


def control_census(work: Path, label: str, body: str) -> list[str]:
    """A harness control: this rail must fail the census, loudly."""
    rail = write_rail(work, label, body)
    code, report = census(rail, work, label)
    errors: list[str] = []
    if report.get("rail") != "external":
        errors.append(
            f"{label}: the harness fell back to its reference rail "
            f"({report.get('railNote')!r}), so this control tested nothing"
        )
        return errors
    totals = report.get("totals") or {}
    if code == 0 or not totals.get("fail"):
        errors.append(
            f"{label}: the census PASSED a rail that answers every vector the same "
            f"way (exit {code}, totals {totals}). A census that cannot fail is not "
            "evidence about any rail."
        )
    return errors


def case_always_accept(work: Path) -> list[str]:
    return control_census(
        work,
        "always-accept",
        echo_json(f'{{"verdict":"valid","result":"{TIER_RESULT}","tiers":[]}}'),
    )


def case_always_reject(work: Path) -> list[str]:
    return control_census(
        work,
        "always-reject",
        echo_json('{"verdict":"invalid","codes":["always"],"primaryCode":"always"}', 1),
    )


def main() -> int:
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="aee-harness-contract-") as tmp:
        work = Path(tmp)
        keys = run_vectors.write_pinned_key_policy(run_vectors.derive_test_keys(), str(work))
        for case in (
            case_emits_nothing,
            case_malformed_json,
            case_omits_tiers,
            case_null_result_without_key,
            case_no_key_pass_fails,
            case_no_key_verdict_differs,
            case_empty_is_not_absent,
        ):
            errors += case(work, keys)
        errors += case_always_accept(work)
        errors += case_always_reject(work)
    if errors:
        print(
            f"FAIL: the external-rail output contract is not enforced "
            f"({len(errors)} finding(s)):",
            file=sys.stderr,
        )
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(
        "OK: absent, null and malformed rail output is refused with the fault "
        "attributed to the rail; an empty answer is kept distinct from an absent "
        "one; a broken no-key pass is fatal rather than a skipped column; and "
        "always-accept and always-reject rails both fail the census."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
