"""Judge a reader of the PriorSeal exact-call matrix on three seams of contract 1.0.1.

The exact-call envelope matrix in imokokok/PriorSeal
(``examples/open-evidence-lab-exact-call-matrix-v1``) publishes an input
contract, version 1.0.1, whose section 4 maps each signed field of an
authorization to a field of an observed execution envelope and names the reason
code a mismatch yields; ``bound`` is true exactly when no section 4 code applies.
In issue 352 on this repository piiiico ran three one-field variants of the
matrix's case-00 through two readers and the shipped profile, ogasurfproject-jpg
and Tetsurohhori reproduced them with two more readers, and imokokok recorded
them as the candidate gaps G9 to G11:

- G9, a missing time: with no ``executedAt`` and no ``observedAt`` the two
  window rows have no observed time to compare (skip both rows, take the
  coerced empty string as 0, or put the case outside both windows);
- G10, a non-numeric time: ``executedAt: "late"`` is not a number, and no
  sentence says what an order comparison against it means;
- G11, the representation of ``chainId``: the row says "strict equality of the
  integer values" and the 1.0.1 paragraph "Comparison semantics" says values
  compare after ``String()`` coercion, so an observed ``"8453"`` matches the
  signed ``8453`` by the paragraph and does not by a type-strict reading.

The reference reader implements section 4 and takes one named reading for each
of the three questions. A case whose answer is the same under every combination
of readings is decided by the text; a case whose answer moves with one question
is open, and the reader answers ``open`` naming that question. A verifier under
test may answer an open case with either reading's answer or with ``open``; any
other answer, a crash included, fails the case.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object, ``{"decision": "bound" | "not_bound", "reasonCodes":
[...]}`` or ``{"decision": "open", "question": "..."}``, and exits 0 for
``bound``, 1 for ``not_bound`` and 2 for ``open``. ``case.json`` carries the
matrix's signed source record under ``source`` and the observed envelope under
``observed``.
"""

from __future__ import annotations

import argparse
import itertools
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import (
    _fixture_error,
    _validated_entries,
    run_corpus,
)

SUITE = "priorseal-exact-call-seams/v1"
BOUND, NOT_BOUND, OPEN = "bound", "not_bound", "open"
EXIT_FOR = {BOUND: 0, NOT_BOUND: 1, OPEN: 2}
WINDOW_CODES = ("OUTSIDE_AUTHORIZATION_WINDOW", "OUTSIDE_TIME_WINDOW")
#: Each question the 1.0.1 text leaves open, and its readings in a fixed order.
QUESTIONS: dict[str, tuple[str, ...]] = {
    "missing-time": ("skip", "zero", "outside"),
    "non-numeric-time": ("comparison-false", "outside"),
    "chain-id-representation": ("decimal-string", "json-type"),
}
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-priorseal-exact-call-seams"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-priorseal-exact-call-seams"
)

Case = dict[str, Any]
Answer = dict[str, Any]
Readings = dict[str, str]


def js_string(value: Any) -> str:
    """The 1.0.1 ``String()`` coercion: null and missing to "", an integer to its decimal."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _same(left: Any, right: Any) -> bool:
    return js_string(left).lower() == js_string(right).lower()


def _is_time(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _chain_mismatch(signed: Any, observed: Any, reading: str) -> bool:
    if reading == "decimal-string":
        return js_string(signed) != js_string(observed)
    return type(signed) is not type(observed) or signed != observed


def _window_codes(authorization: dict[str, Any], observed: dict[str, Any], readings: Readings) -> list[str]:
    """The section 4 window rows over ``executedAt``, falling back to ``observedAt``."""
    when = observed.get("executedAt")
    if when is None:
        when = observed.get("observedAt")
    if when is None and readings["missing-time"] == "zero":
        when = 0
    if when is None:
        return list(WINDOW_CODES) if readings["missing-time"] == "outside" else []
    if not _is_time(when):
        return list(WINDOW_CODES) if readings["non-numeric-time"] == "outside" else []
    codes = []
    if when > authorization["intent"]["validUntil"]:
        codes.append("OUTSIDE_TIME_WINDOW")
    if when < authorization["notBefore"] or when > authorization["expiresAt"]:
        codes.append("OUTSIDE_AUTHORIZATION_WINDOW")
    return codes


def bind(case: Case, readings: Readings) -> Answer:
    """The section 4 mismatch set of one case under one reading of each open question."""
    authorization = case["source"]["authorization"]
    intent, observed = authorization["intent"], case["observed"]
    codes = []
    if _chain_mismatch(intent.get("chainId"), observed.get("chainId"), readings["chain-id-representation"]):
        codes.append("CHAIN_MISMATCH")
    if not _same(observed.get("action"), intent.get("action")):
        codes.append("ACTION_MISMATCH")
    if not _same(observed.get("sender"), intent.get("sender")):
        codes.append("SENDER_MISMATCH")
    if js_string(observed.get("nonce", "0")) != js_string(intent.get("nonce", "0")):
        codes.append("NONCE_MISMATCH")
    for signed, seen, code in (
        ("callTarget", "target", "CALL_TARGET_MISMATCH"),
        ("calldataHash", "calldataHash", "CALLDATA_MISMATCH"),
    ):
        if intent.get(signed) is not None and not _same(observed.get(seen), intent[signed]):
            codes.append(code)
    value = intent.get("transactionValue")
    if value is not None and js_string(observed.get("nativeValue")) != js_string(value):
        codes.append("TRANSACTION_VALUE_MISMATCH")
    codes.extend(_window_codes(authorization, observed, readings))
    reasons = sorted(set(codes))
    return {"decision": NOT_BOUND if reasons else BOUND, "reasonCodes": reasons}


def every_reading() -> list[Readings]:
    """Every combination of one reading per open question."""
    names = sorted(QUESTIONS)
    return [dict(zip(names, chosen)) for chosen in itertools.product(*(QUESTIONS[n] for n in names))]


def moving_questions(case: Case) -> list[str]:
    """The questions whose reading changes this case's answer, all others held fixed."""
    moving = []
    for name, choices in sorted(QUESTIONS.items()):
        for base in every_reading():
            answers = {json.dumps(bind(case, {**base, name: choice}), sort_keys=True) for choice in choices}
            if len(answers) > 1:
                moving.append(name)
                break
    return moving


def judge(case: Case) -> Answer:
    """The reference reader's answer: the decided answer, or ``open`` naming the question."""
    moving = moving_questions(case)
    if moving:
        return {"decision": OPEN, "question": ",".join(moving)}
    return bind(case, every_reading()[0])


def reading_answers(case: Case, question: str) -> dict[str, Answer]:
    """For an open case, the answer under each reading of its one open question."""
    base = every_reading()[0]
    return {choice: bind(case, {**base, question: choice}) for choice in QUESTIONS[question]}


def acceptable(entry: dict[str, Any]) -> list[Answer]:
    """The answers a conformant reader may give: the decided one, or ``open`` or any reading."""
    return [entry["expected"], *(row["answer"] for row in entry.get("readings", []))]


def _load(path: Path) -> Case:
    loaded: Case = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def verify(path: Path) -> Answer:
    """The reference reader's answer for one case file."""
    return judge(_load(path))


def _normalised(answer: Any) -> Answer | None:
    if not isinstance(answer, dict):
        return None
    decision = answer.get("decision")
    if decision == OPEN and isinstance(answer.get("question"), str):
        return {"decision": OPEN, "question": answer["question"]}
    codes = answer.get("reasonCodes")
    if decision in (BOUND, NOT_BOUND) and isinstance(codes, list):
        return {"decision": decision, "reasonCodes": sorted({str(code) for code in codes})}
    return None


def external_answer(command: list[str], path: Path) -> tuple[bool, Answer | str]:
    """Run one external verifier on one case and read its answer."""
    try:
        result = subprocess.run(
            [*command, str(path), "--json"], capture_output=True, text=True, timeout=90, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = _normalised(json.loads(result.stdout))
    except ValueError:
        answer = None
    if answer is None:
        return True, f"verifier returned no answer (exit {result.returncode})"
    if EXIT_FOR[answer["decision"]] != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {answer['decision']}"
    return True, answer


def _declared_error(entry: dict[str, Any], case: Case) -> str | None:
    """Whether the manifest's expected answer and readings are the ones the text gives."""
    if judge(case) != entry["expected"]:
        return "declared expected answer does not hold"
    if entry["expected"]["decision"] != OPEN:
        return None if "readings" not in entry else "a decided case declares readings"
    question = entry["expected"]["question"]
    declared = {row["reading"]: row["answer"] for row in entry.get("readings", [])}
    if question not in QUESTIONS or declared != reading_answers(case, question):
        return "declared readings do not hold"
    return None


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT
) -> tuple[int, list[str]]:
    """Check every case, through the named verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, SUITE)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        case_path = directory / "case.json"
        declared_error = _declared_error(entry, _load(case_path))
        if declared_error:
            errors.append(f"{name}: {declared_error}")
        observed: Answer | str
        if command is None:
            ran, observed = True, verify(case_path)
        else:
            ran, observed = external_answer(command, case_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed not in acceptable(entry):
            errors.append(f"{name}: expected one of {acceptable(entry)}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the answer as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        detail = answer.get("question") or " ".join(answer["reasonCodes"])
        print(json.dumps(answer, sort_keys=True) if args.json else f"{answer['decision']} {detail}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
