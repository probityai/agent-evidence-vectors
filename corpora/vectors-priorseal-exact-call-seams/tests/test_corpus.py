"""The corpus regenerates, every open case turns on exactly one question, a reader may take
any reading of an open case or answer open, and a reader that ignores the windows, the
chain or the fallback, or stops without an answer, fails the cases that say so."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("priorseal_seams_corpus", ROOT / "check_vectors.py")
generator = _load("priorseal_seams_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import priorsealseams as reader  # noqa: E402

MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
ENTRIES = {entry["id"]: entry for entry in MANIFEST["vectors"]}
OPEN = {name for name, entry in ENTRIES.items() if entry["expected"]["decision"] == "open"}

#: A verifier written as a Python program: it reads case.json and prints an answer.
PROGRAM = """
import json, sys
sys.path.insert(0, {packaging!r})
from agent_evidence_vectors import priorsealseams as r
case = json.load(open(sys.argv[1]))
readings = dict(r.every_reading()[0])
readings.update({readings!r})
answer = r.bind(case, readings)
{tweak}
print(json.dumps(answer))
sys.exit(r.EXIT_FOR[answer["decision"]])
"""


def _verifier(tmp_path: Path, readings: dict[str, str], tweak: str = "") -> list[str]:
    script = tmp_path / "verifier.py"
    packaging = str(ROOT.parents[1] / "packaging")
    script.write_text(PROGRAM.format(packaging=packaging, readings=readings, tweak=tweak))
    return [sys.executable, str(script)]


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(ENTRIES)


def test_the_three_seams_are_the_open_cases() -> None:
    questions = {ENTRIES[name]["expected"]["question"] for name in OPEN}
    assert questions == set(reader.QUESTIONS)
    assert len(OPEN) == len(reader.QUESTIONS)


def test_each_open_case_turns_on_one_question_and_no_decided_case_on_any() -> None:
    for entry in ENTRIES.values():
        case = json.loads((ROOT / entry["path"] / "case.json").read_text(encoding="utf-8"))
        question = entry["expected"].get("question")
        assert reader.moving_questions(case) == ([question] if question else [])


@pytest.mark.parametrize(
    "readings",
    [
        dict(zip(sorted(reader.QUESTIONS), chosen, strict=True))
        for chosen in [
            ("json-type", "skip", "comparison-false"),
            ("decimal-string", "zero", "outside"),
            ("json-type", "outside", "outside"),
        ]
    ],
)
def test_any_reading_of_the_open_cases_passes(tmp_path: Path, readings: dict[str, str]) -> None:
    answered, errors = corpus.check(_verifier(tmp_path, readings))
    assert errors == []
    assert answered == len(ENTRIES)


def test_a_reader_that_ignores_both_windows_fails_the_timed_controls(tmp_path: Path) -> None:
    tweak = (
        'codes = [c for c in answer["reasonCodes"] if "WINDOW" not in c]\n'
        'answer = {"decision": "not_bound" if codes else "bound", "reasonCodes": codes}'
    )
    _, errors = corpus.check(_verifier(tmp_path, {}, tweak))
    assert _failed(errors) == {"control-case-05", "decided-observedat-fallback-late"}


def test_a_reader_that_ignores_the_fallback_fails_the_late_fallback(tmp_path: Path) -> None:
    tweak = (
        'if "executedAt" not in case["observed"]:\n'
        '    answer = {"decision": "bound", "reasonCodes": []}'
    )
    _, errors = corpus.check(_verifier(tmp_path, {}, tweak))
    assert _failed(errors) == {"decided-observedat-fallback-late"}


def test_a_reader_that_ignores_the_chain_fails_the_other_chain(tmp_path: Path) -> None:
    tweak = (
        'codes = [c for c in answer["reasonCodes"] if c != "CHAIN_MISMATCH"]\n'
        'answer = {"decision": "not_bound" if codes else "bound", "reasonCodes": codes}'
    )
    _, errors = corpus.check(_verifier(tmp_path, {}, tweak))
    assert _failed(errors) == {"decided-chainid-other-integer"}


def test_a_type_strict_nonce_fails_the_sentence_that_settles_it(tmp_path: Path) -> None:
    tweak = (
        'if case["observed"]["nonce"] != case["source"]["authorization"]["intent"]["nonce"]:\n'
        '    answer = {"decision": "not_bound", "reasonCodes": ["NONCE_MISMATCH"]}'
    )
    _, errors = corpus.check(_verifier(tmp_path, {}, tweak))
    assert _failed(errors) == {"decided-nonce-json-number"}


def test_a_reader_that_stops_on_a_non_numeric_time_fails_that_case(tmp_path: Path) -> None:
    tweak = 'if isinstance(case["observed"].get("executedAt"), str):\n    sys.exit(1)'
    _, errors = corpus.check(_verifier(tmp_path, {}, tweak))
    assert _failed(errors) == {"open-g10-executedat-not-a-number"}


def test_an_answer_outside_every_reading_fails(tmp_path: Path) -> None:
    tweak = (
        'if "executedAt" not in case["observed"] and "observedAt" not in case["observed"]:\n'
        '    answer = {"decision": "not_bound", "reasonCodes": ["OUTSIDE_TIME_WINDOW"]}'
    )
    _, errors = corpus.check(_verifier(tmp_path, {}, tweak))
    assert _failed(errors) == {"open-g9-missing-time"}


def test_a_reader_that_refuses_everything_fails_every_bound_case(tmp_path: Path) -> None:
    tweak = 'answer = {"decision": "not_bound", "reasonCodes": ["CHAIN_MISMATCH"]}'
    _, errors = corpus.check(_verifier(tmp_path, {}, tweak))
    bound = {n for n, e in ENTRIES.items() if e["expected"]["decision"] == "bound"}
    assert bound <= _failed(errors)


def test_an_exit_status_that_disagrees_with_the_answer_fails(tmp_path: Path) -> None:
    script = tmp_path / "verifier.py"
    script.write_text(
        'print(\'{"decision": "bound", "reasonCodes": []}\')\nimport sys\nsys.exit(1)\n'
    )
    _, errors = corpus.check([sys.executable, str(script)])
    assert any("disagrees" in error for error in errors)


def test_the_vendored_source_is_the_pinned_priorseal_file(tmp_path: Path) -> None:
    for name, (_, digest) in generator.PINNED.items():
        assert generator._sha((generator.SOURCE_DIR / name).read_bytes()) == digest
