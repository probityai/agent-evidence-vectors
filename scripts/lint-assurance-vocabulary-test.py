"""The vocabulary lint refuses each scale's word on the other's page."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_PATH = Path(__file__).resolve().parents[0] / "lint-assurance-vocabulary.py"
_SPEC = importlib.util.spec_from_file_location("lint_assurance_vocabulary", _PATH)
assert _SPEC and _SPEC.loader
lint = importlib.util.module_from_spec(_SPEC)
sys.modules["lint_assurance_vocabulary"] = lint
_SPEC.loader.exec_module(lint)

LEVELS = "spec/predicates/identity-assurance-levels.md"
GRADES = "spec/predicates/record-grades.md"
CROSS = "See the other scale. <!-- crosslink -->\n"


def _write(root: Path, relative: str, body: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _run(root: Path) -> int:
    return int(lint.main(["--root", str(root)]))


def test_clean_pages_pass(tmp_path: Path) -> None:
    _write(tmp_path, LEVELS, CROSS + "Level 3 is holder-bound.\n")
    _write(tmp_path, GRADES, CROSS + "Grade W is witnessed.\n")
    assert _run(tmp_path) == 0


def test_grade_word_on_the_levels_page_fails(tmp_path: Path) -> None:
    _write(tmp_path, LEVELS, CROSS + "This is a high grade of proof.\n")
    assert _run(tmp_path) == 1


def test_level_word_on_the_grades_page_fails(tmp_path: Path) -> None:
    _write(tmp_path, GRADES, CROSS + "A higher level of custody.\n")
    assert _run(tmp_path) == 1


def test_code_spans_and_fences_are_exempt(tmp_path: Path) -> None:
    _write(
        tmp_path,
        LEVELS,
        CROSS + "The suite `evidence-grade-floor/v1` and `act_grade`.\n```\ngrade = 1\n```\n",
    )
    assert _run(tmp_path) == 0


def test_missing_or_duplicate_cross_link_fails(tmp_path: Path) -> None:
    _write(tmp_path, LEVELS, "Level 3.\n")
    assert _run(tmp_path) == 1
    _write(tmp_path, LEVELS, CROSS + CROSS)
    assert _run(tmp_path) == 1


def test_a_cross_link_line_may_name_both_words(tmp_path: Path) -> None:
    _write(tmp_path, LEVELS, "Level N and record grade W differ. <!-- crosslink -->\n")
    assert _run(tmp_path) == 0


def test_no_pages_is_an_error_never_a_pass(tmp_path: Path) -> None:
    assert _run(tmp_path) == 1


def test_inflected_forms_are_caught(tmp_path: Path) -> None:
    for word in ("graded", "Grades", "grading"):
        _write(tmp_path, LEVELS, CROSS + f"It is {word} here.\n")
        assert _run(tmp_path) == 1
