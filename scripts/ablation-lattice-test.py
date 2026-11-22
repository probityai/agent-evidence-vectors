"""Tests for scripts/ablation-lattice.py on synthetic readers whose lattice is known.

python -m pytest -q scripts/ablation-lattice-test.py
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ablation_lattice", HERE / "ablation-lattice.py")
assert _spec is not None and _spec.loader is not None
lattice_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lattice_module
_spec.loader.exec_module(lattice_module)

run_lattice = lattice_module.run_lattice
ACCEPT = ("accepted", "ok")
RULES = ["a", "b", "c"]


def reader(
    decide: dict[str, Callable[[frozenset[str]], bool]],
) -> Callable[[Path, frozenset[str]], tuple[str, str]]:
    """A reader whose case ``name`` is refused when ``decide[name](kept)`` is true."""

    def verify(path: Path, skip: frozenset[str]) -> tuple[str, str]:
        kept = frozenset(RULES) - skip
        return ("rejected", f"{path.name}") if decide[path.name](kept) else ACCEPT

    return verify


def cases(
    *names_and_expected: tuple[str, tuple[str, str]],
) -> list[tuple[str, Path, tuple[str, str]]]:
    return [(name, Path(name), expected) for name, expected in names_and_expected]


def test_independent_rules_pass_and_name_the_sole_rule() -> None:
    verify = reader({"needs-a": lambda kept: "a" in kept, "good": lambda kept: False})
    result = run_lattice(
        "t", RULES, verify, cases(("needs-a", ("rejected", "needs-a")), ("good", ACCEPT))
    )
    assert result.failures() == []
    assert result.mode == "exhaustive"
    data = result.to_json()
    case = next(c for c in data["cases"] if c["id"] == "needs-a")
    assert case["movesAlone"] == ["a"]
    assert case["necessary"] == ["a"]
    assert case["minimalSufficientKeptSets"] == [["a"]]
    assert case["sole"] is True
    assert data["unmovedCases"] == ["good"]
    assert data["rulesSufficientFor"]["b"] == []


def test_a_case_refused_by_either_of_two_rules_is_not_sole() -> None:
    verify = reader({"two-routes": lambda kept: bool(kept & {"a", "b"})})
    result = run_lattice("t", RULES, verify, cases(("two-routes", ("rejected", "two-routes"))))
    case = result.to_json()["cases"][0]
    assert case["minimalSufficientKeptSets"] == [["a"], ["b"]]
    assert case["sole"] is False
    assert case["necessary"] == []


def test_an_exemption_is_named_and_held_on() -> None:
    # Switching "c" off refuses the accepted case: c narrows the check that a performs.
    verify = reader({"informational": lambda kept: "a" in kept and "c" not in kept})
    result = run_lattice("t", RULES, verify, cases(("informational", ACCEPT)))
    assert result.exemptions == {"c": ["informational"]}
    assert result.rules == ["a", "b"]
    assert result.failures() == []


def test_a_rule_that_cancels_another_fails_monotonicity() -> None:
    verify = reader({"cancelled": lambda kept: ("a" in kept and "b" not in kept) or "c" in kept})
    result = run_lattice("t", RULES, verify, cases(("cancelled", ("rejected", "cancelled"))))
    assert any(
        "kept ['a'] moves it, adding b does not" in failure for failure in result.nonmonotone
    )
    assert result.failures()


def test_an_accepted_case_moved_by_a_subset_fails_stability() -> None:
    verify = reader({"fragile": lambda kept: kept == frozenset({"a"})})
    result = run_lattice("t", RULES, verify, cases(("fragile", ACCEPT)))
    assert result.exemptions == {}
    assert result.moved_unmoved == [
        "t/fragile: the full reader leaves it at ('accepted', 'ok'), kept ['a'] moves it"
    ]


def test_order_dependence_is_reported_without_failing() -> None:
    verify = reader({"joint": lambda kept: {"a", "b"} <= kept})
    result = run_lattice("t", RULES, verify, cases(("joint", ("rejected", "joint"))))
    case = result.to_json()["cases"][0]
    assert case["movesAlone"] == []
    assert case["minimalSufficientKeptSets"] == [["a", "b"]]
    assert case["interactions"]
    assert result.failures() == []


def test_a_wrong_full_answer_fails() -> None:
    verify = reader({"needs-a": lambda kept: "a" in kept})
    result = run_lattice("t", RULES, verify, cases(("needs-a", ACCEPT)))
    assert result.wrong_full == [
        "t/needs-a: full reader answers ('rejected', 'needs-a'), "
        "manifest expects ('accepted', 'ok')"
    ]


def test_chains_are_seeded_and_find_the_same_lattice() -> None:
    verify = reader({"needs-a": lambda kept: "a" in kept})
    first = run_lattice(
        "t",
        RULES,
        verify,
        cases(("needs-a", ("rejected", "needs-a"))),
        exhaustive=1,
        chains=4,
        seed=7,
    )
    second = run_lattice(
        "t",
        RULES,
        verify,
        cases(("needs-a", ("rejected", "needs-a"))),
        exhaustive=1,
        chains=4,
        seed=7,
    )
    assert first.mode == "chains:4:seed:7"
    assert first.to_json() == second.to_json()
    assert first.failures() == []
    assert first.to_json()["cases"][0]["minimalSufficientKeptSets"] == [["a"]]


def test_chains_catch_a_cancelling_rule() -> None:
    verify = reader({"cancelled": lambda kept: ("a" in kept and "b" not in kept) or "c" in kept})
    result = run_lattice(
        "t", RULES, verify, cases(("cancelled", ("rejected", "cancelled"))), exhaustive=1, chains=32
    )
    assert result.nonmonotone


def test_every_gate_corpus_names_a_reader_with_a_set_skip() -> None:
    for corpus, module in lattice_module.GATE_CORPORA.items():
        assert (HERE.parent / "corpora" / corpus / "MANIFEST.json").is_file(), corpus
        assert (HERE.parent / "packaging" / "agent_evidence_vectors" / f"{module}.py").is_file(), (
            module
        )
