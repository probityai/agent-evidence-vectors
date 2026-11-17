"""Tests for scripts/rule-trace-lint.py over a throwaway registry, documents and corpora.

python -m pytest -q scripts/rule-trace-lint-test.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("rule_trace_lint", HERE / "rule-trace-lint.py")
assert _spec is not None and _spec.loader is not None
lint = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lint
_spec.loader.exec_module(lint)


def tree(root: Path, document: str, cases: list[dict[str, Any]], readme: str = "") -> Path:
    """Write a registry with one defined predicate, its document and its corpus."""
    (root / "spec").mkdir(parents=True)
    (root / "spec" / "p.md").write_text(document)
    corpus = root / "corpora" / "vectors-p"
    corpus.mkdir(parents=True)
    (corpus / "MANIFEST.json").write_text(json.dumps({"vectors": cases}))
    if readme:
        (corpus / "README.md").write_text(readme)
    registry = root / "REGISTRY.md"
    registry.write_text(
        "# R\n\n## Defined here\n\n### `predicate/v1/p`\n\n- Document: `spec/p.md`\n"
        "- Corpus: `corpora/vectors-p/`\n\n## Registered here\n"
    )
    return registry


def run(root: Path, pending: dict[str, set[str]] | None = None) -> tuple[list[Any], list[str]]:
    traces = [lint.trace(entry, root) for entry in lint.defined_entries(root / "REGISTRY.md", root)]
    return traces, lint.problems(traces, pending or {}, root)


def case(reason: str, **extra: Any) -> dict[str, Any]:
    return {"id": f"c-{reason}", "expected": {"decision": "deny", "reason": reason}, **extra}


def test_a_code_the_document_names_passes(tmp_path: Path) -> None:
    tree(tmp_path, "Refused with `scope_widened`.", [case("scope_widened")])
    traces, found = run(tmp_path)
    assert found == []
    assert traces[0].named_in == {"scope_widened": "spec/p.md"}


def test_an_unnamed_code_fails_with_its_cases(tmp_path: Path) -> None:
    tree(tmp_path, "Nothing here.", [case("scope_widened")])
    _, found = run(tmp_path)
    assert found == [
        "predicate/v1/p: `scope_widened` (expected by c-scope_widened) is named in neither "
        "spec/p.md nor the corpus README"
    ]


def test_the_corpus_readme_carries_a_definition_and_says_so(tmp_path: Path) -> None:
    tree(tmp_path, "Nothing here.", [case("scope_widened")], readme="`scope_widened` means ...")
    traces, found = run(tmp_path)
    assert found == []
    assert traces[0].named_in == {"scope_widened": "corpora/vectors-p/README.md"}


def test_a_parameterised_code_is_named_by_its_stem(tmp_path: Path) -> None:
    tree(tmp_path, "Refused with `gate_missing:<gate>`.", [case("gate_missing:authority")])
    assert run(tmp_path)[1] == []


def test_a_table_cell_suffix_names_a_second_code(tmp_path: Path) -> None:
    document = "| 2 | key | `peer_unverified:untrusted_key`, `:signature_invalid` |"
    tree(tmp_path, document, [case("peer_unverified:signature_invalid")])
    assert run(tmp_path)[1] == []


def test_a_numeric_rule_is_named_by_a_numbered_item(tmp_path: Path) -> None:
    tree(tmp_path, "1. first rule\n2. second rule `x`\n", [case("x", rule=2), case("x", rule=3)])
    _, found = run(tmp_path)
    assert len(found) == 1 and "`#3`" in found[0]


def test_a_case_of_another_document_is_left_to_that_entry(tmp_path: Path) -> None:
    tree(tmp_path, "`mine`", [case("mine"), case("theirs", document="spec/other.md")])
    assert run(tmp_path)[1] == []


def test_a_rule_naming_an_acceptance_rule_fixture_is_not_a_rule_id(tmp_path: Path) -> None:
    tree(tmp_path, "`mine`", [case("mine", rule="conformance")])
    (tmp_path / "corpora" / "vectors-p" / "rules").mkdir()
    (tmp_path / "corpora" / "vectors-p" / "rules" / "conformance.json").write_text("{}")
    assert run(tmp_path)[1] == []


def test_codes_and_condition_lists_are_read(tmp_path: Path) -> None:
    cases = [
        {"id": "v1", "conditions": ["c-one"], "expected": {"verdict": "invalid", "codes": ["k"]}}
    ]
    tree(tmp_path, "`k`", cases)
    _, found = run(tmp_path)
    assert len(found) == 1 and "`c-one`" in found[0]


def test_a_pending_identifier_is_reported_not_failed(tmp_path: Path) -> None:
    tree(tmp_path, "Nothing here.", [case("owed")])
    assert run(tmp_path, {"predicate/v1/p": {"owed"}})[1] == []


def test_a_pending_identifier_that_is_now_named_fails(tmp_path: Path) -> None:
    tree(tmp_path, "`owed`", [case("owed")])
    assert run(tmp_path, {"predicate/v1/p": {"owed"}})[1] == [
        "predicate/v1/p: `owed` is named now; remove it from TRACE-PENDING.toml"
    ]


def test_a_pending_identifier_no_case_expects_fails(tmp_path: Path) -> None:
    tree(tmp_path, "`x`", [case("x")])
    assert run(tmp_path, {"predicate/v1/p": {"gone"}})[1] == [
        "predicate/v1/p: `gone` is expected by no case; remove it from TRACE-PENDING.toml"
    ]


def test_an_entry_nothing_could_be_read_from_fails(tmp_path: Path) -> None:
    tree(tmp_path, "`x`", [{"id": "v1", "expected": {"verdict": "accept"}}])
    assert run(tmp_path)[1] == [
        "predicate/v1/p: no reason, rule or condition could be read from its corpus"
    ]


def test_the_repository_traces_clean() -> None:
    traces = [lint.trace(entry) for entry in lint.defined_entries()]
    assert lint.problems(traces, lint.load_pending()) == []
