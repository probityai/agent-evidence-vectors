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
    entries = lint.defined_entries(root / "REGISTRY.md", root)
    every = [*entries, *lint.named_documents(entries, root)]
    traces = [lint.trace(entry, root) for entry in every]
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
    document = "## Rules\n\n1. first rule\n2. second rule `x`\n"
    tree(tmp_path, document, [case("x", rule=2), case("x", rule=3)])
    _, found = run(tmp_path)
    assert len(found) == 1 and "`#3`" in found[0]


def test_a_numbered_list_outside_the_rules_names_no_rule(tmp_path: Path) -> None:
    # The break: any numbered list (install steps) used to define rules #1 to #N.
    document = "## Install\n\n1. clone\n2. build\n3. run\n\nRefused with `x`.\n"
    tree(tmp_path, document, [case("x", rule=3)])
    _, found = run(tmp_path)
    assert len(found) == 1 and "`#3`" in found[0]


def test_a_rule_row_must_name_the_reason_the_case_expects(tmp_path: Path) -> None:
    # The break: both codes were named somewhere, so rule 2 with rule 1's code passed.
    document = (
        "## Rules\n\n| # | Rule | Code |\n|---|---|---|\n| 1 | a | `a-bad` |\n| 2 | b | `b-bad` |\n"
    )
    tree(tmp_path, document, [case("a-bad", rule=1), case("a-bad", rule=2, id="swapped")])
    _, found = run(tmp_path)
    assert found == [
        "predicate/v1/p: swapped expects rule `#2` with `a-bad`, but the row for `#2` in "
        "spec/p.md names b-bad"
    ]


def test_a_row_naming_only_fields_pins_no_reason(tmp_path: Path) -> None:
    document = "## Rules\n\n| R-OBS | `observed_at` is carried | x |\n\nOutcome `follows`.\n"
    tree(tmp_path, document, [case("follows", rule="R-OBS")])
    assert run(tmp_path)[1] == []


def test_a_named_rule_id_is_named_by_its_row(tmp_path: Path) -> None:
    document = "## A bundle\n\n| B4 | no cycles | `predecessor-cycle` |\n\n`x`\n"
    tree(tmp_path, document, [case("predecessor-cycle", rule="B4"), case("x", rule="B9")])
    _, found = run(tmp_path)
    assert len(found) == 1 and "`B9`" in found[0]


def test_a_case_of_another_registered_document_is_left_to_that_entry(tmp_path: Path) -> None:
    registry = tree(tmp_path, "`mine`", [case("mine"), case("theirs", document="spec/q.md")])
    (tmp_path / "spec" / "q.md").write_text("`theirs`, and `mine` for the unmarked case")
    registry.write_text(
        registry.read_text().replace(
            "## Registered here",
            "### `predicate/v1/q`\n\n- Document: `spec/q.md`\n- Corpus: `corpora/vectors-p/`\n\n"
            "## Registered here",
        )
    )
    traces, found = run(tmp_path)
    assert found == []
    assert [trace.entry.name for trace in traces] == ["predicate/v1/p", "predicate/v1/q"]
    assert traces[1].named_in == {"mine": "spec/q.md", "theirs": "spec/q.md"}


def test_a_case_naming_an_unregistered_file_is_traced_against_it(tmp_path: Path) -> None:
    # The break: a case whose document no entry defines was traced by no entry at all.
    tree(tmp_path, "`mine`", [case("mine"), case("theirs", document="profiles/x.md")])
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "x.md").write_text("Nothing here.")
    _, found = run(tmp_path)
    assert found == [
        "profiles/x.md: `theirs` (expected by c-theirs) is named in neither profiles/x.md "
        "nor the corpus README"
    ]


def test_a_case_naming_a_missing_file_fails(tmp_path: Path) -> None:
    tree(tmp_path, "`mine` `theirs`", [case("mine"), case("theirs", document="spec/typo.md")])
    assert run(tmp_path)[1] == [
        "spec/typo.md: cases of corpora/vectors-p name this document, and no such file exists"
    ]


def test_an_unregistered_file_may_rely_on_the_entries_documents(tmp_path: Path) -> None:
    cases = [case("own-code"), case("own-code", document="profiles/x.md", rule="B1", id="b")]
    tree(tmp_path, "`own-code`", cases)
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "x.md").write_text(
        "| # | Rule | Code |\n| --- | --- | --- |\n| B1 | conforms | the record's own code |\n"
    )
    traces, found = run(tmp_path)
    assert found == []
    assert traces[1].named_in == {"B1": "profiles/x.md", "own-code": "spec/p.md"}


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
    entries = lint.defined_entries()
    traces = [lint.trace(entry) for entry in [*entries, *lint.named_documents(entries)]]
    assert lint.problems(traces, lint.load_pending()) == []
