#!/usr/bin/env python3
"""Hold the registry, the validator and the predicate page to change_admission.

The change_admission terms are carried by the agent-change-admission predicate,
version 1, whose page lives at docs/predicates/agent-change-admission-v1.md and
whose URL is the predicate type URI signed decisions already carry. This checks
that every closed value carries a definition where the term defines its values,
that the page names every gate and every term's wire field, that the page's
gate table and the registry's gate list agree, and runs the real validator
over one crosswalk that maps the section and one that files it under the wrong
section. Nothing is restated here.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_VOCAB = _ROOT / "vocabulary.yaml"
_PAGE = _ROOT / "docs" / "predicates" / "agent-change-admission-v1.md"
_URI = ("https://github.com/probityai/agent-evidence-vocabulary/blob/main/"
        "docs/predicates/agent-change-admission-v1.md")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crosswalk(section: str) -> dict:
    return {
        "system": "change-admission-test",
        "system_url": "https://example.invalid/change-admission-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.4.0",
        section: {"admission_gate": {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "change-admission-test.yaml"
        path.write_text(yaml.safe_dump(data))
        validator.validate_crosswalk_file(path, known, match_types, evidence_states, errors, warnings)
    return errors


def _page_gates(page: str) -> list[str]:
    """Gate names in the first column of the page's Gates table, in order."""
    section = page.split("## Gates", 1)[1].split("\n## ", 1)[0]
    return re.findall(r"^\| `([a-z_]+)` \|", section, flags=re.MULTILINE)


def _check_terms(section: dict, page: str) -> list[str]:
    failures = []
    for name, term in section.items():
        if term.get("status") != "proposed":
            failures.append(f"{name}: status must start proposed")
        if term.get("issuers_in_production") != []:
            failures.append(f"{name}: issuers_in_production must be empty")
        values = term.get("values")
        defined = term.get("value_definitions")
        if defined is not None:
            missing = [v for v in values or [] if not str(defined.get(v, "")).strip()]
            extra = sorted(set(defined) - set(values or []))
            if missing or extra:
                failures.append(f"{name}: undefined values {missing}, stray definitions {extra}")
        path = str(term.get("source_path", ""))
        field = path.split(".", 1)[-1].split("[", 1)[0] if path.startswith("predicate.") else ""
        if field and f"`{field}`" not in page:
            failures.append(f"{name}: the page never names the wire field `{field}`")
    return failures


def main() -> int:
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    try:
        vocab = yaml.safe_load(_VOCAB.read_text())
        page = _PAGE.read_text(encoding="utf-8")
        validator = _load_validator()
    except (OSError, yaml.YAMLError) as exc:
        print(f"test_change_admission: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None:
        print("test_change_admission: could not load the validator", file=sys.stderr)
        return 2

    section = vocab.get("change_admission")
    if not isinstance(section, dict) or not section:
        print("FAIL: vocabulary.yaml has no change_admission section")
        return 1
    failures = _check_terms(section, page)
    if _URI not in page:
        failures.append("the page does not state its own predicate type URI")
    gates = (section.get("admission_gate") or {}).get("values") or []
    if sorted(gates) != sorted(_page_gates(page)) or len(set(gates)) != len(gates):
        failures.append(f"registry gates {gates} and page gates {_page_gates(page)} disagree")
    ok = _run(validator, _crosswalk("change_admission"))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("record_lifecycle"))
    if not any("change_admission" in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"test_change_admission: {len(section)} terms and {len(gates)} gates agree "
          "with the predicate page; both validator cases behave")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
