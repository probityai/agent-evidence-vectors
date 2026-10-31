#!/usr/bin/env python3
"""Hold the registry, the validator and the guide to the done_verification section.

The section's eight terms each carry a `check`, the rule a verifier applies to decide
the term. This checks that every term starts proposed with no issuer, that a term
declaring closed values defines each of them, that every term has a non-empty check, that
the guide at docs/done-verification.md names every term and every adapter a check cites,
that the three crosswalks filed for the section validate, and runs the real validator
over one crosswalk that maps the section and one that files its term under the wrong
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
_PAGE = _ROOT / "docs" / "done-verification.md"
_FILINGS = ("claude-code-goal.yaml", "codex-goals.yaml", "in-toto-604.yaml")
_EXPECTED_TERMS = {
    "done_contract", "done_receipt", "acceptance_observed", "protected_path",
    "claimed_tool_output", "observed_tool_output", "stop_decision", "inconclusive_verdict",
}
_ADAPTER = re.compile(r"\b([a-z_]+/v[0-9]+)\b")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crosswalk(section: str) -> dict:
    return {
        "system": "done-verification-test",
        "system_url": "https://example.invalid/done-verification-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.6.0",
        section: {"protected_path": {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "done-verification-test.yaml"
        path.write_text(yaml.safe_dump(data))
        validator.validate_crosswalk_file(path, known, match_types, evidence_states, errors, warnings)
    return errors


def _check_terms(section: dict, page: str) -> list[str]:
    failures = []
    if set(section) != _EXPECTED_TERMS:
        failures.append(f"terms {sorted(set(section) ^ _EXPECTED_TERMS)} differ from the eight the section carries")
    for name, term in section.items():
        if term.get("status") != "proposed":
            failures.append(f"{name}: status must start proposed")
        if term.get("issuers_in_production") != []:
            failures.append(f"{name}: issuers_in_production must be empty")
        if not str(term.get("check", "")).strip():
            failures.append(f"{name}: no check")
        values = term.get("values")
        defined = term.get("value_definitions")
        if defined is not None:
            missing = [v for v in values or [] if not str(defined.get(v, "")).strip()]
            extra = sorted(set(defined) - set(values or []))
            if missing or extra:
                failures.append(f"{name}: undefined values {missing}, stray definitions {extra}")
        if f"`{name}`" not in page:
            failures.append(f"{name}: the guide never names it")
        for adapter in _ADAPTER.findall(str(term.get("check", ""))):
            if f"`{adapter}`" not in page:
                failures.append(f"{name}: the guide never names the check `{adapter}`")
        for value in values or []:
            if f"`{value}`" not in page:
                failures.append(f"{name}: the guide never names the value `{value}`")
    return failures


def main() -> int:
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    try:
        vocab = yaml.safe_load(_VOCAB.read_text())
        page = _PAGE.read_text(encoding="utf-8")
        validator = _load_validator()
    except (OSError, yaml.YAMLError) as exc:
        print(f"test_done_verification: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None:
        print("test_done_verification: could not load the validator", file=sys.stderr)
        return 2

    section = vocab.get("done_verification")
    if not isinstance(section, dict) or not section:
        print("FAIL: vocabulary.yaml has no done_verification section")
        return 1
    failures = _check_terms(section, page)
    ok = _run(validator, _crosswalk("done_verification"))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("change_admission"))
    if not any("done_verification" in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")
    for name in _FILINGS:
        path = _ROOT / "crosswalk" / name
        if not path.is_file():
            failures.append(f"crosswalk/{name} is missing")
            continue
        data = yaml.safe_load(path.read_text())
        if set(data.get("done_verification", {})) != _EXPECTED_TERMS:
            failures.append(f"crosswalk/{name} does not answer all eight terms, with no_mapping where nothing maps")
        if data.get("maintainer", {}).get("third_party_authored") is not True:
            failures.append(f"crosswalk/{name} must declare third_party_authored: true")
        errors: list[str] = []
        known, match_types, evidence_states = validator.load_registry()
        validator.validate_crosswalk_file(path, known, match_types, evidence_states, errors, [])
        failures.extend(errors)

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"test_done_verification: {len(section)} terms, {len(_FILINGS)} crosswalks and the guide agree; "
          "both validator cases behave")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
