#!/usr/bin/env python3
"""Hold the registry, the validator and the guide to the incident_response section.

The section's eleven terms each carry a `check`, the rule a verifier applies to decide
the term. This checks that every term starts proposed with no issuer, carries a
criticality, a review date, a definition and a promotion trigger, that a term declaring
closed values defines each of them, that every term has a non-empty check, that the guide
at docs/incident-response.md names every term and every value, that the five crosswalks
filed for the section validate, and runs the real validator over one crosswalk that maps
the section and one that files its term under the wrong section. Nothing is restated here.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_VOCAB = _ROOT / "vocabulary.yaml"
_PAGE = _ROOT / "docs" / "incident-response.md"
_FILINGS = (
    "nist-sp-800-61r3.yaml", "nist-key-practices-si.yaml", "aws-agentic-ai-lens.yaml",
    "owasp-agent-control-standard.yaml", "aiir-kill-switch-api.yaml",
)
_EXPECTED_TERMS = {
    "response_decision", "response_function", "enforcement_vantage", "control_failure_posture",
    "revocation_state", "containment_scope", "pause_hold", "escalation_outcome",
    "restoration_decision", "restoration_gate", "incident_identifier",
}
_REQUIRED_KEYS = ("criticality", "review_by", "definition", "promotion_trigger", "source_path")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crosswalk(section: str) -> dict:
    return {
        "system": "incident-response-test",
        "system_url": "https://example.invalid/incident-response-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.8.0",
        section: {"response_decision": {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "incident-response-test.yaml"
        path.write_text(yaml.safe_dump(data))
        validator.validate_crosswalk_file(path, known, match_types, evidence_states, errors, warnings)
    return errors


def _check_terms(section: dict, page: str) -> list[str]:
    failures = []
    if set(section) != _EXPECTED_TERMS:
        failures.append(f"terms {sorted(set(section) ^ _EXPECTED_TERMS)} differ from the eleven the section carries")
    for name, term in section.items():
        if term.get("status") != "proposed":
            failures.append(f"{name}: status must start proposed")
        if term.get("issuers_in_production") != []:
            failures.append(f"{name}: issuers_in_production must be empty")
        if not str(term.get("check", "")).strip():
            failures.append(f"{name}: no check")
        for key in _REQUIRED_KEYS:
            if not str(term.get(key, "")).strip():
                failures.append(f"{name}: no {key}")
        values = term.get("values")
        defined = term.get("value_definitions")
        if defined is not None:
            missing = [v for v in values or [] if not str(defined.get(v, "")).strip()]
            extra = sorted(set(defined) - set(values or []))
            if missing or extra:
                failures.append(f"{name}: undefined values {missing}, stray definitions {extra}")
        if f"`{name}`" not in page:
            failures.append(f"{name}: the guide never names it")
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
        print(f"test_incident_response: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None:
        print("test_incident_response: could not load the validator", file=sys.stderr)
        return 2

    section = vocab.get("incident_response")
    if not isinstance(section, dict) or not section:
        print("FAIL: vocabulary.yaml has no incident_response section")
        return 1
    failures = _check_terms(section, page)
    ok = _run(validator, _crosswalk("incident_response"))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("change_admission"))
    if not any("incident_response" in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")
    for name in _FILINGS:
        path = _ROOT / "crosswalk" / name
        if not path.is_file():
            failures.append(f"crosswalk/{name} is missing")
            continue
        data = yaml.safe_load(path.read_text())
        if set(data.get("incident_response", {})) != _EXPECTED_TERMS:
            failures.append(f"crosswalk/{name} does not answer all eleven terms, with no_mapping where nothing maps")
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
    print(f"test_incident_response: {len(section)} terms, {len(_FILINGS)} crosswalks and the guide agree; "
          "both validator cases behave")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
