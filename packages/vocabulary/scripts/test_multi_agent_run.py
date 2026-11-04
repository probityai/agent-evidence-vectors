#!/usr/bin/env python3
"""Hold the registry, the validator and the guide to the multi_agent_run section.

The section's seven terms each carry a `check`, the rule a verifier applies to decide
the term. This checks that every term starts proposed with no issuer, carries a
criticality, a review date, a definition and a promotion trigger, that a term declaring
closed values defines each of them, that every term has a non-empty check, that the guide
at docs/multi-agent-run.md names every term and every value, that every registered value
of every closed term is accepted and an unregistered one refused through
registry.check_value, and runs the real validator over one crosswalk that maps the
section and one that files its term under the wrong section. Nothing is restated here.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_VOCAB = _ROOT / "vocabulary.yaml"
_REGISTRY = _ROOT / "registry.py"
_INDEX = _ROOT / "registry.json"
_PAGE = _ROOT / "docs" / "multi-agent-run.md"
_EXPECTED_TERMS = {
    "message_delivery_disposition", "topology_enforcement", "topology_decision_basis",
    "restart_scope", "restoration_evidence_binding", "assessment_availability",
    "generation_outcome",
}
_REQUIRED_KEYS = ("criticality", "review_by", "definition", "promotion_trigger", "source_path")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_registry():
    spec = importlib.util.spec_from_file_location("vocabulary_registry", _REGISTRY)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _check_one_closed_term(registry, index: dict, name: str, values: list) -> list[str]:
    """Each registered value of one closed term is accepted; an unregistered one is refused."""
    failures = []
    try:
        for value in values:
            judged = registry.check_value(index, name, value, None)
            if judged.outcome != registry.OK:
                failures.append(f"{name}: registered value {value!r} was judged {judged.outcome}")
        refused = registry.check_value(index, name, "not-a-registered-value", None)
    except KeyError:
        return [f"{name}: the registry index declares no values for a term that lists them"]
    if refused.outcome != registry.MALFORMED:
        failures.append(f"{name}: an unregistered value was judged {refused.outcome}, "
                        "not malformed")
    return failures


def _check_closed_values(registry, index: dict, section: dict) -> list[str]:
    """Run the closed-value check for every term that lists values."""
    failures = []
    for name, term in section.items():
        values = term.get("values")
        if values is not None:
            failures.extend(_check_one_closed_term(registry, index, name, values))
    return failures


def _crosswalk(section: str) -> dict:
    return {
        "system": "multi-agent-run-test",
        "system_url": "https://example.invalid/multi-agent-run-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.9.0",
        section: {"topology_enforcement": {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "multi-agent-run-test.yaml"
        path.write_text(yaml.safe_dump(data))
        validator.validate_crosswalk_file(
            path, known, match_types, evidence_states, errors, warnings)
    return errors


def _check_fields(name: str, term: dict) -> list[str]:
    """The status, issuer list, check and required keys of one term."""
    failures = []
    if term.get("status") != "proposed":
        failures.append(f"{name}: status must start proposed")
    if term.get("issuers_in_production") != []:
        failures.append(f"{name}: issuers_in_production must be empty")
    for key in ("check", *_REQUIRED_KEYS):
        if not str(term.get(key, "")).strip():
            failures.append(f"{name}: no {key}")
    return failures


def _check_definitions(name: str, term: dict) -> list[str]:
    """A term that lists values defines each of them and nothing else."""
    values = term.get("values")
    if values is None:
        return []
    defined = term.get("value_definitions") or {}
    missing = [v for v in values if not str(defined.get(v, "")).strip()]
    extra = sorted(set(defined) - set(values))
    if missing or extra:
        return [f"{name}: undefined values {missing}, stray definitions {extra}"]
    return []


def _check_guide(name: str, term: dict, page: str) -> list[str]:
    """The guide names the term and every value it lists."""
    failures = [] if f"`{name}`" in page else [f"{name}: the guide never names it"]
    for value in term.get("values") or []:
        if f"`{value}`" not in page:
            failures.append(f"{name}: the guide never names the value `{value}`")
    return failures


def _check_terms(section: dict, page: str) -> list[str]:
    failures = []
    if set(section) != _EXPECTED_TERMS:
        differ = sorted(set(section) ^ _EXPECTED_TERMS)
        failures.append(f"terms {differ} differ from the seven the section carries")
    for name, term in section.items():
        failures.extend(_check_fields(name, term))
        failures.extend(_check_definitions(name, term))
        failures.extend(_check_guide(name, term, page))
    return failures


def main() -> int:
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    try:
        vocab = yaml.safe_load(_VOCAB.read_text())
        page = _PAGE.read_text(encoding="utf-8")
        validator = _load_validator()
        registry = _load_registry()
        index = json.loads(_INDEX.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, ValueError) as exc:
        print(f"test_multi_agent_run: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None or registry is None:
        print("test_multi_agent_run: could not load the validator or the registry", file=sys.stderr)
        return 2

    section = vocab.get("multi_agent_run")
    if not isinstance(section, dict) or not section:
        print("FAIL: vocabulary.yaml has no multi_agent_run section")
        return 1
    failures = _check_terms(section, page)
    failures.extend(_check_closed_values(registry, index, section))
    ok = _run(validator, _crosswalk("multi_agent_run"))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("incident_response"))
    if not any("multi_agent_run" in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"test_multi_agent_run: {len(section)} terms and the guide agree; "
          "closed values accept and refuse as registered, both validator cases behave")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
