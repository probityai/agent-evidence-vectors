#!/usr/bin/env python3
"""Hold the registry, the validator and the guide to the principal_identity section.

The section's two terms each carry a `check`, the rule a verifier applies to decide
the term. This checks that every term starts proposed with no issuer, carries a
criticality, a review date, a definition and a promotion trigger, that a term declaring
closed values defines each of them, that every term has a non-empty check, that the guide
at docs/principal-identity.md names every term and every value, that every registered value
of every closed term is accepted and an unregistered one refused through
registry.check_value, and runs the real validator over one crosswalk that maps the
section and one that files its term under the wrong section, and holds
registry.identity_provider to a table of issuers. Nothing is restated here.

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
_PAGE = _ROOT / "docs" / "principal-identity.md"
_EXPECTED_TERMS = {"identity_provider", "issuer_key_pinning"}
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
        "system": "principal-identity-test",
        "system_url": "https://example.invalid/principal-identity-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.9.0",
        section: {"identity_provider": {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "principal-identity-test.yaml"
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
        failures.append(f"terms {differ} differ from the two the section carries")
    for name, term in section.items():
        failures.extend(_check_fields(name, term))
        failures.extend(_check_definitions(name, term))
        failures.extend(_check_guide(name, term, page))
    return failures


#: (issuer, declared, self_issuers, expected outcome, expected value)
_DERIVATIONS = (
    ("https://example.okta.com/oauth2/default", None, (), "ok", "okta"),
    ("https://example.oktapreview.com", None, (), "ok", "okta"),
    ("https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0", None, (), "ok", "entra"),
    ("https://sts.windows.net/00000000-0000-0000-0000-000000000000/", None, (), "ok", "entra"),
    ("https://example.ciamlogin.com/tenant/v2.0", None, (), "ok", "entra"),
    ("https://example.us.auth0.com/", None, (), "ok", "auth0"),
    ("https://sso.example.com/realms/agents", None, (), "ok", "keycloak"),
    ("https://sso.example.com/auth/realms/agents/", None, (), "ok", "keycloak"),
    ("https://sso.example.com/realms/agents/protocol", None, (), "ok", "other"),
    ("https://self-issued.me/v2", None, (), "ok", "self_issued"),
    ("https://gateway.example.com", None, ("https://gateway.example.com",), "ok", "self_issued"),
    ("https://id.example.com", None, (), "ok", "other"),
    ("https://id.example.com", "okta", (), "ok", "okta"),
    ("https://example.okta.com", "auth0", (), "malformed", "auth0"),
    ("https://example.okta.com", "okta", (), "ok", "okta"),
    ("https://notokta.com", None, (), "ok", "other"),
    ("http://example.okta.com", None, (), "malformed", "http://example.okta.com"),
    ("https://id.example.com", "ping", (), "malformed", "ping"),
)


def _check_derivations(registry) -> list[str]:
    """registry.identity_provider gives the expected outcome and value for each issuer."""
    failures = []
    for issuer, declared, own, outcome, value in _DERIVATIONS:
        judged = registry.identity_provider(issuer, declared, frozenset(own))
        if (judged.outcome, judged.value) != (outcome, value):
            failures.append(f"identity_provider({issuer!r}, {declared!r}) gave "
                            f"{judged.outcome} {judged.value!r}, expected {outcome} {value!r}")
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
        print(f"test_principal_identity: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None or registry is None:
        print("test_principal_identity: could not load the validator or the registry", file=sys.stderr)
        return 2

    section = vocab.get("principal_identity")
    if not isinstance(section, dict) or not section:
        print("FAIL: vocabulary.yaml has no principal_identity section")
        return 1
    failures = _check_terms(section, page)
    failures.extend(_check_closed_values(registry, index, section))
    failures.extend(_check_derivations(registry))
    ok = _run(validator, _crosswalk("principal_identity"))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("multi_agent_run"))
    if not any("principal_identity" in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"test_principal_identity: {len(section)} terms and the guide agree; "
          "closed values accept and refuse as registered, both validator cases behave, "
          f"{len(_DERIVATIONS)} issuer derivations agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
