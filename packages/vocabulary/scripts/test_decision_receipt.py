#!/usr/bin/env python3
"""Hold the registry, the validator, the guide and the vectors to the decision_receipt section.

The section's terms each carry a `check`. This checks that every term starts proposed with no
issuer, carries the keys every term carries, defines each closed value, that the guide at
docs/decision-receipt.md names every term and value, that every registered value is accepted and an
unregistered one refused, that vectors/decision-receipt/manifest.json is the output of its generator,
that registry.py derives from each case exactly the value or refusal the case states (with both
polarities present for every term the vectors cover), and runs the real validator over a crosswalk that
maps the section and one that files its term under the wrong section.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))
import test_principal_identity as shared

_PAGE = _ROOT / "docs" / "decision-receipt.md"
_MANIFEST = _ROOT / "vectors" / "decision-receipt" / "manifest.json"
_GENERATOR = _ROOT / "scripts" / "gen_decision_receipt_vectors.py"
_EXPECTED_TERMS = {
    "decision_verdict", "request_commitment", "policy_commitment", "trust_root_commitment",
    "revocation_list_in_force", "receipt_chain_link", "possession_proof", "decision_code",
    "enforcement_point_label", "correlation_handle", "upstream_receipt",
}
_VECTORED = _EXPECTED_TERMS - {"decision_verdict", "enforcement_point_label", "correlation_handle"}
_ORDER = ["allow", "constrain", "require_approval", "block", "halt"]


def _derive(registry, case: dict):
    term, given = case["term"], case["input"]
    held = given["bytes"].encode() if "bytes" in given else None
    if term == "request_commitment":
        return registry.request_commitment(given["decision"], held)
    if term == "policy_commitment":
        return registry.policy_commitment(given["decision"], held)
    if term == "trust_root_commitment":
        return registry.trust_root_commitment(given["decision"], held)
    if term == "revocation_list_in_force":
        return registry.revocation_list_in_force(given["decision"], held)
    if term == "receipt_chain_link":
        return registry.receipt_chain_link(given["records"], given.get("anchor"))
    if term == "possession_proof":
        return registry.possession_proof(given["decision"], frozenset(given.get("seen", [])))
    if term == "decision_code":
        known = frozenset(given["known"]) if "known" in given else None
        return registry.decision_code(given["decision"], known)
    if term == "upstream_receipt":
        return registry.upstream_receipt(given["upstream"], given.get("fetched"), checked=given.get("checked", True))
    raise KeyError(term)


def _check_case(registry, case: dict) -> list[str]:
    got = _derive(registry, case)
    want = case["expect"]
    failures = []
    if got.refused != want["refused"] or got.value != want["value"]:
        failures.append(f"{case['id']}: derived {got.value!r} refused={got.refused} ({got.reason}), "
                        f"expected {want['value']!r} refused={want['refused']}")
    if "reason" in want and got.reason != want["reason"]:
        failures.append(f"{case['id']}: reason {got.reason!r}, expected {want['reason']!r}")
    return failures


def _check_vectors(registry, cases: list[dict]) -> list[str]:
    failures = []
    for case in cases:
        failures.extend(_check_case(registry, case))
    for term in sorted(_VECTORED):
        polarities = {c["polarity"] for c in cases if c["term"] == term}
        if polarities != {"positive", "negative"}:
            failures.append(f"{term}: vectors hold {sorted(polarities)}, need both polarities")
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        failures.append("duplicate case ids")
    return failures


def _check_generated() -> list[str]:
    spec = importlib.util.spec_from_file_location("gen_decision_receipt_vectors", _GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    current = _MANIFEST.read_text(encoding="utf-8")
    return [] if current == module.render() else ["vectors/decision-receipt/manifest.json is not the generator's output"]


def _check_upstream_unreachable_is_uniform(registry) -> list[str]:
    """Every way of failing to obtain a record is one outcome with one reason."""
    upstream = {"provider": "p", "generationId": "g", "recheckUrl": "https://p.example/g", "fact": {"a": 1}}
    outcomes = {registry.upstream_receipt(upstream, fetched).reason for fetched in (None, "expired", 404, [], "")}
    return [] if len(outcomes) == 1 else [f"unreachable gave {len(outcomes)} different reasons"]


def _check_order(index: dict) -> list[str]:
    values = index["terms"]["decision_verdict"]["values"]
    return [] if values == _ORDER else [f"decision_verdict values {values} are not the strictness order {_ORDER}"]


def main() -> int:
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    try:
        vocab = yaml.safe_load(shared._VOCAB.read_text())
        page = _PAGE.read_text(encoding="utf-8")
        validator = shared._load_validator()
        registry = shared._load_registry()
        index = json.loads(shared._INDEX.read_text(encoding="utf-8"))
        cases = json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"]
    except (OSError, yaml.YAMLError, ValueError, KeyError) as exc:
        print(f"test_decision_receipt: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None or registry is None:
        print("test_decision_receipt: could not load the validator or the registry", file=sys.stderr)
        return 2
    section = vocab.get("decision_receipt")
    if not isinstance(section, dict) or not section:
        print("FAIL: vocabulary.yaml has no decision_receipt section")
        return 1
    failures = []
    if set(section) != _EXPECTED_TERMS:
        failures.append(f"terms {sorted(set(section) ^ _EXPECTED_TERMS)} differ from the ones the section carries")
    for name, term in section.items():
        failures.extend(shared._check_fields(name, term))
        failures.extend(shared._check_definitions(name, term))
        failures.extend(shared._check_guide(name, term, page))
    failures.extend(shared._check_closed_values(registry, index, section))
    failures.extend(_check_order(index))
    failures.extend(_check_generated())
    failures.extend(_check_vectors(registry, cases))
    failures.extend(_check_upstream_unreachable_is_uniform(registry))
    crosswalk = shared._crosswalk("decision_receipt")
    crosswalk["decision_receipt"] = {"decision_verdict": {"match": "no_mapping", "notes": "test fixture"}}
    ok = shared._run(validator, crosswalk)
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong_data = shared._crosswalk("multi_agent_run")
    wrong_data["multi_agent_run"] = {"decision_verdict": {"match": "no_mapping", "notes": "test fixture"}}
    wrong = shared._run(validator, wrong_data)
    if not any("decision_receipt" in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")
    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    digest = hashlib.sha256(_MANIFEST.read_bytes()).hexdigest()[:12]
    print(f"test_decision_receipt: {len(section)} terms, the guide and {len(cases)} vectors agree "
          f"(manifest {digest}); closed values accept and refuse as registered, both validator cases behave")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
