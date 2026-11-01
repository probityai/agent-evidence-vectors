"""Hold the registry and registry.py to meta.open_value_rule and verdict_classes.

    python3 scripts/test_open_enums.py

Each case names the rule it holds. A synthetic child code is added to a copy of
the registry, never to vocabulary.yaml, because no issuer has registered one.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gen = _load("gen_registry_index", ROOT / "scripts" / "gen_registry_index.py")
registry = _load("registry", ROOT / "registry.py")

SOURCE = (ROOT / "vocabulary.yaml").read_bytes()
INDEX, BUILD_FAILURES = gen.build(SOURCE)
OWN = INDEX["source_sha256"]
FOREIGN = "f" * 64


def _with_child(code: str, parent: str) -> dict:
    data = yaml.safe_load(SOURCE)
    data["verdict_classes"]["children"] = {code: {"parent": parent}}
    index, failures = gen.build(yaml.safe_dump(data).encode())
    assert failures == [], failures
    return index


def test_registry_builds_and_every_term_declares_criticality():
    assert BUILD_FAILURES == [], BUILD_FAILURES
    assert all(t["criticality"] in ("critical", "informational") for t in INDEX["terms"].values())


def test_a_term_without_criticality_is_refused():
    data = yaml.safe_load(SOURCE)
    del data["evidence_dimensions"]["observation_vantage"]["criticality"]
    _, failures = gen.build(yaml.safe_dump(data).encode())
    assert any(f.startswith("observation_vantage: criticality") for f in failures), failures


def test_registry_json_is_generated_from_this_file():
    assert gen.main(["--check"]) == 0


def test_digest_in_a_record_matches_the_published_registry():
    assert OWN == hashlib.sha256(SOURCE).hexdigest() == registry.digest_of(SOURCE)
    published = ROOT.parents[1] / "pages" / "vocab" / "v1" / "registry" / f"sha256-{OWN}.yaml"
    assert published.is_file(), f"no published registry at {published}"
    assert hashlib.sha256(published.read_bytes()).hexdigest() == OWN


def test_unknown_child_under_known_parent_reads_as_the_parent():
    j = registry.resolve_verdict(INDEX, {"class": "egress_to_unlisted_host", "parent": "fail"}, FOREIGN)
    assert (j.outcome, j.meaning, j.value) == (registry.OK, "fail", "egress_to_unlisted_host")


def test_unknown_child_is_malformed_under_a_registry_the_verifier_holds():
    for digest in (OWN, None):
        j = registry.resolve_verdict(INDEX, {"class": "egress_to_unlisted_host", "parent": "fail"}, digest)
        assert j.outcome == registry.MALFORMED, digest
    j = registry.resolve_verdict(INDEX, {"class": "x", "parent": "fail"}, FOREIGN, frozenset({FOREIGN}))
    assert j.outcome == registry.MALFORMED


def test_unknown_parent_is_refused_in_every_case():
    for digest in (OWN, None, FOREIGN):
        j = registry.resolve_verdict(INDEX, {"class": "x", "parent": "catastrophic"}, digest)
        assert j.outcome == registry.MALFORMED, digest


def test_a_parent_carried_as_its_own_class_is_the_parent():
    for parent in INDEX["verdict_classes"]["parents"]:
        assert registry.resolve_verdict(INDEX, {"class": parent, "parent": parent}, OWN).meaning == parent


def test_registered_child_must_carry_its_registered_parent():
    index = _with_child("egress_to_unlisted_host", "fail")
    assert registry.resolve_verdict(index, {"class": "egress_to_unlisted_host", "parent": "fail"}, OWN).meaning == "fail"
    j = registry.resolve_verdict(index, {"class": "egress_to_unlisted_host", "parent": "pass"}, FOREIGN)
    assert j.outcome == registry.MALFORMED


def test_a_child_with_an_unregistered_parent_does_not_build():
    data = yaml.safe_load(SOURCE)
    data["verdict_classes"]["children"] = {"x": {"parent": "catastrophic"}}
    _, failures = gen.build(yaml.safe_dump(data).encode())
    assert any("verdict_classes.x" in f for f in failures), failures


def test_criticality_decides_an_unknown_value_under_another_registry():
    assert INDEX["terms"]["observation_vantage"]["criticality"] == "critical"
    assert INDEX["terms"]["revision_reason"]["criticality"] == "informational"
    j = registry.check_value(INDEX, "observation_vantage", "hypervisor_introspection", FOREIGN)
    assert (j.outcome, j.value) == (registry.DEGRADED, "hypervisor_introspection")
    j = registry.check_value(INDEX, "revision_reason", "late_backfill", FOREIGN)
    assert (j.outcome, j.value) == (registry.IGNORED, "late_backfill")


def test_an_unknown_value_is_malformed_under_exact_checking():
    for digest in (OWN, None):
        for term, value in (("observation_vantage", "hypervisor_introspection"), ("revision_reason", "late_backfill")):
            assert registry.check_value(INDEX, term, value, digest).outcome == registry.MALFORMED


def test_a_registered_value_passes_in_every_case():
    for digest in (OWN, None, FOREIGN):
        assert registry.check_value(INDEX, "observation_vantage", "substrate", digest).outcome == registry.OK


def test_term_uris_follow_the_rule():
    base = "https://w3id.org/agent-evidence/vocab/v1/"
    assert all(t["uri"] == base + name for name, t in INDEX["terms"].items())


def main() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}", file=sys.stderr)
    print(f"{len(tests) - failed} of {len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
