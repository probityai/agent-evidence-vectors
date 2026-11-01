"""The corpus regenerates, forces every condition, and refuses an approve-everything verifier."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import openweight  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("open_weight_generator", ROOT / "gen_vectors.py")
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
TOTAL = len(MANIFEST["vectors"])


def _release(**changes: object) -> dict:
    release = json.loads(json.dumps(generator.GOOD))
    release.update(changes)
    return release


class TestOpenWeightCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_reference_reader_answers_every_case(self) -> None:
            answered, errors = openweight.check()
            assert (answered, errors) == (TOTAL, [])

        def test_every_condition_is_forced_in_both_directions(self) -> None:
            reasons = {v["expected"]["reason"] for v in MANIFEST["vectors"]}
            for name in openweight.CONDITIONS:
                broken = [r for r in reasons if r != "all_conditions_evidenced"
                          and _condition_of(r) == name]
                assert broken, f"no case breaks the {name} condition"
            assert "all_conditions_evidenced" in reasons

        def test_exemption_does_not_remove_the_copyright_duties(self) -> None:
            answer = openweight.assess(_release(copyright_policy={}, training_summary={}))
            assert answer["decision"] == openweight.EXEMPT
            assert answer["remaining"] == {"Article 53(1)(c)": False, "Article 53(1)(d)": False}

        def test_compute_at_the_threshold_is_not_presumed_systemic(self) -> None:
            at = _release(training={"compute_flop": openweight.COMPUTE_THRESHOLD_FLOP})
            over = _release(training={"compute_flop": 1.0000001e25})
            assert openweight.assess(at)["decision"] == openweight.EXEMPT
            assert openweight.assess(over)["reason"] == "systemic_risk_presumed"

    class TestFailingCases:
        def test_one_failure_is_enough(self) -> None:
            for name, change in {
                "licence": {"licence": {"spdx": "CC-BY-NC-4.0"}},
                "weights": {"weights": {"access": "private"}},
                "monetisation": {"monetisation": ["login"]},
            }.items():
                answer = openweight.assess(_release(**change))
                assert answer["decision"] == openweight.NOT_EXEMPT, name

        def test_a_designation_outranks_a_recorded_rebuttal(self) -> None:
            risk = {"commission_designation": "https://example.org/d",
                    "commission_decision_not_systemic": "https://example.org/n"}
            assert openweight.assess(_release(systemic_risk=risk))["reason"] == \
                "systemic_risk_designated"

        def test_not_exempt_outranks_not_established(self) -> None:
            answer = openweight.assess(_release(architecture={}, monetisation=["login"]))
            assert (answer["decision"], answer["reason"]) == (
                openweight.NOT_EXEMPT, "monetised_release")
            assert answer["findings"]["architecture"] == "architecture_not_evidenced"

        def test_a_boolean_or_zero_compute_is_not_a_stated_compute(self) -> None:
            for value in (True, 0, -1, "3e24"):
                answer = openweight.assess(_release(training={"compute_flop": value}))
                assert answer["reason"] == "training_compute_not_stated", value

        def test_a_non_https_locator_is_not_evidence(self) -> None:
            answer = openweight.assess(_release(usage={"url": "file:///etc/passwd"}))
            assert answer["reason"] == "usage_information_not_evidenced"

        def test_a_malformed_digest_is_not_a_binding(self) -> None:
            weights = {"access": "public", "url": "https://example.org/w", "sha256": "ABC"}
            assert openweight.assess(_release(weights=weights))["reason"] == \
                "weights_not_digest_bound"

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = openweight.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert len(errors) == TOTAL

        def test_an_approve_everything_verifier_is_refused(self, tmp_path: Path) -> None:
            script = tmp_path / "approve.py"
            script.write_text('import json\nprint(json.dumps({"decision": "exempt", '
                              '"reason": "all_conditions_evidenced"}))\n', encoding="utf-8")
            answered, errors = openweight.check([sys.executable, str(script)])
            exempt = sum(v["expected"]["decision"] == "exempt" for v in MANIFEST["vectors"])
            assert answered == TOTAL
            assert len(errors) == TOTAL - exempt

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "cases" / "exempt-open-release" / "release.json"
            path.write_bytes(path.read_bytes().replace(b"Apache-2.0", b"CC-BY-NC-4.0"))
            answered, errors = openweight.check(root=copied)
            assert any("fixture digest mismatch" in error for error in errors)
            assert answered == TOTAL - 1

        def test_unreadable_record_exits_two(self, tmp_path: Path) -> None:
            bad = tmp_path / "release.json"
            bad.write_text("not json", encoding="utf-8")
            assert openweight.main([str(bad)]) == 2


def _condition_of(reason: str) -> str:
    table = {"licence": ("licence_",), "weights": ("weights_",),
             "architecture": ("architecture_",), "usage": ("usage_",),
             "monetisation": ("monetis",), "systemic_risk": ("systemic_", "training_")}
    return next(name for name, prefixes in table.items() if reason.startswith(prefixes))
