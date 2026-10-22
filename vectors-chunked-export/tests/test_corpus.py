"""The corpus regenerates, forces every check, and refuses a gate that reads only
the per-step labels."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/chunked-export/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("chunked_export_corpus", ROOT / "check_vectors.py")
generator = _load("chunked_export_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import chunkedexport  # noqa: E402

# Members whose every exported chunk is reversible on its own and which a gate
# must still deny or call understated: the composition decides them.
COMPOSITION_DECIDED = {"variant-a-at-crossing", "variant-a-final-chunk",
                       "variant-a-max-of-labels-seal", "sets-key-field-chunk-alone",
                       "count-same-three-chunks", "sets-key-field-max-of-labels-seal"}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import chunkedexport as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _max_of_labels_gate(tmp_path: Path) -> str:
    """A gate that derives the class as the maximum of the per-step labels."""
    script = tmp_path / "labels.py"
    script.write_text(
        "import json, sys\n"
        "r = json.load(open(sys.argv[1]))\n"
        "label = 'irreversible' if any(c['stepClass'] == 'irreversible' "
        "for c in r['chunks']) else 'reversible'\n"
        "if 'contractId' not in r:\n"
        "    a = {'decision': 'deny', 'reason': 'contract_id_missing'}\n"
        "elif r['contractId'] != " + repr(CONTRACT_ID) + ":\n"
        "    a = {'decision': 'deny', 'reason': 'contract_id_unknown'}\n"
        "elif r['reconstruction']['committedAt'] > min(c['leftAt'] for c in r['chunks']):\n"
        "    a = {'decision': 'deny', 'reason': 'threshold_not_precommitted'}\n"
        "elif r['seal']['maxClass'] != label:\n"
        "    a = {'decision': 'deny', 'reason': 'seal_understates_composition'}\n"
        "elif label == 'irreversible':\n"
        "    a = {'decision': 'deny', 'reason': 'export_irreversible'}\n"
        "else:\n"
        "    a = {'decision': 'allow', 'reason': 'reversible_so_far'}\n"
        "print(json.dumps(a))\n"
        "sys.exit(0 if a['decision'] == 'allow' else 1)\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _records() -> dict[str, dict]:  # type: ignore[type-arg]
    return {p.parent.name: json.loads(p.read_text(encoding="utf-8"))
            for p in (ROOT / "cases").glob("*/record.json")}


class TestChunkedExportCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_every_record_but_the_contract_cases_carries_the_contract_id(self) -> None:
            records = _records()
            assert "contractId" not in records["contract-id-missing"]
            assert records["contract-id-unknown"]["contractId"] != CONTRACT_ID
            others = {k: v for k, v in records.items()
                      if k not in {"contract-id-missing", "contract-id-unknown"}}
            assert others and all(r["contractId"] == CONTRACT_ID for r in others.values())
            assert chunkedexport.CONTRACT_ID == CONTRACT_ID

        def test_composition_cases_have_only_reversible_steps(self) -> None:
            records = _records()
            for name in COMPOSITION_DECIDED:
                assert all(c["stepClass"] == "reversible" for c in records[name]["chunks"]), name

        def test_variant_a_permits_below_and_denies_from_the_crossing(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
            expected = {e["id"]: e["expected"]["decision"] for e in manifest["vectors"]}
            assert expected["variant-a-below-threshold"] == "allow"
            assert expected["variant-a-at-crossing"] == "deny"
            assert expected["variant-a-final-chunk"] == "deny"

        def test_count_and_sets_disagree_on_the_same_chunks(self) -> None:
            records = _records()
            assert records["count-same-three-chunks"]["exported"] == records[
                "sets-three-chunks-no-reconstructing-set"]["exported"]
            assert chunkedexport.composed_class(records["count-same-three-chunks"]) != \
                chunkedexport.composed_class(records["sets-three-chunks-no-reconstructing-set"])

    class TestFailingCases:
        def test_max_of_labels_gate_is_refused_on_every_composition_case(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_max_of_labels_gate(tmp_path))
            assert _failed(errors) == COMPOSITION_DECIDED

        @pytest.mark.parametrize("name", chunkedexport.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "export_irreversible"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert {"variant-a-below-threshold",
                    "sets-three-chunks-no-reconstructing-set"} <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "variant-a-below-threshold" / "chunk-0.bin").write_bytes(b"other")
            _, errors = corpus.check(root=copied)
            assert "variant-a-below-threshold: fixture digest mismatch" in errors

        def test_unknown_rule_kind_is_an_error(self) -> None:
            with pytest.raises(ValueError, match="unknown reconstruction rule kind"):
                chunkedexport.rule_holds({"kind": "entropy"}, {0})
