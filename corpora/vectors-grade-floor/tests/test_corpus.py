"""The corpus regenerates byte for byte, every rule is load-bearing, and the
external contract agrees with the reference reader."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import gradefloor  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("grade_floor_generator", ROOT / "gen_vectors.py")
mutation = _load("grade_floor_mutation", ROOT / "mutation_check.py")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import gradefloor as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", ROOT / "INDEX.md", *(ROOT / "cases").rglob("*")]
                 if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = gradefloor.check()
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_external_contract_agrees(tmp_path: Path) -> None:
    answered, errors = gradefloor.check(_stub(tmp_path, ()))
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_a_verifier_trusting_the_declared_grade_is_refused(tmp_path: Path) -> None:
    _, errors = gradefloor.check(_stub(tmp_path, ("declared_grade_ignored",)))
    assert {e.split(":", 1)[0] for e in errors} >= {"e0-self-stamped-e4"}


def test_every_rule_is_load_bearing() -> None:
    assert mutation.sweep() == []


def test_every_grade_has_an_accepted_member_and_a_rejected_twin() -> None:
    entries = json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]
    accepted = {e["expected"]["derivedGrade"] for e in entries
                if e["expected"]["decision"] == "accepted"}
    assert accepted == set(gradefloor.GRADES)
    twins = {e["twin"] for e in entries if e["expected"]["decision"] == "rejected"}
    assert twins == {e["id"] for e in entries if e["expected"]["decision"] == "accepted"}


def test_corpus_digest_recomputes_from_files() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]
