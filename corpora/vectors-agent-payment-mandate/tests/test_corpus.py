"""The corpus regenerates byte for byte, every rule is load-bearing, and a verifier
missing any one rule (a mutant) is caught by the corpus."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import paymentmandate  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("paymentmandate_generator", ROOT / "gen_vectors.py")
mutation = _load("paymentmandate_mutation", ROOT / "mutation_check.py")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import paymentmandate as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [
            ROOT / "MANIFEST.json",
            ROOT / "INDEX.md",
            ROOT / "profile.json",
            *(ROOT / "cases").rglob("*"),
        ]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = paymentmandate.check()
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_external_contract_agrees(tmp_path: Path) -> None:
    answered, errors = paymentmandate.check(_stub(tmp_path, ()))
    assert errors == []
    assert answered == len(generator.MEMBERS)


@pytest.mark.parametrize("rule", paymentmandate.RULES)
def test_a_mutant_verifier_missing_one_rule_is_caught(tmp_path: Path, rule: str) -> None:
    _, errors = paymentmandate.check(_stub(tmp_path, (rule,)))
    assert errors, f"a verifier without {rule} passed the whole corpus"
    assert any(e.split(":", 1)[0] for e in errors)


def test_every_rule_is_load_bearing() -> None:
    assert mutation.sweep() == []


def test_every_rejected_member_names_an_accepted_twin() -> None:
    entries = json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]
    accepted = {e["id"] for e in entries if e["expected"]["decision"] == "accepted"}
    assert accepted
    for e in entries:
        if e["expected"]["decision"] == "rejected":
            assert e["twin"] in accepted
    assert {
        e["expected"]["reason"] for e in entries if e["expected"]["decision"] == "rejected"
    } == set(paymentmandate.RULES)


def test_corpus_digest_recomputes_from_files() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]


def test_a_tampered_case_is_refused(tmp_path: Path) -> None:
    import shutil

    work = tmp_path / "copy"
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns("__pycache__", "tests"))
    target = next((work / "cases").iterdir()) / "case.json"
    target.write_text(target.read_text() + " ", encoding="utf-8")
    _, errors = paymentmandate.check(root=work)
    assert errors
