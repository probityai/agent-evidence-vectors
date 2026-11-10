"""The corpus regenerates, every check is forced, and every case flips when its check is removed."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("principal_action_corpus", ROOT / "check_vectors.py")
generator = _load("principal_action_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import principalaction  # noqa: E402

ALL_CHECKS = (
    set(principalaction.STATEMENT_CHECKS)
    | set(principalaction.PRINCIPAL_CHECKS)
    | set(principalaction.BLOCK_CHECKS)
)


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def _rejects() -> list[dict]:  # type: ignore[type-arg]
    return [e for e in _manifest()["vectors"] if e["expected"]["decision"] == "rejected"]


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import principalaction as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


class TestPrincipalActionCorpus:
    def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
        generator.generate(tmp_path)
        committed = {
            p.relative_to(ROOT): p.read_bytes()
            for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
            if p.is_file()
        }
        regenerated = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        assert regenerated == committed

    def test_reference_reader_agrees_with_every_case(self) -> None:
        answered, errors = corpus.check()
        assert errors == []
        assert answered == len(generator.cases())

    def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
        answered, errors = corpus.check(_stub(tmp_path, ()))
        assert errors == []
        assert answered == len(generator.cases())

    def test_every_check_has_a_case(self) -> None:
        codes = {e["expected"]["reason"].split(":")[-1] for e in _rejects()}
        assert codes == ALL_CHECKS

    @pytest.mark.parametrize("entry", _rejects(), ids=lambda e: e["id"])
    def test_removing_the_check_flips_its_case(self, entry: dict) -> None:  # type: ignore[type-arg]
        code = entry["expected"]["reason"].split(":")[-1]
        case = ROOT / entry["path"] / "case.json"
        assert principalaction.verify(case) == entry["expected"]
        assert principalaction.verify(case, frozenset({code})) != entry["expected"]

    def test_a_verifier_that_skips_a_check_is_caught(self, tmp_path: Path) -> None:
        _, errors = corpus.check(_stub(tmp_path, ("principal_key_not_pinned",)))
        assert [e.split(":", 1)[0] for e in errors] == ["agent-key-not-pinned"]

    def test_pins_are_policy_not_record(self) -> None:
        # Emptying the verifier's pin set refuses every case that reached the pin check.
        case = ROOT / "cases" / "strict-four-principals" / "case.json"
        producer, record, _ = principalaction._load(case)
        answer = principalaction._decide(producer, record, {}, frozenset())
        assert answer == {"decision": "rejected", "reason": "principal_user:principal_issuer_untrusted"}

    def test_grades(self) -> None:
        verified = {e["id"]: e["expected"] for e in _manifest()["vectors"] if e["expected"]["decision"] == "verified"}
        assert verified["strict-four-principals"]["reason"] == "strict"
        assert verified["basic-four-principals-act-absent"] == {
            "decision": "verified", "delegation": "act-absent", "reason": "basic"}
        assert verified["basic-user-agent-act-chain"]["reason"] == "basic"
