"""The credential-release corpus regenerates, every case reaches its declared verdict, and
every check is forced by some case."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import cardreceipt as reader  # noqa: E402

SUITE = reader.RELEASE_SUITE
CHECKS = reader.CHECKS[SUITE]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("credential_release_generator", ROOT / "gen_vectors.py")
CASES = {name: (decision, reason) for name, _, _, decision, reason in generator.cases()}
REJECTED = {name: reason for name, (decision, reason) in CASES.items() if decision == "reject"}


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _stub(tmp_path: Path, answer: str) -> str:
    script = tmp_path / "stub.py"
    script.write_text(answer, encoding="ascii")
    return f"{sys.executable} {script}"


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")] if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = reader.check(SUITE)
    assert errors == []
    assert answered == len(CASES)


def test_both_decisions_are_present() -> None:
    assert set(REJECTED) and len(REJECTED) < len(CASES)


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = reader.check(SUITE, skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_each_rejected_case_passes_every_earlier_check(name: str) -> None:
    reason = REJECTED[name]
    later = frozenset(CHECKS[CHECKS.index(reason):])
    directory = ROOT / "cases" / name
    assert reader.verify(SUITE, directory) == {"decision": "reject", "reason": reason}
    assert reader.verify(SUITE, directory, later)["decision"] == "accept"


def test_reference_reader_through_the_external_contract(tmp_path: Path) -> None:
    command = _stub(tmp_path, (
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import cardreceipt as m\n"
        "answer = m.verify(sys.argv[1], Path(sys.argv[2]))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n"))
    answered, errors = reader.check(SUITE, command)
    assert errors == []
    assert answered == len(CASES)


def test_verifier_that_accepts_everything_fails_the_rejections(tmp_path: Path) -> None:
    command = _stub(tmp_path, 'import json\nprint(json.dumps({"decision": "accept", '
                    f'"reason": {reader.PASS_REASON[SUITE]!r}}}))\n')
    _, errors = reader.check(SUITE, command)
    assert _failed(errors) == set(REJECTED)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = reader.check(SUITE, str(tmp_path / "no-such-verifier"))
    assert answered == 0
    assert errors and all("verifier did not run" in error for error in errors)


def test_mutated_fixture_is_refused_before_execution(tmp_path: Path) -> None:
    copied = tmp_path / "corpus"
    shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    first = sorted(set(CASES) - set(REJECTED))[0]
    path = copied / "cases" / first / "statement.json"
    path.write_bytes(path.read_bytes() + b" ")
    _, errors = reader.check(SUITE, root=copied)
    assert f"{first}: fixture digest mismatch" in errors


def test_manifest_digest_covers_the_entries(tmp_path: Path) -> None:
    copied = tmp_path / "corpus"
    shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    manifest = json.loads((copied / "MANIFEST.json").read_text(encoding="utf-8"))
    manifest["vectors"][0]["edit"] += " (edited)"
    (copied / "MANIFEST.json").write_bytes(generator.enc(manifest))
    assert reader.check(SUITE, root=copied) == (0, ["manifest digest mismatch"])
