"""The corpus regenerates, forces every check in order, pins its RFC 8785 bytes, and
refuses a verifier, or a hop implementation, that lets the acting-agent marker fall."""

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


corpus = _load("actor_marker_corpus", ROOT / "check_vectors.py")
generator = _load("actor_marker_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import a2ajcs  # noqa: E402
from agent_evidence_vectors import actormarker as reader  # noqa: E402

CHECKS = reader.CHECKS
REJECTED = {c[0]: c[3] for c in generator.cases() if c[2] == "reject"}
ACCEPTED = [c[0] for c in generator.cases() if c[2] == "accept"]
TRUST = json.loads((ROOT / "TRUST.json").read_text(encoding="utf-8"))
HOP = f"{sys.executable} -m agent_evidence_vectors.actormarker --reference-hop"
PACKAGING = str(ROOT.parents[1] / "packaging")


@pytest.fixture(autouse=True)
def _children_import_the_package(monkeypatch: pytest.MonkeyPatch) -> None:
    """Subprocess verifiers and hops import the package from this tree."""
    monkeypatch.setenv("PYTHONPATH", PACKAGING)


def _record(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "cases" / name / "record.json").read_text(encoding="utf-8"))


def _failed(errors: list[str]) -> set[str]:
    return {e.split(":", 1)[0] for e in errors if "declared retained" not in e}


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", ROOT / "TRUST.json", *(ROOT / "cases").rglob("*")]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(generator.cases())


def test_every_check_has_its_own_member() -> None:
    assert set(REJECTED.values()) == set(CHECKS)
    assert len(ACCEPTED) >= 4


def test_signing_inputs_are_the_rfc8785_bytes_of_each_statement() -> None:
    for case in (ROOT / "cases").iterdir():
        record = _record(case.name)
        for index, item in enumerate(record["statements"]):
            pinned = (case / f"signing-input-{index}.jcs").read_bytes()
            assert pinned == a2ajcs.canonicalize(a2ajcs.parse(json.dumps(item["statement"])))


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_each_refusal_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _record(name), REJECTED[name]
    assert reader._first_failure(record, TRUST) == reason
    assert reader._first_failure(record, TRUST, frozenset(CHECKS[CHECKS.index(reason) :])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


@pytest.mark.parametrize("name", ACCEPTED)
def test_controls_hold_with_every_check_on(name: str) -> None:
    assert reader._first_failure(_record(name), TRUST) is None


def test_a_classifier_that_only_checks_containment_misses_reorder_and_insert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def contained(expected: tuple, sent: tuple) -> str | None:  # type: ignore[type-arg]
        return None if set(expected) <= set(sent) else "marker_stripped"

    monkeypatch.setattr(reader, "classify", contained)
    _, errors = corpus.check()
    assert {"actor-order-reversed-by-bridge", "actor-inserted"} <= _failed(errors)


def test_a_reader_that_trusts_unsigned_headers_misses_the_header_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reader._Chain, "unsigned_marker", lambda self: False)
    _, errors = corpus.check()
    assert _failed(errors) == {"marker-only-in-unsigned-header"}


def test_verifier_that_refuses_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "refuse.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "reject", "reason": "marker_stripped"}))\n'
        "sys.exit(1)\n",
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ACCEPTED) <= _failed(errors)


def test_verifier_that_accepts_everything_fails_every_refusal(tmp_path: Path) -> None:
    script = tmp_path / "accept.py"
    script.write_text(
        'import json\nprint(json.dumps({"decision": "accept", "reason": "marker_survives"}))\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(REJECTED) <= _failed(errors)


def test_the_reference_reader_as_an_external_verifier_agrees() -> None:
    answered, errors = corpus.check(f"{sys.executable} -m agent_evidence_vectors.actormarker")
    assert errors == []
    assert answered == len(generator.cases())


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0
    assert errors


def test_a_trust_bundle_that_moved_is_refused(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    (tmp_path / "TRUST.json").write_text("{}\n", encoding="ascii")
    answered, errors = corpus.check(root=tmp_path)
    assert answered == 0
    assert "TRUST.json" in errors[0]


# The hop contract ---------------------------------------------------------------------------


def test_reference_hop_survives_every_accepted_hop_and_refuses_the_critical_one() -> None:
    answered, total, errors = reader.hop_check(HOP)
    assert errors == []
    assert answered == total
    assert any(owed is None for _, _, owed in reader.hop_requests())


def _hop_script(tmp_path: Path, body: str) -> str:
    script = tmp_path / "hop.py"
    script.write_text(
        "import json, sys\nfrom agent_evidence_vectors import actormarker as m\n"
        "req = json.loads(sys.stdin.read())\n" + body,
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def test_a_hop_that_does_not_append_itself_fails(tmp_path: Path) -> None:
    command = _hop_script(
        tmp_path,
        "p = m.decode(req['received'])\n"
        "print(json.dumps({'protocol': req['send']['protocol'], "
        "'token': m.encode(req['send']['protocol'], p)}))\n",
    )
    _, _, errors = reader.hop_check(command)
    assert any("owed" in e for e in errors)


def test_a_hop_that_ignores_crit_fails(tmp_path: Path) -> None:
    command = _hop_script(
        tmp_path,
        "s, a = m.decode(req['received'])\n"
        "a = a + ((req['self'],) if req['role'] == 'agent' else ())\n"
        "print(json.dumps({'protocol': req['send']['protocol'], "
        "'token': m.encode(req['send']['protocol'], (s, a))}))\n",
    )
    _, _, errors = reader.hop_check(command)
    assert errors == [
        "unknown-critical-attribute-ignored#1: the hop forwarded a token with an "
        "unknown critical parameter"
    ]
