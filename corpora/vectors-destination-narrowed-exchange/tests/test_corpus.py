"""The corpus regenerates, forces every check in order, pins its RFC 8785 bytes, and
refuses a verifier that reads a narrowed destination as narrowed rights."""

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


corpus = _load("dest_exchange_corpus", ROOT / "check_vectors.py")
generator = _load("dest_exchange_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import a2ajcs  # noqa: E402
from agent_evidence_vectors import destexchange as reader  # noqa: E402

CHECKS = reader.CHECKS
CASES = generator.cases()
REJECTED = {c[0]: c[3] for c in CASES if c[2] == "reject"}
ACCEPTED = [c[0] for c in CASES if c[2] == "accept"]
TRUST = json.loads((ROOT / "TRUST.json").read_text(encoding="utf-8"))
PACKAGING = str(ROOT.parents[1] / "packaging")


@pytest.fixture(autouse=True)
def _children_import_the_package(monkeypatch: pytest.MonkeyPatch) -> None:
    """Subprocess verifiers import the package from this tree."""
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
    assert answered == len(CASES)


def test_every_check_has_its_own_member() -> None:
    assert set(REJECTED.values()) == set(CHECKS)
    assert len(ACCEPTED) >= 5


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
    later = frozenset(CHECKS[CHECKS.index(reason) + 1 :])
    assert reader._first_failure(record, TRUST, later) == reason
    assert reader._first_failure(record, TRUST, frozenset({reason})) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


@pytest.mark.parametrize("name", ACCEPTED)
def test_controls_hold_with_every_check_on(name: str) -> None:
    assert reader._first_failure(_record(name), TRUST) is None


def test_a_reader_that_treats_a_narrowed_destination_as_narrowed_rights_misses_three(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The design the profile tests: the destination limit holds and rights are not read."""
    monkeypatch.setattr(reader, "rights", lambda *args: None)
    _, errors = corpus.check()
    assert _failed(errors) == {
        "rights-beyond-destination",
        "rights-not-narrowed",
        "rights-widened-while-destination-narrowed",
    }


def test_a_reader_that_trusts_lifetime_alone_misses_holder_binding_and_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("unbound", "proof_missing", "proof_invalid", "revoked"):
        monkeypatch.setattr(reader._Chain, name, lambda self: False)
    _, errors = corpus.check()
    assert {
        "delegated-token-bearer",
        "holder-proof-missing",
        "holder-proof-other-key",
        "holder-proof-signature-invalid",
        "holder-proof-for-another-token",
        "holder-proof-for-another-exchanger",
        "delegated-token-revoked-before-exchange",
        "revoked-at-the-second-of-exchange",
    } <= _failed(errors)


def test_a_reader_that_reads_only_the_last_actor_misses_the_dropped_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def last_only(received: tuple, exchanger: str, sent: tuple) -> str | None:  # type: ignore[type-arg]
        return None if sent and sent[-1] == exchanger and received[-1] in sent else "x"

    monkeypatch.setattr(reader, "classify", last_only)
    _, errors = corpus.check()
    assert {"previous-hop-dropped", "chain-reordered-at-exchange"} <= _failed(errors)


def test_the_allowlist_digest_binds_the_pinned_list() -> None:
    edited = json.loads(json.dumps(TRUST))
    edited["destinations"]["billing"] = {"verifier": "verifier:billing"}
    assert reader.allowlist_digest(edited) != reader.allowlist_digest(TRUST)
    record = _record("accept-single-destination")
    assert reader._first_failure(record, edited) == "destination_check_skipped"


def test_verifier_that_refuses_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "refuse.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "reject", "reason": "rights_widened"}))\n'
        "sys.exit(1)\n",
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ACCEPTED) <= _failed(errors)


def test_verifier_that_accepts_everything_fails_every_refusal(tmp_path: Path) -> None:
    script = tmp_path / "accept.py"
    script.write_text(
        'import json\nprint(json.dumps({"decision": "accept", "reason": "exchange_narrowed"}))\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(REJECTED) <= _failed(errors)


def test_the_reference_reader_as_an_external_verifier_agrees() -> None:
    answered, errors = corpus.check(f"{sys.executable} -m agent_evidence_vectors.destexchange")
    assert errors == []
    assert answered == len(CASES)


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


def test_a_record_out_of_time_order_is_malformed() -> None:
    record = _record("accept-two-destinations")
    record["statements"][2], record["statements"][3] = (
        record["statements"][3],
        record["statements"][2],
    )
    assert reader._first_failure(record, TRUST) == "record_malformed"
