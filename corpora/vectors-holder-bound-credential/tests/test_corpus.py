"""The corpus regenerates, forces every check in order, and refuses a verifier that accepts a
proof a stranger could have made."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("holder_bound_corpus", ROOT / "check_vectors.py")
generator = _load("holder_bound_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import holderbound as reader  # noqa: E402

CHECKS = reader.CHECKS
REJECTED = {c[0]: c[3] for c in generator.cases() if c[2] == "reject"}
ACCEPTED = [c[0] for c in generator.cases() if c[2] == "accept"]


def _record(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "cases" / name / "record.json").read_text(encoding="utf-8"))


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
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


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_each_refusal_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _record(name), REJECTED[name]
    assert reader._first_failure(record) == reason
    assert reader._first_failure(record, frozenset(CHECKS[CHECKS.index(reason) :])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_skipping_a_check_lets_its_member_through_to_a_later_one(name: str) -> None:
    members = [n for n, r in REJECTED.items() if r == name]
    for member in members:
        later = reader._first_failure(_record(member), frozenset({name}))
        assert later != name


def test_the_two_boundaries_of_the_validity_window_are_half_open() -> None:
    assert reader.judge(_record("accept-request-at-credential-start"))["decision"] == "accept"
    assert reader.judge(_record("used-at-expiry")) == {
        "decision": "reject",
        "reason": "credential_expired",
    }


def test_a_proof_signed_by_another_key_with_a_valid_signature_is_still_refused() -> None:
    record = _record("proof-signed-by-other-key")
    assert reader.judge(record, frozenset({"proof_key_not_bound"}))["decision"] == "accept"
    assert reader.judge(record)["reason"] == "proof_key_not_bound"


def test_the_corpus_refuses_a_verifier_that_accepts_everything(tmp_path: Path) -> None:
    script = tmp_path / "yes.py"
    script.write_text(
        "import json,sys\nprint(json.dumps({'decision':'accept','reason':'holder_bound'}))\n",
        encoding="utf-8",
    )
    answered, errors = corpus.check(f"{sys.executable} {script}")
    assert answered == len(generator.cases())
    assert len(errors) == len(REJECTED)


def test_the_corpus_refuses_a_verifier_with_the_wrong_exit_status(tmp_path: Path) -> None:
    script = tmp_path / "bad_exit.py"
    script.write_text(
        "import json,sys\nprint(json.dumps({'decision':'reject','reason':'x'}))\nsys.exit(0)\n",
        encoding="utf-8",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert errors and all("disagrees" in e or "expected" in e for e in errors)


def test_a_malformed_record_file_is_a_refusal_never_a_crash(tmp_path: Path) -> None:
    for text in ("{", "[]", '{"a": 1, "a": 2}', ""):
        path = tmp_path / "record.json"
        path.write_text(text, encoding="utf-8")
        assert reader.verify(path) == {"decision": "reject", "reason": "record_malformed"}


def test_no_case_carries_a_private_key_member_except_the_one_that_must() -> None:
    leaks = []
    for case in (ROOT / "cases").iterdir():
        text = (case / "record.json").read_text(encoding="utf-8")
        record = json.loads(text)
        for item in record.get("presentations", []):
            head = json.loads(reader.unb64url(item["proof"]["protected"]) or b"{}")
            if "d" in head.get("jwk", {}):
                leaks.append(case.name)
    assert leaks == ["proof-jwk-has-private-member"]


def _small_order_keys() -> list[bytes]:
    import run_vectors as rail

    found = []
    for y in [*range(2), rail._P - 1]:
        for sign in (0, 1):
            raw = bytearray(y.to_bytes(32, "little"))
            raw[31] |= sign << 7
            point = rail._pt_decompress(bytes(raw))
            if point is not None and rail._pt_eq(rail._pt_mul(8, point), (0, 1, 1, 0)):
                found.append(bytes(raw))
    return found


def test_every_small_order_key_is_refused_though_a_plain_check_accepts_its_forgery() -> None:
    import run_vectors as rail

    identity = (1).to_bytes(32, "little")
    forgery = identity + bytes(32)
    keys = _small_order_keys()
    assert len(keys) >= 3
    for public in keys:
        try:
            record = generator._weak_key_record(public, lambda m: forgery, public.hex())
        except SystemExit:
            continue  # no message in the search range lets this key's forgery verify
        proof = record["presentations"][0]["proof"]
        signed = f"{proof['protected']}.{proof['payload']}"
        assert rail.ed25519_verify(public, signed.encode(), forgery)
        assert reader.judge(record) == {"decision": "reject", "reason": "proof_key_invalid"}


def test_an_honest_key_is_in_the_prime_order_subgroup() -> None:
    honest = reader.unb64url(generator.jwk("holder")["x"]) or b""
    assert reader._prime_order(honest)
    assert not reader._prime_order((1).to_bytes(32, "little"))
