"""The catalog-trust-manifest corpus regenerates, a second generator that shares no code
re-mints it byte for byte, every case reaches its declared verdict, and every check is
forced by some case."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import catalogtrust as reader  # noqa: E402
from agent_evidence_vectors import p256  # noqa: E402

SUITE = reader.SUITE


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("catalog_trust_manifest_generator", ROOT / "gen_vectors.py")
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
CASES = {v["id"]: v["expected"] for v in MANIFEST["vectors"]}
REJECTED = {name: e["reason"] for name, e in CASES.items() if e["decision"] == "reject"}


def _committed() -> dict[Path, bytes]:
    return {p.relative_to(ROOT): p.read_bytes()
            for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")] if p.is_file()}


def _tree(base: Path) -> dict[Path, bytes]:
    return {p.relative_to(base): p.read_bytes() for p in base.rglob("*") if p.is_file()}


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    assert _tree(tmp_path) == _committed()


def test_case_table_is_the_committed_one() -> None:
    assert (ROOT / "CASES.json").read_bytes() == generator.table_bytes()


def test_independent_generator_remints_every_byte(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    subprocess.run([sys.executable, "-I", str(ROOT / "gen_vectors_independent.py"),
                    str(tmp_path)], check=True)
    assert _tree(tmp_path) == _committed()


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = reader.check(SUITE)
    assert errors == []
    assert answered == len(CASES)


def test_both_decisions_and_every_reason_are_present() -> None:
    reasons = {e["reason"] for e in CASES.values()}
    assert set(REJECTED) and len(REJECTED) < len(CASES)
    assert set(reader.REASONS) <= reasons, set(reader.REASONS) - reasons
    assert {e["reason"] for e in CASES.values() if e["decision"] == "accept"} == \
        {"signature_covers_release", "snapshot_signature_valid"}


@pytest.mark.parametrize("name", reader.CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = reader.check(SUITE, skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


@pytest.mark.parametrize("name", sorted(n for n, r in REJECTED.items() if r in reader.CHECKS))
def test_each_rejected_case_passes_every_earlier_check(name: str) -> None:
    reason = REJECTED[name]
    later = frozenset(reader.CHECKS[reader.CHECKS.index(reason):])
    directory = ROOT / "cases" / name
    assert reader.verify(SUITE, directory) == {"decision": "reject", "reason": reason}
    assert reader.verify(SUITE, directory, later)["decision"] == "accept"


def test_contradict_groups_judge_identical_bytes_four_ways() -> None:
    for signed_as in ("draft", "whole-entry"):
        group = sorted(p for p in (ROOT / "cases").iterdir()
                       if p.name.startswith(f"contradict-{signed_as}-signed-under-"))
        assert len(group) == 4
        assert len({(p / "catalog.json").read_bytes() for p in group}) == 1
        constructions = {json.loads((p / "context.json").read_text())["construction"]
                         for p in group}
        assert constructions == set(reader.CONSTRUCTIONS)


def test_attestation_controls_carry_the_predicate_identifiers() -> None:
    case = ROOT / "cases" / "accept-attestations-dsse-bound"
    entry = json.loads((case / "catalog.json").read_text())["entries"][0]
    types = {item["type"] for item in entry["trustManifest"]["attestations"]}
    assert types == {generator.CARD_RECEIPT, generator.OBSERVED}


def test_p256_agrees_with_cryptography_both_ways() -> None:
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    for label in (b"a", b"b", b"c"):
        secret = int.from_bytes(hashlib.sha256(label).digest(), "big") % (p256.N - 1) + 1
        key = crypto.derive_private_key(secret, crypto.SECP256R1())
        numbers = key.public_key().public_numbers()
        assert p256.public_point(secret) == (numbers.x, numbers.y)
        message = b"catalog-trust-manifest " + label
        ours = p256.sign(secret, message)
        r, s = int.from_bytes(ours[:32], "big"), int.from_bytes(ours[32:], "big")
        key.public_key().verify(encode_dss_signature(r, s), message, crypto.ECDSA(hashes.SHA256()))
        theirs = decode_dss_signature(key.sign(message, crypto.ECDSA(
            hashes.SHA256(), deterministic_signing=True)))
        assert theirs == (r, s)
        assert p256.verify((numbers.x, numbers.y), message, ours)
        assert not p256.verify((numbers.x, numbers.y), message + b"!", ours)


@pytest.mark.parametrize("value,text", [
    (1.0, "1"), (0.5, "0.5"), (1e-7, "1e-7"), (0.000001, "0.000001"), (-2.5e-10, "-2.5e-10"),
    (123.456, "123.456"), (100.0, "100"), (9007199254740991, "9007199254740991")])
def test_number_form_is_ecmascript(value: float, text: str) -> None:
    assert reader.canonical(value) == text.encode()


@pytest.mark.parametrize("value", [9007199254740992, -9007199254740992, 1e20,
                                   9007199254740993.5])
def test_numbers_past_the_safe_range_are_not_interoperable(value: float) -> None:
    with pytest.raises(reader.Refused, match="number_not_interoperable"):
        reader.canonical(value)


def test_reference_reader_through_the_external_contract() -> None:
    env_root = str(ROOT.parents[1] / "packaging")
    program = (f"import sys; sys.path.insert(0, {env_root!r}); "
               "from agent_evidence_vectors.catalogtrust import main; sys.exit(main())")
    answered, errors = reader.check(SUITE, verifier=[sys.executable, "-c", program])
    assert errors == [] and answered == len(CASES)


def test_a_verifier_that_accepts_everything_fails(tmp_path: Path) -> None:
    script = tmp_path / "yes.py"
    script.write_text('import json; print(json.dumps({"decision": "accept", '
                      '"reason": "signature_covers_release"}))\n', encoding="ascii")
    _, errors = reader.check(SUITE, verifier=[sys.executable, str(script)])
    assert errors
