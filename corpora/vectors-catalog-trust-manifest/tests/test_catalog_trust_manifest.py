"""The catalog-trust-manifest corpus regenerates, a second generator that shares no code
re-mints it byte for byte, every case reaches its declared verdict, and every check is
forced by some case."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from fractions import Fraction
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


def test_a_signed_statement_that_is_not_an_object_is_unsigned_not_a_crash() -> None:
    body = b"[]"
    kind = b"application/vnd.in-toto+json"
    signature = generator.raw_sign("assessor", reader._dsse_pae(kind.decode(), body))
    envelope = json.dumps({"payload": base64.b64encode(body).decode(), "payloadType": kind.decode(),
                           "signatures": [{"keyid": generator.ASSESSOR + "#es256",
                                           "sig": base64.b64encode(signature).decode()}]})
    assert reader._signed_statement(envelope.encode(), generator.did_documents()) is None


def test_an_attestation_file_outside_the_case_directory_is_refused(tmp_path: Path) -> None:
    case = tmp_path / "case"
    shutil.copytree(ROOT / "cases" / "accept-attestations-dsse-bound", case)
    (tmp_path / "outside.json").write_bytes((case / "attestation-0.dsse.json").read_bytes())
    context = json.loads((case / "context.json").read_text())
    context["attestationFiles"][0] = "../outside.json"
    (case / "context.json").write_text(json.dumps(context))
    assert reader.verify(SUITE, case) == {"decision": "reject",
                                          "reason": "attestation_digest_mismatch"}


@pytest.mark.parametrize("text,seconds", [
    ("2026-11-01T00:00:00Z", 1793491200), ("2026-11-01T01:00:00+01:00", 1793491200),
    ("2026-11-01t00:00:00.5z", Fraction(3586982401, 2)), ("2026-10-31T19:00:00-05:00", 1793491200),
    ("0000-02-29T00:00:00Z", -62162121600), ("2016-12-31T23:59:60Z", 1483228800),
    ("2016-12-31T18:59:60-05:00", 1483228800), ("1972-06-30T23:59:60.5Z", Fraction(157593601, 2))])
def test_rfc3339_times_are_instants(text: str, seconds: Fraction) -> None:
    assert reader._instant(text) == seconds


@pytest.mark.parametrize("text", ["2026-02-30T00:00:00Z", "2026-11-01T24:00:00Z",
                                  "2026-11-01T00:00:00", "2026-11-01 00:00:00Z",
                                  "2026-11-01T00:00:00+24:00", "1900-02-29T00:00:00Z",
                                  "\u0662\u0660\u0662\u0666-11-01T00:00:00Z", 1793491200,
                                  "2026-11-01T23:59:60Z", "2026-11-01T00:00:60Z",
                                  "2016-12-31T23:59:60+01:00", "2016-12-30T23:59:60Z"])
def test_non_rfc3339_times_are_not_instants(text: object) -> None:
    assert reader._instant(text) is None


def test_nesting_is_bounded_before_parsing() -> None:
    limit = reader.MAX_NESTING
    assert not reader.too_deep(b"[" * limit + b"]" * limit)
    assert reader.too_deep(b"[" * (limit + 1) + b"]" * (limit + 1))
    assert not reader.too_deep(b'{"a": "' + b"[" * 100 + b'"}')  # brackets inside a string
    # A string ending in an escaped backslash closes, so the brackets after it count.
    assert reader.too_deep(b'["\\\\",' + b"[" * limit + b"]" * limit + b"]")
    with pytest.raises(ValueError):
        reader.strict_loads(b"[" * 100000 + b"]" * 100000)


@pytest.mark.parametrize("text,raw", [("YWJj", b"abc"), ("YWI=", b"ab"), ("-_8=", b"\xfb\xff"),
                                      ("+/8=", b"\xfb\xff"), ("", b"")])
def test_dsse_base64_takes_either_alphabet(text: str, raw: bytes) -> None:
    assert reader.dsse_b64_decode(text) == raw


@pytest.mark.parametrize("text", ["YWI", "YW\nJj", "+_8=", "YWJj ", "YQ==YQ==", 5])
def test_dsse_base64_refuses_everything_else(text: object) -> None:
    with pytest.raises(ValueError):
        reader.dsse_b64_decode(text)


@pytest.mark.parametrize("value,index", [(0, 0), (3, 3), (1.0, 1), (-1, None), (0.5, None),
                                         (True, None), ("1", None), (2**40, None)])
def test_context_index_is_a_non_negative_integer(value: object, index: object) -> None:
    assert reader.index_of(value) == index


@pytest.mark.parametrize("url,origin", [
    ("https://publisher.example/a", "https://publisher.example"),
    ("HTTPS://Publisher.Example:443/a", "https://publisher.example"),
    ("https://publisher.example:/a", "https://publisher.example"),
    ("https://publisher.example:8443/a", None), ("http://publisher.example/a", None),
    ("https://user@publisher.example/a", None), ("https://publisher%2Eexample/a", None),
    ("https://[::1]/a", None), ("https:///a", None)])
def test_url_origin_is_rfc6454(url: str, origin: object) -> None:
    assert reader._origin(url) == origin


def test_der_signatures_are_strict() -> None:
    raw = bytes(range(1, 33)) + bytes(range(129, 161))
    der = generator.der(raw)
    assert reader.der_signature(der) == raw
    assert reader.der_signature(generator.der(raw, True)) is None
    assert reader.der_signature(der + b"\x00") is None
    assert reader.der_signature(der[:-1]) is None


@pytest.mark.parametrize("did,root", [
    ("did:web:publisher.example", True), ("did:web:xn--bcher-kva.example", True),
    ("did:web:192.0.2.1", False), ("did:web:agents.2026", False), ("did:web:2026", False),
    ("did:web:" + "a" * 63 + "." + ("b" * 63 + ".") * 2 + "c" * 61, True),
    ("did:web:" + "a" * 63 + "." + ("b" * 63 + ".") * 2 + "c" * 62, False)])
def test_root_did_web(did: str, root: bool) -> None:
    assert reader.root_did_web(did) is root
