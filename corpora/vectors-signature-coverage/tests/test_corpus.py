"""The corpus regenerates, forces every check in order, and separates a verifier or a
signer that reads one signature as one reading from one that holds the rule."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("signature_coverage_corpus", ROOT / "check_vectors.py")
generator = _load("signature_coverage_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import signaturecoverage as reader  # noqa: E402

CHECKS = reader.CHECKS
DENIED = {case[0]: case[3] for case in generator.cases() if case[2] == "deny"}
ALLOWED = [case[0] for case in generator.cases() if case[2] == "allow"]


def _records() -> dict[str, dict[str, Any]]:
    return {p.parent.name: json.loads(p.read_text(encoding="utf-8"))
            for p in (ROOT / "cases").glob("*/record.json")}


def _manifest() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    return loaded


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", ROOT / "signer-pairs.json",
                           *(ROOT / "cases").rglob("*")] if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(generator.cases())


def test_counts_come_from_the_manifest() -> None:
    manifest = _manifest()
    assert manifest["counts"] == {"allow": len(ALLOWED), "deny": len(DENIED)}
    assert manifest["signerPairs"] == len(generator.signer_pairs())


@pytest.mark.parametrize("name", sorted(DENIED))
def test_each_denied_case_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _records()[name], DENIED[name]
    assert reader._first_failure(record, frozenset()) == reason
    assert reader._first_failure(record, frozenset(CHECKS[CHECKS.index(reason):])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


def test_one_signature_carries_two_readings() -> None:
    """A denied record and an allowed record share signed bytes and a signature."""
    rows = {row["id"]: row for row in _manifest()["vectors"]}
    shared = rows["reject-repeat-kept-last"]["sharedSignature"]
    assert "allow-one-entry-for-the-key" in shared
    assert "reject-repeat-kept-first" in shared
    records = _records()
    first = reader.flatten(records["reject-repeat-kept-last"]["source"], keep_first=True)
    last = reader.flatten(records["reject-repeat-kept-last"]["source"])
    assert first == {"decision": "allow"} and last == {"decision": "deny"}
    signed = {(records[name]["envelope"]["payload"], records[name]["envelope"]["signature"])
              for name in shared}
    assert len(signed) == 1


def test_changing_the_shadowed_entry_leaves_the_signed_bytes_as_they_were() -> None:
    records = _records()
    keep_last = reader._canonical(reader.flatten(records["reject-repeat-kept-last"]["source"]))
    identical = reader._canonical(
        reader.flatten(records["reject-repeat-identical-values"]["source"]))
    assert keep_last == identical == generator.DENY_PAYLOAD


def test_every_case_signature_is_real() -> None:
    forged = {"reject-signature-by-another-key", "reject-signature-over-other-bytes"}
    for name, record in _records().items():
        assert reader._signature_valid(record) is (name not in forged), name


# The naive arms. Each stands for a verifier someone would plausibly ship, and each
# must pass every control before what it misses counts.
Arm = Callable[[dict[str, Any]], str | None]
SIGNED_BYTES_CHECKS = ("signature_invalid", "payload_repeated_member",
                       "number_not_interoperable")


def _only(names: tuple[str, ...]) -> Arm:
    def arm(record: dict[str, Any]) -> str | None:
        for name in names:
            failure = reader._first_failure(record, frozenset(set(CHECKS) - {name}))
            if failure:
                return failure
        return None
    return arm


def _one_reading(keep_first: bool) -> Arm:
    def arm(record: dict[str, Any]) -> str | None:
        failure = _only(SIGNED_BYTES_CHECKS)(record)
        if failure:
            return failure
        excluded = record["envelope"]["excluded"]
        reading = reader.flatten(record["source"], keep_first=keep_first)
        covered = {key: item for key, item in reading.items() if key not in excluded}
        return None if reader._same(covered, reader._payload_value(record)) else "differs"
    return arm


def _escaped(arm: Arm) -> set[str]:
    """The cases the arm allowed and the corpus denies; the controls must all pass."""
    records, expected = _records(), {row["id"]: row["expected"]
                                     for row in _manifest()["vectors"]}
    missed = set()
    for name, record in records.items():
        failure = arm(record) if "contractId" in record else None
        if name in ALLOWED:
            assert failure is None, f"a naive arm must pass the controls to count: {name}"
        elif failure is None and expected[name]["decision"] == "deny":
            missed.add(name)
    return missed


def test_signature_only_verifier_misses_every_denial_past_the_signature() -> None:
    past = {name for name, reason in DENIED.items()
            if CHECKS.index(reason) > CHECKS.index("signature_invalid")}
    assert past <= _escaped(_only(("signature_invalid",)))


def test_strict_signed_bytes_do_not_see_a_repeat_in_the_source() -> None:
    """Admission on the signed bytes passes every flattened record: they are clean."""
    past = {name for name, reason in DENIED.items()
            if CHECKS.index(reason) >= CHECKS.index("source_repeated_key")}
    assert past <= _escaped(_only(SIGNED_BYTES_CHECKS))


@pytest.mark.parametrize("keep_first,kept,other", [
    (True, "reject-repeat-kept-first", "reject-repeat-kept-last"),
    (False, "reject-repeat-kept-last", "reject-repeat-kept-first"),
])
def test_a_reader_with_one_rule_misses_the_mirror_case(keep_first: bool, kept: str,
                                                       other: str) -> None:
    """Comparing the payload with one reading finds the repeat only in one order."""
    missed = _escaped(_one_reading(keep_first))
    assert kept in missed and other not in missed
    assert "reject-repeat-identical-values" in missed


def test_verifier_that_denies_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "deny.py"
    script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                      '"reason": "contract_id_missing"}))\nsys.exit(1)\n', encoding="ascii")
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ALLOWED) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors


# The signer surface. The reference signer passes; each naive flatten fails the pairs
# it collapses, and no naive flatten passes all of them.
def _plain(value: Any, *, first: bool = False, fold: Callable[[str], str] = str,
           drop_null: bool = False, scalar: Callable[[Any], Any] = lambda v: v) -> Any:
    if reader._is_map(value):
        out: dict[str, Any] = {}
        for key, item in value["entries"]:
            name = fold(key)
            if drop_null and item is None or (first and name in out):
                continue
            out[name] = _plain(item, first=first, fold=fold, drop_null=drop_null, scalar=scalar)
        return out
    if isinstance(value, list):
        return [_plain(item, first=first, fold=fold, drop_null=drop_null, scalar=scalar)
                for item in value]
    return scalar(value)


NAIVE: dict[str, Callable[[Any], bytes]] = {
    "keep-last": lambda s: reader._canonical(_plain(s)),
    "keep-first": lambda s: reader._canonical(_plain(s, first=True)),
    "fold-case": lambda s: reader._canonical(_plain(s, fold=str.lower)),
    "normalise-keys": lambda s: reader._canonical(
        _plain(s, fold=lambda k: unicodedata.normalize("NFC", k))),
    "drop-null": lambda s: reader._canonical(_plain(s, drop_null=True)),
    "stringify": lambda s: reader._canonical(_plain(s, scalar=str)),
    "number-truthy": lambda s: reader._canonical(
        _plain(s, scalar=lambda v: int(v) if isinstance(v, bool) else v)),
}


def test_reference_signer_passes_every_pair() -> None:
    total, errors = reader.judge_signer(reader.signature_input)
    assert errors == [] and total == len(generator.signer_pairs())


@pytest.mark.parametrize("name", sorted(NAIVE))
def test_every_naive_flatten_fails_a_pair(name: str) -> None:
    _, errors = reader.judge_signer(NAIVE[name])
    assert errors, f"{name} passed every pair, so the pairs cannot tell it from a correct signer"


def test_signing_first_wins_does_not_close_the_gap() -> None:
    """Keeping the first entry matches one reader and leaves the mirror pair open."""
    _, errors = reader.judge_signer(NAIVE["keep-first"])
    assert "repeat-against-the-entry-kept-first" in _failed(errors)
    assert "repeat-with-kept-value-changed" in _failed(errors)


def test_tampered_pairs_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "MANIFEST.json").write_bytes((ROOT / "MANIFEST.json").read_bytes())
    (tmp_path / "signer-pairs.json").write_bytes(b"[]\n")
    with pytest.raises(ValueError, match="does not match"):
        reader.judge_signer(reader.signature_input, tmp_path)


def test_external_signer_contract(tmp_path: Path) -> None:
    script = tmp_path / "signer.py"
    script.write_text(
        "import base64, hashlib, json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from agent_evidence_vectors import signaturecoverage as r\n"
        "source = json.load(open(sys.argv[1], encoding='utf-8'))\n"
        "signed = r.signature_input(source)\n"
        "print(json.dumps({'refused': True} if signed is None else "
        "{'signatureInput': base64.b64encode(signed).decode()}))\n", encoding="utf-8")
    assert reader.main(["--signer", f"{sys.executable} {script}"]) == 0


def test_public_key_is_the_published_test_key() -> None:
    expected = base64.b64encode(generator.rail.ed25519_public_key(generator.SEED)).decode()
    assert {r["envelope"]["publicKey"] for r in _records().values()} == {expected}
    assert hashlib.sha256(b"signature-coverage/v1 test key, published on purpose").digest() == (
        generator.SEED)
