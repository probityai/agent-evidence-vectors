"""The slice regenerates byte for byte, the reference reader agrees with every case, and a verifier
that
compares only the trailing digest accepts all four blocks the slice refuses."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("rsa_digestinfo_corpus", ROOT / "check_vectors.py")
generator = _load("rsa_digestinfo_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import rsadigestinfo as reader  # noqa: E402

MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
FOUR = ("garbage-prefix", "garbage-after-legacy-prefix", "sha512-oid", "short-padding")


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
    assert answered == len(MANIFEST["vectors"])


def _trailing_digest_only(record: dict) -> bool:
    """The defect: strip the padding and compare the last 32 bytes."""
    n, e = reader.b64u_int(record["key"]["n"]), reader.b64u_int(record["key"]["e"])
    k = (n.bit_length() + 7) // 8
    s = reader.b64u_int(record["signature"])
    recovered = pow(s, e, n).to_bytes(k, "big")
    return (
        recovered[:2] == b"\x00\x01"
        and recovered[-32:] == hashlib.sha256(record["message"].encode()).digest()
    )


def test_a_trailing_digest_check_accepts_all_four_refused_blocks() -> None:
    for name in FOUR:
        record = json.loads((ROOT / "cases" / name / "record.json").read_text(encoding="utf-8"))
        assert _trailing_digest_only(record), name
        assert reader.judge(record) == {"decision": "invalid", "reason": "block_not_exact_encoding"}
