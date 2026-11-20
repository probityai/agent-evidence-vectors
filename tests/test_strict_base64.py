"""Every Python reader reads a signature, payload or key in one spelling only.

An 88-character padded base64 Ed25519 signature ends ``xx==``: its last
character carries four bits no byte uses, so sixteen strings decode to the same
64 bytes. A reader that accepts all sixteen lets one signed record appear under
sixteen byte-distinct spellings, each verifying, which defeats any replay or
duplicate check keyed on the record's bytes.
"""

from __future__ import annotations

import base64
import binascii
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))
from agent_evidence_vectors import signaturecoverage, strictb64

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CASE = ROOT / "corpora" / "vectors-signature-coverage" / "cases" / "allow-one-entry-for-the-key"


def _spellings(canonical: str) -> list[str]:
    """Every padded spelling that a lenient decoder reads as ``canonical``."""
    body, pad = canonical.rstrip("="), "=" * (len(canonical) - len(canonical.rstrip("=")))
    keep = 6 - 2 * len(pad)  # bits of the last character that bytes use
    base = ALPHABET.index(body[-1]) >> (6 - keep) << (6 - keep)
    return [body[:-1] + ALPHABET[base + low] + pad for low in range(1 << (6 - keep))]


def test_a_lenient_decoder_reads_sixteen_spellings_as_one_signature() -> None:
    signature = json.loads((CASE / "record.json").read_text())["envelope"]["signature"]
    spellings = _spellings(signature)
    assert len(spellings) == 16 and signature in spellings
    assert len({base64.b64decode(s, validate=True) for s in spellings}) == 1
    assert [s for s in spellings if _reads(strictb64.std, s)] == [signature]


def _reads(decode, text: str) -> bool:
    try:
        decode(text)
    except (ValueError, binascii.Error):
        return False
    return True


@pytest.mark.parametrize("text", ["QQ==\n", "Q Q==", "QQ", "QQ===", "QR==", "QQ=="[:-1]])
def test_std_refuses_every_spelling_but_the_canonical_one(text: str) -> None:
    assert not _reads(strictb64.std, text)
    assert strictb64.std("QQ==") == b"A"


@pytest.mark.parametrize("text", ["QQ==", "QR", "Q+", "QQ\n"])
def test_url_refuses_padding_trailing_bits_and_the_standard_alphabet(text: str) -> None:
    assert not _reads(strictb64.url, text)
    assert strictb64.url("QQ") == b"A"


def test_the_signature_coverage_reader_refuses_a_second_spelling(tmp_path: Path) -> None:
    record = json.loads((CASE / "record.json").read_text())
    canonical = record["envelope"]["signature"]
    assert signaturecoverage.verify(CASE / "record.json")["decision"] == "allow"
    for spelling in _spellings(canonical):
        if spelling == canonical:
            continue
        case = tmp_path / spelling.replace("/", "_").replace("+", "-")
        shutil.copytree(CASE, case)
        record["envelope"]["signature"] = spelling
        (case / "record.json").write_text(json.dumps(record))
        assert signaturecoverage.verify(case / "record.json")["decision"] != "allow", spelling
