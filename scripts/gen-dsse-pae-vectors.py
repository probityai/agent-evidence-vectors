#!/usr/bin/env python3
"""Write interop/dsse-pae-vectors/cases.json: DSSE v1 pre-authentication encoding cases.

PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, where LEN is
the decimal byte length. The expected bytes are built here from the rule, never from the
code under test. The payloadType cases come from a cross-library run in which Python
securesystemslib 1.3.0 counted characters, not bytes, for a non-ASCII payloadType (its
1.6.0 source counts bytes), and Rust ``dsse`` refused an empty payloadType while Go
``go-securesystemslib`` signed it.

Usage (repository root):
    python3 scripts/gen-dsse-pae-vectors.py           # write
    python3 scripts/gen-dsse-pae-vectors.py --check   # exit 1 on drift
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "interop" / "dsse-pae-vectors" / "cases.json"

# id, family, payloadType, payload bytes
PAE: tuple[tuple[str, str, str, bytes], ...] = (
    ("ascii-type", "ascii", "application/vnd.in-toto+json", b'{"a":1}'),
    ("empty-body", "ascii", "text/plain", b""),
    ("two-byte-char-type", "non-ascii-type", "application/vnd.café", b"x"),
    ("three-byte-char-type", "non-ascii-type", "text/€", b"x"),
    ("four-byte-char-type", "non-ascii-type", "text/\U0001f600", b"x"),
    ("cjk-type", "non-ascii-type", "application/文件", b"{}"),
    ("empty-type", "empty-type", "", b"x"),
    ("binary-body", "ascii", "application/octet-stream", bytes(range(256))),
)

EMPTY_NOTE = (
    "the PAE is defined for an empty type; a signer may refuse it, "
    "so a signing result is not compared"
)


def pae(payload_type: str, body: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def cases() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for case_id, family, ptype, body in PAE:
        pinned = pae(ptype, body)
        member: dict[str, object] = {
            "id": f"pae-{case_id}",
            "family": family,
            "payloadType": ptype,
            "payloadHex": body.hex(),
            "typeByteLength": len(ptype.encode("utf-8")),
            "typeCharLength": len(ptype),
            "paeHex": pinned.hex(),
            "sha256": hashlib.sha256(pinned).hexdigest(),
        }
        if family == "empty-type":
            member["note"] = EMPTY_NOTE
        out.append(member)
    return out


def render() -> str:
    return json.dumps({"format": "dsse-pae-vectors/v1", "paeCases": cases()}, indent=2) + "\n"


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print(__doc__)
        return 2
    wanted = render()
    if argv:
        if not CASES.exists() or CASES.read_text("utf-8") != wanted:
            print(f"{CASES.relative_to(ROOT)} differs from what {Path(__file__).name} writes")
            return 1
        return 0
    CASES.parent.mkdir(parents=True, exist_ok=True)
    CASES.write_text(wanted, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
