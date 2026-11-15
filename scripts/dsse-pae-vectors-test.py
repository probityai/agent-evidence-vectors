#!/usr/bin/env python3
"""The DSSE PAE family: generator drift, an independent PAE, and the byte-versus-character split."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = json.loads((ROOT / "interop" / "dsse-pae-vectors" / "cases.json").read_text("utf-8"))


def independent_pae(ptype: str, body: bytes) -> bytes:
    t = ptype.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


class PaeFamily(unittest.TestCase):
    def test_generator_has_nothing_to_rewrite(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "gen-dsse-pae-vectors.py"), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_every_member_matches_an_independent_pae(self) -> None:
        for c in CORPUS["paeCases"]:
            with self.subTest(c["id"]):
                got = independent_pae(c["payloadType"], bytes.fromhex(c["payloadHex"]))
                self.assertEqual(got.hex(), c["paeHex"])

    def test_non_ascii_types_split_bytes_from_characters(self) -> None:
        split = [c for c in CORPUS["paeCases"] if c["family"] == "non-ascii-type"]
        self.assertGreaterEqual(len(split), 4)
        for c in split:
            with self.subTest(c["id"]):
                self.assertGreater(c["typeByteLength"], c["typeCharLength"])
                wrong = b"DSSEv1 %d " % c["typeCharLength"]
                self.assertFalse(bytes.fromhex(c["paeHex"]).startswith(wrong))


if __name__ == "__main__":
    unittest.main()
