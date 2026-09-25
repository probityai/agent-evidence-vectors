#!/usr/bin/env python3
"""Adapt @veritasacta/verify to this corpus's verifier contract.

    AEV_RECEIPT_JWKS=<key set> python3 veritasacta-verify.py <receipt.json>

Runs `npx --yes @veritasacta/verify@<version> <receipt> --jwks <key set> --mode
receipt --json` and answers as the contract in ../README.md requires: the same
exit status (0 valid, 1 invalid, 2 undecidable), and one JSON line on stdout
carrying the verdict and the code. The package's own codes pass through except
`invalid_signature`, which is this corpus's `signature_invalid`.

The version defaults to the one the observed run in the README records and can
be moved with VERITASACTA_VERIFY_VERSION. Standard library only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

DEFAULT_VERSION = "0.10.19"
VERDICTS = {0: "valid", 1: "invalid", 2: "undecidable"}
CODES = {"invalid_signature": "signature_invalid"}


def answer(verdict: str, code: str | None) -> int:
    print(json.dumps({"verdict": verdict, "code": code}))
    return {"valid": 0, "invalid": 1, "undecidable": 2}[verdict]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: veritasacta-verify.py <receipt.json>", file=sys.stderr)
        return os.EX_USAGE
    jwks = os.environ.get("AEV_RECEIPT_JWKS")
    if not jwks:
        print("AEV_RECEIPT_JWKS is not set; the contract passes the key set there", file=sys.stderr)
        return os.EX_USAGE
    version = os.environ.get("VERITASACTA_VERIFY_VERSION", DEFAULT_VERSION)
    cmd = ["npx", "--yes", f"@veritasacta/verify@{version}", argv[1],
           "--jwks", jwks, "--mode", "receipt", "--json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    verdict = VERDICTS.get(proc.returncode)
    if verdict is None:
        print(f"@veritasacta/verify exited {proc.returncode}, not an answer", file=sys.stderr)
        return proc.returncode or os.EX_SOFTWARE
    try:
        report: Any = json.loads(proc.stdout)
    except ValueError:
        print("@veritasacta/verify wrote no JSON report", file=sys.stderr)
        return os.EX_SOFTWARE
    error = report.get("error") if isinstance(report, dict) else None
    if verdict == "valid":
        return answer(verdict, None)
    code = error.get("code") if isinstance(error, dict) else error
    if not isinstance(code, str):
        code = None
    return answer(verdict, CODES.get(code, code) if code else None)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
