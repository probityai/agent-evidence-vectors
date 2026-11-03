#!/usr/bin/env python3
"""Adapt @veritasacta/verify to this corpus's verifier contract.

    AEV_RECEIPT_JWKS=<key set> python3 veritasacta-verify.py <receipt.json>

Runs `npx --yes @veritasacta/verify@<version> <receipt> --jwks <key set> --mode
receipt --json` and answers as the contract in ../README.md requires: the same
exit status (0 valid, 1 invalid, 2 undecidable), and one JSON line on stdout
carrying the verdict and the code. The package's own codes pass through except
`invalid_signature`, which is this corpus's `signature_invalid`.

When the contract hands a context (AEV_RECEIPT_CONTEXT) and the receipt is
valid, the chain it names and the receipt are written as JSONL and given to the
package's `--replay-chain`, whose Section 6.7 link check is the package's own.
A chain break there answers `invalid chain_link_mismatch`. The package reads no
commitment, so a commitment in the context is not handed to it.

The version defaults to the one the latest observed run in the README records
and can be moved with VERITASACTA_VERIFY_VERSION. Standard library only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Any

DEFAULT_VERSION = "0.10.21"
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
        return answer(*chain_verdict(version, argv[1]))
    code = error.get("code") if isinstance(error, dict) else error
    if not isinstance(code, str):
        code = None
    return answer(verdict, CODES.get(code, code) if code else None)


def chain_verdict(version: str, receipt: str) -> tuple[str, str | None]:
    """The receipt verified alone; with a context, its chain position too."""
    handed = os.environ.get("AEV_RECEIPT_CONTEXT")
    if not handed:
        return "valid", None
    with open(handed, encoding="utf-8") as handle:
        chain = json.load(handle)["chain"]
    with tempfile.TemporaryDirectory(prefix="veritasacta-chain-") as work:
        jsonl = os.path.join(work, "chain.jsonl")
        with open(jsonl, "w", encoding="utf-8") as out:
            for path in [*chain, receipt]:
                with open(path, encoding="utf-8") as handle:
                    out.write(json.dumps(json.load(handle)) + "\n")
        cmd = ["npx", "--yes", f"@veritasacta/verify@{version}", "--replay-chain", jsonl, "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    try:
        replay: Any = json.loads(proc.stdout)
        breaks = int(replay["chainBreaks"])
    except (ValueError, KeyError, TypeError):
        print("@veritasacta/verify --replay-chain wrote no chainBreaks count", file=sys.stderr)
        return "undecidable", "chain_not_replayed"
    return ("invalid", "chain_link_mismatch") if breaks else ("valid", None)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
