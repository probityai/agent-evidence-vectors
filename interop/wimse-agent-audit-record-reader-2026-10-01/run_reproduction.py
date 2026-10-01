#!/usr/bin/env python3
"""Run the external reader and compare its output with the retained report."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from verify_report import build


HERE = Path(__file__).resolve().parent
ROOT = HERE / ".build"


if __name__ == "__main__":
    pins = json.loads((HERE / "INPUTS.json").read_text())
    reader = ROOT / "reader"
    corpus = ROOT / "corpus"
    for name, expected in pins["reader"]["sha256"].items():
        if hashlib.sha256((reader / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"reader source changed: {name}")
    for module in ("envelope_reader", "stage2_members", "stage34_recompute"):
        result = subprocess.run(
            [sys.executable, "-m", f"aimsreader.{module}", str(corpus.resolve())],
            cwd=reader,
            capture_output=True,
            text=True,
            check=True,
        )
        (ROOT / f"{module}.stdout").write_text(result.stdout)
    build(corpus)
