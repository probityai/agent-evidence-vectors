"""Run the anchored-record-chain cases through the reference reader or a named verifier."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

import run_vectors  # noqa: E402, F401  (the reader borrows its Ed25519 and RFC 8785)
from agent_evidence_vectors.anchoredchain import check, main  # noqa: E402, F401

if __name__ == "__main__":
    raise SystemExit(main())
