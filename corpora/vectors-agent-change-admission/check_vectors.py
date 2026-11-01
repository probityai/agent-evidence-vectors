"""Run the agent-change-admission cases through the reference reader or a named verifier."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

import run_vectors  # noqa: E402, F401  (the rail owns the Ed25519 primitive the reader borrows)
from agent_evidence_vectors.changeadmission import check, main  # noqa: E402, F401

if __name__ == "__main__":
    raise SystemExit(main())
