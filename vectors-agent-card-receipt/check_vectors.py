"""Run the agent-card-receipt cases through the reference reader or a named verifier."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors.cardreceipt import RECEIPT_SUITE, main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([RECEIPT_SUITE, *sys.argv[1:]]))
