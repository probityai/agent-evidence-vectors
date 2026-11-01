"""Judge the refund-connected runs through the reference reader, or judge a run directory."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors.refundconnected import check, main  # noqa: E402, F401

if __name__ == "__main__":
    raise SystemExit(main())
