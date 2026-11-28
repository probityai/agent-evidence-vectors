"""Run the cbor-receipt-chain cases through the reference reader or a named verifier."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packaging"))

from agent_evidence_vectors.cborreceiptchain import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
