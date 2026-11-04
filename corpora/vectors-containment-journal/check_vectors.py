"""Run the containment-journal cases through the reference reader or a named verifier."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packaging"))

from agent_evidence_vectors.containmentjournal import check, main  # noqa: E402, F401

if __name__ == "__main__":
    raise SystemExit(main())
