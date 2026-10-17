"""Judge the done-receipt/v1 corpus with the packaged reader."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors import donerun  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(donerun.main(["done-receipt/v1", str(Path(__file__).resolve().parent)]))
