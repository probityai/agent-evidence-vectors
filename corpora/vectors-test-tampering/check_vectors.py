"""Judge this corpus with the packaged reader, under the suite the reader names."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors import donerun  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(donerun.main([donerun.TAMPERING_SUITE, str(Path(__file__).resolve().parent)]))
