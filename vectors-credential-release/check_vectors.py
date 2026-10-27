"""Run the credential-release cases through the reference reader or a named verifier."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors.cardreceipt import RELEASE_SUITE, main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([RELEASE_SUITE, *sys.argv[1:]]))
