"""This corpus's preimage, for scripts/release-digests.py, with the standard library alone.

The routine is owned by the packaged reader (``a2ajcs.corpus_digest``), which
reproduces the digest a2a-tck's own gen_manifest.py writes. This module loads
that reader by path and calls it, so the release check and the reader can never
be two spellings of one rule.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
READER = os.path.join(HERE, os.pardir, "packaging", "agent_evidence_vectors", "a2ajcs.py")


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    del manifest
    spec = importlib.util.spec_from_file_location("a2ajcs_digest_owner", READER)
    if spec is None or spec.loader is None:
        raise ImportError(f"{READER} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with open(os.path.join(root, "MANIFEST.json"), "rb") as handle:
        return str(module.corpus_digest(handle.read()))
