"""This corpus's preimage, which is the card receipt corpus's: same files layout, same digest.

The module imports nothing but the standard library, so `scripts/release-digests.py
--check` runs for a reader who installed nothing. The one definition lives in
vectors-agent-card-receipt/digest.py and is loaded from there.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_SPEC = importlib.util.spec_from_file_location(
    "agent_card_receipt_digest",
    Path(__file__).resolve().parent.parent / "vectors-agent-card-receipt" / "digest.py",
)
assert _SPEC and _SPEC.loader
_BASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BASE)

sha, enc = _BASE.sha, _BASE.enc


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    return str(_BASE.corpus_digest(manifest, root))
