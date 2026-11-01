"""This corpus's preimage, in a module that imports nothing but the standard library.

scripts/release-digests.py reaches the module that owns a corpus's preimage,
and that path has to run for somebody who installed nothing. Reaching this
corpus's generator would not: gen_vectors.py imports tools/artifact-binding/
sign.py, which imports `cryptography` to sign the members.

The members here are artifact-binding trial directories, so the preimage is the
one vectors-artifact-binding/digest.py spells: the canonical encoding of the
manifest's entry list. This module loads that one by path rather than restating
it, so the two corpora cannot drift apart.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_BINDING_DIGEST = Path(__file__).resolve().parent.parent / "vectors-artifact-binding" / "digest.py"


def _binding_corpus_digest() -> Any:
    """The artifact-binding corpus_digest, loaded from its own file."""
    spec = importlib.util.spec_from_file_location("binding_digest", _BINDING_DIGEST)
    if spec is None or spec.loader is None:
        raise ImportError(f"{_BINDING_DIGEST} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.corpus_digest


_corpus_digest = _binding_corpus_digest()


def corpus_digest(manifest: dict[str, Any], root: Any = None) -> str:
    """SHA-256 over the canonical encoding of the manifest's entry list.

    `root` is accepted and unused so that every corpus answers
    scripts/release-digests.py through one signature.
    """
    return str(_corpus_digest(manifest, root))
