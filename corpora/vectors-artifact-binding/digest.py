"""This corpus's preimage, in a module that imports nothing but the standard library.

Same rule as vectors-scitt-cose/digest.py, and it is here for the same reason:
scripts/release-digests.py reaches the module that OWNS a corpus's preimage, and
that path has to run for somebody who installed nothing. Reaching this corpus's
generator would not: gen_vectors.py imports tools/artifact-binding/sign.py,
which imports `cryptography` to produce the signatures the members carry.

Unlike its siblings this preimage is over the manifest ENTRIES rather than over
member files. A member here is a whole trial directory, so the entry is where
that member's own per-file digests are gathered into one object, and the
canonical encoding of the entry list is what the corpus commits to. `jcs` does
that canonicalisation with hashlib and json and nothing else.

Found by scripts/scitt-digest-isolation-test.py on its first run, which is the
argument for having written it: the SCITT corpus was the instance that broke
v0.10.0, and this one would have broken the next release the same way.
"""

from __future__ import annotations

import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools", "artifact-binding"))

import jcs  # noqa: E402  (the path above is what makes this importable)


def corpus_digest(manifest: dict[str, Any], root: Any = None) -> str:
    """SHA-256 over the canonical encoding of the manifest's entry list.

    `root` is accepted and unused so that every corpus answers
    scripts/release-digests.py through one signature.
    """
    del root
    return str(jcs.digest(manifest["vectors"]))
