"""This corpus's preimage, in a module that imports nothing but the standard library.

Why this file exists rather than a function inside gen_vectors.py
----------------------------------------------------------------
scripts/release-digests.py recomputes every corpus digest by loading the module
that OWNS that corpus's preimage and calling it, rather than restating the
concatenation itself: a second spelling of one preimage drifts from the first,
and a release signature over a drifted digest certifies the drift instead of the
corpus.

For every other corpus the owning module is the generator. For this one it
cannot be. gen_vectors.py builds COSE_Sign1 messages, so it imports cbor2 and
pycose, and it registers a custom algorithm with a decorator that runs at import
time -- which means the import cannot be deferred with PEP 562 or anything else.
Loading it to reach one hashing routine therefore drags the whole COSE stack
onto the one path that must not have dependencies at all: verifying a published
release has to work for somebody who installed nothing.

That is not hypothetical. v0.10.0 shipped with this routine inside the
generator, and the first command the README tells a reader to run,
`python3 scripts/release-digests.py --check`, failed in a fresh clone with
`ModuleNotFoundError: No module named 'cbor2'`. Generation may depend on
whatever it needs; verification may not.

So the preimage lives here, the generator imports it, and release-digests.py
imports it. Still one definition, and now the verification path reaches it
through the standard library alone. scripts/scitt-digest-isolation-test.py
holds that property by running the check in a subprocess that cannot see any
third-party package.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """sha256 over every member's bytes, concatenated in identifier order."""
    return hashlib.sha256(
        b"".join(
            open(os.path.join(root, entry["file"]), "rb").read()
            for entry in sorted(manifest["vectors"], key=lambda entry: entry["id"])
        )
    ).hexdigest()
