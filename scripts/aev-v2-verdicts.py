#!/usr/bin/env python3
"""Print the reference reader's verdict for every case of one v2 corpus.

Usage: python3 scripts/aev-v2-verdicts.py <corpus-dir>

The corpus directory holds MANIFEST.json and cases/. For every manifest vector,
in manifest order, one line is printed: ``<id>\\t<decision>\\t<reason>``. The
verdict is derived from the case's record.json alone, by the suite's reference
reader; the manifest's expected answer is never read. Exit 0 when the run
completed, 2 when the corpus is unreadable or its suite is unknown.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "packaging"))

from agent_evidence_vectors import (  # noqa: E402
    approvalbindingv2,
    attenuateddelegation,
    decisionclient,
    durablehistory,
    grantuse,
    revocationepoch,
)

_READERS: dict[str, Callable[[Path], dict[str, str]]] = {
    "attenuated-delegation/v1": attenuateddelegation.verify,
    "grant-use/v1": grantuse.verify,
    "revocation-epoch/v1": revocationepoch.verify,
    "durable-history/v1": durablehistory.verify,
    "approval-binding/v2": approvalbindingv2.verify,
    "decision-client-failure-modes/v1": decisionclient.verify,
}


def _fail(message: str) -> int:
    print(f"aev-v2-verdicts: {message}", file=sys.stderr)
    return 2


def _lines(corpus: Path) -> list[str] | str:
    """The verdict lines for a corpus, or the reason it cannot be read."""
    try:
        manifest: dict[str, Any] = json.loads((corpus / "MANIFEST.json").read_text(encoding="utf-8"))
        suite = manifest["suite"]
        vectors = manifest["vectors"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        return f"cannot read {corpus}/MANIFEST.json: {error}"
    reader = _READERS.get(suite)
    if reader is None:
        return f"unknown suite {suite!r}"
    lines = []
    for vector in vectors:
        try:
            verdict = reader(corpus / vector["path"] / "record.json")
            lines.append(f"{vector['id']}\t{verdict['decision']}\t{verdict['reason']}")
        except (OSError, ValueError, KeyError, TypeError) as error:
            return f"cannot judge {vector.get('id')!r}: {error}"
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return _fail("usage: aev-v2-verdicts.py <corpus-dir>")
    result = _lines(Path(argv[1]))
    if isinstance(result, str):
        return _fail(result)
    sys.stdout.write("".join(line + "\n" for line in result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
