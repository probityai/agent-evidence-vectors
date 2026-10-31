"""Resolve a source commit of the atlas to the commit that holds it in this repository.

The atlas was imported into site/ of probityai/agent-evidence with its history rewritten, so a
commit pinned before the import has a different identifier here. IMPORTED-COMMITS.tsv records
both; a revision that is not a source commit is returned unchanged.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

TABLE = Path(__file__).resolve().parents[1] / "IMPORTED-COMMITS.tsv"


@cache
def _table() -> dict[str, str]:
    if not TABLE.exists():
        return {}
    rows = (line.split() for line in TABLE.read_text().splitlines() if line and not line.startswith("#"))
    return {source: here for source, here in rows}


def here(revision: str) -> str:
    """The commit in this checkout that holds ``revision`` of the source repository."""
    return _table().get(revision, revision)
