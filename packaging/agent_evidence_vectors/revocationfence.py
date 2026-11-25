"""Judge the revocation-fence cases: a revocation a target enforces at its own commit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

SUITE = "revocation-fence/v1"
CHECKS: tuple[str, ...] = ()
EXIT_FOR: dict[str, int] = {}
STATUSES = ("live", "partial", "closed", "unknown")
KINDS = ("permit", "epoch-update", "outcome", "commit", "propagation", "ledger", "feed")


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, Any]:
    raise NotImplementedError


def check(
    verifier: str | list[str] | None = None,
    root: Path | None = None,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    raise NotImplementedError


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError
