"""Judge a request against a signed, chained authority log closed by a signed head."""

from __future__ import annotations

SUITE = "authority-epoch-fence/v1"
ADMIT, REFUSE, NO_VERDICT = "admit", "refuse", "no_verdict"
EXIT_FOR = {ADMIT: 0, REFUSE: 1, NO_VERDICT: 2}
STATUSES = ("live", "suspended", "partial", "closed", "unknown")
REASONS: tuple[str, ...] = ()
CHECKS: tuple[str, ...] = ()


def verify(case_path: object, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    raise NotImplementedError


def check(*args: object, **kwargs: object) -> tuple[int, list[str]]:
    raise NotImplementedError


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError
