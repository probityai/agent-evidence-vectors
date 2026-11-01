#!/usr/bin/env python3
"""Hold vocabulary.yaml to the attribution lines this registry has promised.

A credit given in a public thread is a promise about this file. The registry is
CC0 and owes nobody attribution, so nothing else in the repository would notice
if a later edit to a term dropped one: the validator reads term names, not the
keys under them. Each row below names a term, the section it lives in, and the
strings its `attribution` line must carry. Removing a credit, or moving it off
its term, fails here by name.

Exit 0 every credit is present, 1 at least one is missing, 2 the check could not
run.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_REGISTRY = _ROOT / "vocabulary.yaml"

#: (section, term, strings the term's attribution line must contain)
_CREDITS = (
    (
        "evidence_dimensions",
        "witness_scope",
        (
            "Empire Labs",
            "SELF, PEER, EXTERNAL",
            "https://github.com/aaif/wg-agentic-commerce/issues/5",
            "2026-08-26",
        ),
    ),
)


def main() -> int:
    try:
        import yaml
    except ImportError as exc:
        print(f"test_attribution: REFUSED -- PyYAML is not installed ({exc}); "
              "nothing was checked.", file=sys.stderr)
        return 2
    try:
        registry = yaml.safe_load(_REGISTRY.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        print(f"test_attribution: REFUSED -- {_REGISTRY} could not be read ({exc}); "
              "nothing was checked.", file=sys.stderr)
        return 2
    if not isinstance(registry, dict):
        print("test_attribution: REFUSED -- the registry is not a mapping; nothing "
              "was checked.", file=sys.stderr)
        return 2

    failures: list[str] = []
    for section, term, required in _CREDITS:
        failures.extend(_check(registry, section, term, required))

    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    missing = len({line.split(" ", 1)[0] for line in failures})
    print(f"test_attribution: {len(_CREDITS) - missing} of {len(_CREDITS)} credits present.")
    return 1 if failures else 0


def _check(registry: dict, section: str, term: str, required: tuple[str, ...]) -> list[str]:
    """Every way one term's credit can be missing, each naming the term first."""
    entry = (registry.get(section) or {}).get(term)
    if not isinstance(entry, dict):
        return [f"{section}.{term} is not in the registry"]
    line = entry.get("attribution")
    if not isinstance(line, str):
        return [f"{section}.{term} carries no attribution line"]
    return [f"{section}.{term} attribution lacks {text!r}" for text in required if text not in line]


if __name__ == "__main__":
    sys.exit(main())
