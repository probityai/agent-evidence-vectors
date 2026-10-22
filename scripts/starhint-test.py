#!/usr/bin/env python3
"""The star hint prints once, to a terminal, outside CI, and never beside JSON.

Each case holds one condition. The positive control must print, so a hint that
was silently disabled everywhere cannot pass the quiet cases.

Usage: python3 scripts/starhint-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import io
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packaging"))

from agent_evidence_vectors import starhint  # noqa: E402


class _Stream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _run(env_extra: dict[str, str], argv: list[str], tty: bool, home: str) -> tuple[bool, str]:
    env = {"HOME": home, "XDG_STATE_HOME": str(Path(home) / "state"), **env_extra}
    stream = _Stream(tty)
    return starhint.maybe_print_hint(argv, env, stream), stream.getvalue()


def main() -> int:
    failures: list[str] = []

    def expect(label: str, got: tuple[bool, str], printed: bool) -> None:
        if got[0] != printed or bool(got[1]) != printed:
            failures.append(f"{label}: printed={got[0]} text={got[1]!r}, wanted printed={printed}")

    with tempfile.TemporaryDirectory() as home:
        expect("CI set", _run({"CI": "true"}, [], True, home), False)
        expect("not a terminal", _run({}, [], False, home), False)
        expect("json flag", _run({}, ["--report", "out.json"], True, home), False)
        expect("opt-out", _run({starhint.OPT_OUT: "1"}, [], True, home), False)
        first = _run({}, [], True, home)
        expect("first run prints", first, True)
        if first[1].strip() != f"Found this useful? Star github.com/{starhint.REPO}":
            failures.append(f"hint text changed: {first[1]!r}")
        expect("second run is silent", _run({}, [], True, home), False)
    with tempfile.TemporaryDirectory() as home:
        blocked = Path(home) / "state"
        blocked.write_text("a file where the state directory should be\n")
        expect("unwritable state stays silent", _run({}, [], True, home), False)

    for line in failures:
        print(f"FAIL {line}")
    print(f"star hint cases: {'FAIL' if failures else 'ok'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
