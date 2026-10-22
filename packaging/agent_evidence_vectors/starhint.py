"""A one-line, once-per-machine invitation to star the repository.

The hint is printed to standard error after a successful run, so it never
shares a stream with machine-readable output on standard output. It stays quiet
in CI, when standard error is not a terminal, when the run asked for JSON, when
the opt-out variable is set, and after the first time it was shown on this
machine.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

REPO = "probityai/agent-evidence-vectors"
OPT_OUT = "AGENT_EVIDENCE_NO_STAR_HINT"
_FLAG_NAME = "star-hint-shown-agent-evidence-vectors"


def _flag_path(env: Mapping[str, str]) -> Path:
    home = Path(env.get("HOME") or Path.home())
    base = env.get("XDG_STATE_HOME") or str(home / ".local" / "state")
    return Path(base) / "agent-evidence" / _FLAG_NAME


def _quiet(argv: Sequence[str], env: Mapping[str, str], stream: TextIO) -> bool:
    if env.get("CI") or env.get(OPT_OUT):
        return True
    if any("json" in arg.lower() for arg in argv):
        return True
    return not stream.isatty()


def maybe_print_hint(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    stream: TextIO | None = None,
) -> bool:
    """Print the hint if every condition allows it; return whether it was printed."""
    args: Sequence[str] = sys.argv[1:] if argv is None else argv
    environ: Mapping[str, str] = os.environ if env is None else env
    out: TextIO = sys.stderr if stream is None else stream
    if _quiet(args, environ, out):
        return False
    flag = _flag_path(environ)
    if flag.exists():
        return False
    try:
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.write_text("shown\n", encoding="utf-8")
    except OSError:
        return False
    print(f"Found this useful? Star github.com/{REPO}", file=out)
    return True
