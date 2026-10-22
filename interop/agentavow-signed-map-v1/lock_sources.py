"""Write or check the shared-source digests in source-lock.json.

The reproduction refuses to run when a shared source no longer hashes to the
digest the lock names. A change to one of those sources therefore needs the
lock refreshed in the same commit; this script does it from the files on disk,
so no digest is typed by hand. The fixture and license entries name upstream
bytes and are left alone.

    python3 lock_sources.py          # rewrite the file digests
    python3 lock_sources.py --check  # exit 1 when any digest is stale
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOCK = ROOT / "source-lock.json"


def refreshed(lock: dict) -> dict:
    """The lock with every file entry's digest recomputed from disk."""
    files = [{**entry, "sha256": hashlib.sha256((ROOT / entry["file"]).read_bytes()).hexdigest()}
             for entry in lock["files"]]
    return {**lock, "files": files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="refuse rather than write")
    args = parser.parse_args(argv)
    current = json.loads(LOCK.read_text(encoding="utf-8"))
    rendered = json.dumps(refreshed(current), indent=2) + "\n"
    if args.check:
        stale = rendered != LOCK.read_text(encoding="utf-8")
        print("source-lock: stale" if stale else "source-lock: current")
        return 1 if stale else 0
    LOCK.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
