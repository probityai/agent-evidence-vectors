"""Installed CLI for importing pinned saved rows."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .bundle import write_bundle
from .reader import InputError, canonical, import_watch, strict_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probity-watch-import")
    parser.add_argument("input_root", type=Path)
    parser.add_argument("--sources", type=Path, required=True, help="Consumer-held source manifest")
    parser.add_argument("--output", type=Path, help="Absent or empty bundle directory")
    args = parser.parse_args(argv)
    try:
        manifest = strict_json(args.sources.read_bytes())
        result, raw = import_watch(args.input_root, manifest)
        if args.output:
            write_bundle(result, raw, manifest, args.output)
    except (InputError, OSError) as exc:
        print(f"probity-watch-import: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical(result))
    return 0 if result["summary"]["consistent_publisher_claims"] == result["summary"]["rows"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
