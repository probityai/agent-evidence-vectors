"""Fetch exact source pins without executing downloaded implementations."""

from __future__ import annotations

import argparse
import hashlib
import re
import urllib.request
from pathlib import Path, PurePosixPath

from watch_import.reader import MAX_BYTES, InputError, _safe_file, strict_json


def fetch_pins(manifest: dict, output: Path, verify: bool = False) -> int:
    files = manifest["verify"]["files"] if verify else manifest["files"]
    if len(files) > 128:
        raise InputError("source file limit exceeded")
    count = 0
    for item in files:
        repository, revision, relative = item["repository"], item["revision"], item["path"]
        path = PurePosixPath(relative)
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or path.is_absolute()
            or any(part in {".", ".."} for part in path.parts)
            or "\\" in relative
            or ":" in relative
        ):
            raise InputError("unsafe source pin")
        retained = path if verify else PurePosixPath(item["retainedPath"])
        if retained.is_absolute() or any(part in {".", ".."} for part in retained.parts):
            raise InputError("unsafe retained path")
        target = _safe_file(output, str(retained))
        if item["bytes"] > MAX_BYTES:
            raise InputError("source byte limit exceeded")
        if target.exists():
            if target.stat().st_size != item["bytes"]:
                raise InputError("source length mismatch")
            data = target.read_bytes()
        else:
            url = f"https://raw.githubusercontent.com/{repository}/{revision}/{relative}"
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"] or blob != item["gitBlob"]:
            raise InputError(f"source pin mismatch: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or not target.resolve().is_relative_to(output.resolve()):
            raise InputError("unsafe output path")
        target.write_bytes(data)
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, default=Path(__file__).with_name("source-pins.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-source", action="store_true")
    args = parser.parse_args()
    manifest = strict_json(args.sources.read_bytes())
    print(f"Verified {fetch_pins(manifest, args.output, args.verify_source)} exact source files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
