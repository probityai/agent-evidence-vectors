#!/usr/bin/env python3
"""Fetch one pinned release asset and refuse any bytes that miss the pinned sha256.

Order: a file already at --dest (a cache restore) is used only if its digest matches;
otherwise the direct release URL is tried with retries, then the GitHub API asset
endpoint through `gh`. The digest is checked after every path, and the destination
is written only from bytes that matched. Exit 0 verified, 2 nothing verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ATTEMPTS = 5
DELAY = 5.0


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def direct(url: str, part: Path) -> None:
    last: Exception | None = None
    for attempt in range(ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=120) as reply:  # noqa: S310 - https release URL
                part.write_bytes(reply.read())
            return
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last = error
            print(
                f"fetch-tool: direct attempt {attempt + 1}/{ATTEMPTS} failed: {error}",
                file=sys.stderr,
            )
            time.sleep(DELAY)
    raise OSError(f"direct download failed after {ATTEMPTS} attempts: {last}")


def via_api(repo: str, tag: str, asset: str, part: Path) -> None:
    last: Exception | None = None
    for attempt in range(ATTEMPTS):
        try:
            meta = subprocess.run(
                ["gh", "api", f"repos/{repo}/releases/tags/{tag}"],
                check=True,
                capture_output=True,
                text=True,
            )
            ids = [a["id"] for a in json.loads(meta.stdout)["assets"] if a["name"] == asset]
            if len(ids) != 1:
                raise OSError(f"{repo} {tag} has {len(ids)} assets named {asset}")
            with part.open("wb") as handle:
                subprocess.run(
                    # curl-retry: exempt this is the fetch implementation
                    [
                        "gh",
                        "api",
                        "-H",
                        "Accept: application/octet-stream",
                        # curl-retry: exempt this is the fetch implementation
                        f"repos/{repo}/releases/assets/{ids[0]}",
                    ],
                    check=True,
                    stdout=handle,
                )
            return
        except (subprocess.CalledProcessError, OSError, KeyError, ValueError) as error:
            last = error
            print(
                f"fetch-tool: api attempt {attempt + 1}/{ATTEMPTS} failed: {error}", file=sys.stderr
            )
            time.sleep(DELAY)
    raise OSError(f"API download failed after {ATTEMPTS} attempts: {last}")


def fetch(repo: str, tag: str, asset: str, sha256: str, dest: Path) -> str:
    """Return which path produced the verified file: cache, direct or api."""
    if dest.is_file() and digest(dest) == sha256:
        return "cache"
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    # curl-retry: exempt this is the fetch implementation
    url = f"https://github.com/{repo}/releases/download/{tag}/{asset}"
    for name, run in (
        ("direct", lambda: direct(url, part)),
        ("api", lambda: via_api(repo, tag, asset, part)),
    ):
        try:
            run()
        except OSError as error:
            print(f"fetch-tool: {name} path gave nothing: {error}", file=sys.stderr)
            continue
        if digest(part) == sha256:
            part.replace(dest)
            return name
        print(
            f"fetch-tool: {name} bytes have sha256 {digest(part)}, not the pinned {sha256}",
            file=sys.stderr,
        )
        part.unlink()
    raise SystemExit(
        f"fetch-tool: {repo} {tag} {asset}: no path gave the pinned bytes; nothing was installed."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--dest", required=True, type=Path)
    parser.add_argument("--executable", action="store_true")
    args = parser.parse_args(argv)
    try:
        path = fetch(args.repo, args.tag, args.asset, args.sha256, args.dest)
    except SystemExit as stop:
        print(stop, file=sys.stderr)
        return 2
    if args.executable:
        args.dest.chmod(0o755)
    print(f"fetch-tool: {args.asset} verified via {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
