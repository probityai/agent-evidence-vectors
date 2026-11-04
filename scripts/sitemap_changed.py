#!/usr/bin/env python3
"""List the sitemap URLs that are new, or whose lastmod moved, since the live sitemap.

    python3 scripts/sitemap_changed.py --built _site/sitemap.xml --live <url> --out changed/urls.txt

The live sitemap is read before the deploy that replaces it. When it cannot be read (the first
deploy) every built URL counts as new. A URL is written when it is absent from the live sitemap or
its lastmod differs, and the sitemap's own URL is added when anything changed. A built URL with no
lastmod is a failure: the build is meant to refuse it already.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ENTRY = re.compile(r"<url>(.*?)</url>", re.S)
LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")
LASTMOD = re.compile(r"<lastmod>\s*([^<\s]+)\s*</lastmod>")


def entries(xml: str) -> dict[str, str | None]:
    """Map each <loc> of a sitemap to its <lastmod>, or None when it has none."""
    out: dict[str, str | None] = {}
    for body in ENTRY.findall(xml):
        loc = LOC.search(body)
        if loc:
            stamp = LASTMOD.search(body)
            out[loc.group(1)] = stamp.group(1) if stamp else None
    return out


def changed(built: dict[str, str | None], live: dict[str, str | None]) -> list[str]:
    """URLs of built that are not in live, or whose lastmod differs."""
    return sorted(url for url, stamp in built.items() if url not in live or live[url] != stamp)


def read_live(url: str) -> dict[str, str | None]:
    """The live sitemap's entries; an unreadable sitemap is an empty one, so everything is new."""
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            return entries(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        print(f"note: {url} could not be read; every built URL counts as new")
        return {}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--built", type=Path, required=True)
    parser.add_argument("--live", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    built = entries(args.built.read_text(encoding="utf-8"))
    if not built:
        print("FAIL the built sitemap lists no URL")
        return 1
    bare = [url for url, stamp in built.items() if stamp is None]
    if bare:
        print(f"FAIL {len(bare)} built URLs carry no lastmod, first: {bare[0]}")
        return 1
    urls = changed(built, read_live(args.live))
    if urls:
        urls.append(args.live)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("".join(f"{u}\n" for u in urls), encoding="utf-8")
    print(f"{len(built)} built URLs, {len(urls)} to submit")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
