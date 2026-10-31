"""Refuse a change to a published predicate page.

    python3 scripts/check_predicate_pages.py

A predicate type URI under https://w3id.org/agent-evidence/predicate/v1/ redirects to
pages/predicate/v1/<name>/index.html on this repository's Pages site, and a third
party writes the URI inside the bytes they sign. So each page is pinned by digest
in pages/predicate/v1/PAGES.sha256, names its own type URI as its canonical link,
and links to no host but the ones listed here. Changing a page on purpose means
changing its pin in the same commit, which a reviewer sees.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TYPE_BASE = "https://w3id.org/agent-evidence/predicate/v1/"
ALLOWED_HOSTS = {"w3id.org", "github.com", "in-toto.io", "probityai.github.io"}


def check(pages: Path) -> list[str]:
    """Return every failure for the pages under ``pages``; empty when they pass."""
    root = pages / "predicate" / "v1"
    failures = []
    pins = {}
    for line in (root / "PAGES.sha256").read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not re.fullmatch(r"[a-z0-9-]+", name):
            failures.append(f"PAGES.sha256: malformed line {line!r}")
        pins[name] = digest
    names = sorted(d.name for d in root.iterdir() if d.is_dir())
    for name in names:
        page = root / name / "index.html"
        if not page.is_file():
            failures.append(f"{name}: no index.html")
            continue
        data = page.read_bytes()
        text = data.decode("utf-8")
        uri = TYPE_BASE + name
        if name not in pins:
            failures.append(f"{name}: not pinned in PAGES.sha256")
        elif hashlib.sha256(data).hexdigest() != pins[name]:
            failures.append(f"{name}: page changed without its pin (sha256 {hashlib.sha256(data).hexdigest()})")
        if f'<link rel="canonical" href="{uri}">' not in text:
            failures.append(f"{name}: canonical link is not its type URI {uri}")
        if not re.search(rf'Type URI: (<a href="{re.escape(uri)}">)?{re.escape(uri)}', text):
            failures.append(f"{name}: the page does not state its type URI")
        for host in sorted(set(re.findall(r'href="https?://([^/"]+)', text)) - ALLOWED_HOSTS):
            failures.append(f"{name}: links to an unlisted host {host}")
    failures += [f"{name}: pinned but missing" for name in sorted(set(pins) - set(names))]
    return failures


def main() -> int:
    failures = check(ROOT / "pages")
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print("predicate pages ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
