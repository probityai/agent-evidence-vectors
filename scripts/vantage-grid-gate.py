#!/usr/bin/env python3
"""Fail when a cell of the vantage grid loses its evidence link.

    python3 scripts/vantage-grid-gate.py            # offline: files and anchors
    python3 scripts/vantage-grid-gate.py --network  # also every external link

The grid in docs/reference/vantage-grid.md, between its begin and end markers,
must have the five design-class rows and the five columns named below, and every
cell after the first must carry at least one link. A relative link must name a
file in the repository, and a fragment on a Markdown target must match one of
that file's headings under GitHub's anchor rule. An external link must use https
and a host on ALLOWED_HOSTS: standards bodies and large projects, so a grid cell
can never cite a small project or name a vendor through its link. A github.com
link must be pinned to a 40-hex commit. With --network every external link must
answer 200; a control URL is requested first, and when it does not answer the
check exits 2 and reports nothing as missing.

Exit 0 when the grid passes, 1 when a rule fails, 2 when the page cannot be read
or the network read path is broken. Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "reference" / "vantage-grid.md"
BEGIN = "<!-- vantage-grid:begin -->"
END = "<!-- vantage-grid:end -->"
COLUMNS = (
    "Design class",
    "Verifiable offline by a party that distrusts the issuer",
    "Produced by an observer the agent cannot reach",
    "Passing a public corpus",
    "Meets all three",
)
ROWS = (
    "Self-held signed session record",
    "Vendor dashboard verify button",
    "Observability trace",
    "Transparency-log receipt",
    "Independent observer with a public corpus",
)
VERDICTS = {"Yes", "No"}
ALLOWED_HOSTS = {
    "www.rfc-editor.org",
    "datatracker.ietf.org",
    "github.com/open-telemetry",
    "github.com/secure-systems-lab",
    "github.com/sigstore",
    "github.com/in-toto",
    "github.com/probityai",
}
CONTROL = "https://www.rfc-editor.org/"
LINK = re.compile(r"\]\(([^)\s]+)\)")
PINNED = re.compile(r"^/[^/]+/[^/]+/(?:blob|tree)/[0-9a-f]{40}(?:/|$)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
INCONCLUSIVE = 2


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lowercase, markup and punctuation gone,
    spaces to hyphens."""
    text = re.sub(r"`|\*|_", "", heading).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    inside = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        match = None if inside else HEADING.match(line)
        if match:
            found.add(slug(match.group(1)))
    return found


def grid_rows(text: str) -> list[list[str]]:
    start, end = text.find(BEGIN), text.find(END)
    if start < 0 or end < start:
        raise ValueError("grid markers missing or out of order")
    lines = [ln for ln in text[start + len(BEGIN):end].splitlines() if ln.strip()]
    return [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in lines]


def host_allowed(url: str) -> bool:
    parts = urlsplit(url)
    if parts.netloc == "github.com":
        owner = parts.path.split("/")[1] if parts.path.count("/") >= 1 else ""
        return f"github.com/{owner}" in ALLOWED_HOSTS
    return parts.netloc in ALLOWED_HOSTS


def check_link(target: str, page: Path) -> list[str]:
    if target.startswith("#"):
        return [] if target[1:] in anchors(page) else [f"{target}: no such heading on the page"]
    parts = urlsplit(target)
    if parts.scheme:
        if parts.scheme != "https":
            return [f"{target}: not https"]
        if not host_allowed(target):
            return [f"{target}: host not on the allowed list"]
        if parts.netloc == "github.com" and not PINNED.match(parts.path):
            return [f"{target}: github link not pinned to a commit"]
        return []
    path = (page.parent / unquote(parts.path)).resolve()
    if not path.is_file():
        return [f"{target}: no such file"]
    if parts.fragment and path.suffix == ".md" and parts.fragment not in anchors(path):
        return [f"{target}: no heading #{parts.fragment} in {path.name}"]
    return []


def check(page: Path) -> tuple[list[str], list[str]]:
    """Return the failures and every external link, in page order."""
    rows = grid_rows(page.read_text(encoding="utf-8"))
    failures: list[str] = []
    external: list[str] = []
    if len(rows) < 2 or tuple(rows[0]) != COLUMNS:
        return [f"header is {rows[0] if rows else None}, expected {list(COLUMNS)}"], external
    body = rows[2:]
    if tuple(r[0] for r in body) != ROWS:
        failures.append(f"rows are {[r[0] for r in body]}, expected {list(ROWS)}")
    for row in body:
        if len(row) != len(COLUMNS):
            failures.append(f"{row[0]}: {len(row)} cells, expected {len(COLUMNS)}")
            continue
        if row[-1] not in VERDICTS:
            failures.append(f"{row[0]}: last cell {row[-1]!r} is not Yes or No")
        for column, cell in zip(COLUMNS[1:-1], row[1:-1]):
            targets = LINK.findall(cell)
            if not targets:
                failures.append(f"{row[0]} / {column}: cell carries no link")
            for target in targets:
                failures.extend(f"{row[0]} / {column}: {f}" for f in check_link(target, page))
                if urlsplit(target).scheme:
                    external.append(target)
    return failures, external


def answers(url: str) -> int | None:
    request = urllib.request.Request(url, headers={"User-Agent": "vantage-grid-gate"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status)
    except urllib.error.HTTPError as err:
        return int(err.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--page", type=Path, default=PAGE)
    parser.add_argument("--network", action="store_true")
    args = parser.parse_args(argv)
    try:
        failures, external = check(args.page)
    except (OSError, ValueError) as err:
        print(f"vantage-grid-gate: cannot read {args.page}: {err}", file=sys.stderr)
        return INCONCLUSIVE
    if args.network:
        if answers(CONTROL) != 200:
            print(f"vantage-grid-gate: control {CONTROL} did not answer 200; nothing judged", file=sys.stderr)
            return INCONCLUSIVE
        for url in dict.fromkeys(external):
            status = answers(url)
            print(f"{status} {url}")
            if status != 200:
                failures.append(f"{url}: answered {status}")
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"vantage-grid-gate: {len(ROWS)} rows, {len(external)} external links, "
          f"{len(failures)} failures{' (network checked)' if args.network else ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
