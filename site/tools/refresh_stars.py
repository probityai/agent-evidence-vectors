#!/usr/bin/env python3
"""Re-read every atlas star count and write the new values, with their read time.

    python3 tools/refresh_stars.py            read, then rewrite data/atlas.toml and CLAIMS.md
    python3 tools/refresh_stars.py --dry-run  read and print, change nothing

`tools/rederive.py` only compares. This tool is the other half: it takes a fresh
read of every `[[entry]]` in data/atlas.toml that names a `repo`, rewrites each
`stars` value in place, records the read time as `meta.stars_read`, and rewrites every
claim-ledger row that quotes one of those counts. Other tables may carry a `repo` too
(a corpus names the repository its bytes are pinned in); those have no star count and
are left alone. It changes nothing unless every read succeeded, so a partial refresh can
never leave some counts new and others old under one read time. Run
`python3 tools/gen_atlas.py` afterwards to regenerate the page.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "atlas.toml"
CLAIMS = ROOT / "CLAIMS.md"
UA = "agent-evidence-atlas-claim-check (https://github.com/probityai/agent-evidence-atlas)"

# A table header line: `[meta]`, `[[entry]]`, `[[corpus]]` and so on.
HEADER = re.compile(r"^\[\[?[A-Za-z_]+\]\]?\s*$", re.MULTILINE)
REPO = re.compile(r'^repo = "([^"]+)"$', re.MULTILINE)
STARS = re.compile(r"^stars = ([0-9]+)$", re.MULTILINE)


class RefreshError(Exception):
    """The data file does not have the shape this tool rewrites; nothing is written."""


def stars(repo: str) -> int:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return int(json.load(r)["stargazers_count"])


def blocks(text: str) -> list[str]:
    """Split the file into its leading text and one block per table, losslessly."""
    starts = [0] + [m.start() for m in HEADER.finditer(text)]
    return [text[a:b] for a, b in zip(starts, starts[1:] + [len(text)]) if b > a]


def entry_counts(text: str) -> list[tuple[str, int]]:
    """Every (repo, stars) pair in an `[[entry]]` table, refusing an entry missing either."""
    found = []
    for block in blocks(text):
        if not block.startswith("[[entry]]"):
            continue
        repo, count = REPO.findall(block), STARS.findall(block)
        if len(repo) > 1 or len(count) > 1 or bool(repo) != bool(count):
            raise RefreshError(f"an [[entry]] needs one repo and one stars line, or neither:\n{block}")
        if repo:
            found.append((repo[0], int(count[0])))
    declared = sum(1 for e in tomllib.loads(text).get("entry", []) if "repo" in e)
    if not found or len(found) != declared:
        raise RefreshError(f"matched {len(found)} entry repo/stars pairs but the file declares {declared}")
    return found


def rewrite(text: str, claims: str, new: dict[str, int], read_at: str) -> tuple[str, str, int]:
    """Return the data file and claim ledger with every entry count replaced by `new`."""
    old = dict(entry_counts(text))
    old_read = tomllib.loads(text)["meta"]["stars_read"].removesuffix(" UTC")
    out = []
    for block in blocks(text):
        if block.startswith("[[entry]]") and REPO.search(block):
            repo = REPO.search(block).group(1)
            block = STARS.sub(f"stars = {new[repo]}", block, count=1)
        out.append(block)
    text, n = re.subn(r'^stars_read = "[^"]*"$', f'stars_read = "{read_at}"', "".join(out), flags=re.MULTILINE)
    if n != 1:
        raise RefreshError("data/atlas.toml has no single meta.stars_read line")
    changed_rows = 0
    for repo, count in old.items():
        before, after = f"{count:,} stars", f"{new[repo]:,} stars"
        if before != after and before in claims:
            changed_rows += claims.count(before)
            claims = claims.replace(before, after)
    # A ledger row that quotes a star count also carries the read time of that count.
    new_read = read_at.removesuffix(" UTC")
    lines = [line.replace(old_read, new_read) if "stars" in line and line.startswith("| ") else line
             for line in claims.split("\n")]
    return text, "\n".join(lines), changed_rows


def main(argv: list[str] | None = None, reader: Callable[[str], int] = stars) -> int:
    dry = "--dry-run" in (sys.argv[1:] if argv is None else argv)
    text = DATA.read_text(encoding="utf-8")
    try:
        found = entry_counts(text)
    except RefreshError as e:
        print(f"{e}; nothing written")
        return 2
    new: dict[str, int] = {}
    for repo, old in found:
        try:
            new[repo] = reader(repo)
        except Exception as e:  # noqa: BLE001 - one failed read stops the whole refresh
            print(f"UNREAD {repo}: {type(e).__name__}: {e}; nothing written")
            return 2
        print(f"{repo:48} {old:>7} -> {new[repo]:>7}")
    read_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if dry:
        print(f"dry run: {len(new)} counts read at {read_at}; nothing written")
        return 0
    try:
        text, claims, changed_rows = rewrite(text, CLAIMS.read_text(encoding="utf-8"), new, read_at)
    except RefreshError as e:
        print(f"{e}; nothing written")
        return 2
    DATA.write_text(text, encoding="utf-8")
    CLAIMS.write_text(claims, encoding="utf-8")
    print(f"wrote {len(new)} counts read at {read_at}; {changed_rows} claim-ledger quotation(s) updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
