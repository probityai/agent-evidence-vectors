#!/usr/bin/env python3
"""Write the download badges of the README as shields.io endpoint JSON files.

A badge that shields.io builds from pepy or crates.io at view time shows "rate limited by
upstream service" whenever the registry throttles shields. The README instead points
shields at one small JSON file per package, dl-pypi-NAME.json or dl-crates-NAME.json, on
the unprotected `badges` branch. The badges workflow (.github/workflows/badges.yml) runs
this script hourly and pushes the files straight to that branch, so no pull request is
needed and no count goes stale. A source that cannot be read leaves the file unchanged.

The packages are the ones the README names as badges%2Fdl-pypi-NAME.json or
badges%2Fdl-crates-NAME.json inside an img.shields.io/endpoint URL.

usage: refresh-badges.py [--out DIR]   (DIR is a checkout of the badges branch)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

REF = re.compile(r"badges%2Fdl-(pypi|crates)-([A-Za-z0-9._-]+)\.json")
UA = "probityai-badge-refresh"


def fetch(url: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def pypi_total(name: str) -> int:
    key = os.environ.get("PEPY_API_KEY")
    if key:
        data = fetch(
            f"https://api.pepy.tech/api/v2/projects/{name}", {"X-API-Key": key}
        )
        return int(data["total_downloads"])
    data = fetch(f"https://pypistats.org/api/packages/{name}/overall")
    return sum(r["downloads"] for r in data["data"] if r["category"] == "with_mirrors")


def crate_total(name: str) -> int:
    return int(fetch(f"https://crates.io/api/v1/crates/{name}")["crate"]["downloads"])


def human(n: int) -> str:
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k".replace(".0k", "k")
    return f"{n / 1_000_000:.1f}M".replace(".0M", "M")


def payload(message: str, color: str) -> str:
    """The shields.io endpoint document: one flat badge reading "↓ <number>"."""
    doc = {
        "schemaVersion": 1,
        "label": "",
        "message": f"↓ {message}",
        "color": color,
        "cacheSeconds": 3600,
    }
    return json.dumps(doc, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    ap.add_argument("--out", type=Path, default=root / "badges-out")
    ap.add_argument("--readme", type=Path, default=root / "README.md")
    args = ap.parse_args(argv)
    readme = args.readme
    getters = {"pypi": pypi_total, "crates": crate_total}
    found = sorted(set(REF.findall(readme.read_text(encoding="utf-8"))))
    jobs = [(kind, name, getters[kind]) for kind, name in found]
    if not jobs:
        print(f"FAILED: {readme} names no badges%2Fdl-*.json endpoint")
        return 1
    failed = 0
    args.out.mkdir(parents=True, exist_ok=True)
    for kind, name, getter in jobs:
        try:
            total = getter(name)
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
        ) as exc:  # no registry answer changes nothing
            target = args.out / f"dl-{kind}-{name}.json"
            note = "file left unchanged"
            if not target.exists():  # a README must never point at a missing image
                target.write_text(payload("n/a", "lightgrey"), encoding="utf-8")
                note = "no earlier file, wrote an n/a badge"
            print(f"FAILED {kind}/{name}: {type(exc).__name__}: {exc}; {note}")
            failed += 1
            continue
        doc = payload(human(total), "007ec6")
        (args.out / f"dl-{kind}-{name}.json").write_text(doc, encoding="utf-8")
        print(f"{kind}/{name}: {total}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
