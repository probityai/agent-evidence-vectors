#!/usr/bin/env python3
"""Write the download badges of the README tables as static SVG files.

A table badge fetched from shields.io at view time shows "rate limited by upstream
service" whenever pepy or crates.io throttles shields. These files are written by the
pin-refresh run (see .github/workflows/pin-refresh.yml) with scripts/make-badge.py,
committed, and served from the repository, so no table badge calls a third party when
the README is viewed. A source that cannot be read leaves the committed file unchanged.

usage: refresh-badges.py [--out DIR]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import urllib.request
from pathlib import Path

PYPI = ["agent-evidence-vectors", "agent-evidence-vocabulary", "agent-evidence-admission", "jcs-admit"]
CRATES = ["jcs-admit", "dsse"]
UA = "probityai-badge-refresh"


def fetch(url: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https URLs
        return json.load(resp)


def pypi_total(name: str) -> int:
    key = os.environ.get("PEPY_API_KEY")
    if key:
        data = fetch(f"https://api.pepy.tech/api/v2/projects/{name}", {"X-API-Key": key})
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


def load_make_badge():
    path = Path(__file__).with_name("make-badge.py")
    spec = importlib.util.spec_from_file_location("make_badge", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parent.parent / "assets" / "badges"
    ap.add_argument("--out", type=Path, default=default)
    args = ap.parse_args(argv)
    build = load_make_badge().build
    jobs = [("pypi", n, pypi_total) for n in PYPI] + [("crates", n, crate_total) for n in CRATES]
    failed = 0
    args.out.mkdir(parents=True, exist_ok=True)
    for kind, name, getter in jobs:
        try:
            total = getter(name)
        except Exception as exc:  # a registry answer that did not arrive changes nothing
            print(f"FAILED {kind}/{name}: {type(exc).__name__}: {exc}; file left unchanged")
            failed += 1
            continue
        svg = build(human(total), "↓", "#007ec6", None, f"{name} downloads")
        (args.out / f"dl-{kind}-{name}.svg").write_text(svg, encoding="utf-8")
        print(f"{kind}/{name}: {total}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
