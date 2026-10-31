"""Fail when an identifier under https://w3id.org/agent-evidence/ does not resolve.

    python3 scripts/check_uris_resolve.py            # offline, against pages/
    python3 scripts/check_uris_resolve.py --network  # live w3id.org and Pages

The identifiers are the predicate type URIs (one per directory under
pages/predicate/v1/), every vocabulary term URI and every registered value URI
(term URI plus #value) in packages/vocabulary/registry.json, and the listing
roots. Offline, each is rewritten by the rules in w3id/agent-evidence.htaccess,
the copy of the live w3id.org rules, and must land on a file under pages/ that
carries the fragment as an id. With --network the copy is compared with the live
rules, each identifier must answer w3id.org with a 302 to the same target, and
the target must answer 200. The offline check runs on every pull request; the
network check runs on its own schedule, because a rule added here waits for a
w3id.org merge before the live service follows it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W3ID = "https://w3id.org/agent-evidence/"
PAGES_BASE = "https://probityai.github.io/agent-evidence/"
RULES = ROOT / "w3id" / "agent-evidence.htaccess"
LIVE_RULES = "https://raw.githubusercontent.com/perma-id/w3id.org/master/ids/agent-evidence/.htaccess"
RESERVED = {"registry"}
RULE = re.compile(r"^RewriteRule\s+(\S+)\s+(\S+)\s+\[R=302,L\]\s*$")


def rules(text: str) -> list[tuple[re.Pattern, str]]:
    """The RewriteRule lines of an .htaccess file, as (pattern, target) pairs."""
    out = []
    for line in text.splitlines():
        match = RULE.match(line.strip())
        if match:
            out.append((re.compile(match[1]), re.sub(r"\$(\d)", r"\\\1", match[2])))
    return out


def rewrite(uri: str, table: list[tuple[re.Pattern, str]]) -> str | None:
    """The redirect target of ``uri`` (fragment removed), or None when no rule matches."""
    path = uri.split("#", 1)[0].removeprefix(W3ID)
    for pattern, target in table:
        match = pattern.match(path)
        if match:
            return match.expand(target)
    return None


def identifiers(pages: Path, index: dict) -> list[str]:
    uris = [W3ID, W3ID + "predicate/v1/", index["term_uri_base"]]
    uris += [W3ID + "predicate/v1/" + d.name for d in sorted((pages / "predicate" / "v1").iterdir()) if d.is_dir()]
    for term in index["terms"].values():
        uris.append(term["uri"])
        uris += [f"{term['uri']}#{value}" for value in term["values"] or []]
    uris += [child["uri"] for child in index["verdict_classes"]["children"].values()]
    snapshots = pages / "vocab" / "v1" / "registry"
    uris += [index["term_uri_base"] + "registry/" + f.name for f in sorted(snapshots.glob("sha256-*.yaml"))]
    return uris


def check(pages: Path, index: dict, table: list[tuple[re.Pattern, str]]) -> list[str]:
    """Every identifier that does not land on a page (and anchor) under ``pages``."""
    failures = [f"{name}: reserved for the registry snapshots, never a term key"
                for name in index["terms"] if name in RESERVED]
    for uri in identifiers(pages, index):
        target = rewrite(uri, table)
        if target is None or not target.startswith(PAGES_BASE):
            failures.append(f"{uri}: no w3id rule sends it to {PAGES_BASE}")
            continue
        rel = target.removeprefix(PAGES_BASE)
        page = pages / (rel + "index.html" if rel == "" or rel.endswith("/") else rel)
        if page.suffix == ".yaml" and page.is_file():
            if "sha256-" + hashlib.sha256(page.read_bytes()).hexdigest() + ".yaml" != page.name:
                failures.append(f"{uri}: {page.name} does not hash to its name")
            continue
        if not page.is_file():
            failures.append(f"{uri}: {target} has no page at {page.relative_to(pages.parent)}")
            continue
        if "#" in uri and f'id="{uri.split("#", 1)[1]}"' not in page.read_text(encoding="utf-8"):
            failures.append(f"{uri}: {page.relative_to(pages.parent)} has no anchor for the fragment")
    return failures


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def check_network(pages: Path, index: dict, table: list[tuple[re.Pattern, str]]) -> list[str]:
    failures = []
    with urllib.request.urlopen(LIVE_RULES, timeout=30) as response:
        live = rules(response.read().decode("utf-8"))
    if [(p.pattern, t) for p, t in live] != [(p.pattern, t) for p, t in table]:
        failures.append(f"w3id/agent-evidence.htaccess differs from the live rules at {LIVE_RULES}")
    opener = urllib.request.build_opener(_NoRedirect)
    for uri in sorted({u.split("#", 1)[0] for u in identifiers(pages, index)}):
        expected = rewrite(uri, table)
        if expected is None:
            failures.append(f"{uri}: no w3id.org rule matches")
            continue
        try:
            opener.open(urllib.request.Request(uri, method="HEAD"), timeout=30)
            failures.append(f"{uri}: answered without a redirect")
            continue
        except urllib.error.HTTPError as err:
            if err.code != 302 or err.headers.get("Location") != expected:
                failures.append(f"{uri}: answered {err.code} {err.headers.get('Location')}, expected 302 {expected}")
                continue
        try:
            with urllib.request.urlopen(urllib.request.Request(expected, method="HEAD"), timeout=30) as response:
                if response.status != 200:
                    failures.append(f"{expected}: answered {response.status}")
        except urllib.error.HTTPError as err:
            failures.append(f"{expected}: answered {err.code}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").partition("\n")[0])
    parser.add_argument("--network", action="store_true", help="also check the live w3id.org rules and pages")
    args = parser.parse_args(argv)
    pages = ROOT / "pages"
    index = json.loads((ROOT / "packages" / "vocabulary" / "registry.json").read_text(encoding="utf-8"))
    table = rules(RULES.read_text(encoding="utf-8"))
    failures = check(pages, index, table)
    if args.network:
        failures += check_network(pages, index, table)
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(f"{len(identifiers(pages, index))} identifiers resolve" + (" (live)" if args.network else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
