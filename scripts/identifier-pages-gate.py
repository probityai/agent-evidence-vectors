#!/usr/bin/env python3
"""Every identifier a record, corpus or package names under the Pages host resolves to a page.

An identifier (a predicate type, a contract, a schema, an evaluator, a verifier) is written inside
bytes a third party signs or reads, so it cannot move after publication, and one that returns 404
reads to a verifier exactly like one that was withdrawn. ``predicate/v1/self-reported-record`` was
named 18 times and inside every signed member of its corpus and returned 404; later, 48 of the 120
identifiers the public repositories name answered 404, because this gate read only the predicate
prefix of one host in one repository and the site build publishes only what its sources list.

This gate reads every tracked file of the repository (and of every ``--also`` checkout, for example
the public ``probity`` repository whose packages emit identifiers), in plain text and inside every
base64 ``payload`` a signature covers, and finds each identifier under the Pages host
``https://probityai.github.io/<site>/<family>/...`` with ``<family>`` one of predicate, contract,
schema, evaluator or verifiers. Each must be one of:

* served by this site: the site build writes its page, under both routings a static host may use
  (``<path>.html`` and ``<path>/index.html``);
* served by the organisation site and listed in ``spec/identifiers-served-elsewhere.txt``, with the
  organisation site publishing its page;
* a negative vector and listed in ``spec/identifiers-unresolved.txt``: an identifier a test case names
  to be refused as unknown, which must never resolve.

``--live`` (after a Pages deploy) fetches every one: served identifiers must answer 200, negative
vectors 404. The listings are the review point: a new identifier that is in neither file fails here.

    heavy-queue heavy-run --name identifier-pages-gate --timeout 3600 -- python3 scripts/identifier-pages-gate.py
    heavy-queue heavy-run --name identifier-pages-gate --timeout 3600 -- python3 scripts/identifier-pages-gate.py --also ../probity
    heavy-queue heavy-run --name identifier-pages-gate --timeout 3600 -- python3 scripts/identifier-pages-gate.py --live
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://probityai.github.io"
SITE = "agent-evidence-vectors"
FAMILIES = ("predicate", "contract", "schema", "evaluator", "verifiers")
SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._-]*"
URI_RE = re.compile(
    re.escape(ORIGIN)
    + r"/(?:agent-evidence-vectors|agent-evidence-observer|agent-evidence|probity)/(?:"
    + "|".join(FAMILIES)
    + r")(?:/"
    + SEGMENT
    + r")+"
)
SERVED_ELSEWHERE = ROOT / "spec" / "identifiers-served-elsewhere.txt"
UNRESOLVED = ROOT / "spec" / "identifiers-unresolved.txt"


def tracked_files(root: Path) -> list[Path]:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode("utf-8", "replace")
    return [root / rel for rel in listed.split("\0") if rel]


def _payloads(value: Any) -> list[str]:
    """Every string under a ``payload`` key, at any depth."""
    out: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "payload" and isinstance(item, str):
                out.append(item)
            else:
                out.extend(_payloads(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(_payloads(item))
    return out


def clean(uri: str) -> str:
    """Drop the punctuation a sentence leaves after a URI."""
    return uri.rstrip(".-_")


def uris_in(path: Path) -> set[str]:
    """Every identifier a file names, in plain text or inside a base64 payload. A text search alone
    misses the second, which is where the identifier a signature covers usually sits."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return set()
    found = {clean(u) for u in URI_RE.findall(text)}
    if path.suffix in (".json", ".jsonl"):
        for line in text.splitlines() if path.suffix == ".jsonl" else [text]:
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            for payload in _payloads(doc):
                try:
                    decoded = base64.b64decode(payload, validate=True).decode("utf-8", "replace")
                except (binascii.Error, ValueError):
                    continue
                found |= {clean(u) for u in URI_RE.findall(decoded)}
    return found


def referenced(roots: list[Path]) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {}
    for root in roots:
        for path in tracked_files(root):
            if path in (SERVED_ELSEWHERE, UNRESOLVED):
                continue
            for uri in uris_in(path):
                refs.setdefault(uri, []).append(f"{root.name}/{path.relative_to(root)}")
    return refs


def listed(path: Path) -> set[str]:
    """The identifiers one listing file names, one per line; ``#`` starts a comment."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return {ln.split("#", 1)[0].strip() for ln in lines if ln.split("#", 1)[0].strip()}


def own_path(uri: str) -> str | None:
    """The path of an identifier under this site, else None."""
    prefix = f"{ORIGIN}/{SITE}/"
    return uri.removeprefix(prefix) if uri.startswith(prefix) else None


def pages_dir_serves(uri: str) -> bool:
    """True for an identifier the organisation site serves from this repository's ``pages/``.

    ``pages/`` holds the identifier pages of ``agent-evidence/predicate/v1/``, which the organisation
    site copies; a page present there is a page served.
    """
    prefix = f"{ORIGIN}/agent-evidence/"
    if not uri.startswith(prefix):
        return False
    return (ROOT / "pages" / uri.removeprefix(prefix) / "index.html").is_file()


def hermetic(roots: list[Path]) -> list[str]:
    refs = referenced(roots)
    if not refs:
        return ["no identifier under the Pages host was found at all; the scan is broken"]
    elsewhere = listed(SERVED_ELSEWHERE)
    unresolved = listed(UNRESOLVED)
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        build = subprocess.run(
            [sys.executable, str(ROOT / "docs" / "site" / "build.py"), "--out", tmp],
            capture_output=True,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            return [f"the site build failed: {build.stderr.strip()[-400:]}"]
        for uri, where in sorted(refs.items()):
            if uri in unresolved:
                continue
            if uri in elsewhere:
                continue
            if pages_dir_serves(uri):
                continue
            rel = own_path(uri)
            if rel is None:
                failures.append(
                    f"{uri} is named in {len(where)} file(s) ({', '.join(where[:3])}) on a host this "
                    "site does not serve and is in neither spec/identifiers-served-elsewhere.txt nor "
                    "spec/identifiers-unresolved.txt"
                )
                continue
            # A family listing (predicate/v1) is a directory page; an identifier has both routings.
            routes = (f"{rel}/index.html",) if rel.count("/") < 2 else (f"{rel}.html", f"{rel}/index.html")
            for route in routes:
                if not (Path(tmp) / route).is_file():
                    failures.append(
                        f"{uri} is named in {len(where)} file(s) ({', '.join(where[:3])}) and the site "
                        f"build writes no {route}, so the identifier returns 404; register it "
                        "(predicates: spec/predicates/REGISTRY.md; schemas: spec/schemas/; contracts: "
                        "a corpus manifest contractId) or list it as a negative vector in "
                        "spec/identifiers-unresolved.txt"
                    )
                    break
    stale = sorted((elsewhere | unresolved) - set(refs))
    failures.extend(f"{uri} is listed but no tracked file names it; delete the line" for uri in stale)
    both = sorted(elsewhere & unresolved)
    failures.extend(f"{uri} is listed as both served and unresolved" for uri in both)
    print(
        f"{len(refs)} identifier(s) named in tracked files of {len(roots)} checkout(s); "
        f"{len(unresolved)} negative vector(s), {len(elsewhere)} served by the organisation site"
    )
    return failures


def status(url: str) -> int | str:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 -- a fixed https host
            return response.status
    except urllib.error.HTTPError as err:
        return err.code
    except (urllib.error.URLError, TimeoutError) as err:
        return f"the request did not complete ({err})"


def built_identifiers() -> set[str]:
    """Every identifier-family URL in the sitemap of the site this tree builds."""
    with tempfile.TemporaryDirectory() as tmp:
        build = subprocess.run(
            [sys.executable, str(ROOT / "docs" / "site" / "build.py"), "--out", tmp],
            capture_output=True,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            raise SystemExit(f"FAIL: the site build failed: {build.stderr.strip()[-400:]}")
        sitemap = (Path(tmp) / "sitemap.xml").read_text(encoding="utf-8")
    family = "|".join(FAMILIES)
    pattern = re.escape(f"{ORIGIN}/{SITE}/") + rf"(?:{family})/[^<\s]+"
    return {clean(u.rstrip("/")) for u in re.findall(pattern, sitemap)}


def live(roots: list[Path]) -> list[str]:
    failures = []
    unresolved = listed(UNRESOLVED)
    wanted = set(referenced(roots)) | listed(SERVED_ELSEWHERE) | unresolved | built_identifiers()
    for uri in sorted(wanted):
        got = status(uri)
        want = 404 if uri in unresolved else 200
        print(f"{got} {uri}")
        if isinstance(got, str):
            failures.append(f"{uri}: {got}; nothing was established")
        elif got != want:
            failures.append(f"{uri} answered {got}, expected {want}")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--live", action="store_true", help="fetch each identifier from the published host")
    parser.add_argument("--also", type=Path, action="append", default=[], help="another checkout to scan")
    args = parser.parse_args(argv)
    roots = [ROOT, *[p.resolve() for p in args.also]]
    failures = live(roots) if args.live else hermetic(roots)
    for failure in failures:
        print(f"FAIL: {failure}")
    if not failures:
        print("OK: every identifier resolves" + (" on the published host" if args.live else " as listed"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
