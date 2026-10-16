#!/usr/bin/env python3
"""Every predicate type URI this repository names resolves on the Pages site.

A ``predicateType`` is written inside bytes a third party signs, so it cannot
move after publication, and a type URI that returns 404 reads to a verifier
exactly like a type that was withdrawn. ``predicate/v1/self-reported-record``
was named 18 times on the default branch and inside every signed member of its
corpus, and returned 404, because it was never entered in
``spec/predicates/REGISTRY.md`` and the site build publishes what the registry
lists.

Two checks, and they answer different questions:

* default (hermetic, every push): every URI under this host's ``/predicate/``
  prefix that appears in a tracked file, including inside a base64 ``payload``
  a signature covers, is registered, and the site build writes a page for it
  under both routings a static host may use (``<name>.html`` and
  ``<name>/index.html``);
* ``--live`` (after a Pages deploy): each of those URIs answers 200 from the
  published host. It cannot run before the deploy that publishes a new page, so
  it runs in the Pages workflow after deploy, never as a pre-push step.

    python3 scripts/predicate-uri-gate.py
    python3 scripts/predicate-uri-gate.py --live
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
HOST = "https://probityai.github.io/agent-evidence-vectors"
URI_RE = re.compile(re.escape(HOST) + r"/predicate/(v\d+)/([a-z0-9-]+)")
REGISTRY_RE = re.compile(r"^### `predicate/(v\d+)/([a-z0-9-]+)`$", re.MULTILINE)


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


def uris_in(path: Path) -> set[tuple[str, str]]:
    """The (version, name) of every type URI a file names, in plain text or
    inside a base64 payload. A text search alone misses the second, which is
    where the URI a signature covers usually sits."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return set()
    found = set(URI_RE.findall(text))
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
                found |= set(URI_RE.findall(decoded))
    return found


def referenced(root: Path) -> dict[tuple[str, str], list[str]]:
    refs: dict[tuple[str, str], list[str]] = {}
    for path in tracked_files(root):
        for key in uris_in(path):
            refs.setdefault(key, []).append(str(path.relative_to(root)))
    return refs


def registered(root: Path) -> set[tuple[str, str]]:
    text = (root / "spec" / "predicates" / "REGISTRY.md").read_text(encoding="utf-8")
    return set(REGISTRY_RE.findall(text))


def hermetic(root: Path) -> list[str]:
    refs = referenced(root)
    if not refs:
        return ["no predicate type URI under the Pages host was found at all; the scan is broken"]
    failures = []
    known = registered(root)
    for key, where in sorted(refs.items()):
        if key not in known:
            failures.append(
                f"predicate/{key[0]}/{key[1]} is named in {len(where)} file(s) "
                f"({', '.join(where[:3])}) and is not in spec/predicates/REGISTRY.md, "
                "so the site publishes no page for it and the URI returns 404"
            )
    with tempfile.TemporaryDirectory() as tmp:
        build = subprocess.run(
            [sys.executable, str(root / "docs" / "site" / "build.py"), "--out", tmp],
            capture_output=True,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            return failures + [f"the site build failed: {build.stderr.strip()[-400:]}"]
        for version, name in sorted(refs):
            for rel in (
                f"predicate/{version}/{name}.html",
                f"predicate/{version}/{name}/index.html",
            ):
                if not (Path(tmp) / rel).is_file():
                    failures.append(f"the site build writes no {rel}")
    print(
        f"{len(refs)} predicate type URI(s) named in tracked files; each is checked against "
        "the registry and the built site"
    )
    return failures


def live(root: Path) -> list[str]:
    failures = []
    for version, name in sorted(set(referenced(root)) | registered(root)):
        url = f"{HOST}/predicate/{version}/{name}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 -- a fixed https host
                status = response.status
        except urllib.error.HTTPError as err:
            status = err.code
        except (urllib.error.URLError, TimeoutError) as err:
            failures.append(f"{url}: the request did not complete ({err}); nothing was established")
            continue
        print(f"{status} {url}")
        if status != 200:
            failures.append(f"{url} answered {status}")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--live", action="store_true", help="fetch each URI from the published host"
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    failures = live(args.root) if args.live else hermetic(args.root)
    for failure in failures:
        print(f"FAIL: {failure}")
    if not failures:
        print(
            "OK: every predicate type URI resolves"
            + (" on the published host" if args.live else " in the built site")
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
