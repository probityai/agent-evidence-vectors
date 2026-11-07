"""Check that every distribution file in a directory is on the package index
with the same SHA-256.

Usage: verify_pypi_upload.py <packages-dir> [<simple-index-url>]

Reads the PEP 691 JSON simple page of each project named by the files. A file
the index does not list yet is retried for up to five minutes, because the
index's cache can lag an upload; a file listed with another digest fails at
once. Exit 0 only when every file was found with its digest.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SUFFIXES = (".whl", ".tar.gz", ".zip")
ATTEMPTS = 30
PAUSE_S = 10


def project_of(filename: str) -> str:
    """The PEP 503 normalised project name a distribution filename belongs to."""
    if filename.endswith(".whl"):
        name = filename.split("-", 1)[0]
    else:
        stem = filename.removesuffix(".tar.gz").removesuffix(".zip")
        name = stem.rsplit("-", 1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()


def listed_digests(index: str, project: str) -> dict[str, str]:
    request = urllib.request.Request(
        f"{index.rstrip('/')}/{project}/",
        headers={"Accept": "application/vnd.pypi.simple.v1+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            page = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise
    return {f["filename"]: f["hashes"].get("sha256", "") for f in page["files"]}


def main(argv: list[str]) -> int:
    directory = Path(argv[1])
    index = argv[2] if len(argv) > 2 else "https://pypi.org/simple"
    local = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir())
        if p.is_file() and p.name.endswith(SUFFIXES)
    }
    if not local:
        print(f"no distribution files in {directory}", file=sys.stderr)
        return 1
    pending = dict(local)
    for attempt in range(1, ATTEMPTS + 1):
        for project in sorted({project_of(name) for name in pending}):
            listed = listed_digests(index, project)
            for name in [n for n in pending if project_of(n) == project]:
                if name not in listed:
                    continue
                if listed[name] != pending[name]:
                    print(
                        f"MISMATCH {name}: index has {listed[name]}, built file is {pending[name]}",
                        file=sys.stderr,
                    )
                    return 1
                print(f"ok {name} sha256 {pending.pop(name)}")
        if not pending:
            print(f"all {len(local)} files on {index} with the built digests")
            return 0
        if attempt < ATTEMPTS:
            time.sleep(PAUSE_S)
    for name in pending:
        print(f"NOT LISTED {name} after {ATTEMPTS * PAUSE_S} s", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
