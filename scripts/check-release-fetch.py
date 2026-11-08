#!/usr/bin/env python3
"""Fail any release-asset fetch that does not go through the fetch-tool action.

A release asset fetched with a bare client (curl, urllib, requests, wget, `gh release
download`, or a third-party action that downloads one itself) fails the whole job when
the release CDN returns a 5xx. The one allowed route is .github/actions/fetch-tool, which
tries the cache, a retried direct download and the API asset endpoint and checks the
sha256 on every path.

A line that must fetch another way carries `# curl-retry: exempt <reason>` on the same
line or on the line above. The reason is mandatory; a marker without one fails.

Scanned: the workflows, the composite actions, and every repository file those name by
path (one level). Exit 0 clean, 1 findings, 2 the scan could not run.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FETCH = re.compile(
    # curl-retry: exempt the pattern that detects fetches, not a fetch
    r"releases/(?:latest/)?download/|releases/assets/|gh\s+release\s+download|golangci/golangci-lint-action@"
)
MARKER = re.compile(r"curl-retry:\s*exempt\b(.*)$")
PATH_REF = re.compile(r"(?<![\w./-])((?:scripts|actions|packaging)/[\w./-]+\.(?:py|sh))")


def scan_text(name: str, text: str) -> list[str]:
    """Return one finding per unexempted fetch line in this file."""
    lines = text.splitlines()
    findings = []
    for number, line in enumerate(lines, start=1):
        marker = MARKER.search(line) or (MARKER.search(lines[number - 2]) if number > 1 else None)
        if marker is not None and not marker.group(1).strip(" -:\t"):
            findings.append(f"{name}:{number}: `curl-retry: exempt` carries no reason")
            continue
        if FETCH.search(line) and marker is None:
            findings.append(
                f"{name}:{number}: release-asset fetch outside fetch-tool: {line.strip()[:110]}"
            )
    return findings


def scanned_files(root: Path) -> list[Path]:
    seeds = sorted((root / ".github" / "workflows").glob("*.y*ml")) + sorted(
        (root / ".github" / "actions").glob("**/*.y*ml")
    )
    files = {path for path in seeds}
    for path in seeds:
        for ref in PATH_REF.findall(path.read_text(encoding="utf-8")):
            target = root / ref
            if target.is_file():
                files.add(target)
    return sorted(files)


def main() -> int:
    try:
        files = scanned_files(ROOT)
        findings = []
        for path in files:
            findings += scan_text(str(path.relative_to(ROOT)), path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"check-release-fetch: could not scan: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    print(f"check-release-fetch: {len(files)} files scanned, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
