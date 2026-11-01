#!/usr/bin/env python3
"""Offline cases for scripts/field-readiness.py: each state of each check.

Every read goes through a stand-in fetcher and tally, so no case touches the
network. The cases that matter most are the ones that keep a failed read from
printing as a finding: an unreachable page, a release with no digests, and a
tally that did not start must each read INCONCLUSIVE and make the exit 2.

    python3 scripts/field-readiness-test.py

Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fr", HERE / "field-readiness.py")
fr = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["fr"] = fr
spec.loader.exec_module(fr)

CONFIG = {
    "host": "https://h",
    "repository": "o/r",
    "excluded_owners": ["o"],
    "fields": {"f": {"corpus": "vectors-x", "predicates": ["p1", "p2"], "outside_ci": []}},
}
DIGESTS = "https://d/CORPUS-DIGESTS.txt"
LISTED = b"# header\nabc  vectors-x/MANIFEST.json  x  vectors=3  no-suiteRevision\n"
UNLISTED = b"abc  vectors-y/MANIFEST.json  y  vectors=3  no-suiteRevision\n"
FAILURES: list[str] = []


def web(pages: dict[str, tuple[int, bytes]], down: set[str] = frozenset()):
    def get(url: str) -> tuple[int, bytes]:
        if url in down:
            raise fr.ReadFailed(f"{url}: down")
        return pages.get(url, (404, b""))

    return get


def release(digests: bytes | None) -> dict[str, tuple[int, bytes]]:
    assets = (
        [{"name": "CORPUS-DIGESTS.txt", "browser_download_url": DIGESTS}]
        if digests is not None
        else []
    )
    pages = {
        f"{fr.API}/repos/o/r/releases/latest": (
            200,
            json.dumps({"tag_name": "v1", "assets": assets}).encode(),
        ),
        "https://h/predicate/v1/p1": (200, b"<h1>p1</h1>"),
        "https://h/predicate/v1/p2": (200, b"<h1>p2</h1>"),
    }
    if digests is not None:
        pages[DIGESTS] = (200, digests)
    return pages


def full(checked: int, total: int):
    return lambda tag, corpus: {"checked": checked, "total": total, "notes": []}


def expect(label: str, checks: list, states: list[str]) -> None:
    got = [c.status for c in checks]
    if got != states:
        FAILURES.append(f"{label}: expected {states}, got {got}")


def outside(config: dict, workflow_text: str, conclusion: str) -> dict[str, tuple[int, bytes]]:
    pages = release(LISTED)
    pages[f"{fr.API}/repos/a/b"] = (200, json.dumps({"default_branch": "main"}).encode())
    pages[f"{fr.API}/repos/a/b/contents/.github/workflows/w.yml?ref=main"] = (
        200,
        json.dumps({"content": base64.b64encode(workflow_text.encode()).decode()}).encode(),
    )
    pages[
        f"{fr.API}/repos/a/b/actions/workflows/w.yml/runs?branch=main&status=completed&per_page=1"
    ] = (200, json.dumps({"workflow_runs": [{"conclusion": conclusion, "html_url": "u"}]}).encode())
    return pages


def main() -> int:
    G, R, Q, N = fr.GREEN, fr.RED, fr.INCONCLUSIVE, fr.NOT_READ
    expect(
        "listed corpus, full tally",
        fr.run_checks("f", CONFIG, web(release(LISTED)), full(3, 3)),
        [G, G, G, R, N],
    )
    expect(
        "partial tally is red",
        fr.run_checks("f", CONFIG, web(release(LISTED)), full(0, 3)),
        [G, G, R, R, N],
    )
    expect(
        "empty corpus is red",
        fr.run_checks("f", CONFIG, web(release(LISTED)), full(0, 0)),
        [G, G, R, R, N],
    )
    expect(
        "unlisted corpus",
        fr.run_checks("f", CONFIG, web(release(UNLISTED)), full(3, 3)),
        [G, R, R, R, N],
    )
    expect(
        "no digests asset",
        fr.run_checks("f", CONFIG, web(release(None)), full(3, 3)),
        [G, R, R, R, N],
    )
    expect(
        "empty digests file",
        fr.run_checks("f", CONFIG, web(release(b"# only\n")), full(3, 3)),
        [G, Q, Q, R, N],
    )
    missing = release(LISTED)
    del missing["https://h/predicate/v1/p2"]
    expect(
        "a 404 page is red", fr.run_checks("f", CONFIG, web(missing), full(3, 3)), [R, G, G, R, N]
    )
    expect(
        "an unreachable page is inconclusive",
        fr.run_checks("f", CONFIG, web(release(LISTED), {"https://h/predicate/v1/p1"}), full(3, 3)),
        [Q, G, G, R, N],
    )
    expect(
        "an unreadable release is inconclusive",
        fr.run_checks(
            "f", CONFIG, web(release(LISTED), {f"{fr.API}/repos/o/r/releases/latest"}), full(3, 3)
        ),
        [G, Q, Q, R, N],
    )

    def broken(tag: str, corpus: str) -> dict:
        raise fr.ReadFailed("uv did not start")

    checks = fr.run_checks("f", CONFIG, web(release(LISTED)), broken)
    expect("a tally that did not start", checks, [G, G, Q, R, N])
    if fr.exit_code(checks, None) != 2:
        FAILURES.append("an inconclusive check must exit 2")

    config = json.loads(json.dumps(CONFIG))
    config["fields"]["f"]["outside_ci"] = [{"repo": "a/b", "workflow": ".github/workflows/w.yml"}]
    uses = "uses: o/r@v1\n  with:\n    corpus: vectors-x\n"
    expect(
        "outside run passed",
        fr.run_checks("f", config, web(outside(config, uses, "success")), full(3, 3)),
        [G, G, G, G, N],
    )
    expect(
        "outside run failed",
        fr.run_checks("f", config, web(outside(config, uses, "failure")), full(3, 3)),
        [G, G, G, R, N],
    )
    expect(
        "outside run of another corpus",
        fr.run_checks("f", config, web(outside(config, "uses: o/r@v1\n", "success")), full(3, 3)),
        [G, G, G, R, N],
    )
    own = json.loads(json.dumps(config))
    own["fields"]["f"]["outside_ci"] = [{"repo": "o/z", "workflow": ".github/workflows/w.yml"}]
    expect(
        "our own repository is not outside",
        fr.run_checks("f", own, web(release(LISTED)), full(3, 3)),
        [G, G, G, R, N],
    )

    with tempfile.TemporaryDirectory() as tmp:
        held = Path(tmp) / "held.json"
        held.write_text(
            json.dumps(
                {"records": [{"field": "f", "date": "2026-11-01", "digest": "sha256:" + "a" * 64}]}
            )
        )
        checks = fr.run_checks(
            "f", config, web(outside(config, uses, "success")), full(3, 3), records=held
        )
        expect("all five", checks, [G, G, G, G, G])
        if fr.exit_code(checks, 5) != 0 or "5 of 5 green" not in fr.summary("f", checks):
            FAILURES.append("five greens must meet a floor of five")
        held.write_text(
            json.dumps({"records": [{"field": "other", "digest": "sha256:" + "a" * 64}]})
        )
        expect(
            "a record for another field",
            fr.run_checks(
                "f", config, web(outside(config, uses, "success")), full(3, 3), records=held
            ),
            [G, G, G, G, R],
        )
    if fr.exit_code([fr.Check(1, "x", G, ""), fr.Check(2, "y", R, "")], 2) != 1:
        FAILURES.append("a floor that is not met must exit 1")

    for failure in FAILURES:
        print(f"FAIL {failure}")
    print(f"field-readiness-test: {len(FAILURES)} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
