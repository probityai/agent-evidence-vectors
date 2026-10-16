#!/usr/bin/env python3
"""Every comparison of the write-chain replay is pinned by its own corpus member.

The agent audit record draft requires the ordered write chain to reproduce the
after-state root from the before-state root. The replay that requirement implies
has four comparisons: the running root starts at beforeRoot, each write's
preStateDigest equals the running root (its postStateDigest then replaces it),
the root after the last write equals afterRoot, and with no write at all the two
roots are equal. The mutation sweep in check_vectors.py disables the write-chain
rule as a whole, so it cannot tell a reader that drops one of the four from one
that keeps them all. Until E4, E5 and E6 existed, a reader that skipped the end
comparison passed the whole corpus.

This test swaps the packaged reader's write-chain rule for four weakened copies,
each dropping exactly one comparison, and requires the corpus judge to flag
exactly the member that pins it: E4 for the start, E2 for a link, E5 for the end
after at least one write, E6 for the empty case. The unweakened reader must leave
the corpus clean.

Usage: uv run --extra generators python scripts/write-chain-replay-test.py
Exit 0 when every case holds; 1 with a summary of the failures.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "vectors-agent-audit-record"
sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402,F401  (the reader resolves the rail's Ed25519 through it)
from agent_evidence_vectors import auditrecord  # noqa: E402

Rule = Callable[[Any], None]


def _interval(state: Any) -> tuple[str, str, list[dict[str, Any]]]:
    pred = state.predicate
    interval = pred["effect"]["interval"]
    return interval["beforeRoot"], interval["afterRoot"], pred["effect"]["writes"]


def _refuse() -> None:
    raise auditrecord.Malformed("write-chain-broken")


def without_start(state: Any) -> None:
    """The running root starts at the first write's pre-state, not at beforeRoot."""
    before, after, writes = _interval(state)
    current = writes[0]["preStateDigest"] if writes else before
    for write in writes:
        if write["preStateDigest"] != current:
            _refuse()
        current = write["postStateDigest"]
    if current != after:
        _refuse()


def without_links(state: Any) -> None:
    """Both ends are compared and the links between writes are not."""
    before, after, writes = _interval(state)
    if not writes:
        if before != after:
            _refuse()
        return
    if writes[0]["preStateDigest"] != before or writes[-1]["postStateDigest"] != after:
        _refuse()


def without_end(state: Any) -> None:
    """The root after the last write is never compared with afterRoot."""
    before, after, writes = _interval(state)
    if not writes:
        if before != after:
            _refuse()
        return
    current = before
    for write in writes:
        if write["preStateDigest"] != current:
            _refuse()
        current = write["postStateDigest"]


def without_empty_case(state: Any) -> None:
    """A record with no write is passed without comparing its roots."""
    before, after, writes = _interval(state)
    if not writes:
        return
    current = before
    for write in writes:
        if write["preStateDigest"] != current:
            _refuse()
        current = write["postStateDigest"]
    if current != after:
        _refuse()


WEAKENED: list[tuple[str, Rule, set[str]]] = [
    ("start", without_start, {"E4"}),
    ("links", without_links, {"E2"}),
    ("end", without_end, {"E5"}),
    ("empty case", without_empty_case, {"E6"}),
]


def flagged(rule: Rule | None) -> tuple[set[str], list[str]]:
    """Judge the tracked corpus with the write-chain rule replaced by ``rule``."""
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    draft_ids = {e["id"]: e["draftId"] for e in manifest["vectors"]}
    original = list(auditrecord.RULES)
    if rule is not None:
        auditrecord.RULES[:] = [
            (name, rule if name == "write-chain" else check) for name, check in original
        ]
    try:
        judged = auditrecord.judge(str(CORPUS))
    finally:
        auditrecord.RULES[:] = original
    members = {draft_ids.get(str(m[0]), str(m[0])) for m in judged.members if m[2]}
    return members, list(judged.findings)


def main() -> int:
    if "write-chain" not in auditrecord.rule_names():
        print("FAIL the packaged reader has no rule named write-chain, so nothing was tested")
        return 1
    failures: list[str] = []
    clean, corpus_findings = flagged(None)
    if clean or corpus_findings:
        failures.append(f"the unweakened reader does not judge the corpus clean: {sorted(clean)}")
    for label, rule, want in WEAKENED:
        got, _ = flagged(rule)
        if got != want:
            failures.append(
                f"a reader without the {label} comparison is caught by {sorted(got)}, "
                f"expected exactly {sorted(want)}"
            )
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print("ok   each comparison of the write-chain replay is pinned by its own member")
    return 0


if __name__ == "__main__":
    sys.exit(main())
