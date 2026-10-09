#!/usr/bin/env python3
"""Unit tests for rules of the v0.1 report reader that the corpus alone cannot pin.

A corpus member proves that a report is judged the way its manifest entry says.
It cannot prove what the reader does with an input no member carries, and two
of the rules here are about exactly that: a tree shape outside the closed set
must be refused rather than hashed as some other shape, and each registered
shape must be hashed by the construction its name denotes. The corpus members
of the same rules live in vectors-w3c-report/; these are the checks below them.

Usage: python3 scripts/w3c-report-rules-test.py
Exit 0 when every case holds; 1 otherwise, naming each case that did not.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import contextdiscovery, runmetrics, w3creport  # noqa: E402

CORPUS = REPO / "vectors-w3c-report"

CHECKS: list[dict[str, Any]] = [
    {"check": "c-pass", "state": "pass"},
    {"check": "c-pass-2", "state": "pass"},
    {"check": "c-pass-3", "state": "pass"},
]


def rfc9162_mth(entries: list[bytes]) -> bytes:
    """The Merkle Tree Hash of RFC 9162 section 2.1.1, written from the RFC text.

    Deliberately not the reader's own function: a test that compared the reader
    with itself would pass whatever the reader computed.
    """
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    k = 1
    while k * 2 < len(entries):
        k *= 2
    left, right = rfc9162_mth(entries[:k]), rfc9162_mth(entries[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


def test_unregistered_shape_is_refused() -> None:
    """A shape outside the closed set raises; it is never hashed as another shape."""
    for shape in ("RFC 9162 SHA-256", "rfc9162", "", "FLAT"):
        try:
            w3creport.check_set_root(CHECKS, shape)
        except w3creport.UnregisteredShape:
            continue
        raise AssertionError(f"check_set_root hashed the unregistered shape {shape!r}")


def test_every_registered_shape_has_its_own_root() -> None:
    """The registry and the dispatch are one table, so no member falls through."""
    for shape in w3creport.TREE_SHAPES:
        w3creport.check_set_root(CHECKS, shape)


def test_rfc9162_sha256_is_the_rfc_9162_tree() -> None:
    """RFC9162_SHA256 (RFC 9942 section 5.1) hashes by RFC 9162 section 2.1.1."""
    if "RFC9162_SHA256" not in w3creport.TREE_SHAPES:
        raise AssertionError("RFC9162_SHA256 is not in the closed set")
    leaves = [w3creport.compact(check) for check in CHECKS]
    expected = rfc9162_mth(leaves).hex()
    got = w3creport.check_set_root(CHECKS, "RFC9162_SHA256")
    if got != expected:
        raise AssertionError(f"RFC9162_SHA256 root {got} is not the RFC 9162 tree {expected}")
    if got == w3creport.flat_root(leaves):
        raise AssertionError("RFC9162_SHA256 hashed as the flat shape")


def _accept_subject(subject_type: str, family: str | None = None) -> dict[str, Any]:
    """The subject of the first accept member of one subject type, as a fresh copy."""
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    for entry in manifest["vectors"]:
        if entry["kind"] != "accept" or entry["subjectType"] != subject_type:
            continue
        if family is not None and entry["family"] != family:
            continue
        member = json.loads((CORPUS / entry["file"]).read_text(encoding="utf-8"))
        subject: dict[str, Any] = copy.deepcopy(member["subject"])
        return subject
    raise AssertionError(f"no accept member of subject type {subject_type}")


def _refused(shape_errors: Callable[[Any], list[str]], subject: Any, what: str) -> None:
    errors = shape_errors(subject)
    if not errors:
        raise AssertionError(f"{what} was read as well-formed")


def test_snapshot_member_types_are_read() -> None:
    """Each list or object the discovery draft gives a type is refused when it has another.

    The draft makes robots.txt exclusion rules and records sequences (section
    4.3, RFC 9309), the resources a consumer retrieved a list of URIs, and each
    resource a description. A snapshot carrying another JSON type there is not
    a snapshot, and reading it as one either crashed the reader or let it pass.
    """
    base = _accept_subject("llm-context-discovery")
    first = next(iter(base["resources"]))
    edits: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("robots.disallow as an integer", lambda d: d["robots"].__setitem__("disallow", 2)),
        ("robots.disallow as a string", lambda d: d["robots"].__setitem__("disallow", "/x/")),
        ("robots.disallow holding an integer", lambda d: d["robots"].__setitem__("disallow", [1])),
        ("robots.records as an integer", lambda d: d["robots"].__setitem__("records", 1)),
        ("robots.records holding a string", lambda d: d["robots"].__setitem__("records", ["x"])),
        ("consumer.retrieved as a string",
         lambda d: d["consumer"].__setitem__("retrieved", "https://example.invalid/llms.txt")),
        ("consumer.retrieved holding an integer",
         lambda d: d["consumer"].__setitem__("retrieved", [0])),
        ("a resource as a string", lambda d: d["resources"].__setitem__(first, "index")),
    ]
    if contextdiscovery.shape_errors(base):
        raise AssertionError("the unmutated accept snapshot was refused")
    for what, edit in edits:
        subject = copy.deepcopy(base)
        edit(subject)
        _refused(contextdiscovery.shape_errors, subject, what)


def test_run_member_types_are_read() -> None:
    """step_count is an integer and every cache_writes ledger is an array of objects."""
    base = _accept_subject("agent-run-metrics")
    edits: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("step_count as a string", lambda d: d.__setitem__("step_count", "3")),
        ("step cache_writes as a string",
         lambda d: d["steps"][0]["usage"].__setitem__("cache_writes", "running")),
        ("step cache_writes holding a string",
         lambda d: d["steps"][0]["usage"].__setitem__("cache_writes", ["PT5M"])),
        ("totals cache_writes as an integer",
         lambda d: d["totals"].__setitem__("cache_writes", 10)),
    ]
    if runmetrics.shape_errors(base):
        raise AssertionError("the unmutated accept Run was refused")
    for what, edit in edits:
        subject = copy.deepcopy(base)
        edit(subject)
        _refused(runmetrics.shape_errors, subject, what)


def test_ledger_tokens_that_are_not_counts_break_the_sum() -> None:
    """A ledger element whose tokens is not a non-negative integer cannot sum to the aggregate.

    Section 3.5: "The sum of the tokens members of cache_writes MUST equal the
    cache_write_tokens member of the same Usage object". A string or a negative
    number is not a token count, so the equality the sentence requires does not
    hold, and row 14 fires instead of the element being skipped.
    """
    base = _accept_subject("agent-run-metrics")
    if "ARM-R-014" in runmetrics.rejections(base):
        raise AssertionError("the unmutated accept Run fired ARM-R-014")
    for tokens in ("demonstrated", -10, None, True):
        subject = copy.deepcopy(base)
        subject["steps"][0]["usage"]["cache_writes"][0]["tokens"] = tokens
        if runmetrics.shape_errors(subject):
            raise AssertionError(f"tokens {tokens!r} was refused as a shape, not read as row 14")
        if "ARM-R-014" not in runmetrics.rejections(subject):
            raise AssertionError(f"tokens {tokens!r} did not fire ARM-R-014")


def test_delta_changes_type_is_read() -> None:
    """A stated delta lists its changes as an array of objects (0087 section 1.3, "delta")."""
    base = _accept_subject("report", family="w3c-f-21")
    if w3creport.shape_errors(base):
        raise AssertionError("the unmutated accept report was refused")
    item = next(e for e in base["evidence"] if "delta" in e)
    index = base["evidence"].index(item)
    for what, changes in (("a string", "fired-rule list"), ("holding a string", ["/llms.txt"])):
        subject = copy.deepcopy(base)
        subject["evidence"][index]["delta"]["changes"] = changes
        _refused(w3creport.shape_errors, subject, f"delta.changes as {what}")


def test_a_malformed_snapshot_is_judged_not_crashed() -> None:
    """robots.disallow as an integer in one member: that member fails, every other is judged.

    The reader used to stop with a TypeError and print no verdict for any
    member.
    """
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    entry = next(
        e for e in manifest["vectors"]
        if e["subjectType"] == "llm-context-discovery" and e["kind"] == "accept"
    )
    with tempfile.TemporaryDirectory(prefix="w3c-rules-") as tmp:
        corpus = Path(tmp) / "vectors-w3c-report"
        shutil.copytree(CORPUS, corpus)
        path = corpus / entry["file"]
        member = json.loads(path.read_text(encoding="utf-8"))
        member["subject"]["robots"]["disallow"] = 2
        path.write_text(json.dumps(member, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(REPO / "packaging" / "run_vectors.py"), "--vectors", str(corpus)],
            capture_output=True, text=True, check=False,
        )
    if "Traceback" in proc.stderr or proc.returncode != 1:
        raise AssertionError(f"exit {proc.returncode}, stderr: {proc.stderr.strip()[-300:]}")
    # The edit also moves the member's identifier and the corpus digest, which
    # both rails report; what must not happen is a finding on any other member.
    failing = [
        line for line in proc.stdout.splitlines()
        if line.startswith("FAIL") and not line.startswith("FAIL corpus:")
    ]
    if not failing or not all(entry["id"] in line for line in failing):
        raise AssertionError(f"expected findings on {entry['id']} alone, got {failing}")
    if "robots.disallow" not in proc.stdout:
        raise AssertionError("the finding does not name robots.disallow")


def run(cases: list[Callable[[], None]]) -> int:
    failures = 0
    for case in cases:
        try:
            case()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {case.__name__}: {exc}")
        else:
            print(f"ok   {case.__name__}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run([
        test_unregistered_shape_is_refused,
        test_every_registered_shape_has_its_own_root,
        test_rfc9162_sha256_is_the_rfc_9162_tree,
        test_snapshot_member_types_are_read,
        test_run_member_types_are_read,
        test_ledger_tokens_that_are_not_counts_break_the_sum,
        test_delta_changes_type_is_read,
        test_a_malformed_snapshot_is_judged_not_crashed,
    ]))
