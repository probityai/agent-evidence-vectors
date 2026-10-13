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
import re
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
    # Each check holds ASCII strings only, so its RFC 8785 form is the compact,
    # sorted-key JSON written here without the reader's encoder.
    leaves = [json.dumps(c, sort_keys=True, separators=(",", ":")).encode() for c in CHECKS]
    expected = rfc9162_mth(leaves).hex()
    got = w3creport.check_set_root(CHECKS, "RFC9162_SHA256")
    if got != expected:
        raise AssertionError(f"RFC9162_SHA256 root {got} is not the RFC 9162 tree {expected}")
    if got == w3creport.flat_root(leaves):
        raise AssertionError("RFC9162_SHA256 hashed as the flat shape")


def _bound(checks: list[dict[str, Any]], declared: Any) -> dict[str, Any]:
    """A report over ``checks`` whose check-set binding declares an encoding.

    The root is computed here from the RFC 8785 text of each check, not by the
    reader, so the test does not compare the reader with itself.
    """
    leaves = [json.dumps(c, sort_keys=True, separators=(",", ":")).encode() for c in checks]
    report = _accept_subject("report", family="w3c-f-15")
    report["checks"] = copy.deepcopy(checks)
    counts = {"declared": 3, "exercised": 3, "pass": 3, "fail": 0, "inconclusive": 0,
              "not-exercised": 0, "void": 0, "carried": 0, "referenced": 0}
    report["roll-up"] = dict(counts, **{"negative-capable": {"kind": "nothing"}})
    report["evidence"] = []
    report["check-set"] = {"sha256": rfc9162_mth(leaves).hex(), "leaf-count": len(checks),
                           "tree-shape": "rfc6962", "digest-encoding": declared}
    return report


def test_a_declared_encoding_comes_from_the_closed_set() -> None:
    """jcs-sha256 binds; any other declaration is refused under W3C-R-015 by name.

    The closed set is proposed (2026Oct/0038), and the corpus pins its members
    with reports whose encodings part. What no member can pin is a declaration
    that is not a string, or a spelling of the one name that differs only in
    case: each must be refused, never read as the member it resembles.
    """
    if w3creport.rejections(_bound(CHECKS, "jcs-sha256")):
        raise AssertionError("a report declaring jcs-sha256 over its own root was rejected")
    for declared in ("JCS-SHA256", "jcs_sha256", "rfc8785", "", 7, None, ["jcs-sha256"]):
        report = _bound(CHECKS, declared)
        if w3creport.rejections(report) != ["W3C-R-015"]:
            raise AssertionError(f"the declaration {declared!r} was not refused under W3C-R-015")
        if w3creport.check_set_cause(report) != w3creport.UNSUPPORTED_ENCODING:
            raise AssertionError(f"the refusal of {declared!r} does not name its cause")


def test_a_refused_number_names_its_cause_and_token() -> None:
    """A number outside the profile is refused under W3C-R-020 naming cause and token."""
    cases = (
        ("0.5", "non-integer-number"),
        ("9007199254740992", "integer-outside-safe-range"),
        ("1e21", "integer-outside-safe-range"),
        ("1.0e16", "integer-outside-safe-range"),
    )
    for token, cause in cases:
        text = json.dumps(_bound(CHECKS, "jcs-sha256"))
        doc = w3creport.load_json(text.replace('"c-pass"', '"c-pass", "n": ' + token, 1))
        if w3creport.rejections(doc) != ["W3C-R-020"]:
            raise AssertionError(f"{token} was not refused under W3C-R-020")
        if w3creport.check_set_cause(doc) != cause:
            raise AssertionError(f"{token} names {w3creport.check_set_cause(doc)}, not {cause}")
        if w3creport.check_set_refusal(doc) != f"W3C-R-020 ({cause}: {token})":
            raise AssertionError(f"{token} is named {w3creport.check_set_refusal(doc)!r}")


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


WORKED = "## Worked digests for the digest-encoding members"
WORKED_BLOCK = re.compile(r"```\n(\( printf .*? \| sha256sum)\n# ([0-9a-f]{64})\n```")


def test_the_worked_digests_reproduce_in_a_posix_shell() -> None:
    """Each worked digest in INDEX.md, run as printed under sh, gives the root its member declares.

    The commands are what a verifier outside this repository copies, so they
    are run rather than re-derived: a wrong escape in a printf format prints a
    command that hashes other bytes, and only running it shows that. Every
    member of a digest-encoding family must have exactly one block.
    """
    for tool in ("sh", "openssl", "sha256sum"):
        if shutil.which(tool) is None:
            raise AssertionError(f"{tool} is not on PATH, so the worked digests cannot be run")
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    members = {e["id"]: e for e in manifest["vectors"] if e["family"].startswith("w3c-f-jcs-")}
    _, found, section = (CORPUS / "INDEX.md").read_text(encoding="utf-8").partition(WORKED)
    if not found:
        raise AssertionError(f"INDEX.md has no section {WORKED!r}")
    parts = re.split(r"\n\*\*`(v[0-9a-f]{16})`\*\*", section)
    blocks = dict(zip(parts[1::2], parts[2::2], strict=True))
    if sorted(blocks) != sorted(members):
        raise AssertionError(
            f"worked digests for {sorted(set(blocks) - set(members))} without a member, "
            f"members without one: {sorted(set(members) - set(blocks))}"
        )
    for vid, body in sorted(blocks.items()):
        commands = WORKED_BLOCK.findall(body)
        if len(commands) != 1:
            raise AssertionError(f"{vid}: {len(commands)} worked digest blocks, want 1")
        command, printed = commands[0]
        member = json.loads((CORPUS / members[vid]["file"]).read_text(encoding="utf-8"))
        declared = member["subject"]["check-set"]["sha256"]
        if printed != declared:
            raise AssertionError(
                f"{vid}: INDEX.md prints {printed}, the member declares {declared}"
            )
        status, got, err = _first_field(command)
        if status != 0 or got != declared:
            raise AssertionError(
                f"{vid}: the command gives {got or 'nothing'} (exit {status}, {err}), "
                f"the member declares {declared}"
            )


def _family_members(family: str) -> list[dict[str, Any]]:
    """The members of one family, read from the files on disk."""
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    return [w3creport.load_json((CORPUS / e["file"]).read_bytes())
            for e in manifest["vectors"] if e["family"] == family]


def test_compared_set_rule_reads_the_recomputed_moved() -> None:
    """W3C-R-016 holds the recomputed moved, not the declared one, against compared.

    v0.1 section 2: "moved is recomputed, not declared. It is recomputed over
    what the referenced observations actually contain, and an object whose
    moved is not contained in its declared compared set is rejected." Section
    2.1: no rejection row reads the recompute-opaque error list. So a declared
    error list outside compared carries no rejection, a recomputed slot outside
    compared does, and observations the reader cannot resolve fire neither way.
    """
    kinds = {m["kind"]: m for m in _family_members("w3c-f-16")}
    reject, accept = kinds["reject"], kinds["accept"]
    if w3creport.rejections(reject["subject"], resolves=reject["resolves"]) != ["W3C-R-016"]:
        raise AssertionError("a recomputed fired-rule list outside compared is not rejected")
    if w3creport.rejections(reject["subject"], resolves={}):
        raise AssertionError("observations the reader cannot read still fire a moved row")
    item = accept["subject"]["evidence"][0]
    if "error list" not in item["moved"] or "error list" in item["compared"]:
        raise AssertionError("the accept member no longer declares the error list outside compared")
    if w3creport.rejections(accept["subject"], resolves=accept["resolves"]):
        raise AssertionError("a declared error list outside compared carries a rejection")
    widened = copy.deepcopy(reject["subject"])
    widened["evidence"][0]["compared"] = ["verdict", "fired-rule list"]
    if w3creport.rejections(widened, resolves=reject["resolves"]):
        raise AssertionError("a recomputed moved inside compared is still rejected")
    emitted = [m for m in _family_members("w3c-f-disensor")
               if "error list" in m["subject"]["evidence"][0]["moved"]]
    if len(emitted) != 42:
        raise AssertionError(f"{len(emitted)} disensor members carry the error list, want 42")
    for member in emitted:
        if w3creport.rejections(member["subject"], resolves=member["resolves"]):
            raise AssertionError(f"{member['id']}: the pair as emitted is rejected")


#: RFC 8785 writes -0 and -0.0 as 0 (section 3.2.2.3, ECMAScript Number::toString),
#: so this is the leaf a conforming reader produces for the negative-zero check.
NEGATIVE_ZERO_LEAF = b'{"annotations":{"zero":0,"zero-fraction":0},"check":"c-negative-zero",' \
    b'"state":"pass"}'


def _leaf_block_holds(vid: str, name: str, block: dict[str, Any]) -> list[bytes]:
    """A carried block's leaves hash to their digests, its root to them, its command to it."""
    leaves = [bytes.fromhex(leaf["hex"]) for leaf in block["leaves"]]
    for leaf, entry in zip(leaves, block["leaves"], strict=True):
        if hashlib.sha256(leaf).hexdigest() != entry["sha256"]:
            raise AssertionError(f"{vid}: {name} carries a leaf whose sha256 is not its bytes'")
    root = hashlib.sha256(b"".join(hashlib.sha256(leaf).digest() for leaf in leaves)).hexdigest()
    if root != block["root"]:
        raise AssertionError(f"{vid}: {name} root {block['root']} is not the flat root {root}")
    status, got, err = _first_field(block["command"])
    if status != 0 or got != root:
        raise AssertionError(f"{vid}: {name} command gives {got or 'nothing'} (exit {status}, "
                             f"{err}), the block's root is {root}")
    return leaves


def _conforming_holds(vid: str, entry: dict[str, Any], member: dict[str, Any]) -> None:
    """The conforming block: the reader's bytes and root, or the refusal the member expects."""
    conforming = member["canonical"]["conforming"]
    if "refused" in conforming:
        if entry["expected"].get("cause") not in conforming["refused"]:
            raise AssertionError(f"{vid}: refused {conforming['refused']!r} does not name "
                                 f"the cause {entry['expected'].get('cause')}")
        return
    leaves = _leaf_block_holds(vid, "conforming", conforming)
    checks = member["subject"]["checks"]
    if leaves != [w3creport.jcs_sha256(c) for c in checks]:
        raise AssertionError(f"{vid}: the conforming bytes are not the reader's jcs-sha256")
    matches = conforming["root"] == member["subject"]["check-set"]["sha256"]
    if matches != (entry["kind"] == "accept"):
        raise AssertionError(f"{vid}: a {entry['kind']} member whose conforming root "
                             f"{'is' if matches else 'is not'} the one it declares")
    if checks[0]["check"] == "c-negative-zero" and leaves[0] != NEGATIVE_ZERO_LEAF:
        raise AssertionError(f"{vid}: the negative-zero leaf is {leaves[0]!r}")


def _declared_holds(vid: str, entry: dict[str, Any], member: dict[str, Any]) -> None:
    """A reject member's rule-off bytes give the root it declares; an accept has none."""
    declared = member["canonical"].get("declared")
    if entry["kind"] != "reject":
        if declared is not None:
            raise AssertionError(f"{vid}: an accept member carries rule-off bytes")
        return
    if not isinstance(declared, dict) or not declared.get("rule-switched-off"):
        raise AssertionError(f"{vid}: a reject member carries no rule-off bytes")
    _leaf_block_holds(vid, "declared", declared)
    if declared["root"] != member["subject"]["check-set"]["sha256"]:
        raise AssertionError(f"{vid}: the rule-off root is not the root it declares")


def test_each_encoding_member_carries_its_canonical_bytes() -> None:
    """Every digest-encoding member file states the bytes a conforming reader produces.

    The member, not only INDEX.md, carries the jcs-sha256 bytes of each check,
    the flat root over them and the command that prints it, so a reader that
    fails the member learns from the member alone what it should have written.
    A reject member also carries the bytes its declared root was computed over,
    with the rule that was switched off. Read from the files on disk, hashed
    here rather than by the generator, and each command run under sh.
    """
    for tool in ("sh", "openssl", "sha256sum"):
        if shutil.which(tool) is None:
            raise AssertionError(f"{tool} is not on PATH, so the member commands cannot be run")
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = [e for e in manifest["vectors"] if e["family"].startswith("w3c-f-jcs-")]
    if not entries:
        raise AssertionError("the manifest lists no digest-encoding member")
    for entry in entries:
        vid = entry["id"]
        member = w3creport.load_json((CORPUS / entry["file"]).read_bytes())
        block = member.get("canonical")
        if not isinstance(block, dict):
            raise AssertionError(f"{vid}: the member file carries no canonical block")
        if (block.get("encoding"), block.get("tree-shape")) != ("jcs-sha256", "flat"):
            raise AssertionError(f"{vid}: the block names {block.get('encoding')}, "
                                 f"{block.get('tree-shape')}")
        _conforming_holds(vid, entry, member)
        _declared_holds(vid, entry, member)


README_PRINTS_CORPUS_DIGEST = "# prints the corpusDigest in MANIFEST.json"


def _first_field(command: str) -> tuple[int, str, str]:
    """Run a printed command under sh in the corpus directory: exit, first field, stderr."""
    proc = subprocess.run(["sh", "-c", command], cwd=CORPUS, capture_output=True, text=True,
                          check=False)
    fields = proc.stdout.split()
    return proc.returncode, fields[0] if fields else "", proc.stderr.strip()[:200]


def test_the_readme_commands_run_as_printed() -> None:
    """Every sh block of the corpus README, run as printed from the corpus directory.

    A block ends in a comment saying what it prints: a SHA-256 in hex, which
    must be a root that a member of a digest-encoding family declares, or the
    line saying it prints the corpusDigest, which must be the one in
    MANIFEST.json. A block that says neither fails, so no printed command goes
    unrun.
    """
    for tool in ("sh", "openssl", "sha256sum", "python3"):
        if shutil.which(tool) is None:
            raise AssertionError(f"{tool} is not on PATH, so the README commands cannot be run")
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    members = [
        json.loads((CORPUS / e["file"]).read_text(encoding="utf-8"))
        for e in manifest["vectors"] if e["family"].startswith("w3c-f-jcs-")
    ]
    roots = {m["subject"]["check-set"]["sha256"] for m in members}
    blocks = re.findall(r"```sh\n(.*?)\n```", (CORPUS / "README.md").read_text(encoding="utf-8"),
                        re.S)
    if not blocks:
        raise AssertionError("README.md prints no sh block")
    for block in blocks:
        command, _, said = block.rpartition("\n")
        if re.fullmatch(r"# [0-9a-f]{64}", said):
            want = said[2:]
            if want not in roots:
                raise AssertionError(f"README.md prints {want}, a root no encoding member declares")
        elif said == README_PRINTS_CORPUS_DIGEST:
            want = manifest["corpusDigest"]
        else:
            raise AssertionError(f"a README.md sh block ends in {said!r}, not in what it prints")
        status, got, err = _first_field(command)
        if status != 0 or got != want:
            raise AssertionError(
                f"{command.splitlines()[0][:60]}...: gives {got or 'nothing'} (exit {status}, "
                f"{err}), want {want}"
            )


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
        test_a_declared_encoding_comes_from_the_closed_set,
        test_a_refused_number_names_its_cause_and_token,
        test_the_worked_digests_reproduce_in_a_posix_shell,
        test_each_encoding_member_carries_its_canonical_bytes,
        test_compared_set_rule_reads_the_recomputed_moved,
        test_the_readme_commands_run_as_printed,
        test_snapshot_member_types_are_read,
        test_run_member_types_are_read,
        test_ledger_tokens_that_are_not_counts_break_the_sum,
        test_delta_changes_type_is_read,
        test_a_malformed_snapshot_is_judged_not_crashed,
    ]))
