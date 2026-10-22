#!/usr/bin/env python3
"""Regenerate the W3C intake-criteria conformance corpus byte-identically.

    python3 gen_vectors.py            # write vectors/, trees/, MANIFEST.json, INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The text this corpus tests is vendored in ``spec-vendored/`` and pinned by
digest: the intake criteria v2 as posted to the W3C public-agent-conformance
list on 2026-10-13 (2026Oct/0067), the four wording deltas the editor accepted
the same day (0070), the field he announced for the consolidated text (0073),
the fifth delta (0075), and the criterion-6 consumed state proposed in 0090
and measured in 0091. None of them carries an identifier, so each
rejection ground is minted here as ``W3C-I-NNN`` and bound to its sentence by
sha256; a reword stops the build rather than re-pointing the members that cite
it.

The attack comes first. For every ground there is a record a careless intake
reader admits: a footer total that proves itself, a selection silently bound to
the first of three matches, a relaxed control that reads as isolating because
the state did not move, a checker named by a branch. Each reject member is
refused under exactly that ground and no other, and each ground also has a
member that must be admitted, so a reader that refuses everything scores zero.
Members that need bytes on disk carry a ``root`` under ``trees/`` and are
judged with it.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Callable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "packaging"))

from agent_evidence_vectors import w3cintake  # noqa: E402
from agent_evidence_vectors.w3cintake import G  # noqa: E402

SUITE = w3cintake.SUITE
SPEC_VERSION = "2"
ARCHIVE = "https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/"

VENDORED = {
    "2026Oct-0067": "spec-vendored/2026Oct-0067-wang-2026-10-13-intake-criteria-v2.txt",
    "2026Oct-0070": "spec-vendored/2026Oct-0070-wang-2026-10-13-four-deltas.txt",
    "2026Oct-0073": "spec-vendored/2026Oct-0073-wang-2026-10-13-criterion-8-terminology.txt",
    "2026Oct-0075": "spec-vendored/2026Oct-0075-wang-2026-10-13-fifth-delta.txt",
    "2026Oct-0090": "spec-vendored/2026Oct-0090-kroehl-2026-10-14-consumed-state.txt",
    "2026Oct-0091": "spec-vendored/2026Oct-0091-rocchia-2026-10-14-swap-and-re-pin.txt",
}
#: Who posted each vendored message, as the archive's Author field names them.
AUTHORS = {
    "2026Oct-0067": "Guigui Wang",
    "2026Oct-0070": "Guigui Wang",
    "2026Oct-0073": "Guigui Wang",
    "2026Oct-0075": "Guigui Wang",
    "2026Oct-0090": "Lars Kersten Kroehl",
    "2026Oct-0091": "Nicolas Rocchia",
}

#: What each vendored text is, as the list states it. 0090 proposes the
#: wording for the criterion-6 consumed state and 0091 measures it; the editor
#: has not yet ruled on either.
STATUS = {
    "2026Oct-0067": "v2",
    "2026Oct-0070": "v2.1-delta",
    "2026Oct-0075": "v2.1-delta",
    "2026Oct-0073": "v2.1-announced",
    "2026Oct-0090": "v2.1-proposed",
    "2026Oct-0091": "v2.1-proposed",
}

V2, D = "2026Oct-0067", "2026Oct-0070"
LK, NR = "2026Oct-0090", "2026Oct-0091"

#: One row per ground: (number, criterion, message, verbatim sentence, needs root).
GROUNDS: tuple[tuple[int, str, str, str, bool], ...] = (
    (1, "1", V2, "Every member of the admitted population is pinned by a digest over its "
     "exact bytes", False),
    (2, "1", V2, "a corpus digest covers the full tree together with its manifest", False),
    (3, "1", V2, "A reader refuses any member whose bytes do not match the pin.", True),
    (4, "2", V2, "The record carries a closed manifest of unique case or report identifiers, "
     "checked in both directions.", False),
    (5, "2(i)", V2, "(i) missing from the population", False),
    (6, "2(ii)", V2, "(ii) duplicated", False),
    (7, "2(iii)", D, "returned member outside the declared population is refused", False),
    (8, "2(iii)", D, "an unexpected member inside a package declared complete", True),
    (9, "2(iii)", D, "The boundary is declared before the check", False),
    (10, "3", V2, "Alongside the digest the record names which members were selected, by what "
     "expression, and how many matched.", False),
    (11, "3", V2, "A selection resolving to zero reports", False),
    (12, "3", V2, "or to more than one where exactly one is required, is refused at intake "
     "rather than silently bound", False),
    (13, "4", V2, "The per-case lines, the aggregate line and the exit code are all carried, so "
     "the finding does not rest on one line.", False),
    (14, "4", V2, "The printed total is one more value compared against the recount; any "
     "divergence is a refusal with both numbers recorded.", False),
    (15, "4", V2, "The reader recounts outcomes from the per-case records and never takes a "
     "printed summary line as the result.", False),
    (16, "4", V2, "For each refusal the record names the decision rule and the exact inputs it "
     "was recomputed from", False),
    (17, "4", "2026Oct-0075", "the pinned record\nbytes, including the carried per-case lines, "
     "aggregate line and exit code\nnamed in this criterion", False),
    (18, "5", V2, "Native verdicts, reasons and process status are carried unchanged.", False),
    (19, "5", V2, "Native verdicts, reasons and process status are carried unchanged.", True),
    (20, "6", V2, "For each observation the record states one of three states: carried inline, "
     "referenced by digest, or absent.", False),
    (21, "6", V2, "An observation declared inline and not present is a fail-closed refusal.",
     False),
    (22, "7", V2, "The submitter declares an anchor carrying enough data to distinguish an "
     "availability failure (the reference does not resolve) from an integrity failure (it "
     "resolves but the digest does not match), and names the verdict for each.", False),
    (23, "7", V2, "the reference does not resolve", True),
    (24, "7", V2, "it resolves but the digest does not match", True),
    (25, "8", V2, "The checker is named by an immutable source revision and the exact command "
     "run", True),
    (26, "8", V2, "with runtime and dependencies named rather than inherited from whichever "
     "reader ran first", True),
    (27, "8", V2, "Any helper script, fixture fetcher or other artifact acquired at run time is "
     "named by both its acquisition URI and a content digest", False),
    (28, "8", V2, "an unresolvable helper or a digest mismatch is a refusal, never a silent "
     "fallback.", True),
    (29, "8", D, "The submitter also states the reader's relationship to the reference\n"
     "  implementation - the same implementation, reference-derived code, or\n"
     "  an implementation written from the specification", False),
    (30, "8", D, "identifies any\n  shared verification code relevant to that distinction",
     False),
    (31, "8", "2026Oct-0073", "no reader written from the specification has yet been run "
     "against the\nEd25519/JCS corpus, and the v2.1 record will say so as an explicit field.",
     False),
    (32, "9", V2, "The encoding identifier is drawn from a closed set, and a reader that does "
     "not implement the declared encoding rejects the record.", False),
    (33, "9", V2, "Every digest offered as evidence declares its exact input serialization; a "
     "digest whose input serialization is undeclared stays outside the record.", False),
    (34, "10", V2, "Byte identity - the same bytes always produce the same digest - and replay "
     "stability - the same pinned inputs produce byte-identical output across independent "
     "processes - are separate claims and are recorded separately.", False),
    (35, "10", D, "the record\n  declares the ordering used and the seed settings where "
     "applicable", False),
    (36, "10", D, "Where raw outputs differ, that difference\n  is retained even when a "
     "separately declared comparison of results\n  agrees.", False),
    (37, "10", D, "Output that varies across processes with no declared cause is\n  a refusal.",
     False),
    (38, "11", V2, "The record states whether the expected answers were visible to the "
     "implementer before the run.", False),
    (39, "11", V2, "Reproducing recorded answers and detecting an injected fault are separate "
     "claims kept in separate records, even when one suite produces both", False),
    (40, "11", V2, "each deliberate fault has its own result, separate from the reproduction "
     "result and the exposure declaration.", False),
    (41, "11", D, "Pair each relaxed-check result with its baseline", False),
    (42, "11", D, "A FAIL that persists\n  with a different refusing ground is not an unchanged "
     "native result", False),
    (43, "11", D, "where another ground can still reject the object, that control alone\n  does "
     "not isolate the relaxed check.", False),
    (44, "12", V2, "The record states what the suite establishes and what it leaves open.",
     False),
    (45, "12", V2, "It does not claim coverage of the whole attack surface, does not rank "
     "implementations, makes no claim about threats outside the corpus, and does not establish "
     "that an action happened or that its actor had authority", False),
    (46, "6", LK, "for each artifact declared carried inline, the record states whether the "
     "checker read it.", False),
    (47, "6", LK, "An artifact that no check consumes gets its own state, distinct from carried.",
     False),
    (48, "6", NR, "a\nfile no check reads gets its own state, and the record says which\nground "
     "refused.", False),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as handle:
        return handle.read()


def locate(key: str, sentence: str, ident: str) -> int:
    text = read(VENDORED[key]).decode("utf-8")
    if any(ord(ch) > 0x7F for ch in sentence):
        raise SystemExit(f"FAIL: {ident} quotes a non-ASCII sentence")
    index = text.find(sentence)
    if index < 0:
        raise SystemExit(f"FAIL: {ident} quotes a sentence that is not in {VENDORED[key]}")
    if text.find(sentence, index + 1) >= 0:
        raise SystemExit(f"FAIL: {ident} quotes a sentence appearing more than once")
    return text.count("\n", 0, index) + 1


def requirements() -> list[dict[str, Any]]:
    rows = []
    for number, criterion, key, sentence, needs_root in GROUNDS:
        ident = G[number]
        rows.append({
            "id": ident,
            "criterion": criterion,
            "file": key,
            "vendored": VENDORED[key],
            "line": locate(key, sentence, ident),
            "sentence": sentence,
            "sentenceDigest": sha(sentence.encode("utf-8")),
            "status": STATUS[key],
            "needsRoot": needs_root,
        })
    return rows


# --------------------------------------------------------------------------
# The fixture package every record describes: a three-member suite, the
# output its checker printed, the digest list that anchors it, the checker's
# source and lock file, and one helper fetched at run time.
# --------------------------------------------------------------------------

CASES = {
    "c1": {"case": "c1", "statement": {"claim": "the receipt is signed"}, "expect": "accept"},
    "c2": {"case": "c2", "statement": {"claim": "the signature is forged"}, "expect": "reject"},
    "c3": {"case": "c3", "statement": {"claim": "the receipt names its key"}, "expect": "accept"},
}
NATIVE_KIND = {"c1": "accept", "c2": "reject", "c3": "accept"}
#: A shell script rather than Python: the wheel leaves every .py file under a
#: corpus directory out, and a fixture missing from the wheel is a tree that no
#: longer matches its digest there.
CHECKER_SOURCE = (
    "#!/bin/sh\n"
    "# The fixture suite's checker: print the expectation a case carries.\n"
    "sed -n 's/.*\"expect\": \"\\([a-z]*\\)\".*/\\1/p' \"$1\"\n"
)
LOCKFILE = "fixture-dependency==1.0.0 --hash=sha256:" + "0" * 64 + "\n"
HELPER = "#!/bin/sh\n# fetches the fixture suite at run time\nexit 0\n"
HELPER_URI = "https://example.invalid/fixture/fetch.sh"
ANCHOR_URI = "https://example.invalid/fixture/DIGESTS.txt"
SUMMARY_LINE = "verdict: every member behaves as MANIFEST.json declares"
#: The fixture suite's digest routine, as code the record can name by its file.
ROUTINE_SOURCE = (
    "#!/bin/sh\n"
    "# The fixture suite's corpus digest: SHA-256 over the case files in identifier order.\n"
    "cat suite/cases/*.json | sha256sum | cut -d' ' -f1\n"
)
#: The fixture's signing keys. They sign only the fixture digest list and are
#: derived from these labels so the corpus regenerates byte for byte; neither
#: is a secret, and neither signs anything else.
FIXTURE_SEED = hashlib.sha256(b"vectors-w3c-intake fixture anchor key").digest()
OTHER_SEED = hashlib.sha256(b"vectors-w3c-intake fixture key of another signer").digest()
SIGNATURE_PATH, KEY_PATH = "anchor/DIGESTS.txt.sig", "anchor/key.pub"


def jdump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def compact(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _clamped(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(h[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, h[32:]


def public_key(seed: bytes) -> bytes:
    scalar, _ = _clamped(seed)
    return w3cintake._encode_point(w3cintake._point_mul(scalar, w3cintake.BASE_POINT))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """RFC 8032 section 5.1.6; the checker verifies with w3cintake.ed25519_verify."""
    scalar, prefix = _clamped(seed)
    public = public_key(seed)
    order = w3cintake._L
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % order
    big_r = w3cintake._encode_point(w3cintake._point_mul(r, w3cintake.BASE_POINT))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % order
    return big_r + ((r + k * scalar) % order).to_bytes(32, "little")


def key_pem(seed: bytes) -> bytes:
    der = w3cintake.ED25519_SPKI_PREFIX + public_key(seed)
    body = base64.b64encode(der).decode("ascii")
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n".encode("ascii")


def signature_file(seed: bytes, message: bytes) -> bytes:
    """The cosign blob form: the 64 signature bytes in standard base64, no newline."""
    return base64.b64encode(ed25519_sign(seed, message))


def case_bytes(cid: str) -> bytes:
    return jdump(CASES[cid])


def routine_digest(cases: dict[str, bytes] | None = None) -> str:
    """The fixture suite's own corpus routine: member bytes in identifier order."""
    if cases is None:
        cases = {cid: case_bytes(cid) for cid in CASES}
    digest = hashlib.sha256()
    for cid in sorted(cases):
        digest.update(cases[cid])
    return digest.hexdigest()


def digest_line(digest: str, count: int) -> bytes:
    line = f"{digest}  suite/MANIFEST.json  fixture-suite  vectors={count}  no-suiteRevision\n"
    return line.encode("ascii")


def native_cases(kinds: dict[str, str], findings: dict[str, list[str]] | None = None) -> bytes:
    members = []
    for cid in sorted(kinds):
        member: dict[str, Any] = {"id": cid, "kind": kinds[cid]}
        if findings and findings.get(cid):
            member["findings"] = findings[cid]
        members.append(member)
    document = {"suite": "fixture-suite", "dir": "suite", "members": members}
    return (json.dumps(document, separators=(",", ":")) + "\n").encode("utf-8")


def native_summary(kinds: dict[str, str] | None = None) -> bytes:
    kinds = NATIVE_KIND if kinds is None else kinds
    counts: dict[str, int] = {}
    for kind in kinds.values():
        counts[kind] = counts.get(kind, 0) + 1
    lines = ["suite: fixture-suite", f"members: {len(kinds)}"]
    lines += [f"  {kind}: {counts[kind]}" for kind in sorted(counts)]
    return ("\n".join(lines + [SUMMARY_LINE]) + "\n").encode("utf-8")


def suite_files(cases: dict[str, bytes]) -> dict[str, bytes]:
    """The suite, its manifest and the signed digest list that anchors it."""
    manifest = {
        "suite": "fixture-suite",
        "corpusDigest": routine_digest(cases),
        "vectors": [{"id": cid, "file": f"cases/{cid}.json"} for cid in sorted(cases)],
    }
    files = {f"suite/cases/{cid}.json": body for cid, body in cases.items()}
    files["suite/MANIFEST.json"] = jdump(manifest)
    files["anchor/DIGESTS.txt"] = digest_line(routine_digest(cases), len(cases))
    return files


def base_tree() -> dict[str, bytes]:
    files = suite_files({cid: case_bytes(cid) for cid in CASES})
    files["suite/README.md"] = b"A fixture suite; this file is outside the member locations.\n"
    files["out/cases.json"] = native_cases(NATIVE_KIND)
    files["out/summary.txt"] = native_summary()
    files[SIGNATURE_PATH] = signature_file(FIXTURE_SEED, files["anchor/DIGESTS.txt"])
    files[KEY_PATH] = key_pem(FIXTURE_SEED)
    files["checker/check.sh"] = CHECKER_SOURCE.encode("utf-8")
    files["checker/deps.lock"] = LOCKFILE.encode("utf-8")
    files["checker/digest.sh"] = ROUTINE_SOURCE.encode("utf-8")
    files["helpers/fetch.sh"] = HELPER.encode("utf-8")
    return files


def listing(entries: list[tuple[str, str]]) -> str:
    return w3cintake.listing_digest(entries)


def base_record(tree: dict[str, bytes]) -> dict[str, Any]:
    """A record every check admits, built from the fixture tree's own bytes."""
    members = [
        {"id": cid, "files": [{"path": f"suite/cases/{cid}.json",
                                "sha256": sha(tree[f"suite/cases/{cid}.json"])}]}
        for cid in sorted(CASES)
    ]
    manifest = {
        "closed": True,
        "path": "suite/MANIFEST.json",
        "sha256": sha(tree["suite/MANIFEST.json"]),
        "ids": sorted(CASES),
    }
    checks = [
        {"check": cid, "state": "pass", "native": {"verdict": NATIVE_KIND[cid], "reasons": []}}
        for cid in sorted(CASES)
    ]
    record: dict[str, Any] = {
        "format": w3cintake.FORMAT,
        "suite": "fixture-suite",
        "boundary": {
            "root": "suite",
            "complete": True,
            "member-locations": [{"dir": "cases", "suffix": ".json", "recursive": False}],
        },
        "manifest": manifest,
        "members": members,
        "pin-serialization": "bytes",
        "corpus-digest": {"serialization": "sha256-listing-v1", "sha256": ""},
        "selector": {
            "language": "id-glob", "expression": "*", "require": "at-least-one",
            "selected": sorted(CASES), "matched": len(CASES),
        },
        "checks": checks,
        "aggregate": {"line": SUMMARY_LINE, "total": 3, "counts": {"accept": 2, "reject": 1}},
        "exit-code": 0,
        "exit-rule": "zero-iff-every-check-passes",
        "state": "pass",
        "refusal-verdicts": ["reject"],
        "refusals": [{
            "check": "c2",
            "rule": "the fixture checker refuses a case whose expectation is reject",
            "inputs": ["member:c2", "check:c2"],
        }],
        "native": {
            "format": "corpus-result-json-v1",
            "cases": "cases-json",
            "summary": "summary-text",
            "process-status": {"exit-code": 0},
        },
        "observations": [
            {"id": "cases-json", "carry": "referenced", "reference": {
                "path": "out/cases.json", "sha256": sha(tree["out/cases.json"]),
                "serialization": "bytes"}},
            {"id": "summary-text", "carry": "referenced", "reference": {
                "path": "out/summary.txt", "sha256": sha(tree["out/summary.txt"]),
                "serialization": "bytes"}},
            {"id": "stderr", "carry": "carried", "carried": ""},
            {"id": "timing", "carry": "absent"},
        ],
        "anchor": {
            "kind": "digest-list-line",
            "reference": {"uri": ANCHOR_URI, "path": "anchor/DIGESTS.txt"},
            "manifest": "suite/MANIFEST.json",
            "sha256": routine_digest(),
            "serialization": "corpus-routine",
            "routine": "SHA-256 over the member files concatenated in identifier order",
            "routine-file": "checker/digest.sh",
            "verdicts": {"availability-failure": "inconclusive", "integrity-failure": "fail"},
        },
        "artifacts": [{
            "path": "suite/README.md",
            "sha256": sha(tree["suite/README.md"]),
            "serialization": "bytes",
            "consumed": "unconsumed",
            "evidence": {
                "test": "swap-and-re-pin",
                "baseline": {"sha256": sha(tree["out/cases.json"]), "exit-code": 0},
                "swapped": {"sha256": sha(tree["out/cases.json"]), "exit-code": 0},
                "refused-by": [G[2]],
            },
        }],
        "checker": {
            "name": "fixture-check",
            "revision": {
                "kind": "source-listing", "paths": ["checker/check.sh"],
                "serialization": "sha256-listing-v1",
                "sha256": listing([("checker/check.sh", sha(tree["checker/check.sh"]))]),
            },
            "commands": ["sh checker/check.sh suite/cases/<id>.json"],
            "runtime": {"name": "posix-sh", "version": "POSIX.1-2017"},
            "dependencies": [{"path": "checker/deps.lock",
                              "sha256": sha(tree["checker/deps.lock"]),
                              "serialization": "bytes"}],
            "helpers": [{"uri": HELPER_URI, "path": "helpers/fetch.sh",
                         "sha256": sha(tree["helpers/fetch.sh"]), "serialization": "bytes"}],
            "relationship": "same-implementation",
            "shared-verification-code": ["checker/check.sh"],
        },
        "specification-readers": [],
        "non-author-runs": [],
        "canonicalization": {"encoding": "jcs-sha256"},
        "byte-identity": {"pins": 3, "serialization": "bytes"},
        "replay-stability": {
            "state": "stable",
            "ordering": "emission-order",
            "seed": None,
            "cause": None,
            "runs": [
                {"process": "run-1", "sha256": sha(tree["out/cases.json"])},
                {"process": "run-2", "sha256": sha(tree["out/cases.json"])},
            ],
        },
        "exposure": "visible",
        "faults": [],
        "relaxed-controls": [],
        "scope": {
            "establishes": ["the fixture checker, at its source listing, judges each pinned "
                            "member as the fixture manifest declares"],
            "leaves-open": ["whether an implementation written from the specification agrees"],
            "does-not-claim": list(w3cintake.SCOPE_LIMITS),
        },
    }
    return reseal(record)


def reseal(record: dict[str, Any]) -> dict[str, Any]:
    """Recompute the corpus digest and the pin count after a deliberate edit."""
    entries = w3cintake._member_files(record) + w3cintake._artifact_files(record)
    manifest = record.get("manifest") or {}
    if isinstance(manifest, dict) and "path" in manifest and "sha256" in manifest:
        entries = entries + [(manifest["path"], manifest["sha256"])]
    digest = record.get("corpus-digest")
    if isinstance(digest, dict) and "sha256" in digest:
        digest["sha256"] = listing(entries)
    identity = record.get("byte-identity")
    if isinstance(identity, dict) and "pins" in identity:
        identity["pins"] = len(w3cintake._member_files(record))
    return record


def recount(record: dict[str, Any]) -> dict[str, Any]:
    """Make the aggregate, state and exit code agree with the per-case lines."""
    counts: dict[str, int] = {}
    for check in record["checks"]:
        verdict = check["native"]["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
    every = all(c["state"] == "pass" for c in record["checks"])
    record["aggregate"] = dict(record["aggregate"], total=len(record["checks"]), counts=counts)
    record["state"] = "pass" if every else "fail"
    record["exit-code"] = 0 if every else 1
    record["native"]["process-status"]["exit-code"] = record["exit-code"]
    return record


# --------------------------------------------------------------------------
# Members.
# --------------------------------------------------------------------------

Edit = Callable[[dict[str, Any]], Any]


class Members:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.trees: dict[str, dict[str, bytes]] = {}
        self.families: dict[str, str] = {}
        self.base_tree = base_tree()
        self.base = base_record(self.base_tree)

    def tree(self, name: str, change: Callable[[dict[str, bytes]], None] | None = None) -> str:
        if name not in self.trees:
            files = dict(self.base_tree)
            if change is not None:
                change(files)
            self.trees[name] = files
        return "trees/" + name

    def add(
        self,
        number: int,
        kind: str,
        cites: str,
        edit: Edit | None = None,
        root: str | None = None,
    ) -> None:
        record = copy.deepcopy(self.base)
        if edit is not None:
            edit(record)
        ground = G[number]
        self.rows.append({
            "kind": kind,
            "family": f"w3c-i-f-{number:03d}",
            "requirements": [ground],
            "root": root,
            "record": record,
            "expected": {"verdict": kind, "rejects": [ground] if kind == "reject" else []},
            "cites": cites,
        })


def drop(key: str) -> Edit:
    return lambda r: r.pop(key)


def build_population(m: Members) -> None:
    base = m.tree("base")

    def unpin_c3(r: dict[str, Any]) -> None:
        r["members"] = [x for x in r["members"] if x["id"] != "c3"]
        reseal(r)

    def pin_without_digest(r: dict[str, Any]) -> None:
        r["members"][0]["files"][0].pop("sha256")
        reseal(r)

    m.add(1, "accept", "every manifest id pinned by the bytes of its one file")
    m.add(1, "reject", "manifest id c3 is in the result and no pin covers its bytes",
          unpin_c3)
    m.add(1, "reject", "a member pin carries a path and no digest", pin_without_digest)

    def members_only(r: dict[str, Any]) -> None:
        entries = w3cintake._member_files(r)
        r["corpus-digest"]["sha256"] = listing(entries)

    def manifest_moved(files: dict[str, bytes]) -> None:
        files["suite/MANIFEST.json"] = files["suite/MANIFEST.json"].rstrip(b"\n") + b"  \n"

    m.add(2, "accept", "the corpus digest is the listing over the members and the manifest",
          root=base)
    m.add(2, "reject", "the corpus digest covers the member bytes and leaves the manifest out",
          members_only)
    m.add(2, "reject", "the manifest on disk is not the manifest the corpus digest covers",
          root=m.tree("manifest-moved", manifest_moved))

    def readme_moved(files: dict[str, bytes]) -> None:
        files["suite/README.md"] = b"A fixture suite; edited after the run.\n"

    m.add(2, "reject", "the README, which no check reads, was edited after the run; the "
          "artifact pin is the only ground that refuses it", root=m.tree("readme-moved",
                                                                          readme_moved))

    def member_moved(files: dict[str, bytes]) -> None:
        files["suite/cases/c2.json"] = files["suite/cases/c2.json"].replace(
            b"forged", b"genuine")

    m.add(3, "accept", "every member's bytes match its pin", root=base)
    m.add(3, "reject", "c2 on disk is not the bytes its pin names, and the run reported on it",
          root=m.tree("member-moved", member_moved))


def build_inventory(m: Members) -> None:
    def open_manifest(r: dict[str, Any]) -> None:
        r["manifest"]["closed"] = False

    def extra_pin(r: dict[str, Any]) -> None:
        r["members"].append({"id": "c4", "files": [{"path": "suite/cases/c4.json",
                                                    "sha256": "0" * 64}]})
        reseal(r)

    m.add(4, "accept", "a closed manifest of three unique identifiers")
    m.add(4, "reject", "the manifest is declared open, so nothing is checked in both directions",
          open_manifest)
    m.add(4, "reject", "a member is pinned that the manifest does not close over", extra_pin)

    def lose(cid: str) -> Edit:
        def edit(r: dict[str, Any]) -> None:
            r["checks"] = [c for c in r["checks"] if c["check"] != cid]
            r["refusals"] = [x for x in r["refusals"] if x["check"] != cid]
            recount(r)
        return edit

    m.add(5, "accept", "every selected member is returned")
    m.add(5, "reject", "c3 is in the manifest and the result never returned it, so 2 of 2 "
          "printed as a clean run", lose("c3"))

    def duplicate(r: dict[str, Any]) -> None:
        r["checks"].append(copy.deepcopy(r["checks"][0]))
        recount(r)

    m.add(6, "accept", "each identifier is returned once")
    m.add(6, "reject", "c1 is returned twice and counted twice", duplicate)

    def stray(r: dict[str, Any]) -> None:
        r["checks"].append({"check": "c9", "state": "pass",
                            "native": {"verdict": "accept", "reasons": []}})
        recount(r)

    m.add(7, "accept", "the result returns only members of the declared population")
    m.add(7, "reject", "the tooling printed c9, a member outside the manifest, and the record "
          "counts it", stray)


def build_boundary(m: Members) -> None:

    def unexpected(files: dict[str, bytes]) -> None:
        files["suite/cases/c4.json"] = b'{"case": "c4"}\n'

    def outside(files: dict[str, bytes]) -> None:
        files["suite/notes/c4.json"] = b'{"note": "outside the member locations"}\n'
        files["elsewhere/c4.json"] = b'{"note": "outside the package"}\n'

    m.add(8, "accept", "a file outside the member locations is outside the claim and does not "
          "invalidate the report", root=m.tree("outside-package", outside))
    m.add(8, "reject", "c4.json sits among the members of a package declared complete and no "
          "pin covers it", root=m.tree("unexpected-member", unexpected))

    m.add(9, "accept", "the boundary is declared: package root, complete, member locations")
    m.add(9, "reject", "no boundary is declared, so an unexpected member cannot be told from a "
          "stray file", drop("boundary"))


def build_selector(m: Members) -> None:
    def miscount(r: dict[str, Any]) -> None:
        r["selector"]["matched"] = 2

    m.add(10, "accept", "the expression, the three it selects and the count agree")
    m.add(10, "reject", "the record says two matched and lists three", miscount)
    m.add(10, "reject", "no selector: the digest says nothing about which members a result "
          "concerns", drop("selector"))

    def to_none(r: dict[str, Any]) -> None:
        r["selector"].update(expression="z*", selected=[], matched=0)
        r["checks"], r["refusals"] = [], []
        recount(r)

    def exactly_c2(r: dict[str, Any]) -> None:
        r["selector"].update(expression="c2", require="exactly-one", selected=["c2"], matched=1)
        r["checks"] = [c for c in r["checks"] if c["check"] == "c2"]
        recount(r)

    m.add(11, "accept", "a selection resolving to members", exactly_c2)
    m.add(11, "reject", "the selection resolves to zero members and an empty run reads as clean",
          to_none)

    def exactly_many(r: dict[str, Any]) -> None:
        r["selector"].update(expression="c*", require="exactly-one")

    m.add(12, "accept", "exactly one required and exactly one matched", exactly_c2)
    m.add(12, "reject", "exactly one member was requested and c* matches three, which a reader "
          "binds to the first", exactly_many)


def build_recount(m: Members) -> None:
    m.add(13, "accept", "per-case lines, aggregate line and exit code all carried")
    m.add(13, "reject", "only the per-case lines are carried; the aggregate line is gone",
          drop("aggregate"))
    m.add(13, "reject", "the exit code is not carried", drop("exit-code"))

    def footer(r: dict[str, Any]) -> None:
        r["aggregate"]["total"] = 2

    def counts(r: dict[str, Any]) -> None:
        r["aggregate"]["counts"] = {"accept": 3}

    def exit_lies(r: dict[str, Any]) -> None:
        r["checks"][2]["state"] = "fail"
        r["checks"][2]["native"]["reasons"] = ["the reader accepts c3 and rejects nothing"]
        r["refusals"].append({"check": "c3", "rule": "the fixture checker refuses c3",
                              "inputs": ["member:c3"]})
        r["state"] = "fail"

    m.add(14, "accept", "the printed total and counts recount from the per-case lines")
    m.add(14, "reject", "a self-proving footer: the aggregate prints 2 and three lines are "
          "carried", footer)
    m.add(14, "reject", "the aggregate prints three accepts and the lines carry a reject", counts)
    m.add(14, "reject", "exit code 0 under a zero-iff-every-check-passes rule beside a failing "
          "line", exit_lies)



def build_headline(m: Members) -> None:
    def headline(r: dict[str, Any]) -> None:
        r["checks"][1]["state"] = "fail"
        r["checks"][1]["native"]["reasons"] = ["the reader accepts c2, a forged signature"]
        r["exit-code"] = 1
        r["native"]["process-status"]["exit-code"] = 1

    def honest_fail(r: dict[str, Any]) -> None:
        r["checks"][1]["state"] = "fail"
        r["checks"][1]["native"]["reasons"] = ["the reader accepts c2, a forged signature"]
        recount(r)

    def line_contradicts(r: dict[str, Any]) -> None:
        r["checks"][0]["native"]["reasons"] = ["the reader rejects c1 and the manifest "
                                               "expects accept"]

    m.add(15, "accept", "a failing line, and the record states fail", honest_fail)
    m.add(15, "reject", "the record states pass while c2's line fails", headline)
    m.add(15, "reject", "c1's line states pass while its own native line carries a finding",
          line_contradicts)

    def no_refusal(r: dict[str, Any]) -> None:
        r["refusals"] = []

    def no_inputs(r: dict[str, Any]) -> None:
        r["refusals"][0]["inputs"] = []

    m.add(16, "accept", "the refusal of c2 names its rule and its inputs")
    m.add(16, "reject", "c2 is refused and the record names neither rule nor inputs", no_refusal)
    m.add(16, "reject", "c2's refusal names a rule and no inputs", no_inputs)

    def all_inputs(r: dict[str, Any]) -> None:
        r["refusals"][0]["inputs"] = ["member:c2", "check:c2", "aggregate", "exit-code"]

    def tooling(r: dict[str, Any]) -> None:
        r["refusals"][0]["inputs"] = ["member:c2", "tool:stdout-of-the-original-run"]

    m.add(17, "accept", "every input is a pinned member, a carried line, the aggregate or the "
          "exit code", all_inputs)
    m.add(17, "reject", "the refusal is recomputed from the original tool's stdout, which the "
          "record does not hold", tooling)


def build_native(m: Members) -> None:
    base = m.tree("base")

    def no_reasons(r: dict[str, Any]) -> None:
        r["checks"][0]["native"].pop("reasons")

    def no_status(r: dict[str, Any]) -> None:
        r["native"].pop("process-status")

    m.add(18, "accept", "every line carries the native verdict and reasons; the process status "
          "is carried")
    m.add(18, "reject", "c1 carries a verdict and no reasons", no_reasons)
    m.add(18, "reject", "the native process status is not carried", no_status)

    def status_rewritten(r: dict[str, Any]) -> None:
        r["native"]["process-status"]["exit-code"] = 1

    def transcribed(files: dict[str, bytes]) -> None:
        files["out/cases.json"] = native_cases(
            NATIVE_KIND, {"c1": ["the reader rejects c1 and the manifest expects accept"]})

    def transcribed_record(r: dict[str, Any]) -> None:
        body = native_cases(
            NATIVE_KIND, {"c1": ["the reader rejects c1 and the manifest expects accept"]})
        r["observations"][0]["reference"]["sha256"] = sha(body)

    m.add(19, "accept", "the carried lines and aggregate are the native output, byte for byte",
          root=base)
    m.add(19, "reject", "the native process exited 1 and the record carries exit code 0",
          status_rewritten)
    m.add(19, "reject", "the native output names a finding on c1 and the carried line was "
          "transcribed clean", transcribed_record, root=m.tree("native-transcribed", transcribed))

    def inline_word(r: dict[str, Any]) -> None:
        r["observations"][3]["carry"] = "inline"

    def no_digest(r: dict[str, Any]) -> None:
        r["observations"][0]["reference"].pop("sha256")

    m.add(20, "accept", "carried, referenced and absent observations, each stated")
    m.add(20, "reject", "an observation states a carry outside the three", inline_word)
    m.add(20, "reject", "an observation is referenced and carries no digest", no_digest)

    def inline_missing(r: dict[str, Any]) -> None:
        r["observations"][2].pop("carried")

    m.add(21, "accept", "stderr declared inline and present")
    m.add(21, "reject", "stderr declared inline and not present", inline_missing)


def build_consumption(m: Members) -> None:
    """Criterion 6 with 0090 and 0091: pinned, listed and carried is not consumed."""

    def readme(r: dict[str, Any]) -> dict[str, Any]:
        item: dict[str, Any] = r["artifacts"][0]
        return item

    def opened(r: dict[str, Any]) -> None:
        readme(r)["consumed"] = "read"

    def unlisted(r: dict[str, Any]) -> None:
        r.pop("artifacts")
        reseal(r)

    m.add(46, "accept", "the README, the one file beside members and manifest, declared with "
          "its consumed state and the swap that decides it")
    m.add(46, "reject", "the record says nothing about which files a check consumed",
          unlisted)
    m.add(46, "reject", "the README is declared read, which says it was opened, not whether "
          "it entered a verdict", opened)

    def consumed(state: str, changed: bool) -> Edit:
        def edit(r: dict[str, Any]) -> None:
            item = readme(r)
            item["consumed"] = state
            if changed:
                item["evidence"]["swapped"] = {"sha256": "3" * 64, "exit-code": 1}
            if state == "consumed":
                item["evidence"].pop("refused-by")
        return edit

    m.add(47, "accept", "a file whose swap, with every pin moved, changes the native result, "
          "declared consumed", consumed("consumed", True))
    m.add(47, "reject", "the README declared consumed while its swap with every pin moved "
          "leaves the native result byte for byte the baseline", consumed("consumed", False))
    m.add(47, "reject", "the README declared unconsumed while its swap changes the native "
          "result", consumed("unconsumed", True))

    def unnamed(r: dict[str, Any]) -> None:
        readme(r)["evidence"].pop("refused-by")

    def by_a_check(r: dict[str, Any]) -> None:
        readme(r)["evidence"]["refused-by"] = ["the signature check"]

    m.add(48, "accept", "the README enters no verdict, and the record names the artifact pin's "
          "ground as what refuses its swap")
    m.add(48, "reject", "the README enters no verdict and the record does not say which ground "
          "refused its swap", unnamed)
    m.add(48, "reject", "the README enters no verdict and the record credits a check, not a "
          "ground, with refusing its swap", by_a_check)


def build_anchor(m: Members) -> None:
    base = m.tree("base")

    def passes(r: dict[str, Any]) -> None:
        r["anchor"]["verdicts"]["availability-failure"] = "pass"

    def no_digest(r: dict[str, Any]) -> None:
        r["anchor"].pop("sha256")

    m.add(22, "accept", "the anchor carries its reference, its digest and a verdict for each "
          "failure")
    m.add(22, "reject", "an anchor that does not resolve is named as a pass", passes)
    m.add(22, "reject", "the anchor carries a reference and no digest", no_digest)

    def gone(files: dict[str, bytes]) -> None:
        files.pop("anchor/DIGESTS.txt")

    def other_line(files: dict[str, bytes]) -> None:
        files["anchor/DIGESTS.txt"] = (
            f"{'1' * 64}  suite/MANIFEST.json  fixture-suite  vectors=3  no-suiteRevision\n"
        ).encode()

    m.add(23, "accept", "an anchor outside the group's registry, declared and reachable",
          root=base)
    m.add(23, "reject", "the anchor does not resolve: an availability failure",
          root=m.tree("anchor-gone", gone))
    m.add(24, "accept", "the anchor resolves and binds the manifest's own digest", root=base)
    m.add(24, "reject", "the anchor resolves and binds another digest: an integrity failure",
          root=m.tree("anchor-other", other_line))
    build_signed_anchor(m)


def signed(r: dict[str, Any]) -> None:
    r["anchor"]["kind"] = "signed-digest-list"
    r["anchor"]["signature"] = {
        "path": SIGNATURE_PATH, "key": KEY_PATH, "key-sha256": sha(key_pem(FIXTURE_SEED)),
        "scheme": "ed25519", "serialization": "bytes",
    }


def rewritten_cases() -> dict[str, bytes]:
    """c2 rewritten consistently: the shape of a corpus edit whose digests all move with it."""
    cases = {cid: case_bytes(cid) for cid in CASES}
    cases["c2"] = cases["c2"].replace(b"forged", b"genuine")
    return cases


def dropped_cases() -> dict[str, bytes]:
    """c3 deleted consistently from the suite, its manifest and the digest list."""
    return {cid: case_bytes(cid) for cid in CASES if cid != "c3"}


def repinned(cases: dict[str, bytes]) -> Callable[[dict[str, bytes]], None]:
    """The suite and its digest-list line moved to these cases; the signature left as it was."""
    def change(files: dict[str, bytes]) -> None:
        for cid in CASES:
            files.pop(f"suite/cases/{cid}.json", None)
        files.update(suite_files(cases))
        kinds = {cid: NATIVE_KIND[cid] for cid in cases}
        files["out/cases.json"] = native_cases(kinds)
        files["out/summary.txt"] = native_summary(kinds)
    return change


def record_for(cases: dict[str, bytes]) -> Edit:
    """A record re-pinned in full to these cases, the way a consistent rewrite repins it."""
    def edit(r: dict[str, Any]) -> None:
        signed(r)
        tree = suite_files(cases)
        kinds = {cid: NATIVE_KIND[cid] for cid in cases}
        ids = sorted(cases)
        r["members"] = [{"id": cid, "files": [{"path": f"suite/cases/{cid}.json",
                                                "sha256": sha(cases[cid])}]} for cid in ids]
        r["manifest"].update(sha256=sha(tree["suite/MANIFEST.json"]), ids=ids)
        r["selector"].update(selected=ids, matched=len(ids))
        r["checks"] = [c for c in r["checks"] if c["check"] in cases]
        r["refusals"] = [x for x in r["refusals"] if x["check"] in cases]
        recount(r)
        cases_json, summary = native_cases(kinds), native_summary(kinds)
        r["observations"][0]["reference"]["sha256"] = sha(cases_json)
        r["observations"][1]["reference"]["sha256"] = sha(summary)
        for run in r["replay-stability"]["runs"]:
            run["sha256"] = sha(cases_json)
        r["anchor"]["sha256"] = routine_digest(cases)
        reseal(r)
    return edit


def build_signed_anchor(m: Members) -> None:
    base = m.tree("base")

    def unsigned_signed(r: dict[str, Any]) -> None:
        r["anchor"]["kind"] = "signed-digest-list"

    m.add(22, "accept", "a signed digest list naming its signature, its pinned key and the "
          "scheme it is verified under", signed)
    m.add(22, "reject", "the anchor calls itself a signed digest list and names no signature, "
          "so nothing can be verified", unsigned_signed)

    def signature_gone(files: dict[str, bytes]) -> None:
        files.pop(SIGNATURE_PATH)

    m.add(23, "accept", "the signed digest list, its signature and its key all resolve",
          signed, root=base)
    m.add(23, "reject", "the signature over the digest list does not resolve: an availability "
          "failure", signed, root=m.tree("signature-gone", signature_gone))

    def other_signer(files: dict[str, bytes]) -> None:
        files[KEY_PATH] = key_pem(OTHER_SEED)
        files[SIGNATURE_PATH] = signature_file(OTHER_SEED, files["anchor/DIGESTS.txt"])

    m.add(24, "accept", "the signature over the digest list verifies under the pinned key",
          signed, root=base)
    m.add(24, "reject", "c2 rewritten, its pin, the manifest and the digest-list line re-pinned "
          "to match, and the list's signature no longer verifies",
          record_for(rewritten_cases()),
          root=m.tree("anchor-repinned", repinned(rewritten_cases())))
    m.add(24, "reject", "c3 deleted from the suite, the record, the manifest and the digest "
          "list, and the list's signature no longer verifies",
          record_for(dropped_cases()),
          root=m.tree("member-dropped-repinned", repinned(dropped_cases())))
    m.add(24, "reject", "the list re-signed under another key placed beside it, which is not "
          "the key the record pins", signed, root=m.tree("other-signer", other_signer))


def build_checker(m: Members) -> None:
    base = m.tree("base")

    def branch(r: dict[str, Any]) -> None:
        r["checker"]["revision"] = {"kind": "git-commit", "value": "main"}

    def commit(r: dict[str, Any]) -> None:
        r["checker"]["revision"] = {"kind": "git-commit", "value": "a" * 40}

    def source_moved(files: dict[str, bytes]) -> None:
        files["checker/check.sh"] = files["checker/check.sh"] + b"# patched after the run\n"

    m.add(25, "accept", "the checker named by a forty-digit commit and its command", commit)
    m.add(25, "accept", "the checker named by its source listing, which recomputes", root=base)
    m.add(25, "reject", "the checker is named by a branch, which moves", branch)
    m.add(25, "reject", "the checker source on disk is not the source the record names",
          root=m.tree("checker-moved", source_moved))


def build_environment(m: Members) -> None:
    base = m.tree("base")

    def no_runtime(r: dict[str, Any]) -> None:
        r["checker"].pop("runtime")

    def lock_moved(files: dict[str, bytes]) -> None:
        files["checker/deps.lock"] = files["checker/deps.lock"].replace(b"1.0.0", b"1.0.1")

    m.add(26, "accept", "runtime and pinned dependencies named", root=base)
    m.add(26, "reject", "no runtime named: whichever reader ran first supplies one", no_runtime)
    m.add(26, "reject", "the dependency lock on disk is not the one pinned",
          root=m.tree("lock-moved", lock_moved))

    def no_helper_digest(r: dict[str, Any]) -> None:
        r["checker"]["helpers"][0].pop("sha256")

    m.add(27, "accept", "the run-time helper named by URI and digest")
    m.add(27, "reject", "the helper is named by URI only", no_helper_digest)

    def helper_gone(files: dict[str, bytes]) -> None:
        files.pop("helpers/fetch.sh")

    def helper_moved(files: dict[str, bytes]) -> None:
        files["helpers/fetch.sh"] = HELPER.replace("exit 0", "exit 1").encode("utf-8")

    m.add(28, "accept", "the helper resolves to its digest", root=base)
    m.add(28, "reject", "the helper does not resolve and a silent fallback would carry on",
          root=m.tree("helper-gone", helper_gone))
    m.add(28, "reject", "the helper resolves to other bytes",
          root=m.tree("helper-moved", helper_moved))


def build_relationship(m: Members) -> None:

    def independent(r: dict[str, Any]) -> None:
        r["checker"]["relationship"] = "independent"

    def rerun_unstated(r: dict[str, Any]) -> None:
        r["non-author-runs"] = [{"operator": "a second operator", "reader": "fixture-check"}]

    def rerun_derived(r: dict[str, Any]) -> None:
        r["non-author-runs"] = [{
            "operator": "a second operator", "reader": "a reader that read the reference source",
            "relationship": "reference-derived", "shared-verification-code": [],
        }]

    m.add(29, "accept", "the checker is the same implementation; a re-run is reference-derived",
          rerun_derived)
    m.add(29, "reject", "the relationship is stated as independent, outside the closed set",
          independent)
    m.add(29, "reject", "a re-run by another operator states no relationship", rerun_unstated)

    def spec_shares(r: dict[str, Any]) -> None:
        r["checker"]["relationship"] = "written-from-specification"

    def same_shares_nothing(r: dict[str, Any]) -> None:
        r["checker"]["shared-verification-code"] = []

    def spec_clean(r: dict[str, Any]) -> None:
        r["checker"]["relationship"] = "written-from-specification"
        r["checker"]["shared-verification-code"] = []

    m.add(30, "accept", "written from the specification and sharing no verification code",
          spec_clean)
    m.add(30, "reject", "written from the specification while sharing checker/check.sh",
          spec_shares)
    m.add(30, "reject", "the same implementation, recorded as sharing nothing",
          same_shares_nothing)

    def named(r: dict[str, Any]) -> None:
        r["specification-readers"] = [{"reader": "a reader written from the text"}]

    m.add(31, "accept", "a reader written from the specification is named", named)
    m.add(31, "reject", "the record leaves unsaid whether any reader written from the "
          "specification has run", drop("specification-readers"))


def build_encoding(m: Members) -> None:
    def unimplemented(r: dict[str, Any]) -> None:
        r["canonicalization"]["encoding"] = "jcs-sha256-with-floats"

    m.add(32, "accept", "jcs-sha256, which this reader implements")
    m.add(32, "reject", "an encoding outside the set this reader implements", unimplemented)
    m.add(32, "reject", "no canonicalization declared, so it is inherited",
          drop("canonicalization"))

    def corpus_undeclared(r: dict[str, Any]) -> None:
        r["corpus-digest"].pop("serialization")

    def anchor_undeclared(r: dict[str, Any]) -> None:
        r["anchor"].pop("serialization")

    def observation_undeclared(r: dict[str, Any]) -> None:
        r["observations"][1]["reference"].pop("serialization")

    m.add(33, "accept", "every digest declares the bytes it was taken over")
    m.add(33, "reject", "the corpus digest declares no input serialization", corpus_undeclared)
    m.add(33, "reject", "the anchor digest declares no input serialization", anchor_undeclared)
    m.add(33, "reject", "a referenced observation's digest declares no input serialization",
          observation_undeclared)

    def routine_escapes(r: dict[str, Any]) -> None:
        r["anchor"]["routine-file"] = "../digest.sh"

    def routine_gone(files: dict[str, bytes]) -> None:
        files.pop("checker/digest.sh")

    m.add(33, "accept", "the anchor digest's routine is named by a file that resolves",
          root=m.tree("base"))
    m.add(33, "reject", "the anchor digest's routine names a file outside the root",
          routine_escapes)
    m.add(33, "reject", "the anchor digest's routine names a file that is not here",
          root=m.tree("routine-gone", routine_gone))


def build_replay(m: Members) -> None:
    m.add(34, "accept", "byte identity and replay stability recorded as two claims")
    m.add(34, "reject", "replay stability is not recorded; byte identity stands in for it",
          drop("replay-stability"))
    m.add(34, "reject", "byte identity is not recorded", drop("byte-identity"))

    def unordered(r: dict[str, Any]) -> None:
        r["replay-stability"].pop("ordering")

    def seedless(r: dict[str, Any]) -> None:
        r["replay-stability"]["ordering"] = "hash-order"

    def seeded(r: dict[str, Any]) -> None:
        r["replay-stability"].update(ordering="hash-order", seed="PYTHONHASHSEED=2")

    m.add(35, "accept", "hash order with the seed declared", seeded)
    m.add(35, "reject", "a digested stream with no ordering declared", unordered)
    m.add(35, "reject", "hash order with no seed", seedless)

    def differ(state: str, cause: str | None) -> Edit:
        def edit(r: dict[str, Any]) -> None:
            r["replay-stability"]["state"] = state
            r["replay-stability"]["cause"] = cause
            r["replay-stability"]["runs"][1]["sha256"] = "2" * 64
        return edit

    m.add(36, "accept", "the raw outputs differ, the difference is kept and its cause declared",
          differ("varies", "the second run printed absolute paths"))
    m.add(36, "reject", "the raw outputs differ and the record says stable because the results "
          "compare equal", differ("stable", "a separately declared comparison of results agrees"))
    m.add(37, "accept", "outputs that vary with a declared cause",
          differ("varies", "the second run printed absolute paths"))
    m.add(37, "reject", "outputs that vary across processes with no declared cause",
          differ("varies", None))


def build_faults(m: Members) -> None:
    m.add(38, "accept", "the expected answers were visible, and the record says so")
    m.add(38, "reject", "the record does not say whether the expected answers were visible",
          drop("exposure"))

    def one_fault(r: dict[str, Any]) -> None:
        r["faults"] = [{"id": "f-signature", "injected": "flip one byte of c1's signature",
                        "result": {"state": "pass"}}]

    def folded(r: dict[str, Any]) -> None:
        r["faults"] = [{"id": "c2", "injected": "the forged signature in c2",
                        "result": {"state": "pass"}}]

    m.add(39, "accept", "an injected fault kept in its own record", one_fault)
    m.add(39, "reject", "the injected fault is counted among the reproduction checks", folded)
    m.add(39, "reject", "no separate fault record is kept", drop("faults"))

    def resultless(r: dict[str, Any]) -> None:
        r["faults"] = [{"id": "f-signature", "injected": "flip one byte of c1's signature"}]

    m.add(40, "accept", "the fault carries its own result", one_fault)
    m.add(40, "reject", "the fault carries no result of its own", resultless)

    def control(
        baseline: tuple[str, list[str]], relaxed: tuple[str, list[str]] | None,
        native: str, isolation: str,
    ) -> Edit:
        def edit(r: dict[str, Any]) -> None:
            item: dict[str, Any] = {
                "id": "control-2", "relaxed-check": "payload-digest",
                "baseline": {"state": baseline[0], "grounds": baseline[1]},
                "native-claim": native, "isolation-claim": isolation,
            }
            if relaxed is not None:
                item["relaxed"] = {"state": relaxed[0], "grounds": relaxed[1]}
            r["relaxed-controls"] = [item]
        return edit

    isolating = control(("fail", ["payload-digest"]), ("pass", []), "changed", "isolates")
    second = control(("fail", ["payload-digest"]), ("fail", ["artifact-digest"]),
                     "changed", "does-not-isolate")
    m.add(41, "accept", "the relaxed result paired with its baseline", isolating)
    m.add(41, "reject", "a relaxed result with no baseline beside it",
          control(("fail", ["payload-digest"]), None, "changed", "isolates"))
    m.add(42, "accept", "the FAIL persists with another ground, and the record says changed",
          second)
    m.add(42, "reject", "the FAIL persists with another ground and the record calls the native "
          "result unchanged because the state did not move",
          control(("fail", ["payload-digest"]), ("fail", ["artifact-digest"]),
                  "unchanged", "does-not-isolate"))
    m.add(43, "accept", "relaxing the check admits the object, so the control isolates it",
          isolating)
    m.add(43, "reject", "another ground still rejects the object and the control is claimed to "
          "isolate the relaxed check",
          control(("fail", ["payload-digest"]), ("fail", ["artifact-digest"]),
                  "changed", "isolates"))


def build_scope(m: Members) -> None:
    def no_establishes(r: dict[str, Any]) -> None:
        r["scope"].pop("establishes")

    m.add(44, "accept", "what the suite establishes and leaves open, both stated")
    m.add(44, "reject", "the record says what it leaves open and not what it establishes",
          no_establishes)

    def ranks(r: dict[str, Any]) -> None:
        r["scope"]["does-not-claim"].remove("implementation-ranking")

    def surface(r: dict[str, Any]) -> None:
        r["scope"]["establishes"].append("whole-attack-surface")

    m.add(45, "accept", "all four limits kept beside what is established")
    m.add(45, "reject", "the record drops the limit on ranking implementations", ranks)
    m.add(45, "reject", "the record claims coverage of the whole attack surface", surface)


BUILDERS = (
    build_population, build_inventory, build_boundary, build_selector, build_recount,
    build_headline,
    build_native, build_consumption, build_anchor, build_checker, build_environment,
    build_relationship,
    build_encoding, build_replay, build_faults, build_scope,
)

FAMILY_TEXT = "rejection ground {ground}, criterion {criterion}"


def write_tree(out: str, rel: str, files: dict[str, bytes]) -> None:
    for path, body in files.items():
        full = os.path.join(out, rel, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(body)


def build(out: str) -> dict[str, Any]:
    m = Members()
    for builder in BUILDERS:
        builder(m)
    for name, files in m.trees.items():
        write_tree(out, "trees/" + name, files)
    rows = requirements()
    criterion = {row["id"]: row["criterion"] for row in rows}
    entries = []
    for row in m.rows:
        document = dict(row)
        document["specVersion"] = SPEC_VERSION
        document["tree"] = (
            w3cintake.tree_digest(out, row["root"]) if row["root"] is not None else None
        )
        document["id"] = w3cintake.identify(document)
        root = os.path.join(out, row["root"]) if row["root"] is not None else None
        observed = w3cintake.rejections(document["record"], root)
        if observed != document["expected"]["rejects"]:
            raise SystemExit(
                f"FAIL: {document['id']} ({row['cites']}) is refused under {observed}, "
                f"expected {document['expected']['rejects']}"
            )
        rel = f"vectors/{document['id']}.json"
        full = os.path.join(out, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(jdump(document))
        entries.append({
            "id": document["id"], "kind": row["kind"], "file": rel, "family": row["family"],
            "requirements": row["requirements"], "root": row["root"],
            "specVersion": SPEC_VERSION, "expected": row["expected"], "cites": row["cites"],
        })
    entries.sort(key=lambda e: (e["family"], e["kind"], e["id"]))
    seen: set[str] = set()
    for entry in entries:
        if entry["id"] in seen:
            raise SystemExit(f"FAIL: two members share the identifier {entry['id']}")
        seen.add(entry["id"])
    families = {
        f"w3c-i-f-{n:03d}": FAMILY_TEXT.format(ground=G[n], criterion=criterion[G[n]])
        for n in range(1, len(G) + 1)
    }
    manifest: dict[str, Any] = {
        "suite": SUITE,
        "specName": "W3C public-agent-conformance intake criteria for a submitted "
                    "conformance result",
        "specVersion": SPEC_VERSION,
        "specAmendments": "the five wording deltas accepted in 2026Oct/0070 and 2026Oct/0075, "
                          "the field announced in 2026Oct/0073, and the criterion-6 consumed "
                          "state proposed in 2026Oct/0090 and measured in 2026Oct/0091, for "
                          "the consolidated v2.1",
        "specVendored": {
            key: {"path": path, "sha256": sha(read(path)), "author": AUTHORS[key],
                  "source": ARCHIVE + key.split("-", 1)[1] + ".html"}
            for key, path in VENDORED.items()
        },
        "identifierPolicy": "A ground identifier is minted by this corpus and bound to the "
                            "sentence of the list message that fixed it by sha256 over its "
                            "bytes. The messages carry no identifiers, and a criterion number "
                            "names a paragraph rather than a ground.",
        "recordFormat": w3cintake.FORMAT,
        "codeRegistry": {
            "state": list(w3cintake.STATES),
            "selector-language": list(w3cintake.SELECTOR_LANGUAGES),
            "selector-require": list(w3cintake.SELECTOR_REQUIRE),
            "exit-rule": list(w3cintake.EXIT_RULES),
            "native-format": list(w3cintake.NATIVE_FORMATS),
            "carry": list(w3cintake.CARRY),
            "anchor-kind": list(w3cintake.ANCHOR_KINDS),
            "anchor-verdict": list(w3cintake.ANCHOR_VERDICTS),
            "revision-kind": list(w3cintake.REVISION_KINDS),
            "relationship": list(w3cintake.RELATIONSHIPS),
            "encoding": list(w3cintake.ENCODINGS),
            "serialization": list(w3cintake.SERIALIZATIONS),
            "replay-state": list(w3cintake.REPLAY_STATES),
            "ordering": list(w3cintake.ORDERINGS),
            "exposure": list(w3cintake.EXPOSURE),
            "native-claim": list(w3cintake.NATIVE_CLAIMS),
            "isolation-claim": list(w3cintake.ISOLATION_CLAIMS),
            "scope-limit": list(w3cintake.SCOPE_LIMITS),
        },
        "families": families,
        "requirements": rows,
        "counts": {
            "accept": sum(1 for e in entries if e["kind"] == "accept"),
            "reject": sum(1 for e in entries if e["kind"] == "reject"),
        },
        "corpusDigest": "",
        "note": "A member is one intake record, judged with the bytes under its root when it "
                "names one. Each reject member is refused under exactly one ground and every "
                "ground has a member that must be admitted, so a reader that refuses every "
                "record scores zero. Criterion 13 carries no ground: the criteria name no "
                "implementation, and these vectors, not any reader, are the shared test.",
        "vectors": entries,
    }
    manifest["corpusDigest"] = w3cintake.corpus_digest(manifest, out)
    with open(os.path.join(out, "MANIFEST.json"), "wb") as handle:
        handle.write(jdump(manifest))
    with open(os.path.join(out, "INDEX.md"), "wb") as handle:
        handle.write(index(manifest).encode("utf-8"))
    return manifest


def index(manifest: dict[str, Any]) -> str:
    counts = manifest["counts"]
    total = counts["accept"] + counts["reject"]
    lines = [
        "# Conformance vectors (W3C intake criteria v2 with the v2.1 deltas)",
        "",
        "Generated by `gen_vectors.py`; do not edit. Every ground of the intake criteria for a "
        "submitted conformance result, the sentence of the list message that fixed it, and "
        "every member that must be admitted or refused under it.",
        "",
        f"This corpus is {total} members: {counts['accept']} a conformant intake reader must "
        f"admit and {counts['reject']} it must refuse, over {len(manifest['requirements'])} "
        "grounds. Corpus digest (sha256-listing-v1 over `vectors/` and `trees/`): "
        f"`{manifest['corpusDigest']}`.",
        "",
        "Check one member: `python -m agent_evidence_vectors.w3cintake --member "
        "vectors-w3c-intake/vectors/<id>.json` checks the record the member carries, under the "
        "root it names. The command prints which checks read bytes on disk.",
        "",
        "Judge the corpus: `python -m agent_evidence_vectors.w3cintake --judge "
        "vectors-w3c-intake` or `aee-verify vectors-w3c-intake`.",
        "",
        "## Grounds",
        "",
        "| ground | criterion | status | bytes on disk | sentence (message, line) | sha256 |",
        "|---|---|---|---|---|---|",
    ]
    for row in manifest["requirements"]:
        sentence = " ".join(row["sentence"].split())
        lines.append(
            f"| {row['id']} | {row['criterion']} | {row['status']} | "
            f"{'yes' if row['needsRoot'] else 'no'} | {sentence} ({row['file']}, "
            f"line {row['line']}) | `{row['sentenceDigest'][:16]}` |"
        )
    lines += ["", "## Members", "", "| member | kind | ground | root | what it carries |",
              "|---|---|---|---|---|"]
    for entry in manifest["vectors"]:
        lines.append(
            f"| `{entry['id']}` | {entry['kind']} | {entry['requirements'][0]} | "
            f"{entry['root'] or '-'} | {entry['cites']} |"
        )
    return "\n".join(lines) + "\n"


OWNED_DIRS = ("vectors", "trees")
OWNED_FILES = ("MANIFEST.json", "INDEX.md")


def snapshot(root: str) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for name in OWNED_FILES:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            files[name] = read_abs(path)
    for directory in OWNED_DIRS:
        base = os.path.join(root, directory)
        for current, _, names in os.walk(base):
            for name in names:
                full = os.path.join(current, name)
                files[os.path.relpath(full, root).replace(os.sep, "/")] = read_abs(full)
    return files


def read_abs(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def corpus_digest(manifest: dict[str, Any], root: str = HERE) -> str:
    """The digest this corpus publishes, recomputed from the files on disk.

    Imported by scripts/release-digests.py rather than restated there.
    """
    return w3cintake.corpus_digest(manifest, root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    scratch = tempfile.mkdtemp(prefix="w3c-intake-")
    try:
        shutil.copytree(os.path.join(HERE, "spec-vendored"), os.path.join(scratch, "spec-vendored"))
        built = build(scratch)
        fresh = snapshot(scratch)
        if args.check:
            if fresh != snapshot(HERE):
                print("FAIL: vectors-w3c-intake differs from what gen_vectors.py writes; "
                      "run python3 vectors-w3c-intake/gen_vectors.py", file=sys.stderr)
                return 1
            print(f"OK {built['counts']} corpus {built['corpusDigest'][:12]}")
            return 0
        for directory in OWNED_DIRS:
            shutil.rmtree(os.path.join(HERE, directory), ignore_errors=True)
        for rel, body in fresh.items():
            full = os.path.join(HERE, *rel.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as handle:
                handle.write(body)
        print(f"wrote {built['counts']} corpus {built['corpusDigest'][:12]}")
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
