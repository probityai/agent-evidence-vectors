#!/usr/bin/env python3
"""Regenerate the anchor-stream reject corpus byte-identically.

    python3 gen_vectors.py            # write streams/, sidecars/, witness/, MANIFEST.json, INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

Every member is built from the stream bundled with the pinned tag
`anchors-verify-v0.4` of `aos-standard/catalog`, which is vendored in
`baseline/`. A member is one triple: the presented stream, the digest sidecar
presented with it, and the platform bytes a verifier would read while checking
it. The third file is what makes a run offline and repeatable: the verifier
reads the witness platform over the network, and a corpus whose verdict depends
on a live fetch is a corpus whose verdict expires.

Identifiers are a digest of the member's own three files. There is no
`accept/` directory, no `reject/` directory and no verdict in a name: the
expectation lives in MANIFEST.json, which is where a scoring harness reads it.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

SUITE = "anchor-stream-conformance"
TARGET_REPO = "aos-standard/catalog"
TARGET_TAG = "anchors-verify-v0.4"
TARGET_COMMIT = "44c40ba4fd6a12aa19c419e440a2f69512e99acc"
TRACKS_UPSTREAM = "aos-standard/catalog#1"
SPEC_VENDORED = "spec-vendored/anchors-verify-44c40ba.md"

#: The two witness commits the bundled stream names, and the third one an
#: attacker reaches for. Reachability is a fact about the platform, not about
#: the bytes, so it is carried per commit and never inferred from the digest.
WITNESS_ATTESTED = "e000814f60f393469479df795114d5b595f7ff49"
WITNESS_ACTIVE = "0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582"
WITNESS_FORK_PR_HEAD = "cafecafecafecafecafecafecafecafecafecafe"

BASELINE_STREAM = "baseline/ANCHORS.jsonl"
BASELINE_SIDECAR = "baseline/ANCHORS.jsonl.digests.json"
BASELINE_WITNESS_ATTESTED = "baseline/witness-e000814.jsonl"
BASELINE_WITNESS_ACTIVE = "baseline/witness-0eb69bf.jsonl"
EXTERNAL_TERMINATED = "baseline/external-unterminated-final-line/terminated.jsonl"
EXTERNAL_SIDECAR = "baseline/external-unterminated-final-line/sidecar.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def corpus_digest(manifest: dict, root: str = str(HERE)) -> str:
    """The digest this corpus publishes, recomputed from the files on disk.

    It lives with the GENERATOR because the generator owns the preimage. Its
    one caller besides this file is scripts/release-digests.py, which loads it
    by path rather than restating the concatenation: a second spelling of one
    preimage drifts from the first, and a release signature over a drifted
    digest certifies the drift instead of the corpus.
    """
    return sha(b"".join(
        open(os.path.join(root, entry["stream"]), "rb").read()
        for entry in manifest["vectors"]))



def read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as handle:
        return handle.read()


def split_lines(raw: bytes) -> list[bytes]:
    """Split on the JSONL delimiter and nothing else, keeping the delimiter.

    The corpus splits on `\\n` over raw bytes because that is what the format
    says a line is. The verifier under test decoded UTF-8 and used Unicode
    `str.splitlines`, which treats nine further code points as boundaries; the
    first vector family exists because those two readings disagree.
    """
    parts = raw.split(b"\n")
    lines = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def sidecar_over(raw: bytes) -> bytes:
    digests = [sha(line) for line in split_lines(raw)]
    return json.dumps({"version": "1.0.0", "line_sha256": digests}).encode("utf-8")


def row(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("utf-8") + b"\n"


def record(index: int, *, note: str = "", witnessed: bool = True) -> dict:
    out: dict = {
        "date": "2026-W34",
        "asset_id": f"corpus-patterns-{index}",
        "sha256": f"{index:064x}",
        "size_bytes": 1 + index,
        "note": note,
        "rows": 7,
    }
    if witnessed:
        out["witness"] = {"kind": "public_vcs", "repo": TARGET_REPO, "commit": WITNESS_ACTIVE}
        out["signature_suite"] = "none"
    return out


# --------------------------------------------------------------------------
# The conditions. Each one is a sentence the vendored contract text states, or
# a sentence a verdict-emitting branch of the pinned verifier needs in order to
# mean anything. `cites` quotes the contract where the contract says it.
# --------------------------------------------------------------------------

#: Per condition: what it requires, and whether the contract text vendored here
#: already requires it. `as-vendored` means the v0.4 text states the rule and the
#: reject members are rejectable under it as written. `proposed` means the text
#: leaves the case open and this corpus is asserting a correction, which is a
#: claim about what the format should say and not about what it says. Reading a
#: `proposed` row as a conformance failure against the published text overstates
#: it, and every table quoted out of this directory carries this sentence.
#: `adopted` records that upstream has since made the same change and at which
#: tag, which is a fact about their history rather than a licence to restate the
#: row as vendored.
CONDITIONS: dict[str, dict[str, str]] = {
    "ans-c-1": {
        "requires": (
            "A line digest covers the stored bytes of that line. Two streams whose bytes differ "
            "inside an attested prefix do not verify identically."
        ),
        "basis": "as-vendored",
        "why": (
            "the vendored text: hashes cover the full stored line including the trailing "
            "newline byte"
        ),
        "adoptedUpstreamAt": "anchors-verify-v0.5",
    },
    "ans-c-2": {
        "requires": (
            "A stream whose final line carries no terminator is a different stream from one "
            "whose final line carries a terminator."
        ),
        "basis": "as-vendored",
        "why": (
            "the same sentence of the vendored text, applied to the line that has no trailing "
            "newline byte"
        ),
    },
    "ans-c-3": {
        "requires": (
            "Every presented line has a sidecar entry. A line with no entry has not been "
            "verified, and the verdict says so."
        ),
        "basis": "proposed",
        "why": (
            "the vendored truncation rule fires only when the sidecar is longer than the "
            "stream, so a shorter one is not refused by the text as written"
        ),
    },
    "ans-c-4": {
        "requires": (
            "The success outcome is reachable by an honest stream. An outcome table does not "
            "document a verdict no input can produce."
        ),
        "basis": "proposed",
        "why": (
            "the vendored table documents the success verdict and the predicate beside it makes "
            "that verdict unreachable, so the correction is to the predicate"
        ),
        "adoptedUpstreamAt": "anchors-verify-v0.7",
    },
    "ans-c-5": {
        "requires": (
            "A named witness commit is reachable from the pinned repository's default-branch "
            "history, not merely fetchable under its path."
        ),
        "basis": "proposed",
        "why": (
            "the vendored text pins a repository name and says nothing about whose history a "
            "commit came from"
        ),
        "adoptedUpstreamAt": "anchors-verify-v0.7",
    },
    "ans-c-6": {
        "requires": (
            "A row carrying a recognised boundary event carries no record-shaped fields. A row "
            "that is both is malformed."
        ),
        "basis": "proposed",
        "why": (
            "the vendored text defines a record by the absence of an event and leaves a row "
            "that is both unresolved"
        ),
        "adoptedUpstreamAt": "anchors-verify-v0.9",
    },
    "ans-c-7": {
        "requires": (
            "An unrecognised rule_version fails closed. Not knowing a rule set is not the same "
            "as that rule set being satisfied."
        ),
        "basis": "proposed",
        "why": (
            "the vendored text names three rule sets and does not say what a verifier does with "
            "a fourth"
        ),
        "adoptedUpstreamAt": "anchors-verify-v0.8",
    },
    "ans-c-8": {
        "requires": (
            "A field the format declares an integer rejects a JSON boolean. Python's bool-is- "
            "int identity is not a property of the wire format."
        ),
        "basis": "proposed",
        "why": (
            "the vendored text calls these fields counts and lengths and pins no JSON type for "
            "them"
        ),
        "adoptedUpstreamAt": "anchors-verify-v0.9",
    },
    "ans-c-9": {
        "requires": (
            "A position binding names the repository its witness lives in, and the pinned trust "
            "anchor is compared against that name."
        ),
        "basis": "proposed",
        "why": (
            "the vendored text says a stream naming a different repository fails closed and "
            "does not say what a stream naming none does"
        ),
    },
    "ans-c-10": {
        "requires": (
            "The verdict is a function of the pinned artifact. A run described as tag-fixed "
            "does not read a moving branch."
        ),
        "basis": "proposed",
        "why": (
            "the vendored text calls the run tag-fixed and reproducible while the "
            "implementation reads the default branch during it"
        ),
    },
}

#: The nine code points `str.splitlines` treats as line boundaries and the
#: JSONL delimiter does not. Each one is a separate member because the family
#: was reported for one of them and closed for all nine, and a corpus that
#: carried only the reported case would not have measured the closure.
SPLITLINES_ONLY = (
    ("carriage-return", "\r"),
    ("vertical-tab", "\x0b"),
    ("form-feed", "\x0c"),
    ("file-separator", "\x1c"),
    ("group-separator", "\x1d"),
    ("record-separator", "\x1e"),
    ("next-line", "\x85"),
    ("line-separator", "\u2028"),
    ("paragraph-separator", "\u2029"),
)


def build() -> list[dict]:
    """Every member, as (stream, sidecar, witness, entry-without-id) tuples."""
    base = read(BASELINE_STREAM)
    base_sidecar = read(BASELINE_SIDECAR)
    wit_attested = read(BASELINE_WITNESS_ATTESTED)
    wit_active = read(BASELINE_WITNESS_ACTIVE)
    lines = split_lines(base)
    binding = json.loads(lines[18])

    def platform(
        *,
        by_ref: list[tuple[str, str, bool, bytes]] | None = None,
        active: bytes | None = None,
        default_branch: bytes | None = None,
    ) -> dict:
        refs = by_ref if by_ref is not None else [
            (TARGET_REPO, WITNESS_ATTESTED, True, wit_attested),
        ]
        return {
            "note": (
                "What the witness platform serves during a run, pinned so the "
                "verdict does not depend on a live fetch."
            ),
            "activeWitness": {
                "repo": TARGET_REPO,
                "commit": WITNESS_ACTIVE,
                "bytesBase64": base64.b64encode(
                    active if active is not None else wit_active
                ).decode("ascii"),
            },
            "defaultBranch": {
                "repo": TARGET_REPO,
                "ref": "main",
                # None means "whatever this member presents". A deployment
                # publishes the stream it publishes, so the honest default
                # branch for a member is that member, and a corpus that pinned
                # the bundled 24-line branch under a 19-line member would be
                # measuring its own scaffolding.
                "bytesBase64": (
                    base64.b64encode(default_branch).decode("ascii")
                    if default_branch is not None
                    else None
                ),
            },
            "byRef": [
                {
                    "repo": repo,
                    "commit": commit,
                    "reachableFromDefaultBranch": reachable,
                    "bytesBase64": base64.b64encode(payload).decode("ascii"),
                }
                for repo, commit, reachable, payload in refs
            ],
        }

    members: list[dict] = []

    def add(
        *,
        kind: str,
        condition: str,
        stream: bytes,
        sidecar: bytes | None = None,
        witness: dict | None = None,
        outcome: str,
        exit_code: int,
        stop_reason: str | None,
        cites: str,
        properties: dict | None = None,
    ) -> None:
        resolved = witness if witness is not None else platform()
        if resolved["defaultBranch"]["bytesBase64"] is None:
            resolved["defaultBranch"]["bytesBase64"] = base64.b64encode(stream).decode("ascii")
        members.append(
            {
                "kind": kind,
                "conditions": [condition],
                "stream": stream,
                "sidecar": sidecar if sidecar is not None else sidecar_over(stream),
                "witness": resolved,
                "expected": {
                    "outcome": outcome,
                    "exit": exit_code,
                    "stopReason": stop_reason,
                },
                "cites": cites,
                "properties": properties or {},
            }
        )

    # ans-c-1 -------------------------------------------------------------
    # A separator byte inserted between line 1 and line 2, inside the prefix
    # the binding attests. The sidecar is left as published, which is the
    # stricter attacker model: nothing about the sidecar has to be regenerated
    # for the mutation to survive.
    boundary = base.index(b"\n") + 1
    for name, char in SPLITLINES_ONLY:
        inserted = char.encode("utf-8")
        stream = base[:boundary] + inserted + base[boundary:]
        add(
            kind="reject",
            condition="ans-c-1",
            stream=stream,
            sidecar=base_sidecar,
            outcome="VERIFY FAILED",
            exit_code=1,
            stop_reason="digest-mismatch",
            cites=(
                f"a standalone {name} inside the attested prefix. The contract "
                "says hashes cover the full stored line including the trailing "
                "newline byte, so a stream carrying this byte is not the stream "
                "the sidecar describes."
            ),
            properties={
                "insertedCodepoint": f"U+{ord(char):04X}",
                "insertedAtByteOffset": boundary,
                "sidecarRegenerated": False,
            },
        )
    # The accepting twin. A carriage return appears in the file's text, as the
    # two-character JSON escape inside a string, so the byte sequence carries
    # no delimiter and the stream is well formed.
    escaped = row(record(1, note="line one\\rline two"))
    add(
        kind="accept",
        condition="ans-c-1",
        stream=base + escaped,
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the same separator spelled as a JSON escape inside a string, which "
            "is legal and carries no delimiter byte. The rule is about stored "
            "bytes at a line boundary, and this member is what shows it."
        ),
        properties={"escapeInString": "\\r"},
    )

    # ans-c-2 -------------------------------------------------------------
    add(
        kind="reject",
        condition="ans-c-2",
        stream=base[:-1],
        sidecar=base_sidecar,
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="digest-mismatch",
        cites=(
            "the final line terminator removed and the published sidecar kept. "
            "The sidecar's last entry is the digest of a line ending in a "
            "newline byte; this stream's last line has no newline byte."
        ),
        properties={"endsWithNewline": False, "sidecarRegenerated": False},
    )
    appended = base + row(record(2, note="terminated"))
    add(
        kind="accept",
        condition="ans-c-2",
        stream=appended,
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "a record appended with its terminator, and a sidecar that covers "
            "it. The append is honest and must verify, so the rejection above "
            "is caused by the missing byte and not by the length change."
        ),
        properties={"endsWithNewline": True},
    )

    # ans-c-2, the real stream ---------------------------------------------
    # Tetsurohhori's pair from aos-standard/catalog at anchors-verify-v0.12:
    # the real 73-line stream and the sidecar computed over its terminated form,
    # one byte apart. The stop reason is the assertion: a verifier can reach
    # FAILED here through a length guard or a parse error on the last line, and
    # the verdict column would not show it.
    real = read(EXTERNAL_TERMINATED)
    real_sidecar = read(EXTERNAL_SIDECAR)
    add(
        kind="accept",
        condition="ans-c-2",
        stream=real,
        sidecar=real_sidecar,
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the real 73-line stream with its final newline, and the sidecar "
            "computed over it. PARTIAL is the correct answer, not a soft pass: "
            "the witness covers the first 18 lines only. Contributed by "
            "Tetsurohhori from aos-standard/catalog at anchors-verify-v0.12."
        ),
        properties={
            "endsWithNewline": True,
            "streamLines": 73,
            "external": True,
            "baselineStream": EXTERNAL_TERMINATED,
        },
    )
    add(
        kind="reject",
        condition="ans-c-2",
        stream=real[:-1],
        sidecar=real_sidecar,
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="digest-mismatch",
        cites=(
            "the same real stream with its final byte (0a) removed and the same "
            "sidecar kept: one byte apart from the member above, nothing else to "
            "explain the verdict. The reason must be the digest comparison of "
            "line 73, not a length guard or a parse error on the last line. "
            "Through anchors-verify-v0.10 this stream returned VERIFY PARTIAL. "
            "Contributed by Tetsurohhori."
        ),
        properties={
            "endsWithNewline": False,
            "sidecarRegenerated": False,
            "streamLines": 73,
            "external": True,
            "baselineStream": EXTERNAL_TERMINATED,
        },
    )

    # ans-c-3 -------------------------------------------------------------
    short = json.loads(base_sidecar)
    short["line_sha256"] = short["line_sha256"][:18]
    short_bytes = json.dumps(short).encode("utf-8")
    mutated_tail = b"".join(
        lines[:21] + [lines[21].replace(b'"note":""', b'"note":"x"')] + lines[22:]
    )
    add(
        kind="reject",
        condition="ans-c-3",
        stream=mutated_tail,
        sidecar=short_bytes,
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="sidecar-coverage",
        cites=(
            "a sidecar covering the first 18 lines of a 24-line stream, with "
            "line 22 altered. The contract's truncation rule fires only when "
            "the sidecar is longer than the stream, so a shorter one leaves six "
            "lines with no digest to disagree with."
        ),
        properties={"sidecarEntries": 18, "streamLines": 24, "mutatedLine": 22},
    )
    add(
        kind="reject",
        condition="ans-c-3",
        stream=base,
        sidecar=short_bytes,
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="sidecar-coverage",
        cites=(
            "the same short sidecar over an unaltered stream. The pair separates "
            "the coverage gap from the mutation: this member carries no bad line "
            "at all, and a verifier that reports a verified stream here has "
            "reported six lines it never read."
        ),
        properties={"sidecarEntries": 18, "streamLines": 24, "mutatedLine": None},
    )
    add(
        kind="accept",
        condition="ans-c-3",
        stream=base + row(record(3, note="covered")),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "an appended line with a sidecar entry of its own, which is the "
            "conformant form of the same growth."
        ),
        properties={"sidecarEntries": 25, "streamLines": 25},
    )

    # ans-c-4 -------------------------------------------------------------
    maximal = b"".join(lines[:19])
    add(
        kind="accept",
        condition="ans-c-4",
        stream=maximal,
        outcome="VERIFY OK",
        exit_code=0,
        stop_reason=None,
        cites=(
            "every anchor record row sits inside the attested prefix and only "
            "the binding follows. This is the maximal honest stream, and the "
            "outcome table's success row describes exactly it."
        ),
        properties={"recordRowsAfterPrefix": 0},
    )
    add(
        kind="accept",
        condition="ans-c-4",
        stream=maximal + row(record(4)),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the same stream with one record appended after the binding. The "
            "pair is the outcome boundary: one record row outside the prefix is "
            "the difference between the success outcome and the partial one."
        ),
        properties={"recordRowsAfterPrefix": 1},
    )

    # ans-c-5 -------------------------------------------------------------
    forged = [row(record(5)), row(record(6))]
    attacker_prefix = b"".join(lines[:19]) + b"".join(forged)
    fork_binding = copy.deepcopy(binding)
    fork_binding["attestation"]["witness"]["commit"] = WITNESS_FORK_PR_HEAD
    fork_binding["introduced_at"] = "2026-08-23"
    fork_binding["attestation"]["prefix"] = {
        "line_count": 21,
        "byte_length": len(attacker_prefix),
        "sha256": sha(attacker_prefix),
    }
    add(
        kind="reject",
        condition="ans-c-5",
        stream=attacker_prefix + row(fork_binding),
        witness=platform(
            by_ref=[
                (TARGET_REPO, WITNESS_ATTESTED, True, wit_attested),
                (TARGET_REPO, WITNESS_FORK_PR_HEAD, False, attacker_prefix),
            ],
            default_branch=attacker_prefix + row(fork_binding),
        ),
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="witness-unreachable",
        cites=(
            "a binding naming a commit that the platform serves under the "
            "pinned repository's path and that no default-branch history "
            "contains. Two rows the deployment never published sit inside the "
            "prefix the binding covers. The pinned trust anchor is satisfied "
            "throughout, because it constrains a name."
        ),
        properties={
            "witnessCommit": WITNESS_FORK_PR_HEAD,
            "reachableFromDefaultBranch": False,
            "forgedRowsInsidePrefix": 2,
        },
    )
    add(
        kind="accept",
        condition="ans-c-5",
        stream=base,
        witness=platform(
            by_ref=[(TARGET_REPO, WITNESS_ATTESTED, True, wit_attested)]
        ),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the published stream, whose binding names a commit that is an "
            "ancestor of the default branch. The reachability test has to admit "
            "this member, and a test keyed on being the head of a branch does "
            "not: an ancestor is the head of nothing."
        ),
        properties={
            "witnessCommit": WITNESS_ATTESTED,
            "reachableFromDefaultBranch": True,
        },
    )

    # ans-c-6 -------------------------------------------------------------
    smuggled = copy.deepcopy(binding)
    smuggled["introduced_at"] = "2026-08-22"
    smuggled["asset_id"] = "smuggled"
    smuggled["sha256"] = "00" * 32
    smuggled["size_bytes"] = 1
    add(
        kind="reject",
        condition="ans-c-6",
        stream=base + row(smuggled),
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="malformed-row",
        cites=(
            "one row carrying a recognised boundary event and the fields of an "
            "anchor record. A record is defined by the absence of an event, so "
            "this row resolves to the event branch and the record rules never "
            "run over it: no witness is required of it and no digest of its "
            "asset is compared."
        ),
        properties={"carriesEvent": True, "carriesRecordFields": True},
    )
    plain = copy.deepcopy(binding)
    plain["introduced_at"] = "2026-08-24"
    add(
        kind="accept",
        condition="ans-c-6",
        stream=base + row(plain),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "a second binding carrying only event fields, which is the "
            "conformant form of the same append and is what shows the rejection "
            "above is caused by the collision and not by the second binding."
        ),
        properties={"carriesEvent": True, "carriesRecordFields": False},
    )

    # ans-c-7 -------------------------------------------------------------
    unknown_binding = copy.deepcopy(binding)
    unknown_binding["rule_version"] = "position-binding-v99"
    unknown_binding["introduced_at"] = "2026-08-25"
    add(
        kind="reject",
        condition="ans-c-7",
        stream=base + row(unknown_binding),
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="unknown-rule-version",
        cites=(
            "a binding declaring a rule set the verifier has never heard of, "
            "carrying an attestation shaped for the rule set it does know. A "
            "verifier that reads it under the older rules has answered a "
            "question about rules it cannot name."
        ),
        properties={"ruleVersion": "position-binding-v99", "field": "rule_version"},
    )
    # The witness introduction sits inside the prefix the bundled binding
    # attests, so mutating it there is confounded: the prefix stops matching and
    # a fork rejection explains the stop without the rule set ever being read.
    # This member is built on a stream whose binding attests the sixteen records
    # before it, so the two boundary rows that follow are outside the attested
    # prefix and the unrecognised rule set is the only thing left to stop on.
    # It ends with one witnessed record after those rows, which is what keeps
    # the accepting twin's outcome the same under the vendored predicate and
    # under the correction ans-c-4 proposes: with a record row outside the
    # prefix both readings give the partial outcome, so the twin isolates the
    # rule set instead of also testing which contract is in force.
    early_binding = copy.deepcopy(binding)
    early_binding["introduced_at"] = "2026-08-09"
    early_binding["attestation"]["witness"]["commit"] = WITNESS_ACTIVE
    early_binding["attestation"]["prefix"] = {
        "line_count": 16,
        "byte_length": len(b"".join(lines[:16])),
        "sha256": sha(b"".join(lines[:16])),
    }
    tail_witness = json.loads(lines[16])
    unknown_witness = dict(tail_witness, rule_version="witness-ref-v99")
    early = b"".join(lines[:16]) + row(early_binding)
    early_platform = platform(
        by_ref=[(TARGET_REPO, WITNESS_ACTIVE, True, wit_active)],
    )
    add(
        kind="reject",
        condition="ans-c-7",
        stream=early + row(unknown_witness) + lines[17] + row(record(7)),
        witness=early_platform,
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="unknown-rule-version",
        cites=(
            "the same unknown rule set on the witness introduction rather than "
            "the binding, on a stream whose attested prefix ends before that "
            "row. The two members are one condition on two of the three rows "
            "that carry a rule set, and a verifier that narrows only the row it "
            "was shown has narrowed one call site of three."
        ),
        properties={"ruleVersion": "witness-ref-v99", "field": "rule_version"},
    )
    add(
        kind="accept",
        condition="ans-c-7",
        stream=early + row(tail_witness) + lines[17] + row(record(7)),
        witness=platform(by_ref=[(TARGET_REPO, WITNESS_ACTIVE, True, wit_active)]),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the same stream with the rule set the format defines. It is what "
            "shows the rejection above is caused by the unrecognised name and "
            "not by the shape of the stream around it."
        ),
        properties={
            "ruleVersions": ["witness-ref-v1", "signature-suite-v1", "position-binding-v1"]
        },
    )
    add(
        kind="accept",
        condition="ans-c-7",
        stream=base + row(plain | {"introduced_at": "2026-08-26"}),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the three rule-set names the format defines, on the three rows "
            "that carry them. A narrowing that refuses this member has refused "
            "the deployment's own stream."
        ),
        properties={
            "ruleVersions": ["witness-ref-v1", "signature-suite-v1", "position-binding-v1"]
        },
    )

    # ans-c-8 -------------------------------------------------------------
    bool_count = copy.deepcopy(binding)
    bool_count["introduced_at"] = "2026-08-27"
    bool_count["attestation"]["prefix"] = {
        "line_count": True,
        "byte_length": len(lines[0]),
        "sha256": sha(lines[0]),
    }
    sole_bool = b"".join(lines[:18] + [row(bool_count)] + lines[19:])
    add(
        kind="reject",
        condition="ans-c-8",
        stream=sole_bool,
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="invalid-line-count",
        cites=(
            "the only binding in the stream, declaring a line count of JSON "
            "true. A verifier written in a language where a boolean is an "
            "integer reads it as one, attests a single line, and prints the "
            "boolean where a count belongs."
        ),
        properties={"field": "line_count", "jsonType": "boolean"},
    )
    bool_bytes = copy.deepcopy(binding)
    bool_bytes["introduced_at"] = "2026-08-28"
    bool_bytes["attestation"]["prefix"] = {
        "line_count": 1,
        "byte_length": True,
        "sha256": sha(lines[0]),
    }
    add(
        kind="reject",
        condition="ans-c-8",
        stream=b"".join(lines[:18] + [row(bool_bytes)] + lines[19:]),
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="invalid-byte-length",
        cites=(
            "the same confusion on the byte length rather than the line count. "
            "One field narrowed and the other left open is the shape a "
            "single-field repair leaves behind."
        ),
        properties={"field": "byte_length", "jsonType": "boolean"},
    )
    int_prefix = copy.deepcopy(binding)
    int_prefix["introduced_at"] = "2026-08-29"
    int_prefix["attestation"]["prefix"] = {
        "line_count": 1,
        "byte_length": len(lines[0]),
        "sha256": sha(lines[0]),
    }
    add(
        kind="accept",
        condition="ans-c-8",
        stream=b"".join(lines[:18] + [row(int_prefix)] + lines[19:]),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the same one-line attestation with both fields written as "
            "integers, which a narrowing on the type must still accept."
        ),
        properties={"field": "line_count", "jsonType": "integer"},
    )

    # ans-c-9 -------------------------------------------------------------
    empty_repo = copy.deepcopy(binding)
    empty_repo["introduced_at"] = "2026-08-30"
    empty_repo["attestation"]["witness"]["repo"] = ""
    add(
        kind="reject",
        condition="ans-c-9",
        stream=b"".join(lines[:18] + [row(empty_repo)] + lines[19:]),
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="binding-repo-absent",
        cites=(
            "a binding whose witness repository is the empty string, verified "
            "with the trust anchor pinned. The comparison the pin exists for "
            "runs only when the stream names a repository, and the empty string "
            "names none, so the pin is satisfied by a stream that says nothing "
            "about where its witness lives."
        ),
        properties={"bindingRepo": "", "pinSupplied": True},
    )
    add(
        kind="accept",
        condition="ans-c-9",
        stream=b"".join(lines[:18] + [row(plain | {"introduced_at": "2026-08-31"})] + lines[19:]),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the same binding naming the pinned repository, which is the form "
            "the comparison is written for."
        ),
        properties={"bindingRepo": TARGET_REPO, "pinSupplied": True},
    )

    # ans-c-10 ------------------------------------------------------------
    grown = base + b"".join(row(record(20 + n)) for n in range(25))
    add(
        kind="accept",
        condition="ans-c-10",
        stream=base,
        witness=platform(default_branch=grown),
        outcome="VERIFY PARTIAL",
        exit_code=3,
        stop_reason=None,
        cites=(
            "the stream bundled with the pinned tag, verified while the "
            "default branch carries 49 lines. The bundled artifact has not "
            "changed and its verdict may not, so a verifier that reads the "
            "branch has made the verdict a function of a clock."
        ),
        properties={"defaultBranchLines": 49, "presentedLines": 24},
    )
    add(
        kind="reject",
        condition="ans-c-10",
        stream=b"".join(lines[:12]),
        sidecar=sidecar_over(b"".join(lines[:12])),
        witness=platform(default_branch=grown, active=wit_active),
        outcome="VERIFY FAILED",
        exit_code=1,
        stop_reason="truncation",
        cites=(
            "a stream truncated below the witness commit its own rows name. "
            "Truncation is still caught here, against a commit the stream "
            "pins, which is the comparison that survives the branch moving."
        ),
        properties={"presentedLines": 12, "activeWitnessLines": 16},
    )

    return members


def identify(member: dict) -> str:
    payload = (
        member["stream"]
        + member["sidecar"]
        + json.dumps(member["witness"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return "v" + sha(payload)[:16]


def render_index(manifest: dict) -> str:
    rows = []
    for entry in manifest["vectors"]:
        expected = entry["expected"]
        rows.append(
            "| `{id}` | {kind} | {cond} | `{outcome}` | {exit} | {stop} |".format(
                id=entry["id"],
                kind=entry["kind"],
                cond=", ".join(entry["conditions"]),
                outcome=expected["outcome"],
                exit=expected["exit"],
                stop=f"`{expected['stopReason']}`" if expected["stopReason"] else "none",
            )
        )
    conditions = "\n".join(
        "| `{key}` | {basis} | {requires} {why} |".format(
            key=key,
            basis=value["basis"],
            requires=value["requires"],
            why=(
                "Already required by "
                if value["basis"] == "as-vendored"
                else "Left open by "
            )
            + value["why"]
            + (
                f", and upstream made the same change at `{value['adoptedUpstreamAt']}`."
                if value.get("adoptedUpstreamAt")
                else "."
            ),
        )
        for key, value in sorted(CONDITIONS.items(), key=lambda kv: int(kv[0].rsplit("-", 1)[1]))
    )
    accept = manifest["counts"]["accept"]
    reject = manifest["counts"]["reject"]
    total = accept + reject
    return f"""# Conformance vectors (ANCHORS stream, `anchors-verify-v0.4`)

Every member of this suite in one table, accepted and rejected alike.
Ground truth: `{SPEC_VENDORED}`, the contract text bundled with the pinned tag
`{TARGET_TAG}` of `{TARGET_REPO}` at `{TARGET_COMMIT[:7]}`, whose sha256
`MANIFEST.json` pins as `specDigest`.

This corpus is {total} vectors, of which {accept} a conformant verifier must
not fail closed on and {reject} it must reject.

**What this corpus certifies against, which is not the vendored text alone.**
Two conditions are required by the contract as vendored, and their reject
members are rejectable under it as written. The other eight are corrections
this corpus proposes: the vendored text leaves those cases open, which is why
the correction is worth writing down at all. A row's `basis` column says which
it is, `MANIFEST.json` carries the same field per member, and any table or
count quoted out of this directory carries this sentence with it. Reading a
`proposed` row as a conformance failure against the published text overstates
what the published text requires. Where upstream has since made the same change
the condition names the tag it landed at, which is a fact about their history
rather than a licence to restate the row as vendored.

**What a row states.** An `accept` row states that a conformant verifier does
not fail closed on those bytes, and names the outcome the contract's own table
assigns them. A `reject` row states that a conformant verifier fails closed,
and names the reason it stops. The reason is the load-bearing half. A verifier
that reaches the right verdict from a guard that fired before it evaluated the
property has not evaluated the property, and the verdict column cannot tell
you which happened.

**The platform bytes are pinned.** A verifier for this format reads the witness
platform over the network. Every member therefore carries `witness/<id>.json`,
which holds the bytes the platform serves for each commit the member names,
the bytes of the default branch, and, per commit, whether it is reachable from
that branch. Reachability is a fact about the platform rather than about the
bytes, so it is carried rather than derived. `run_verifier.py` refuses to run
a verifier that reaches for a socket.

**Identifiers name the bytes.** Each identifier is a digest of the member's own
three files. There is no directory per verdict and no prefix per verdict; the
expectation lives in `MANIFEST.json`. A verifier could otherwise certify
against this corpus without opening a stream.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-anchor-stream/` from the repository root.
Run a verifier: `python3 run_verifier.py --verifier <path-to-anchors_verify.py>`.

## Conditions

| id | basis | what it requires |
|---|---|---|
{conditions}

## Vectors

| id | kind | conditions | expected outcome | exit | stop reason |
|---|---|---|---|---|---|
{chr(10).join(rows)}
"""


def emit(check: bool) -> int:
    members = build()
    seen: set[str] = set()
    files: dict[str, bytes] = {}
    entries = []
    for member in members:
        vid = identify(member)
        if vid in seen:
            print(f"FAIL duplicate identifier {vid}", file=sys.stderr)
            return 1
        seen.add(vid)
        stream_rel = f"streams/{vid}.jsonl"
        sidecar_rel = f"sidecars/{vid}.json"
        witness_rel = f"witness/{vid}.json"
        files[stream_rel] = member["stream"]
        files[sidecar_rel] = member["sidecar"]
        files[witness_rel] = (
            json.dumps(member["witness"], indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
        entries.append(
            {
                "id": vid,
                "kind": member["kind"],
                "stream": stream_rel,
                "sidecar": sidecar_rel,
                "witness": witness_rel,
                "conditions": member["conditions"],
                "expected": member["expected"],
                "properties": member["properties"],
                "contractBasis": CONDITIONS[member["conditions"][0]]["basis"],
                "cites": member["cites"],
                "streamSha256": sha(member["stream"]),
            }
        )

    entries.sort(key=lambda entry: entry["id"])
    counts = {
        kind: sum(1 for entry in entries if entry["kind"] == kind)
        for kind in ("accept", "reject")
    }
    corpus = sha(b"".join(files[entry["stream"]] for entry in entries))
    manifest = {
        "suite": SUITE,
        "target": f"{TARGET_REPO} anchors_verify.py",
        "targetTag": TARGET_TAG,
        "targetCommit": TARGET_COMMIT,
        "tracksUpstream": TRACKS_UPSTREAM,
        "specVendored": SPEC_VENDORED,
        "specDigest": sha(read(SPEC_VENDORED)),
        "specAuthority": "specDigest",
        "specProvenanceNote": (
            "targetTag and targetCommit name where the contract text was read. "
            "The pin a run acts on is specDigest over specVendored, which is a "
            "file in this directory: the tag is a name the upstream project "
            "could re-point, and it has published one tag against the wrong "
            "commit already."
        ),
        "conditions": CONDITIONS,
        "counts": counts,
        "corpusDigest": corpus,
        "note": (
            "Two of the ten conditions are required by the contract text "
            "vendored here and their reject members are rejectable under it as "
            "written. The other eight are corrections this corpus proposes, and "
            "each member carries the field contractBasis saying which. Each "
            "accept member is the conformant twin of a reject member sharing "
            "its condition, so a verifier that fails everything scores zero "
            "rather than full marks."
        ),
        "vectors": entries,
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2).encode("utf-8") + b"\n"
    files["INDEX.md"] = render_index(manifest).encode("utf-8")

    if check:
        return verify_tree(files)

    for directory in ("streams", "sidecars", "witness"):
        os.makedirs(os.path.join(HERE, directory), exist_ok=True)
        for name in sorted(os.listdir(os.path.join(HERE, directory))):
            rel = f"{directory}/{name}"
            if rel not in files:
                os.unlink(os.path.join(HERE, rel))
    for rel, payload in sorted(files.items()):
        with open(os.path.join(HERE, rel), "wb") as handle:
            handle.write(payload)
    print(
        f"wrote {len(files)} file(s): {counts['accept']} accept, "
        f"{counts['reject']} reject, corpus {corpus[:12]}"
    )
    return 0


def verify_tree(files: dict[str, bytes]) -> int:
    """Refuse a tree the generator does not emit, in either direction."""
    bad = []
    for rel, payload in sorted(files.items()):
        path = os.path.join(HERE, rel)
        if not os.path.exists(path):
            bad.append(f"{rel} is missing")
            continue
        with open(path, "rb") as handle:
            if handle.read() != payload:
                bad.append(f"{rel} differs from what the generator emits")
    for directory in ("streams", "sidecars", "witness"):
        root = os.path.join(HERE, directory)
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            rel = f"{directory}/{name}"
            if rel not in files:
                bad.append(f"{rel} is on disk and the generator emits no such file")
    if bad:
        for line in bad:
            print("FAIL", line, file=sys.stderr)
        print("\nRun `python3 gen_vectors.py` to rebuild, and commit the diff.", file=sys.stderr)
        return 1
    print(f"OK generator reproduces {len(files)} file(s) byte-identically")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="refuse when the tree on disk is not what this generator emits",
    )
    return emit(parser.parse_args().check)


if __name__ == "__main__":
    raise SystemExit(main())
