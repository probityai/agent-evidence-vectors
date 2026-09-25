#!/usr/bin/env python3
"""Generate the AI Agent Action v0.1 conformance vector suite.

Regenerate byte-identically: python3 gen_vectors.py

Ground truth: in-toto/attestation#588, spec/predicates/ai-agent-action.md at
a5dd509c7476bcd7c738bee1afc3c02a57ac9e91.

Every member is a complete in-toto Statement. Members whose claim is about
the hash chain carry a sidecar under records/, the JSONL lines the chain hash
is computed over, because the chain hash's preimage is the underlying gateway
record and not the Statement.

Every reject member declares its BASIS: the lines of the vendored #588 text
that make it rejectable, or, for the one condition #588 does not yet carry,
the section of the canonicalization text this suite proposes
(docs/ai-agent-action-canonicalization.md). A blanket sentence saying which
text the rejects rest on was true of one revision and false of the next; a
basis per member is checked against the vendored bytes on every run.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
PREDICATE_TYPE = "https://in-toto.io/attestation/ai-agent-action/v0.1"
UPSTREAM_PR = "in-toto/attestation#588"
UPSTREAM_COMMIT = "a5dd509c7476bcd7c738bee1afc3c02a57ac9e91"

# WHERE THE COMMIT LIVES.
#
# in-toto/attestation#588 is opened from a branch on a third party's fork. On
# 2026-09-25 this commit is the head of that branch and of the review venue's
# refs/pull/588/head, so `git fetch origin pull/588/head` in a clone of
# in-toto/attestation retrieves it; a plain clone does not, because it fetches
# no refs/pull/* at all. The branch has been rewritten before (on 2026-08-26 it
# headed at 66de88f6 and an earlier pinned commit was unreachable), so a later
# review round may move it again.
#
# THE DIGEST IS THEREFORE THE PIN, AND THE COMMIT IS ONLY PROVENANCE. A commit
# id names bytes that may stop being fetchable; `specDigest` names bytes that
# are in this directory, and `aee-verify` refuses a copy whose bytes moved.
# That refusal is what keeps the corpus honest about what it certifies
# against, and it is why a rewritten branch costs the suite nothing.
SPEC_UPSTREAM_REPO = "elang2/attestation"
SPEC_UPSTREAM_REF = "add-ai-agent-action-predicate"

for sub in ("statements", "records"):
    os.makedirs(os.path.join(HERE, sub), exist_ok=True)

MANIFEST: list[dict] = []

# Every vector, in the order add() was called, before any of them has a name.
#
# A vector's published identifier is a digest of the vector itself, so it cannot
# be known until the bytes exist, and the bytes are what add() is given. So the
# build runs in two passes: this list collects what each vector IS, and emit()
# below turns each entry into bytes, derives the identifier from those bytes,
# and only then chooses a path. The authoring slug each call still passes stays
# in this process and reaches no published artifact.
DRAFTS: list[dict] = []

# The identifier is sixteen hex characters of SHA-256 over the vector's own
# bytes -- the statement, and the record sidecar too where one ships, because a
# vector distinguished only by its record lines is a different vector. Sixteen
# is 64 bits: for a corpus of this size the chance of a collision is far below
# the chance of every other thing that could go wrong, and the distinctness gate
# refuses one anyway rather than trusting the arithmetic.
ID_HEX = 16


def vector_id(statement_bytes: bytes, record_bytes: bytes | None) -> str:
    joined = statement_bytes if record_bytes is None else (
        statement_bytes + b"\x00" + record_bytes)
    return "v" + hashlib.sha256(joined).hexdigest()[:ID_HEX]


def jcs(obj) -> bytes:
    """RFC 8785 for the value space this suite uses.

    Every member is built from BMP strings, safe integers, booleans, null,
    objects and arrays, so lexicographic member sorting on the Python string
    and the shortest round-tripping number form coincide with JCS. Floats
    appear only inside content payloads, where they round-trip exactly.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def jcs_utf16(obj) -> bytes:
    """RFC 8785 with member names sorted by UTF-16 code unit.

    That is what RFC 8785 actually says, and what ``jcs`` above only
    approximates: ``sort_keys`` sorts Python strings, and Python compares
    strings by code point. Inside the BMP the two orders coincide, which is why
    every other member of this suite can use ``jcs`` and be right. They part
    exactly where a member name is a supplementary-plane character, whose
    leading surrogate sorts below U+E000 while its code point sorts above
    U+FFFF.

    That parting is the fault ``bad-116`` carries, so the corpus needs a
    serializer that can write the bytes the specification requires for a record
    ``jcs`` cannot canonicalize correctly. Both functions are kept, and the pair
    of digests they produce is what the vector declares.
    """
    def enc(node) -> str:
        if isinstance(node, dict):
            members = sorted(node.items(),
                             key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(
                json.dumps(name, ensure_ascii=False) + ":" + enc(value)
                for name, value in members) + "}"
        if isinstance(node, list):
            return "[" + ",".join(enc(value) for value in node) + "]"
        return json.dumps(node, ensure_ascii=False, separators=(",", ":"))
    return enc(obj).encode("utf-8")


def es6_number(value: float) -> str:
    """ECMA-262 7.1.12.1 Number::toString, which is what RFC 8785 requires.

    ``json.dumps`` writes Python's ``repr``, and the two part company on
    values Appendix B names: 2**68 reprs as ``2.9514790517935283e+20`` where
    ECMAScript writes ``295147905179352830000``, 1e-6 reprs as ``1e-06``
    where ECMAScript writes ``0.000001``, and negative zero reprs as
    ``-0.0`` where ECMAScript writes ``0``. So ``jcs`` cannot serialize the
    Appendix B rows and a third serializer is needed, for the same reason
    ``jcs_utf16`` exists.

    The digits are not recomputed here. Python's ``repr`` already selects the
    shortest round-tripping decimal, which is the digit string ECMAScript
    selects too, so the only work is re-laying those digits out under the
    ECMAScript exponent rules.
    """
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not JSON numbers")
    if value == 0:
        return "0"                    # both zeros, which is Appendix B row 2
    if value < 0:
        return "-" + es6_number(-value)

    # Recover the digit string s and the exponent n for which the value is
    # 0.s * 10**n, which is how ECMA-262 7.1.12.1 states its cases.
    mantissa, _, exponent = repr(value).partition("e")
    n = int(exponent) if exponent else 0
    whole, _, frac = mantissa.partition(".")
    if whole == "0":
        stripped = frac.lstrip("0")
        n -= len(frac) - len(stripped)
        digits = stripped
    else:
        digits = whole + frac
        n += len(whole)
    digits = digits.rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * -n + digits
    sign = "+" if n - 1 >= 0 else "-"
    tail = f"e{sign}{abs(n - 1)}"
    return (digits if k == 1 else digits[0] + "." + digits[1:]) + tail


def jcs_es6(obj) -> bytes:
    """RFC 8785 with numbers written per ECMA-262, not per Python.

    ``jcs`` above is correct for every value the rest of this suite uses,
    because those are safe integers and floats that happen to round-trip to
    the same text. It is wrong for the Appendix B rows, so those vectors
    declare the bytes this function produces.
    """
    def enc(node) -> str:
        if isinstance(node, dict):
            return "{" + ",".join(
                json.dumps(name, ensure_ascii=False) + ":" + enc(value)
                for name, value in sorted(node.items(),
                                          key=lambda kv: kv[0].encode("utf-16-be"))) + "}"
        if isinstance(node, list):
            return "[" + ",".join(enc(value) for value in node) + "]"
        if isinstance(node, float):
            return es6_number(node)
        if isinstance(node, bool) or node is None or isinstance(node, int):
            return json.dumps(node, ensure_ascii=False)
        return json.dumps(node, ensure_ascii=False, separators=(",", ":"))
    return enc(obj).encode("utf-8")


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def corpus_digest(manifest: dict, root: str = HERE) -> str:
    """The digest this corpus publishes, recomputed from the files on disk.

    It lives with the GENERATOR because the generator owns the preimage: this
    corpus is whatever gen_vectors.py emitted, and the digest is a function of
    those bytes in identifier order. scripts/release-digests.py loads this by
    path and calls it rather than restating the concatenation, for the reason
    that script gives about every corpus it covers: a second spelling of one
    preimage is drift, and a signature over a drifted digest certifies the
    drift. The AEE corpus is already read this way, through corpus_digest in
    vectors/gen_manifest.py, so both corpora now answer the same question from
    the same kind of place.
    """
    return h(b"".join(
        open(os.path.join(root, entry["file"]), "rb").read()
        for entry in sorted(manifest["vectors"], key=lambda entry: entry["id"])))


def chain_hash(record: dict) -> str:
    return h(jcs(record))


def write(rel: str, data: bytes) -> None:
    with open(os.path.join(HERE, rel), "wb") as fh:
        fh.write(data)


def statement(subject_digest: str, predicate: dict,
              subject_name: str = "session:agent-workspace-4f2a") -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": subject_name,
                     "digest": {"sha256": subject_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def tool_call(previous_hash: str, tool: str = "create_pull_request",
              extensions: dict | None = None,
              content: dict | None = None,
              duration: int = 412, success: bool = True) -> dict:
    pred = {
        "action": {
            "type": "tool_call",
            "protocol": "mcp",
            "method": "tools/call",
            "toolName": tool,
            "timestamp": "2026-08-18T14:33:41.882Z",
            "durationMs": duration,
            "success": success,
        },
        "agent": {"principal": "svc:agent-workspace",
                  "sessionId": "sess-4f2a"},
        "parties": [{"party": "gateway", "role": "witness",
                     "scope": ["toolName", "timestamp", "durationMs"]}],
        "chain": {"previousHash": previous_hash},
        "metadata": {"attestorVersion": "example-gateway/0.4.0"},
    }
    if extensions is not None:
        pred["extensions"] = extensions
    if content is not None:
        pred["contentDigest"] = content
    return pred


CALL_TIME = "2026-08-18T14:33:41.882Z"
BREAK_TIME = "2026-08-18T15:01:00.000Z"
# A record that follows a break is written after it. Every successor used to
# carry CALL_TIME, which put it half an hour BEFORE the break it chains from.
AFTER_BREAK_TIME = "2026-08-18T15:01:05.000Z"


def underlying(previous_hash: str, tool: str = "create_pull_request",
               extensions: dict | None = None, rid: str = "r1",
               success: bool = True, timestamp: str = CALL_TIME) -> dict:
    rec = {
        "id": rid,
        "type": "tool_call",
        "timestamp": timestamp,
        "toolName": tool,
        "durationMs": 412,
        "success": success,
        "previousHash": previous_hash,
    }
    if extensions is not None:
        rec["extensions"] = extensions
    return rec


def add(slug: str, kind: str, predicate: dict, subject: str,
        conditions: list[str], expected: dict, records: list[bytes] | None,
        cites: str, basis: dict | None = None,
        profile: str | None = None) -> None:
    """Record what a vector IS. Naming it is emit()'s job, once it has bytes.

    `slug` is the authoring name -- the thing a person types when writing the
    vector and greps for when changing it. It is deliberately NOT the published
    identifier and it reaches no artifact this repository ships: it stays in
    DRAFTS, it is used to keep the build order readable and to make a duplicate
    obvious, and it is dropped at emit(). It used to be both, and being both is
    what made the corpus scoreable without reading it -- an `ok-`/`bad-` prefix
    on the input's own name is the answer, handed to the rail with the question.
    """
    if (kind == "reject") != (basis is not None):
        raise SystemExit(
            f"{slug}: a reject member declares the text that makes it "
            "rejectable, and an accept member declares none")
    if profile is not None and profile not in PROFILES:
        raise SystemExit(f"{slug}: profile {profile!r} is not defined")
    DRAFTS.append({"slug": slug, "kind": kind,
                   "statement": statement(subject, predicate),
                   "conditions": conditions, "expected": expected,
                   "records": records, "cites": cites, "basis": basis,
                   "profile": profile})


def emit() -> None:
    """Serialize every draft, name it after its own bytes, and write it out."""
    seen: dict[str, str] = {}
    for draft in DRAFTS:
        body = json.dumps(draft["statement"], indent=2, sort_keys=True,
                          ensure_ascii=False).encode() + b"\n"
        record_bytes = None
        if draft["records"] is not None:
            record_bytes = b"\n".join(draft["records"]) + b"\n"
        vid = vector_id(body, record_bytes)
        if vid in seen:
            raise SystemExit(
                f"{draft['slug']} and {seen[vid]} are the same vector: identical "
                f"bytes, so they share the identifier {vid}. A content-addressed "
                "corpus cannot give one statement two names, and it should not "
                "want to -- one of them is a copy of the other."
            )
        seen[vid] = draft["slug"]
        rel = f"statements/{vid}.json"
        write(rel, body)
        entry = {"id": vid, "kind": draft["kind"], "file": rel,
                 "conditions": draft["conditions"], "expected": draft["expected"],
                 "cites": draft["cites"]}
        if draft["basis"] is not None:
            entry["basis"] = draft["basis"]
        if draft["profile"] is not None:
            entry["profile"] = draft["profile"]
        if record_bytes is not None:
            rec_rel = f"records/{vid}.jsonl"
            write(rec_rel, record_bytes)
            entry["records"] = rec_rel
        MANIFEST.append(entry)


# ---------------------------------------------------------------------------
# The canonical parent. Every member below is this record with one mutation.
# ---------------------------------------------------------------------------
EXT = {"10": "ten", "2": "two", "aa": "first", "zz": "last"}
PARENT_REC = underlying("genesis", extensions=EXT)
PARENT_HASH = chain_hash(PARENT_REC)

# The member names the ok-013 / bad-116 pair turns on. U+FF21 and U+FF3A are
# BMP; U+1F680 is supplementary and is encoded UTF-16 as D83D DE80, so its
# FIRST CODE UNIT sorts below both of them while its CODE POINT sorts above
# both. Swapping U+FF21 for U+1F680 is therefore one edit that changes nothing
# about the record except whether its canonical bytes are determined.
BMP_NAME_LOW = "Ａ"
BMP_NAME_HIGH = "Ｚ"
ASTRAL_NAME = "\U0001F680"

REQ = {"owner": "example", "repo": "widgets", "title": "Bump dependency"}
RESP_OK = {"content": [{"type": "text", "text": "opened #41"}]}
ERR = {"code": -32000, "message": "permission denied"}


# ---------------------------------------------------------------------------
# RFC 8785 Appendix B, Table 1: every row that has a JSON representation.
#
# Transcribed from the RFC's own text, never from a library's output. The two
# rows the table leaves blank, 7fffffffffffffff and 7ff0000000000000, are NaN
# and Infinity; section 3.2.2.3 requires a compliant implementation to refuse
# both, so they are not serialization samples and are not vectors here.
#
# The IEEE column is the input. Driving these from the bit pattern rather than
# from a decimal literal removes the one place a transcription error could hide,
# because a literal has to be parsed back to a double before it means anything
# and the parse is the step under test.
#
# (IEEE 754 hex, JSON representation, slug, the RFC's own comment)
# ---------------------------------------------------------------------------
APPENDIX_B: list[tuple[str, str, str, str]] = [
    ("0000000000000000", "0", "zero", "Zero"),
    ("8000000000000000", "0", "minus-zero", "Minus zero"),
    ("0000000000000001", "5e-324", "min-pos-number", "Min pos number"),
    ("8000000000000001", "-5e-324", "min-neg-number", "Min neg number"),
    ("7fefffffffffffff", "1.7976931348623157e+308", "max-pos-number",
     "Max pos number"),
    ("ffefffffffffffff", "-1.7976931348623157e+308", "max-neg-number",
     "Max neg number"),
    ("4340000000000000", "9007199254740992", "max-pos-int", "Max pos int"),
    ("c340000000000000", "-9007199254740992", "max-neg-int", "Max neg int"),
    ("4430000000000000", "295147905179352830000", "two-to-the-68", "~2**68"),
    ("44b52d02c7e14af5", "9.999999999999997e+22", "below-1e23", ""),
    ("44b52d02c7e14af6", "1e+23", "at-1e23", ""),
    ("44b52d02c7e14af7", "1.0000000000000001e+23", "above-1e23", ""),
    ("444b1ae4d6e2ef4e", "999999999999999700000", "below-1e21", ""),
    ("444b1ae4d6e2ef4f", "999999999999999900000", "just-below-1e21", ""),
    ("444b1ae4d6e2ef50", "1e+21", "at-1e21", ""),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7", "below-1e-6", ""),
    ("3eb0c6f7a0b5ed8d", "0.000001", "at-1e-6", ""),
    ("41b3de4355555553", "333333333.3333332", "ulp-minus-two", ""),
    ("41b3de4355555554", "333333333.33333325", "ulp-minus-one", ""),
    ("41b3de4355555555", "333333333.3333333", "ulp-centre", ""),
    ("41b3de4355555556", "333333333.3333334", "ulp-plus-one", ""),
    ("41b3de4355555557", "333333333.33333343", "ulp-plus-two", ""),
    ("becbf647612f3696", "-0.0000033333333333333333", "negative-small-fraction",
     ""),
    ("43143ff3c1cb0959", "1424953923781206.2", "round-to-even", "Round to even"),
]


def build_appendix_b() -> None:
    """One accept vector per Appendix B row with a JSON representation.

    The number lives in a content payload rather than in a signed record
    field, because ok-007 and bad-108 place it there: the safe-integer profile
    binds the fields the chain hash covers, and payloads are JCS and admit
    floats. So the statement carries the digest of the canonical payload, and
    the manifest carries the IEEE input and the canonical number the digest is
    over, which is where a reader checks the row.

    Rows 1 and 2 are the two IEEE patterns that share one JSON representation,
    so their payload digests are equal by construction. Each statement names
    its own bit pattern in the tool name, which keeps the two vectors distinct
    and makes the shared digest a declared fact rather than a collision.
    """
    for index, (hexpat, want, slug, comment) in enumerate(APPENDIX_B, start=1):
        value = struct.unpack(">d", bytes.fromhex(hexpat))[0]
        canonical = jcs_es6({"value": value})
        expected_bytes = ('{"value":' + want + "}").encode("utf-8")
        assert canonical == expected_bytes, (
            f"Appendix B row {index} ({hexpat}) canonicalizes to "
            f"{canonical!r}, and the RFC says {expected_bytes!r}")
        content = {"request": {"sha256": h(canonical)},
                   "response": {"sha256": h(jcs(RESP_OK))}}
        note = f" {comment}." if comment else ""
        add(f"ok-{13 + index:03d}-appendix-b-{slug}", "accept",
            tool_call("genesis", tool=f"canonicalize_{hexpat}",
                      content=content),
            PARENT_HASH, ["aia-c-16"],
            {"verdict": "valid",
             "ieee754": hexpat,
             "canonicalNumber": want,
             "requestDigest": h(canonical)},
            None,
            f"number serialization: RFC 8785 Appendix B row {index}. The IEEE "
            f"754 double {hexpat} is the JSON number {want}, and no other "
            f"text.{note}")


# ---------------------------------------------------------------------------
# ACCEPT: the conformant twin of every reject member below.
# ---------------------------------------------------------------------------
def build_accept() -> None:
    add("ok-001-canonical-chain-hash-integer-like-keys", "accept",
        tool_call("genesis", extensions=EXT), PARENT_HASH,
        ["aia-c-1", "aia-c-2"],
        {"verdict": "valid", "chainHash": PARENT_HASH},
        [jcs(PARENT_REC)],
        "canonicalization: member ordering is JCS, never the host language's "
        "property order")

    rec = underlying("genesis", tool="creer_fichier_été")
    add("ok-002-canonical-chain-hash-non-ascii", "accept",
        tool_call("genesis", tool="creer_fichier_été"),
        chain_hash(rec), ["aia-c-3"],
        {"verdict": "valid", "chainHash": chain_hash(rec)}, [jcs(rec)],
        "canonicalization: JCS emits the character, never a \\u escape")

    # A record OF ITS OWN, and that is the whole of this edit. Built from the
    # shared parent, this vector was byte-identical to ok-001 above -- statement
    # and record line both -- so aia-c-4 was credited with a discriminator
    # aia-c-1 and aia-c-2 already carried, and the accept side of this corpus
    # counted one statement twice. Nothing could see it: the distinctness gate
    # read the other corpus's manifest only. Any record whose log line is its
    # canonical serialization forces this condition, so a distinct tool name is
    # the smallest change that makes the vector a vector.
    log_rec = underlying("genesis", tool="append_audit_log", extensions=EXT)
    add("ok-003-log-line-equals-canonical-bytes", "accept",
        tool_call("genesis", tool="append_audit_log", extensions=EXT),
        chain_hash(log_rec),
        ["aia-c-4"],
        {"verdict": "valid", "chainHash": chain_hash(log_rec)}, [jcs(log_rec)],
        "canonicalization: the log line IS the canonical bytes, so the two "
        "readings of the preimage coincide")

    add("ok-004-unique-members", "accept",
        tool_call("genesis", tool="read_file"),
        chain_hash(underlying("genesis", tool="read_file")),
        ["aia-c-5"],
        {"verdict": "valid",
         "chainHash": chain_hash(underlying("genesis", tool="read_file"))},
        [jcs(underlying("genesis", tool="read_file"))],
        "canonicalization: I-JSON, no duplicate member at any depth")

    # A linear three-record chain: the predecessor relation is injective.
    r1 = underlying("genesis", tool="list_files", rid="r1")
    h1 = chain_hash(r1)
    r2 = underlying(h1, tool="read_config", rid="r2")
    h2 = chain_hash(r2)
    r3 = underlying(h2, tool="create_pull_request", rid="r3")
    add("ok-005-linear-chain-single-head", "accept",
        tool_call(h2), h1, ["aia-c-6", "aia-c-7"],
        {"verdict": "valid", "chainHash": chain_hash(r3), "records": 3},
        [jcs(r1), jcs(r2), jcs(r3)],
        "chain shape: exactly one record carries any given previousHash")

    ck = {"id": "ckpt_1", "type": "checkpoint",
          "timestamp": "2026-08-18T14:33:42.101Z",
          "previousHash": PARENT_HASH,
          "sequence": 1, "recordCount": 1}
    ck_pred = {
        "action": {"type": "checkpoint",
                   "timestamp": "2026-08-18T14:33:42.101Z"},
        "chain": {"previousHash": PARENT_HASH},
        "checkpoint": {"sequence": 1, "recordCount": 1,
                       "previousHash": PARENT_HASH},
        "parties": [{"party": "gateway", "role": "witness",
                     "scope": ["sequence", "recordCount", "previousHash"]}],
        "metadata": {"attestorVersion": "example-gateway/0.4.0"},
    }
    add("ok-006-checkpoint-carries-chain-link", "accept", ck_pred,
        PARENT_HASH, ["aia-c-8"],
        {"verdict": "valid", "chainHash": chain_hash(ck)},
        [jcs(PARENT_REC), jcs(ck)],
        "chain shape: every record type links through predicate.chain")

    content = {"request": {"sha256": h(jcs(dict(REQ, temperature=0.7)))},
               "response": {"sha256": h(jcs(RESP_OK))}}
    add("ok-007-float-in-content-payload-only", "accept",
        tool_call("genesis", content=content), PARENT_HASH,
        ["aia-c-9"],
        {"verdict": "valid"}, None,
        "canonicalization: the float boundary is where the bytes live. A "
        "payload behind its content digest may carry floats; a record or a "
        "Statement may not")

    err_content = {"request": {"sha256": h(jcs(REQ))},
                   "response": {"sha256": h(jcs(ERR))}}
    err_rec = underlying("genesis", tool="delete_branch", success=False)
    add("ok-008-error-response-digest-over-error-member", "accept",
        tool_call("genesis", tool="delete_branch", content=err_content,
                  success=False),
        chain_hash(err_rec), ["aia-c-10"],
        {"verdict": "valid", "responseDigest": err_content["response"]["sha256"]},
        [jcs(err_rec)],
        "content digest: a failed call digests the error member, named "
        "explicitly rather than left to the reader")

    add("ok-009-previoushash-lowercase-64-hex", "accept",
        tool_call(PARENT_HASH), PARENT_HASH, ["aia-c-11"],
        {"verdict": "valid"}, None,
        "chain shape: previousHash is lowercase 64-hex or the literal genesis")

    add("ok-010-extensions-depth-128", "accept",
        tool_call("genesis", extensions=nested(128)), PARENT_HASH,
        ["aia-c-12"], {"verdict": "valid"}, None,
        "bounds: 128 is admissible; the counting rule is #570's")

    # The twin of bad-113. A surrogate PAIR is one supplementary-plane
    # character and is well formed; only a lone half is not.
    pair_rec = underlying("genesis", tool="deploy_\U0001F680")
    add("ok-011-paired-surrogate-in-toolname", "accept",
        tool_call("genesis", tool="deploy_\U0001F680"),
        chain_hash(pair_rec), ["aia-c-13"],
        {"verdict": "valid", "chainHash": chain_hash(pair_rec)},
        [jcs(pair_rec)],
        "strings: the rule excludes an unpaired half, never a valid "
        "supplementary-plane character, so a verifier that rejects both is "
        "over-rejecting")

    # The twin of bad-115: the largest value the profile admits.
    add("ok-012-largest-safe-integer-durationms", "accept",
        tool_call("genesis", duration=2 ** 53 - 1), PARENT_HASH,
        ["aia-c-14"], {"verdict": "valid"}, None,
        "bounds: 2^53 - 1 is admissible, so the boundary is exercised from "
        "both sides rather than assumed")

    # The twin of bad-116, and the positive control for it. Both member names
    # are BMP, so UTF-16 code-unit order and code-point order agree and the
    # record has ONE canonical byte string. The two declared digests are equal
    # here and unequal in bad-116, which is the whole measurement.
    bmp_ext = {BMP_NAME_LOW: "first", BMP_NAME_HIGH: "last"}
    bmp_rec = underlying("genesis", extensions=bmp_ext)
    assert jcs(bmp_rec) == jcs_utf16(bmp_rec), "a BMP-only record must canonicalize identically under both orders"
    add("ok-013-bmp-extension-member-names", "accept",
        tool_call("genesis", extensions=bmp_ext), chain_hash(bmp_rec),
        ["aia-c-15"],
        {"verdict": "valid", "chainHash": chain_hash(bmp_rec),
         "chainHashUtf16": h(jcs_utf16(bmp_rec)),
         "chainHashCodePoint": h(jcs(bmp_rec))},
        [jcs(bmp_rec)],
        "strings: extension member names inside the BMP sort the same way "
        "under UTF-16 code units and under code points, so the record has one "
        "canonical form and one chain hash")


SPEC_VENDORED_REL = f"spec-vendored/ai-agent-action-{UPSTREAM_COMMIT[:7]}.md"
SPEC_SOURCE = f"{UPSTREAM_PR}@{UPSTREAM_COMMIT[:7]}"
PROPOSED_TEXT = "docs/ai-agent-action-canonicalization.md"


def spec_basis(lines: str, quote: str) -> dict:
    """The lines of the vendored #588 text a reject member rests on.

    `quote` must occur in those lines once their hard wrapping is flattened,
    and aee-verify checks that it does. A bare line range survives an edit
    that moves the text it pointed at; a range and the words it is supposed
    to hold do not, so the next re-vendor reopens every basis whose text
    moved instead of carrying it forward as though it still held.
    """
    return {"source": SPEC_SOURCE, "lines": lines, "quote": quote}


def spec_digest() -> str:
    """The digest of the vendored specification copy.

    The suite certifies against #588 as it read at UPSTREAM_COMMIT, and each
    reject member names the lines of that text it rests on (or, for the one
    condition #588 does not carry, the proposed text). The vendored file is the
    evidence on disk of what that upstream text said. Pinning its bytes here is
    what lets aee-verify refuse a copy edited in place: without the pin the
    manifest names a commit, which anyone can write, rather than the bytes,
    which they cannot.
    """
    with open(os.path.join(HERE, SPEC_VENDORED_REL), "rb") as fh:
        return h(fh.read())


def nested(levels: int) -> dict:
    """An object whose own outermost brace is depth 1 and whose innermost
    open container is depth `levels`, matching #588's counting rule.

    `levels` is at least 1: depth 0 is the absence of a container, not a
    container, and the bare "leaf" it used to return is a string the record
    schema has nowhere to put. Building the innermost object first makes the
    return a dict for every admissible input rather than only for the two the
    call sites happen to pass.
    """
    if levels < 1:
        raise ValueError(f"levels must be at least 1, got {levels}")
    node: dict = {"n": "leaf"}
    for _ in range(levels - 1):
        node = {"n": node}
    return node


def break_record(prior_head: str | None, reason: str = "crash_recovery",
                 prior_record_count: int | None = None) -> dict:
    """A chain_break record as #588 lays it out at the record layer.

    The linkage lives in `priorHead`, not in a `previousHash` member, and all
    three prior* members are present even when their value is null: two
    producers with the same knowledge must not disagree about whether a member
    appears, because JCS would then give them two chain hashes.
    """
    return {"id": "brk_1", "type": "chain_break", "timestamp": BREAK_TIME,
            "reason": reason, "priorHead": prior_head, "priorSequence": None,
            "priorRecordCount": prior_record_count}


# ---------------------------------------------------------------------------
# REJECT: one declared fault each.
# ---------------------------------------------------------------------------
def build_reject() -> None:
    # A1: ECMAScript hoists canonical numeric member names to the front.
    js_order = {"2": "two", "10": "ten", "zz": "last", "aa": "first"}
    js_rec = dict(PARENT_REC)
    js_rec["extensions"] = js_order
    js_bytes = json.dumps(js_rec, separators=(",", ":"),
                          ensure_ascii=False).encode()
    add("bad-101-chain-hash-ecmascript-member-order", "reject",
        tool_call("genesis", extensions=EXT), h(js_bytes),
        ["aia-c-1"], {"verdict": "invalid", "codes": ["chain-hash-mismatch"]},
        [js_bytes],
        "A1: JSON.stringify orders 2 before 10 and leaves zz before aa; JCS "
        "orders 10, 2, aa, zz. Three languages, three chain hashes.",
        basis=spec_basis("379-383,387-391,400-409",
                         '`JSON.stringify` MUST NOT be used to derive the record canonical form'))

    # A2: escaping policy.
    esc_rec = underlying("genesis", tool="creer_fichier_été")
    esc_bytes = json.dumps(esc_rec, separators=(",", ":"),
                           ensure_ascii=True).encode()
    add("bad-102-chain-hash-ascii-escaped-string", "reject",
        tool_call("genesis", tool="creer_fichier_été"),
        h(esc_bytes), ["aia-c-3"],
        {"verdict": "invalid", "codes": ["chain-hash-mismatch"]}, [esc_bytes],
        "A2: a producer whose serializer defaults to ASCII escaping emits "
        "different bytes for the same string",
        basis=spec_basis("411-415",
                         'both produce non-canonical bytes and both are rejected'))

    html_rec = underlying("genesis", tool="run<script>")
    html_bytes = (json.dumps(html_rec, separators=(",", ":"),
                             ensure_ascii=False)
                  .replace("<", "\\u003c").replace(">", "\\u003e")
                  .encode())
    add("bad-103-chain-hash-html-escaped-string", "reject",
        tool_call("genesis", tool="run<script>"), h(html_bytes),
        ["aia-c-3"], {"verdict": "invalid", "codes": ["chain-hash-mismatch"]},
        [html_bytes],
        "A2b: Go's encoding/json escapes <, > and & by default, so a Go "
        "gateway and a Node gateway disagree on identical input",
        basis=spec_basis("411-415",
                         'both produce non-canonical bytes and both are rejected'))

    # A3: the log line carries insignificant whitespace.
    ws_bytes = json.dumps(PARENT_REC, separators=(", ", ": "),
                          ensure_ascii=False).encode()
    add("bad-104-log-line-not-canonical-bytes", "reject",
        tool_call("genesis", extensions=EXT), h(ws_bytes),
        ["aia-c-4"], {"verdict": "invalid", "codes": ["noncanonical-bytes"]},
        [ws_bytes],
        "A3: the record parses identically and hashes differently; any log "
        "shipper that reserializes produces this",
        basis=spec_basis("387-391",
                         'MUST reject, fail-closed, any line whose bytes differ from the recomputation'))

    # A4: duplicate member.
    dup = (b'{"durationMs":412,"id":"r1","previousHash":"genesis",'
           b'"success":true,"timestamp":"2026-08-18T14:33:41.882Z",'
           b'"toolName":"read_file","toolName":"delete_repository",'
           b'"type":"tool_call"}')
    add("bad-105-duplicate-member-toolname", "reject",
        tool_call("genesis", tool="read_file"), h(dup),
        ["aia-c-5"], {"verdict": "invalid", "codes": ["duplicate-member"]},
        [dup],
        "A4: a first-wins reader displays read_file while the hash commits "
        "to delete_repository",
        basis=spec_basis("604-609",
                         'A duplicate member anywhere, at any depth, makes the record malformed'))

    # A5: the chain forks.
    f1 = underlying("genesis", tool="list_files", rid="r1")
    fh1 = chain_hash(f1)
    f2a = underlying(fh1, tool="read_secrets", rid="r2a")
    f2b = underlying(fh1, tool="create_pull_request", rid="r2b")
    add("bad-106-chain-fork-shared-previoushash", "reject",
        tool_call(fh1), fh1, ["aia-c-6"],
        {"verdict": "invalid", "codes": ["chain-fork"]},
        [jcs(f1), jcs(f2a), jcs(f2b)],
        "A5: two records carry one previousHash. Every hash verifies, the "
        "genesis hash and therefore the subject digest are unchanged, and "
        "the presenter chooses which branch the auditor sees.",
        basis=spec_basis("700-704",
                         'Exactly one record in a chain MUST carry any given `previousHash` value'))

    ck_nolink = {"id": "ckpt_1", "type": "checkpoint",
                 "timestamp": "2026-08-18T14:33:42.101Z",
                 "sequence": 1, "recordCount": 1,
                 "previousHash": PARENT_HASH}
    ck_pred = {
        "action": {"type": "checkpoint",
                   "timestamp": "2026-08-18T14:33:42.101Z"},
        "checkpoint": {"sequence": 1, "recordCount": 1,
                       "previousHash": PARENT_HASH},
        "metadata": {"attestorVersion": "example-gateway/0.4.0"},
    }
    succ = underlying(PARENT_HASH, tool="create_pull_request", rid="r2")
    add("bad-107-checkpoint-omitted-from-chain", "reject", ck_pred,
        PARENT_HASH, ["aia-c-8"],
        {"verdict": "invalid", "codes": ["checkpoint-not-linked"]},
        [jcs(PARENT_REC), jcs(ck_nolink), jcs(succ)],
        "A6: the successor chains past the checkpoint to the record before "
        "it, so the checkpoint is deletable and the anti-truncation "
        "mechanism carries no weight",
        basis=spec_basis("719-722",
                         "the record following any record of any type carries that record's chain hash"))

    float_rec = dict(PARENT_REC)
    float_rec["durationMs"] = 412.5
    add("bad-108-float-in-signed-record-field", "reject",
        tool_call("genesis", extensions=EXT, duration=412),
        chain_hash(float_rec), ["aia-c-9"],
        {"verdict": "invalid", "codes": ["non-integer-in-signed-field"]},
        [jcs(float_rec)],
        "A7: a float inside the record itself. The record canonical form "
        "admits no non-integer number, whatever the content digests bind; "
        "the content-digest form is where a float belongs",
        basis=spec_basis("384-387,461-466",
                         'Non-integer numbers *inside* a record or a Statement, by contrast, are malformed and MUST be rejected fail-closed'))

    err_null = {"request": {"sha256": h(jcs(REQ))},
                "response": {"sha256": h(b"null")}}
    err_rec = underlying("genesis", tool="delete_branch", success=False)
    add("bad-109-error-response-digest-over-null", "reject",
        tool_call("genesis", tool="delete_branch", content=err_null,
                  success=False),
        chain_hash(err_rec), ["aia-c-10"],
        {"verdict": "invalid", "codes": ["content-digest-mismatch"]},
        [jcs(err_rec)],
        "A8: one of four readings a verifier could take of an absent result "
        "member, and the only one this suite forbids by naming the other",
        basis=spec_basis("434-442",
                         'A producer MUST NOT digest `null`, an empty object, or the whole response envelope in place of the named member'))

    add("bad-110-previoushash-uppercase-hex", "reject",
        tool_call(PARENT_HASH.upper()), PARENT_HASH, ["aia-c-11"],
        {"verdict": "invalid", "codes": ["previoushash-not-canonical"]}, None,
        "A9: a case-normalizing verifier links it and a byte-comparing one "
        "does not, so the same logical link has two spellings",
        basis=spec_basis("685-692",
                         'Uppercase hex is not canonical.'))

    add("bad-111-previoushash-wrong-length", "reject",
        tool_call("da39a3ee5e6b4b0d3255bfef95601890afd80709"), PARENT_HASH,
        ["aia-c-11"],
        {"verdict": "invalid", "codes": ["previoushash-not-canonical"]}, None,
        "A9b: 40 hex digits. Nothing in the current text excludes a digest "
        "from another algorithm",
        basis=spec_basis("685-692",
                         'A digest of any other length is not admissible'))

    # The break carries all three prior* members, as #588 requires of every
    # chain_break record. It used to omit priorSequence and priorRecordCount,
    # so a conformant verifier could reject this member as a malformed break
    # before it ever reached the second genesis the member exists to show.
    g1 = underlying("genesis", tool="list_files", rid="r1")
    brk = break_record(chain_hash(g1), prior_record_count=1)
    g2 = underlying("genesis", tool="create_pull_request", rid="r2",
                    timestamp=AFTER_BREAK_TIME)
    add("bad-112-second-genesis-after-break", "reject",
        tool_call("genesis"), chain_hash(g1), ["aia-c-7"],
        {"verdict": "invalid", "codes": ["duplicate-genesis"]},
        [jcs(g1), jcs(brk), jcs(g2)],
        "F3: the successor of a break restarts at genesis instead of "
        "chaining from the break, discarding the scar. Detection is a MUST, "
        "not a SHOULD",
        basis=spec_basis("775-779,796-797",
                         'A verifier MUST reject, fail-closed, a log in which `genesis` appears more than once'))

    sur = ('{"id":"r1","previousHash":"genesis","toolName":"bad\\ud800",'
           '"type":"tool_call"}').encode()
    add("bad-113-unpaired-surrogate-in-toolname", "reject",
        tool_call("genesis", tool="bad"), h(sur), ["aia-c-13"],
        {"verdict": "invalid", "codes": ["ill-formed-string"]}, [sur],
        "F2: already forbidden by #588's own text. The vector is what stops "
        "the rule from being advice",
        basis=spec_basis("611-615",
                         'an unpaired escape of either half is malformed'))

    add("bad-114-extensions-depth-129", "reject",
        tool_call("genesis", extensions=nested(129)), PARENT_HASH,
        ["aia-c-12"], {"verdict": "invalid", "codes": ["depth-exceeded"]},
        None,
        "bounds: one level past the stated cap, so the counting rule is "
        "exercised rather than assumed",
        basis=spec_basis("602,627-629",
                         'A verifier MUST reject, fail-closed, a record whose JSON nesting depth exceeds 128'))

    add("bad-115-unsafe-integer-durationms", "reject",
        tool_call("genesis", duration=9007199254740993), PARENT_HASH,
        ["aia-c-14"], {"verdict": "invalid", "codes": ["unsafe-integer"]},
        None,
        "bounds: 2^53 + 1, the first value the I-JSON profile excludes",
        basis=spec_basis("1320-1323",
                         'Implementations MUST reject records with integers at or above this bound'))

    # ok-013 with one member name lifted out of the BMP. The sidecar carries
    # the bytes RFC 8785 requires, sorted by UTF-16 code unit, which this
    # file's own `jcs` cannot produce -- that inability IS the divergence, and
    # it is why the two declared digests differ.
    astral_ext = {ASTRAL_NAME: "first", BMP_NAME_HIGH: "last"}
    astral_rec = underlying("genesis", extensions=astral_ext)
    assert jcs(astral_rec) != jcs_utf16(astral_rec), "the astral member name must split the two orders"
    add("bad-116-astral-extension-member-name", "reject",
        tool_call("genesis", extensions=astral_ext), h(jcs_utf16(astral_rec)),
        ["aia-c-15"],
        {"verdict": "invalid", "codes": ["non-bmp-member-name"],
         "chainHashUtf16": h(jcs_utf16(astral_rec)),
         "chainHashCodePoint": h(jcs(astral_rec))},
        [jcs_utf16(astral_rec)],
        "strings: U+1F680 is encoded UTF-16 as D83D DE80, so it sorts before "
        "U+FF3A by code unit and after it by code point. The record is "
        "well formed and every field is untouched; it has two canonical byte "
        "strings and therefore two chain hashes, so the successor's "
        "previousHash and the chain's subject digest both fork.",
        basis={"source": PROPOSED_TEXT,
               "section": "Member names are BMP-only",
               "against": {"source": SPEC_SOURCE, "lines": "611-612,624-625",
                           "quote": "A verifier that rejects it is "
                                    "over-rejecting"},
               "note": "The one reject condition #588 does not carry. Its "
                       "string rule admits a well-formed supplementary-plane "
                       "character in member-name position, and its record "
                       "canonical form sorts that name by UTF-16 code unit, "
                       "so a verifier conforming to #588 alone accepts this "
                       "member. It is rejectable under the proposed BMP-only "
                       "rule, carried over from in-toto/attestation#570."})


# ---------------------------------------------------------------------------
# PROFILES. #588 makes one verdict depend on a deployment choice: a deployment
# claiming resistance against a compromised attestor MUST forbid a chain_break
# with priorHead null, and absent that claim such a break is accepted and
# should be surfaced. The text names no place the choice is carried, so a
# verifier learns it as configuration, and a member whose verdict depends on it
# names the profile its kind and expected verdict hold under.
# ---------------------------------------------------------------------------
DEFAULT = "default"
RESISTANT = "compromised-attestor-resistant"
PROFILES = {
    DEFAULT: {
        "nullPriorHead": "permitted",
        "description": "No claim of resistance against a compromised "
                       "attestor. A chain_break with priorHead null roots a "
                       "new segment, and a verifier should surface it as an "
                       "unattested discontinuity.",
        "cites": spec_basis(
            "1275-1277",
            "Absent this prohibition, a planted break is an accepted "
            "residual risk"),
    },
    RESISTANT: {
        "nullPriorHead": "forbidden",
        "description": "The deployment claims resistance against a "
                       "compromised attestor, so a chain_break with priorHead "
                       "null is rejected wherever it appears.",
        "cites": spec_basis(
            "1271-1274",
            "MUST forbid `priorHead: null` in the deployment profile"),
    },
}


def break_predicate(rec: dict) -> dict:
    """The Statement predicate a chain_break record surfaces as.

    `predicate.chain` carries the linkage only when the prior head is known;
    a break with priorHead null carries none. No `parties`: v0.1 does not
    admit them on a chain_break.
    """
    pred = {"action": {"type": "chain_break", "timestamp": rec["timestamp"]},
            "chainBreak": {"reason": rec["reason"],
                           "priorHead": rec["priorHead"],
                           "priorSequence": rec["priorSequence"],
                           "priorRecordCount": rec["priorRecordCount"]},
            "metadata": {"attestorVersion": "example-gateway/0.4.0"}}
    if rec["priorHead"] is not None:
        pred["chain"] = {"previousHash": rec["priorHead"]}
    return pred


# ---------------------------------------------------------------------------
# CHAIN BREAKS. Which record roots a chain, and therefore which digest every
# statement in it carries as its subject: a genesis record, or a chain_break
# whose priorHead is null. A break with a known prior head is not a root.
# PARENT_HASH, the genesis identifier ok-001 declares, stands for the chain an
# unrecoverable crash abandoned.
# ---------------------------------------------------------------------------
def build_chain_break() -> None:
    brk_a = break_record(None)
    root_a = chain_hash(brk_a)
    succ_a = underlying(root_a, rid="r2", timestamp=AFTER_BREAK_TIME)
    brk_b = break_record(None, reason="forced_rotation")
    root_b = chain_hash(brk_b)
    brk_n = break_record(PARENT_HASH, prior_record_count=1)
    link_n = chain_hash(brk_n)
    succ_n = underlying(link_n, rid="r2", timestamp=AFTER_BREAK_TIME)

    add("ok-017-break-rooted-successor", "accept", tool_call(root_a), root_a,
        ["aia-c-17"],
        {"verdict": "valid", "chainHash": chain_hash(succ_a),
         "chainRoot": root_a},
        [jcs(brk_a), jcs(succ_a)],
        "chain breaks: a segment rooted at a chain_break with priorHead null "
        "is identified by the break record's own chain hash, and its "
        "successor carries that hash as its subject digest",
        profile=DEFAULT)
    add("ok-018-break-rooted-own-statement", "accept", break_predicate(brk_b),
        root_b, ["aia-c-17"],
        {"verdict": "valid", "chainHash": root_b, "chainRoot": root_b},
        [jcs(brk_b)],
        "chain breaks: the break record's own Statement is in the segment it "
        "roots, so it carries its own chain hash, and it carries no "
        "predicate.chain because the prior head is unrecoverable",
        profile=DEFAULT)
    add("bad-117-break-rooted-successor-pre-break-identifier", "reject",
        tool_call(root_a), PARENT_HASH, ["aia-c-17"],
        {"verdict": "invalid", "codes": ["break-rooted-foreign-identifier"],
         "chainRoot": root_a, "preBreakIdentifier": PARENT_HASH},
        [jcs(brk_a), jcs(succ_a)],
        "chain breaks: the successor claims the identifier of the chain the "
        "crash abandoned. The attestor holds no truthful value for it, and "
        "carrying it would let a break-rooted segment pass for the complete "
        "history of the session",
        basis=spec_basis("784-790",
                         "A statement in a break-rooted segment MUST NOT "
                         "carry any other chain's identifier"),
        profile=DEFAULT)
    add("bad-118-break-own-statement-pre-break-identifier", "reject",
        break_predicate(brk_b), PARENT_HASH, ["aia-c-17"],
        {"verdict": "invalid", "codes": ["break-rooted-foreign-identifier"],
         "chainRoot": root_b, "preBreakIdentifier": PARENT_HASH},
        [jcs(brk_b)],
        "chain breaks: the break record's own Statement claims the abandoned "
        "chain's identifier, which the rule forbids for every statement in "
        "the segment, the break's own included",
        basis=spec_basis("784-790",
                         "A statement in a break-rooted segment MUST NOT "
                         "carry any other chain's identifier"),
        profile=DEFAULT)
    add("bad-119-null-priorhead-under-prohibition", "reject",
        break_predicate(brk_a), root_a, ["aia-c-18"],
        {"verdict": "invalid", "codes": ["null-priorhead-forbidden"],
         "chainRoot": root_a},
        [jcs(brk_a)],
        "planted break: under a profile claiming resistance against a "
        "compromised attestor, a chain_break with priorHead null is rejected "
        "however well formed it is, because every field on it is one the "
        "restarted attestor controls",
        basis=spec_basis("1271-1274",
                         "verifiers MUST reject, fail-closed, any such record "
                         "they receive"),
        profile=RESISTANT)
    add("ok-019-known-prior-head-under-prohibition", "accept",
        break_predicate(brk_n), PARENT_HASH, ["aia-c-18"],
        {"verdict": "valid", "chainHash": link_n, "chainRoot": PARENT_HASH},
        [jcs(PARENT_REC), jcs(brk_n)],
        "planted break: the prohibition forbids an unrecoverable prior head, "
        "not a break. A break whose priorHead is the chain hash of the record "
        "before it, and whose predicate.chain carries the same value, is "
        "accepted under that profile",
        profile=RESISTANT)
    add("ok-020-known-prior-head-keeps-genesis-identifier", "accept",
        tool_call(link_n), PARENT_HASH, ["aia-c-19"],
        {"verdict": "valid", "chainHash": chain_hash(succ_n),
         "chainRoot": PARENT_HASH},
        [jcs(PARENT_REC), jcs(brk_n), jcs(succ_n)],
        "chain breaks: a break with a known prior head does not root a chain, "
        "so the successor chains from the break and still carries the "
        "genesis record's chain hash as its subject digest")
    add("bad-120-known-prior-head-re-roots-identifier", "reject",
        tool_call(link_n), link_n, ["aia-c-19"],
        {"verdict": "invalid", "codes": ["subject-not-chain-root"],
         "chainRoot": PARENT_HASH},
        [jcs(PARENT_REC), jcs(brk_n), jcs(succ_n)],
        "chain breaks: the successor re-roots its identifier at a break whose "
        "prior head is known. Only a genesis record or a break with priorHead "
        "null roots a chain, so one session now carries two identifiers",
        basis=spec_basis("771-773",
                         "a root is either a genesis record or a "
                         "`chain_break` with `priorHead: null`"))


def main() -> None:
    build_accept()
    build_appendix_b()
    build_reject()
    build_chain_break()
    emit()
    counts = {"accept": sum(1 for m in MANIFEST if m["kind"] == "accept"),
              "reject": sum(1 for m in MANIFEST if m["kind"] == "reject")}
    corpus = corpus_digest({"vectors": MANIFEST}, HERE)
    manifest = {
        "suite": "ai-agent-action-conformance",
        "predicateType": PREDICATE_TYPE,
        "tracksUpstream": UPSTREAM_PR,
        "specUpstreamCommit": UPSTREAM_COMMIT,
        "specUpstreamRepo": SPEC_UPSTREAM_REPO,
        "specUpstreamRef": SPEC_UPSTREAM_REF,
        "specAuthority": "specDigest",
        "specProvenanceNote":
            "tracksUpstream names where the predicate is REVIEWED. "
            "specUpstreamRepo and specUpstreamRef name the fork branch the "
            "pull request is opened from. On 2026-09-25 specUpstreamCommit is "
            "the head of that branch and of refs/pull/588/head in the review "
            "venue, so `git fetch origin pull/588/head` retrieves it; a plain "
            "clone does not, because it fetches no pull refs. The branch has "
            "been rewritten before and may be again, so the pin a verifier "
            "acts on is specDigest over specVendored, which is in this "
            "directory and which aee-verify recomputes on every run.",
        "specVendored": SPEC_VENDORED_REL,
        "specDigest": spec_digest(),
        "proposedText": PROPOSED_TEXT,
        "profiles": PROFILES,
        "counts": counts,
        "corpusDigest": corpus,
        "note": "Each reject member declares its basis: the lines of the "
                "vendored #588 text that make it rejectable, with a quotation "
                "aee-verify finds in them, or the section of proposedText for "
                "the one condition #588 does not carry. Each accept member is "
                "the conformant twin of the reject member sharing its "
                "condition, so a verifier that rejects everything scores zero "
                "rather than full marks.",
        "vectors": sorted(MANIFEST, key=lambda m: m["id"]),
    }
    write("MANIFEST.json",
          json.dumps(manifest, indent=2, ensure_ascii=False).encode() + b"\n")
    print(json.dumps(counts), "corpusDigest", corpus)


if __name__ == "__main__":
    main()
