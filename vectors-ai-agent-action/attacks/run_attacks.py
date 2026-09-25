#!/usr/bin/env python3
"""Adversarial harness against in-toto/attestation#588 at the vendored revision.

Every attack constructs concrete artifacts on disk and reports SUCCEEDED
(the text as written permits the divergence) or FORECLOSED (the text
already rules it out). Nothing here is a claim about the reference
implementation; the target is the specification text, because a second
implementer has only the text.

Ground truth: the file MANIFEST.json names as specVendored, at the commit it
names as specUpstreamCommit. Both are read from the manifest rather than
spelled here, so re-vendoring the specification is one edit to the generator
and not five edits to this file.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "artifacts")
os.makedirs(OUT, exist_ok=True)

RESULTS: list[tuple[str, str, str, str]] = []

with open(os.path.join(HERE, "..", "MANIFEST.json"), encoding="utf-8") as _fh:
    SPEC = os.path.join(HERE, "..", json.load(_fh)["specVendored"])


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def emit(name: str, content: bytes) -> str:
    path = os.path.join(OUT, name)
    with open(path, "wb") as fh:
        fh.write(content)
    return path


def record(attack: str, verdict: str, invariant: str, artifact: str) -> None:
    RESULTS.append((attack, verdict, invariant, artifact))
    print(f"[{verdict:10s}] {attack}\n             invariant: {invariant}\n"
          f"             artifact:  {os.path.relpath(artifact, HERE)}")


def node_stringify(obj_literal_js: str) -> bytes:
    """Run JSON.stringify in a real ECMAScript engine, not an emulation."""
    proc = subprocess.run(
        ["node", "-e",
         f"process.stdout.write(Buffer.from(JSON.stringify({obj_literal_js}),'utf8'))"],
        capture_output=True, check=True)
    return proc.stdout


# The logical record used across the canonicalization attacks. Field values
# are taken from the worked example in the spec so that nothing here depends
# on an invented shape.
BASE_RECORD_JS = """{
  id: "call_01J8XQ",
  type: "tool_call",
  timestamp: "2026-08-18T14:33:41.882Z",
  toolName: "create_pull_request",
  durationMs: 412,
  success: true,
  previousHash: "genesis",
  extensions: %s
}"""


# ---------------------------------------------------------------------------
# A1  ECMAScript integer-like member ordering inside extensions
# ---------------------------------------------------------------------------
def section(text: str, start: str, end: str) -> str:
    """The span between two headings, or a REFUSAL naming the one that is missing.

    WHY THIS EXISTS. Both call sites used ``text.split(heading)[1]`` directly, so a spec
    revision that RENAMED a heading raised ``IndexError: list index out of range`` from
    inside an attack function. That is the wrong failure in two ways: it names a list
    index instead of the heading, and it aborts the whole harness, so every attack after
    it never runs and the run reports nothing about them. Measured when the vendored spec
    moved from 639ec56 to 8783c6b and ``### Genesis and chain continuity`` became
    ``#### Genesis and breaks``: F3 crashed and the run exited 1 with no verdict.

    A heading this harness cannot find is a fact about the spec, so say which one.
    """
    if start not in text:
        raise SystemExit(
            f"run_attacks: REFUSED -- the vendored spec has no heading {start!r}. "
            "It was renamed or removed upstream. Re-read the spec, update the heading "
            "here, and re-run; do not delete the check."
        )
    tail = text.split(start, 1)[1]
    if end not in tail:
        raise SystemExit(
            f"run_attacks: REFUSED -- no heading {end!r} follows {start!r} in the "
            "vendored spec, so the section has no end and the span cannot be read."
        )
    return tail.split(end, 1)[0]


def attack_a1() -> None:
    ext_js = '{"10": "ten", "2": "two", "zz": "last", "aa": "first"}'
    js_bytes = node_stringify(BASE_RECORD_JS % ext_js)

    # A Python producer building the identical logical record. dict preserves
    # insertion order, which is what json.dumps emits.
    py_obj = {
        "id": "call_01J8XQ",
        "type": "tool_call",
        "timestamp": "2026-08-18T14:33:41.882Z",
        "toolName": "create_pull_request",
        "durationMs": 412,
        "success": True,
        "previousHash": "genesis",
        "extensions": {"10": "ten", "2": "two", "zz": "last", "aa": "first"},
    }
    py_bytes = json.dumps(py_obj, separators=(",", ":")).encode()

    # A Go producer: encoding/json sorts map keys lexicographically.
    go_obj = dict(py_obj)
    go_obj["extensions"] = dict(sorted(py_obj["extensions"].items()))
    go_bytes = json.dumps(go_obj, separators=(",", ":")).encode()

    hashes = {
        "ecmascript-JSON.stringify": (js_bytes, sha256_hex(js_bytes)),
        "python-json.dumps-insertion-order": (py_bytes, sha256_hex(py_bytes)),
        "go-encoding-json-sorted-keys": (go_bytes, sha256_hex(go_bytes)),
    }
    distinct = {h for _, h in hashes.values()}

    body = {
        "attack": "a1-chain-hash-integer-like-key-order",
        "spec_clause": "chain hash = SHA-256(JSON.stringify(record))",
        "logical_record_is_identical_across_all_three": True,
        "serializations": {
            k: {"bytes": v.decode(), "chainHash": h}
            for k, (v, h) in hashes.items()
        },
        "distinctChainHashes": len(distinct),
    }
    path = emit("a1-integer-like-key-order.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "SUCCEEDED" if len(distinct) == 3 else "FORECLOSED"
    record("A1 chain hash diverges on integer-like extension keys", verdict,
           "one logical record has exactly one chain hash", path)


# ---------------------------------------------------------------------------
# A2  Non-ASCII escaping and HTML escaping
# ---------------------------------------------------------------------------
def attack_a2() -> None:
    tool = "créer_fichier<script>"
    js_src = ('{id:"call_02", type:"tool_call", toolName:'
              + json.dumps(tool) + ', previousHash:"genesis"}')
    js_bytes = node_stringify(js_src)

    obj = {"id": "call_02", "type": "tool_call", "toolName": tool,
           "previousHash": "genesis"}
    py_ascii = json.dumps(obj, separators=(",", ":")).encode()  # ensure_ascii=True
    py_raw = json.dumps(obj, separators=(",", ":"),
                        ensure_ascii=False).encode("utf-8")
    # Go encoding/json escapes <, > and & by default.
    go_bytes = (py_raw.decode()
                .replace("<", "\\u003c").replace(">", "\\u003e")
                .replace("&", "\\u0026")).encode()

    variants = {
        "ecmascript-JSON.stringify": js_bytes,
        "python-json.dumps-default-ensure-ascii": py_ascii,
        "python-json.dumps-ensure-ascii-false": py_raw,
        "go-encoding-json-html-escaped": go_bytes,
    }
    hashes = {k: sha256_hex(v) for k, v in variants.items()}
    distinct = set(hashes.values())

    body = {
        "attack": "a2-chain-hash-string-escaping",
        "spec_clause": "chain hash = SHA-256(JSON.stringify(record))",
        "toolName_codepoints": [hex(ord(c)) for c in tool],
        "serializations": {k: {"bytes": v.decode(), "chainHash": hashes[k]}
                           for k, v in variants.items()},
        "distinctChainHashes": len(distinct),
    }
    path = emit("a2-string-escaping.json",
                json.dumps(body, indent=2, ensure_ascii=False).encode() + b"\n")
    verdict = "SUCCEEDED" if len(distinct) > 1 else "FORECLOSED"
    record("A2 chain hash diverges on string escaping policy", verdict,
           "one logical record has exactly one chain hash", path)


# ---------------------------------------------------------------------------
# A3  Two readings of the preimage: re-serialize vs bytes-as-written
# ---------------------------------------------------------------------------
def attack_a3() -> None:
    on_disk = b'{"id": "call_03", "type": "tool_call", "previousHash": "genesis"}'
    reserialized = json.dumps(json.loads(on_disk),
                              separators=(",", ":")).encode()
    h_disk, h_re = sha256_hex(on_disk), sha256_hex(reserialized)

    body = {
        "attack": "a3-preimage-reading-split",
        "spec_clause_a": "SHA-256(JSON.stringify(record))",
        "spec_clause_b": "the complete JSON-serialized audit record as written "
                         "to the JSONL log",
        "readings": {
            "bytes-as-written": {"bytes": on_disk.decode(), "chainHash": h_disk},
            "reserialize-parsed-object": {"bytes": reserialized.decode(),
                                          "chainHash": h_re},
        },
        "note": "Any log shipper that reparses and re-emits JSON (fluentd, "
                "vector, logstash) moves a verifier from one reading to the "
                "other without touching a single field value.",
        "distinctChainHashes": len({h_disk, h_re}),
    }
    path = emit("a3-preimage-reading-split.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "SUCCEEDED" if h_disk != h_re else "FORECLOSED"
    record("A3 the chain-hash preimage has two readings in one paragraph",
           verdict, "the chain-hash preimage is a single named byte string",
           path)


# ---------------------------------------------------------------------------
# A4  Duplicate member: two logical records, one chain hash
# ---------------------------------------------------------------------------
def attack_a4() -> None:
    dup = (b'{"id":"call_04","type":"tool_call","toolName":"read_file",'
           b'"toolName":"delete_repository","previousHash":"genesis"}')
    last_wins = json.loads(dup)            # Python, JS, Go: last wins
    benign = {"id": "call_04", "type": "tool_call", "toolName": "read_file",
              "previousHash": "genesis"}
    hostile = {"id": "call_04", "type": "tool_call",
               "toolName": "delete_repository", "previousHash": "genesis"}

    h_dup_bytes = sha256_hex(dup)
    h_re = sha256_hex(json.dumps(last_wins, separators=(",", ":")).encode())
    h_hostile = sha256_hex(json.dumps(hostile, separators=(",", ":")).encode())

    body = {
        "attack": "a4-duplicate-member",
        "spec_clause": "no statement-wide duplicate-member rule is stated",
        "wire_bytes": dup.decode(),
        "parsed_last_wins_toolName": last_wins["toolName"],
        "parsed_first_wins_toolName": "read_file",
        "chainHash_of_wire_bytes": h_dup_bytes,
        "chainHash_after_reserialization": h_re,
        "chainHash_of_hostile_record_alone": h_hostile,
        "collapses_to_hostile_record": h_re == h_hostile,
        "benign_reading": benign,
        "hostile_reading": hostile,
        "note": "Under the re-serialize reading these bytes carry the same "
                "chain hash as a record naming delete_repository, while a "
                "first-wins reader displays read_file. The audit trail and "
                "the hash then describe different tool calls.",
    }
    path = emit("a4-duplicate-member.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "SUCCEEDED" if h_re == h_hostile and h_dup_bytes != h_re \
        else "FORECLOSED"
    record("A4 a duplicate member makes two logical records share a hash",
           verdict, "distinct logical records have distinct chain hashes",
           path)


# ---------------------------------------------------------------------------
# A5  Chain fork: the interior branches while the genesis hash is untouched
# ---------------------------------------------------------------------------
def attack_a5() -> None:
    def line(rec: dict) -> bytes:
        return json.dumps(rec, separators=(",", ":")).encode()

    r1 = {"id": "r1", "type": "tool_call", "toolName": "list_files",
          "previousHash": "genesis"}
    h1 = sha256_hex(line(r1))

    # The honest branch: three further calls, one of them sensitive.
    honest = []
    prev = h1
    for i, tool in enumerate(["read_secrets", "exfiltrate_env",
                              "create_pull_request"], start=2):
        rec = {"id": f"r{i}", "type": "tool_call", "toolName": tool,
               "previousHash": prev}
        honest.append(rec)
        prev = sha256_hex(line(rec))
    honest_head = prev

    # The presented branch: a single record that also chains from r1.
    fork = {"id": "r2b", "type": "tool_call", "toolName": "create_pull_request",
            "previousHash": h1}
    fork_head = sha256_hex(line(fork))

    honest_log = b"\n".join([line(r1)] + [line(r) for r in honest]) + b"\n"
    presented_log = line(r1) + b"\n" + line(fork) + b"\n"

    p_honest = emit("a5-chain-fork-honest.jsonl", honest_log)
    p_pres = emit("a5-chain-fork-presented.jsonl", presented_log)

    body = {
        "attack": "a5-chain-fork",
        "genesis_record_chain_hash": h1,
        "subject_digest_both_branches": h1,
        "honest_branch_records": 4,
        "presented_branch_records": 2,
        "honest_head": honest_head,
        "presented_head": fork_head,
        "records_omitted_from_presentation": ["read_secrets", "exfiltrate_env"],
        "every_previousHash_resolves_in_presented_set": True,
        "genesis_marker_appears_once": True,
        "note": "Nothing in the text requires the predecessor relation to be "
                "injective. Two records may carry the same previousHash, so a "
                "chain is a tree and the presenter chooses the branch. The "
                "subject digest is the genesis hash, which is identical on "
                "both branches, so a policy targeting the chain cannot tell "
                "them apart. No hash is broken and no second genesis appears.",
        "artifacts": [os.path.basename(p_honest), os.path.basename(p_pres)],
    }
    path = emit("a5-chain-fork.json", json.dumps(body, indent=2).encode() + b"\n")
    record("A5 the chain forks; the short branch verifies completely",
           "SUCCEEDED",
           "a chain has one head, and the predecessor relation is injective",
           path)


# ---------------------------------------------------------------------------
# A6  Checkpoint records are not on the chain the Fields table defines
# ---------------------------------------------------------------------------
def attack_a6() -> None:
    spec = SPEC
    with open(spec, encoding="utf-8") as fh:
        text = fh.read()

    # Positive control and the absence, measured in the same run.
    flat = " ".join(text.split())
    control = flat.count("carries the break record's chain hash")
    absent = flat.count("carries the checkpoint record's chain hash")
    chain_field_on_checkpoint = "\"chain\"" in section(
        text, "### Checkpoint record", "### Chain break record")

    body = {
        "attack": "a6-checkpoint-not-on-the-chain",
        "read_path_control": {
            "phrase": "carries the break record's chain hash",
            "occurrences": control,
        },
        "measured_absence": {
            "phrase": "carries the checkpoint record's chain hash",
            "occurrences": absent,
        },
        "checkpoint_schema_carries_predicate_chain_object":
            chain_field_on_checkpoint,
        "finding": "chain_break has an explicit successor-linkage sentence; "
                   "checkpoint has none, and the checkpoint record carries its "
                   "head in predicate.checkpoint.previousHash rather than in "
                   "the predicate.chain.previousHash the Fields table defines "
                   "as the chain link. A verifier that walks the documented "
                   "field steps straight past every checkpoint, so deleting a "
                   "checkpoint breaks no documented linkage. The checkpoint is "
                   "the whole anti-truncation mechanism.",
    }
    path = emit("a6-checkpoint-not-on-chain.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "SUCCEEDED" if control >= 1 and absent == 0 and \
        not chain_field_on_checkpoint else "FORECLOSED"
    record("A6 checkpoints sit off the chain the Fields table defines",
           verdict,
           "every record type is linked by one named field and is undeletable",
           path)


# ---------------------------------------------------------------------------
# A7  The float rule contradicts itself
# ---------------------------------------------------------------------------
def attack_a7() -> None:
    spec = SPEC
    with open(spec, encoding="utf-8") as fh:
        text = fh.read()
    # The spec is hard-wrapped, so a phrase spanning a line break is absent
    # from the raw text and present in the prose. Normalize before probing,
    # or the probe reports an absence the document does not have.
    flat = " ".join(text.split())
    # READ-PATH CONTROL FIRST. This probe was two literal searches with no control,
    # so when 8783c6b reworded both clauses the searches returned False and the attack
    # reported FORECLOSED -- the right verdict reached by a route that cannot tell a
    # resolved contradiction from a renamed heading. Same defect as F2, opposite sign.
    control_phrase = "safe integer"
    control = flat.lower().count(control_phrase)
    if control == 0:
        raise SystemExit(
            "run_attacks: REFUSED -- A7's read-path control found no occurrence of "
            f"{control_phrase!r} in the vendored spec. An absence measured through a "
            "read path that cannot find a present thing is not a finding."
        )
    # Probe the SUBSTANCE, in any phrasing: a safe-integer bound on the signing form,
    # and floats admitted anywhere in the document.
    both_forms = ("Constraints on both forms" in flat
                  or "MUST be safe integers" in flat
                  or "MUST remain within the I-JSON safe integer range" in flat)
    floats_needed = ("MCP payloads can contain floating-point values" in flat
                     or "tool payloads are arbitrary JSON that may contain floats" in flat
                     or "Floats are permitted here and only here" in flat)

    payload = {"temperature": 0.7, "maxTokens": 4096}
    jcs = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    body = {
        "attack": "a7-float-rule-contradiction",
        "clause_a": "Constraints on both forms: Numbers MUST be safe integers "
                    "(absolute value < 2^53, per RFC 7493 Section 2.2).",
        "clause_a_present": both_forms,
        "clause_b": "This is necessary because MCP payloads can contain "
                    "floating-point values that the signing canonical form "
                    "rejects by design.",
        "clause_b_present": floats_needed,
        "read_path_control": {"phrase": control_phrase, "occurrences": control},
        "payload": payload,
        "implementer_reading_clause_a": "reject the record",
        "implementer_reading_clause_b": "accept and digest under JCS",
        "digest_under_clause_b": sha256_hex(jcs),
        "note": "Both sentences are in the same subsection. One forbids the "
                "float in every form; the other says the second form exists "
                "because of the float.",
    }
    path = emit("a7-float-rule-contradiction.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "SUCCEEDED" if both_forms and floats_needed else "FORECLOSED"
    record("A7 the safe-integer constraint contradicts the content-digest form",
           verdict, "a conformant implementer reaches one verdict per payload",
           path)


# ---------------------------------------------------------------------------
# A8  contentDigest.response has no preimage for a failed tool call
# ---------------------------------------------------------------------------
def attack_a8() -> None:
    err = {"jsonrpc": "2.0", "id": 7,
           "error": {"code": -32000, "message": "permission denied"}}
    candidates = {
        "omit-the-field": None,
        "JCS-of-null": b"null",
        "JCS-of-empty-object": b"{}",
        "JCS-of-the-error-member":
            json.dumps(err["error"], separators=(",", ":"),
                       sort_keys=True).encode(),
        "JCS-of-the-whole-response":
            json.dumps(err, separators=(",", ":"), sort_keys=True).encode(),
    }
    digests = {k: (None if v is None else sha256_hex(v))
               for k, v in candidates.items()}
    distinct = {d for d in digests.values() if d}

    body = {
        "attack": "a8-error-response-has-no-preimage",
        "spec_clause": "payload is the JSON-RPC params object (for requests) "
                       "or result object (for responses)",
        "failed_response": err,
        "candidate_preimages": {
            k: {"bytes": (v.decode() if v else None), "digest": digests[k]}
            for k, v in candidates.items()
        },
        "distinctDigests": len(distinct),
        "note": "A JSON-RPC error response carries no result member, and every "
                "record with success:false is one. The failures are where an "
                "audit trail earns its keep.",
    }
    path = emit("a8-error-response-preimage.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "SUCCEEDED" if len(distinct) >= 2 else "FORECLOSED"
    record("A8 a failed tool call has no defined response preimage", verdict,
           "every content digest names exactly one preimage", path)


# ---------------------------------------------------------------------------
# A9  previousHash case and length are unpinned
# ---------------------------------------------------------------------------
def attack_a9() -> None:
    lower = "cd26e6c4930f34da6dbbb53988f4920b13eedc7e3354ac51a82efeac9574e664"
    upper = lower.upper()
    sha1_len = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def succ(ph: str) -> bytes:
        return json.dumps({"id": "r2", "type": "tool_call",
                           "toolName": "create_pull_request",
                           "previousHash": ph},
                          separators=(",", ":")).encode()

    hashes = {k: sha256_hex(succ(k)) for k in (lower, upper, sha1_len)}
    body = {
        "attack": "a9-previoushash-case-and-length-unpinned",
        "spec_clause": "previousHash | string | Yes | Chain hash of the "
                       "preceding record",
        "note": "The type is string. No case, no length, no algorithm "
                "identifier. A verifier that compares hex case-insensitively "
                "accepts both spellings as the same link, while the two "
                "successors serialize to different bytes and therefore to "
                "different chain hashes of their own. A 40-hex value is not "
                "excluded by anything written.",
        "successor_chain_hash_by_previousHash_spelling": hashes,
        "genesis_literal_case_pinned": False,
    }
    path = emit("a9-previoushash-unpinned.json",
                json.dumps(body, indent=2).encode() + b"\n")
    record("A9 previousHash case, length and algorithm are unpinned",
           "SUCCEEDED",
           "one logical link has exactly one spelling", path)


# ---------------------------------------------------------------------------
# A10 The signing canonical form's field list is not in the specification
# ---------------------------------------------------------------------------
def attack_a10() -> None:
    spec = SPEC
    with open(spec, encoding="utf-8") as fh:
        text = fh.read()
    flat = " ".join(text.split())
    control = flat.count("keys sorted by UTF-16")          # form IS described
    admits = "fixed by the implementation" in flat
    enumerates = "the signing tuple contains" in flat

    body = {
        "attack": "a10-signing-field-list-absent",
        "read_path_control": {"phrase": "keys sorted by UTF-16",
                              "occurrences": control},
        "clause": "The field order is fixed by the implementation (not sorted "
                  "alphabetically -- the order matches the type definition).",
        "clause_present": admits,
        "field_list_enumerated_in_spec": enumerates,
        "note": "The tagging rules, the sort order and the type tags are all "
                "written down. The list of fields the tuple contains, and "
                "their order, live in a type definition the specification does "
                "not carry. A second implementer can reproduce the encoding "
                "and still not reproduce a single signature, and no "
                "conformance vector can be written for a form whose input "
                "list is unpublished.",
    }
    path = emit("a10-signing-field-list-absent.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "SUCCEEDED" if control >= 1 and admits and not enumerates \
        else "FORECLOSED"
    record("A10 the signing tuple's field list is not in the specification",
           verdict, "a signed form is reproducible from the text alone", path)


# ---------------------------------------------------------------------------
# Foreclosed probes: attacks the text already stops
# ---------------------------------------------------------------------------
def attack_f1() -> None:
    """Strip predicate.chain from a mid-chain record to detach it."""
    def line(rec: dict) -> bytes:
        return json.dumps(rec, separators=(",", ":")).encode()

    r1 = {"id": "r1", "type": "tool_call", "previousHash": "genesis"}
    h1 = sha256_hex(line(r1))
    r2 = {"id": "r2", "type": "tool_call", "previousHash": h1}
    h2 = sha256_hex(line(r2))
    r2_stripped = {"id": "r2", "type": "tool_call"}
    h2_stripped = sha256_hex(line(r2_stripped))

    body = {
        "attack": "f1-strip-chain-object",
        "spec_clause": "The predicate.chain object is OPTIONAL on tool_call "
                       "records. When absent, the attestation stands alone "
                       "without ordering guarantees.",
        "chainHash_with_chain": h2,
        "chainHash_without_chain": h2_stripped,
        "successor_link_still_valid": h2 == h2_stripped,
        "why_foreclosed": "The chain hash covers the complete serialized "
                          "record, so removing the chain object changes the "
                          "record's own hash and the next record's "
                          "previousHash no longer resolves. Hashing the whole "
                          "record rather than a field subset is what stops "
                          "this, and it is the strongest property the design "
                          "currently has.",
    }
    path = emit("f1-strip-chain-object.json",
                json.dumps(body, indent=2).encode() + b"\n")
    verdict = "FORECLOSED" if h2 != h2_stripped else "SUCCEEDED"
    record("F1 detaching a mid-chain record by deleting predicate.chain",
           verdict, "a record cannot leave the chain without breaking it",
           path)


def attack_f2() -> None:
    """Unpaired surrogate in a signed string."""
    spec = SPEC
    with open(spec, encoding="utf-8") as fh:
        text = fh.read()
    # PROBE THE RULE, NOT THE SENTENCE. This was a single literal search for
    # "MUST NOT contain unpaired UTF-16 surrogates", which is how 639ec56 worded it.
    # 8783c6b REWORDED and STRENGTHENED the same constraint (unpaired escape halves
    # are malformed, no surrogate encoded directly in UTF-8, no overlong form), and
    # the literal probe returned False -- so the harness reported the attack
    # SUCCEEDED against a spec that had closed it harder. A probe that reads a
    # rewording as a removal manufactures a regression, which is the most expensive
    # false positive available to a conformance corpus. Any one of these phrasings
    # establishes the constraint.
    surrogate_rules = (
        "MUST NOT contain unpaired UTF-16 surrogates",
        "unpaired escape of either half is malformed",
        "no surrogate encoded directly in UTF-8",
    )
    matched = [r for r in surrogate_rules if r in text]
    pinned = bool(matched)
    body = {
        "attack": "f2-unpaired-surrogate",
        "clause": "Strings MUST NOT contain unpaired UTF-16 surrogates.",
        "clause_present": pinned,
        "matched_phrasings": matched,
        "why_foreclosed": "Stated for both forms, so a lone \\ud800 is "
                          "malformed rather than a divergence. The narrower "
                          "gaps #570 also closes -- noncharacters, overlong "
                          "UTF-8, raw control characters, a permissive \\u "
                          "escape parser -- remain open, but the surrogate "
                          "half is genuinely shut.",
    }
    path = emit("f2-unpaired-surrogate.json",
                json.dumps(body, indent=2).encode() + b"\n")
    record("F2 unpaired surrogate in a signed string",
           "FORECLOSED" if pinned else "SUCCEEDED",
           "signed strings are well-formed Unicode", path)


def attack_f3() -> None:
    """Replay a second genesis to restart the chain and drop history."""
    spec = SPEC
    with open(spec, encoding="utf-8") as fh:
        text = fh.read()
    must = "MUST" in section(
        text, "#### Genesis and breaks", "### Parsing Rules")
    should_only = "SHOULD treat it as" in text
    body = {
        "attack": "f3-second-genesis",
        "clause": "A consumer that encounters a second \"genesis\" anywhere in "
                  "the log SHOULD treat it as evidence of adversarial chain "
                  "replacement.",
        "genesis_section_contains_MUST": must,
        "detection_is_SHOULD_not_MUST": should_only,
        "verdict_reasoning": "Partly foreclosed. The convention is stated and "
                             "the chain_break successor rule makes the scar "
                             "load-bearing, which is a real improvement. But "
                             "the detection obligation is SHOULD, so a "
                             "verifier that ignores a second genesis is "
                             "conformant, and the fork in A5 needs no second "
                             "genesis at all.",
    }
    path = emit("f3-second-genesis.json",
                json.dumps(body, indent=2).encode() + b"\n")
    record("F3 restarting the chain with a second genesis",
           "PARTLY" if should_only else "FORECLOSED",
           "chain replacement is detected, not merely detectable", path)


def main() -> None:
    for fn in (attack_a1, attack_a2, attack_a3, attack_a4, attack_a5,
               attack_a6, attack_a7, attack_a8, attack_a9, attack_a10,
               attack_f1, attack_f2, attack_f3):
        fn()
    print("\n=== SUMMARY ===")
    for name, verdict, _, _ in RESULTS:
        print(f"{verdict:10s} {name}")
    summary = [{"attack": n, "verdict": v, "invariant": i,
                "artifact": os.path.relpath(a, HERE)}
               for n, v, i, a in RESULTS]
    with open(os.path.join(OUT, "SUMMARY.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main()
