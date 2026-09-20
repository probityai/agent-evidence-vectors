#!/usr/bin/env python3
"""Differential conformance harness for the Adversarial Execution Evidence
(AEE) predicate, v0.7.

Predicate type URI:
    https://in-toto.io/attestation/adversarial-execution-evidence/v0.7

This harness loads every conformance vector under ``vectors/`` (a sibling of
this script's parent directory by default) and checks each one against the
suite MANIFEST expectations:

* accept vectors (``accept/ok-*.json``) must be VALID, recompute to the
  expected ``result``, and derive the expected per-row evidence tiers under
  both key policies (with the pinned TEST substrate key, and with no key);
* reject vectors (``reject/bad-*.json``) must be INVALID with a failure code
  drawn from the MANIFEST's ``expected.codes`` set.

Rails
-----
1. EXTERNAL RAIL (optional): pass ``--verifier <path>`` (or set the
   ``AEE_EXTERNAL_VERIFIER`` environment variable) to run every vector
   through an external verifier.  A named verifier is ALWAYS the program
   that runs: when it cannot be started (not found, not executable, an
   empty or unparseable setting) the harness exits 2 saying it did NOT
   run, and it never substitutes the reference rail.  The report's
   ``verifier.vectorsExecuted`` counts the vectors it answered, and a count
   below the vector count fails the run.  Without ``--verifier`` the
   reference rail below runs, so the suite is verifiable standalone.

   External-implementation contract: a third-party verifier is invoked as
   ``<cmd> <vector-file>``; exit 0 means valid, non-zero means invalid; and
   the LAST stdout line must be a JSON object of the shape
   ``{"verdict": "valid"|"invalid", "codes": [...], "result": "...",
   "tiers": [...]}``.  ONE line: the harness reads the last line and parses
   that line alone, so an indented encoding whose last line is ``}`` carries
   no answer at all.  The exit status alone does not carry a vector: a
   reject vector is checked against its MANIFEST ``expected.codes`` and an
   accept vector against its ``expected.result``, so a rail that answers with
   a verdict and nothing else fails every vector declaring either.  ``codes``
   is compared as a SET -- order carries nothing and message text carries
   nothing.  This paragraph is pinned to the evaluator below by
   ``scripts/code-contract-gate.py``, which drives each response shape through
   it and asserts the outcome, because the paragraph previously said the
   harness falls back to checking the verdict alone and nothing contradicted
   it.

   The consumer key policy travels in the environment variable
   ``AEE_SUBSTRATE_KEYS``, holding a path to
   ``{"substrateObservationKeys": [{"keyid": ..., "publicKeyHex": ...}]}``.
   Argv is fixed by the contract, so naming a flag would dictate a spelling to
   every rail; naming a variable dictates only where to look.  Each vector is
   run TWICE through the same argv: once with the variable set to the suite's
   pinned TEST key policy, whose ``tiers`` are compared against
   ``expected.tierWithPinnedKey``, and once with the variable absent, whose
   ``tiers`` are compared against ``expected.tierWithoutKey``.  The second run
   is what puts a third-party rail under GATE 2's no-TOFU rule -- no pinned key
   means every substrate row derives ``unattested`` and the substrate root is
   never inferred from the predicate -- and it is also where the assertion that
   tier derivation never alters ``result`` becomes checkable from outside.
   ``--verifier`` accepts a full command line, not only a path, so a rail
   needing flags (``"./aee-verify -json"``) is drivable without a wrapper.

2. REFERENCE RAIL (default, self-contained, stdlib-only): an independent
   Python implementation of the spec's checks -- statement well-formedness
   (GATE 0), the byte-checkable per-substrate-row coverage validity gate
   (GATE 1), the pure ``result`` recompute, and the per-row evidence tier
   (GATE 2) -- including RFC 8785 (JCS) canonicalization, RFC 7493
   (I-JSON) payload strictness, DSSE PAEv1, the RFC 6962 domain-separated
   batch root, the versioned run-binding derivation, and pure-Python
   Ed25519 (RFC 8032) for tier signature verification.

The reference rail deliberately emits the SET of every failure it detects;
conformance for a reject vector is ``expected.codes`` intersecting the
emitted set plus verdict equality, so a strict single-code rail and this
superset-emitting rail can both pass the same MANIFEST.

Second-fault-absence self-checks: for every reject vector the harness
additionally asserts that commitments NOT named by the vector's expected
codes still verify (batch root recomputes, vocabulary digest verifies,
corpus digest verifies, record bindings equal the derived binding), which
machine-checks the suite's single-fault discipline.

Outputs a gate-by-vector coverage report: a human table on stdout plus
``conformance-report.json`` (all paths repo-relative).  Exit status: 0 all
checks pass, 1 any check fails, 2 usage or suite-not-found.

TEST KEYS ONLY: the harness re-derives the suite's Ed25519 test keys from
the published recipe ``seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")``.
These keys prove nothing and must never sign real evidence.

Run ``run_vectors.py --self-test`` to exercise the reference rail against
built-in synthetic statements without needing the vector files.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import decimal
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, NamedTuple, TypeGuard

# The v0.1 per-check report: its validator, the judge for its corpus, and the
# emitter that crosswalks this harness's report into it. A sibling module of
# this file in the wheel and beside it under packaging/ in a checkout, so the
# import resolves the same way in both layouts.
#
# observedeffect is the reader for a SECOND predicate, dispatched the same way.
# Without it this rail replayed all forty-nine members of that corpus through the
# verifier for the predicate below and refused every one of them with
# predicate-type-unsupported, which is a rail answering about the wrong predicate
# rather than a corpus that fails.
#
# receiptsignature is the third, and the first whose corpus defines an
# external-verifier contract of its own: a named verifier runs over it through
# that contract instead of being refused.
from agent_evidence_vectors import observedeffect, receiptsignature, w3creport

AEE_PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SAFE_INT_LIMIT = 2**53

KEY_ROLES = ("substrate-observation-test", "wrong-signer-test", "statement-test")
PINNED_ROLE = "substrate-observation-test"

RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# ---------------------------------------------------------------------------
# RFC 8785 (JCS) canonical JSON -- subset sufficient for this suite
# (null / bool / int / str / array / object; non-integer numbers are outside
# the suite's I-JSON profile and are rejected).
# ---------------------------------------------------------------------------


class JcsError(ValueError):
    pass


_JCS_CTRL = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _utf16_sort_key(s: str) -> bytes:
    """UTF-16 code-unit sort key (RFC 8785 section 3.2.3).

    Big-endian UTF-16 bytes compare lexicographically exactly as the 16-bit
    code-unit sequence does, so ``sorted(..., key=_utf16_sort_key)`` is the
    code-unit order the spec pins. This is deliberately NOT plain ``sorted``
    (code-point order): a supplementary-plane string's lead surrogate
    (0xD800..0xDBFF) sorts before a BMP code point in 0xE000..0xFFFF under
    UTF-16 and after it under code points. The BMP-only string profile makes
    that divergence unconstructible in accepted input, so this key is the
    comparator-level pin, shared by member-name canonicalization and the
    vocabulary sortedness check.
    """
    return s.encode("utf-16-be")


def _all_bmp(strings: list[str]) -> bool:
    """True when every code point of every string lies inside the BMP."""
    return all(ord(ch) <= 0xFFFF for s in strings for ch in s)


def _member_names_bmp(v: Any) -> bool:
    """True when every object member name, at any depth, is BMP-only.

    Member values are unconstrained; only the sorted member names participate
    in RFC 8785 member ordering.
    """
    if isinstance(v, dict):
        return all(_all_bmp([k]) and _member_names_bmp(x) for k, x in v.items())
    if isinstance(v, list):
        return all(_member_names_bmp(x) for x in v)
    return True


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append(_JCS_CTRL.get(o, f"\\u{o:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_float(v: float) -> str:
    """Serialize a float under the integers-only profile, by its VALUE.

    RFC 8785 serializes a number as ES6 Number::toString, which emits "1" for the
    double 1.0, so an integral float canonicalizes to plain integer form.
    Refusing every float outright was a deviation from the RFC rather than the
    integers-only profile being enforced: the profile is over the value, and 1.0
    denotes the integer 1. The Go sibling keeps the literal as a number token and
    has always canonicalized it that way -- ``TestSafeIntegerProfile`` pins
    ``Canonicalize("1e2") == "100"``. Deciding it on the Python TYPE instead is
    the same type-versus-value confusion the parse hook corrects, one layer down,
    and it is what split this rail from its own reference.

    A fractional value, a magnitude outside the safe range, and the non-finite
    values a lenient parse can produce are all still refused, so nothing widens
    except the case the RFC already decided.
    """
    if not v.is_integer():
        raise JcsError("non-integer number outside the suite I-JSON profile")
    if abs(v) >= SAFE_INT_LIMIT:
        raise JcsError("integer outside safe range")
    return str(int(v))


def jcs_dumps(obj: Any) -> bytes:
    def ser(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            return _jcs_float(v)
        if isinstance(v, str):
            return _jcs_string(v)
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys(), key=_utf16_sort_key)
            return "{" + ",".join(_jcs_string(k) + ":" + ser(v[k]) for k in keys) + "}"
        raise JcsError(f"unsupported type: {type(v)!r}")

    return ser(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Byte-level string-scalar scan, mirroring the Go rail (aee/jcs.go
# checkStringScalars). Every check downstream of a decode reads Python str
# objects, and both decoders this rail uses are lossy in exactly the ways the
# profile forbids: json.loads turns an unpaired "\ud800" escape into a lone
# surrogate that no later comparison can distinguish from a legitimately
# written one, and it is not even encodable, so the UTF-16 sort key and the
# canonical re-serialization raise UnicodeEncodeError from deep inside checks
# that have no business seeing an encoding fault. The bytes are the only place
# the fault is still visible, so it is rejected there, before any caller reads
# a decoded string.
# ---------------------------------------------------------------------------


class StringNotScalarError(ValueError):
    """A JSON string literal whose bytes do not denote Unicode scalar values."""


def _hex4(b: bytes) -> int | None:
    """Value of the four hex digits of a \\u escape at the start of b."""
    if len(b) < 4:
        return None
    v = 0
    for c in b[:4]:
        if 0x30 <= c <= 0x39:
            v = v << 4 | (c - 0x30)
        elif 0x61 <= c <= 0x66:
            v = v << 4 | (c - 0x61 + 10)
        elif 0x41 <= c <= 0x46:
            v = v << 4 | (c - 0x41 + 10)
        else:
            return None
    return v


def _is_noncharacter(cp: int) -> bool:
    """Whether cp is a Unicode noncharacter: U+FDD0..U+FDEF or U+nFFFE/U+nFFFF in
    any of the 17 planes. RFC 7493 (I-JSON) section 2.1 forbids these in the same
    sentence as surrogates, so strict I-JSON rejects them wherever a string literal
    appears. They are valid scalar values that nothing substitutes for, so every rail
    decodes identical bytes identically; the rejection makes the RFC 7493 label true
    for a from-spec verifier rather than a narrower carve-out."""
    return cp & 0xFFFE == 0xFFFE or 0xFDD0 <= cp <= 0xFDEF


def _check_surrogate_pair(b: bytes, hi: int) -> int:
    """Validate the low-surrogate escape that MUST follow a high surrogate at hi,
    and return the 12-byte span of the pair. Rejects a lone or malformed low half
    and a paired code point that is a noncharacter."""
    if len(b) < 12 or b[6:8] != b"\\u":
        raise StringNotScalarError(f"unpaired high surrogate \\u{hi:04X}")
    lo = _hex4(b[8:])
    if lo is None:
        raise StringNotScalarError(f"malformed \\u escape after high surrogate \\u{hi:04X}")
    if not 0xDC00 <= lo < 0xE000:
        raise StringNotScalarError(
            f"high surrogate \\u{hi:04X} followed by \\u{lo:04X}, which is not a low surrogate"
        )
    cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
    if _is_noncharacter(cp):
        raise StringNotScalarError(f"noncharacter U+{cp:04X} in string")
    return 12  # \uXXXX\uXXXX


def _check_escape(b: bytes) -> int:
    """Validate one escape sequence at b[0] ('\\') and return its byte span.

    A \\u escape naming a high surrogate spans the low-surrogate escape that
    MUST follow it, so the pair is validated and consumed as one unit and a
    lone surrogate of either half is rejected.
    """
    if len(b) < 2:
        raise StringNotScalarError("unterminated escape sequence")
    if b[1:2] != b"u":
        return 2  # \" \\ \/ \b \f \n \r \t: syntax already validated by the decode
    hi = _hex4(b[2:])
    if hi is None:
        raise StringNotScalarError("malformed \\u escape")
    if 0xD800 <= hi < 0xDC00:  # high surrogate: a low surrogate escape MUST follow
        return _check_surrogate_pair(b, hi)
    if 0xDC00 <= hi < 0xE000:
        raise StringNotScalarError(f"unpaired low surrogate \\u{hi:04X}")
    if _is_noncharacter(hi):
        raise StringNotScalarError(f"noncharacter U+{hi:04X} in string")
    return 6


def _check_string_literal(b: bytes) -> int:
    """Validate one JSON string literal at b[0] ('"'), returning its byte span
    including both quotes."""
    i = 1
    while i < len(b):
        c = b[i]
        if c == 0x22:  # '"'
            return i + 1
        if c == 0x5C:  # '\'
            i += _check_escape(b[i:])
        elif c < 0x20:
            raise StringNotScalarError(f"raw control character U+{c:04X} in string")
        elif c < 0x80:
            i += 1
        else:
            # A multi-byte sequence is legal only if it round-trips: strict
            # UTF-8 decoding rejects overlong forms and surrogates encoded in
            # UTF-8 (CESU-8), which is what separates a genuine U+FFFD the
            # producer wrote from an ill-formed sequence.
            size = _utf8_seq_len(c)
            if size == 0 or i + size > len(b):
                raise StringNotScalarError(f"invalid UTF-8 at byte {i} of string")
            try:
                ch = b[i : i + size].decode("utf-8")
            except UnicodeDecodeError:
                raise StringNotScalarError(f"invalid UTF-8 at byte {i} of string") from None
            if _is_noncharacter(ord(ch)):
                raise StringNotScalarError(f"noncharacter U+{ord(ch):04X} in string")
            i += size
    raise StringNotScalarError("unterminated string literal")


def _utf8_seq_len(lead: int) -> int:
    """Byte length a UTF-8 lead byte announces, or 0 if it is not a lead byte."""
    if 0xC2 <= lead <= 0xDF:
        return 2
    if 0xE0 <= lead <= 0xEF:
        return 3
    if 0xF0 <= lead <= 0xF4:
        return 4
    return 0  # continuation byte, or a lead byte no valid sequence starts with


def check_string_scalars(raw: bytes) -> None:
    """Apply _check_string_literal to every string literal in raw, at any depth
    and in both member-name and value position.

    Requires raw to be syntactically valid JSON, so that every '"' met outside
    a literal opens one.
    """
    i = 0
    n = len(raw)
    while i < n:
        if raw[i] != 0x22:  # '"'
            i += 1
            continue
        i += _check_string_literal(raw[i:])


# ---------------------------------------------------------------------------
# RFC 7493 (I-JSON) strict payload parse: duplicate members and unsafe
# integers rejected.
# ---------------------------------------------------------------------------


class IJsonError(ValueError):
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


def _safe_integer_literal(s: str) -> int:
    """Apply the integers-only safe-integer profile to a number literal's VALUE.

    ``json.loads`` routes every token carrying a '.', an 'e' or an 'E' here, so
    this is the only place this rail sees the literal rather than the object
    CPython made of it. The Go rail's ``checkSafeInteger`` (aee/jcs.go) tests
    the same literals with exact rational arithmetic and accepts ``1e2`` and
    ``100.0``, because those denote the integer 100; its own
    ``TestSafeIntegerProfile`` pins that, and pins ``Canonicalize("1e2") ==
    "100"`` besides. Reading the profile off the CPython type instead made this
    rail answer ``payload-not-ijson`` for a payload satisfying every clause of
    the I-JSON requirement the specification states, and disagree with its own
    Go sibling about which condition a payload carrying ``1e2`` violates. The
    condition that does hold is ``payload-not-canonical``, and the caller
    reaches it once the value parses.

    A genuinely fractional value and an integer outside the safe range are
    still refused, so ``payload-not-ijson`` keeps naming a condition that holds.

    ``Decimal`` rather than ``Fraction``: both are exact, but ``Fraction``
    materializes the numerator, so ``1e1000000000`` -- a legal JSON token an
    attacker writes in 13 bytes -- expands to a billion digits inside the parse.
    ``Decimal`` keeps the exponent, and neither test below expands it.
    """
    d = decimal.Decimal(s)
    if d != d.to_integral_value():
        raise IJsonError("payload-not-ijson", f"non-integer number {s!r}")
    if not -SAFE_INT_LIMIT < d < SAFE_INT_LIMIT:
        raise IJsonError("payload-not-ijson", "integer outside safe range")
    return int(d)


def _reject_dup_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise IJsonError("payload-not-ijson", f"duplicate member {k!r}")
        d[k] = v
    return d


def _walk_check_ints(v: Any) -> None:
    if isinstance(v, bool):
        return
    if isinstance(v, int):
        if abs(v) >= SAFE_INT_LIMIT:
            raise IJsonError("payload-not-ijson", "integer outside safe range")
    elif isinstance(v, float):
        # Unreachable while parse_json_value installs _safe_integer_literal as
        # its parse_float hook, which turns every number literal into an int or
        # refuses it. Kept so this walk's guarantee does not rest on a caller
        # remembering that hook, and so a value assembled some other way still
        # fails closed rather than reaching jcs_dumps as a float.
        raise IJsonError("payload-not-ijson", "non-integer number")
    elif isinstance(v, list):
        for x in v:
            _walk_check_ints(x)
    elif isinstance(v, dict):
        for x in v.values():
            _walk_check_ints(x)


# Untrusted-input resource bounds, pinned to match the Go rail (aee/jcs.go
# maxParseDepth / maxParseBytes) so the two independent rails accept and reject
# exactly the same payloads. The depth bound is a cross-rail parity requirement,
# not only a DoS defense: stdlib JSON parser depth defaults diverge across
# languages (Go 10000, CPython ~1000-10000 by platform, serde_json 128), so a
# shared explicit bound is what keeps the rails from splitting on deep input.
MAX_PARSE_DEPTH = 128
MAX_PARSE_BYTES = 20 << 20  # 20 MiB
# Whole-statement bound, matched with the Go rail (aee/types.go maxStatementBytes)
# so the two rails split on the same oversized input; a resource guard, not a
# conformance rule.
MAX_STATEMENT_BYTES = 64 << 20  # 64 MiB


def _max_json_depth(text: str) -> int:
    """Maximum bracket-nesting depth of a JSON text, ignoring string bodies."""
    depth = maxd = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > maxd:
                maxd = depth
        elif ch in "]}":
            depth -= 1
    return maxd


def strict_b64decode(s: str) -> bytes:
    """Decode standard base64, mirroring Go's base64.StdEncoding.Strict()
    (aee/validity.go:108, aee/tier.go:93): reject non-alphabet characters
    (validate=True) AND non-canonical encodings -- trailing bits in the final
    quantum ("QUJ=" decodes to "AB" only under a lenient decoder), non-standard
    padding -- that Python's b64decode would otherwise accept. A payload the Go
    rail rejects as record-undecodable must not decode on the Python rail, or
    the two rails disagree at the encoding layer. Raises binascii.Error /
    ValueError on any rejection, matching the callers' existing except clauses."""
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("non-canonical base64 (fails re-encode round-trip)")
    return raw


def parse_json_value(raw: bytes) -> Any:
    """Parse payload bytes into a faithful Python value under the I-JSON
    profile, or raise IJsonError with a registry code.

    The counterpart of the Go rail's parseJSONValue (aee/jcs.go): bounds, then
    the decode, then the checks the decode cannot express. Split from the
    canonical-form checks in strict_payload_parse for the same reason the Go
    rail splits parseJSONValue from analyzePayload, and the split is where the
    two codes divide.

    EVERY failure here is payload-not-ijson, matching the Go rail, whose
    analyzePayload maps every parseJSONValue error to CodePayloadNotIJSON on the
    reasoning that a payload which is not a parseable I-JSON value at all is the
    same covers-nothing class as one that parses and then violates the profile.
    payload-not-canonical is reserved for a payload that IS a valid I-JSON value
    whose bytes are not the RFC 8785 canonical form of it -- the caller's
    concern, not this function's. The condition registry splits the same way:
    aee-c-18 is "valid I-JSON (RFC 7493)" and aee-c-17 is "canonical RFC 8785",
    and asking whether bytes are in canonical form presupposes they denote a
    value.

    This rail used to answer payload-not-canonical for a payload that was
    oversized, over-deep, not UTF-8, or not syntactically JSON, which put four
    parse failures under the serialization-form code. No vector pinned any of
    them, so the divergence from Go was invisible to the suite.
    """
    if len(raw) > MAX_PARSE_BYTES:
        raise IJsonError("payload-not-ijson", "payload exceeds the maximum size")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise IJsonError("payload-not-ijson", "payload is not UTF-8") from None
    if _max_json_depth(text) > MAX_PARSE_DEPTH:
        raise IJsonError("payload-not-ijson", "payload nesting exceeds the maximum depth")
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_dup_pairs,
            parse_float=_safe_integer_literal,
        )
    except IJsonError:
        raise
    except (ValueError, RecursionError):
        raise IJsonError("payload-not-ijson", "payload does not parse as JSON") from None
    # String scalars are checked on the RAW bytes, after the parse above has
    # established that they are exactly one syntactically valid JSON value and
    # before any caller reads a decoded string. obj is already lossy wherever
    # this check fails.
    try:
        check_string_scalars(raw)
    except StringNotScalarError as e:
        raise IJsonError("payload-not-ijson", f"payload string is not scalar: {e}") from None
    return obj


def strict_payload_parse(raw: bytes) -> dict[str, Any]:
    """Parse record payload bytes and require RFC 8785 canonical form; raise
    IJsonError with a registry code."""
    obj = parse_json_value(raw)
    if not isinstance(obj, dict):
        raise IJsonError("payload-not-canonical", "payload is not a JSON object")
    if not _member_names_bmp(obj):
        # BMP-only string profile: a supplementary-plane member name makes the
        # covering payload cover nothing, the same handling as non-canonical
        # bytes (the payload can be byte-canonical under both member orders
        # when they happen to agree on its names; the name itself is rejected).
        raise IJsonError("payload-not-canonical", "supplementary-plane object member name")
    _walk_check_ints(obj)
    try:
        canon = jcs_dumps(obj)
    except JcsError:
        raise IJsonError("payload-not-ijson", "payload not canonicalizable") from None
    if canon != raw:
        raise IJsonError("payload-not-canonical", "payload bytes are not RFC 8785 canonical")
    return obj


# ---------------------------------------------------------------------------
# DSSE PAEv1 + RFC 6962 Merkle root (domain-separated, recursive split)
# ---------------------------------------------------------------------------


def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d " % (len(pt), pt, len(payload)) + payload


def merkle_root_hex(leaves: list[bytes]) -> str:
    def node(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 1:
            return hashlib.sha256(b"\x00" + leaves[lo]).digest()
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(b"\x01" + node(lo, lo + k) + node(lo + k, hi)).digest()

    if not leaves:
        raise ValueError("empty leaf set has no root")
    return node(0, len(leaves)).hex()


# ---------------------------------------------------------------------------
# Pure-Python Ed25519 (RFC 8032).  Slow but dependency-free and sufficient
# for a conformance suite; TEST keys only.
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


# Points are extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z.
_Point = tuple[int, int, int, int]
_IDENT: _Point = (0, 1, 1, 0)


def _pt_add(p: _Point, q: _Point) -> _Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _pt_mul(s: int, p: _Point) -> _Point:
    q = _IDENT
    while s > 0:
        if s & 1:
            q = _pt_add(q, p)
        p = _pt_add(p, p)
        s >>= 1
    return q


def _pt_eq(p: _Point, q: _Point) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


_BY = 4 * _inv(5) % _P


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _pt_compress(p: _Point) -> bytes:
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _pt_decompress(s: bytes) -> _Point | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def ed25519_public_key(seed: bytes) -> bytes:
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _pt_compress(_pt_mul(a, _B))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _pt_compress(_pt_mul(a, _B))
    r = int.from_bytes(_sha512(prefix, msg), "little") % _L
    rp = _pt_compress(_pt_mul(r, _B))
    k = int.from_bytes(_sha512(rp, pub, msg), "little") % _L
    s = (r + k * a) % _L
    return rp + s.to_bytes(32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    a = _pt_decompress(pub)
    if a is None:
        return False
    rp = _pt_decompress(sig[:32])
    if rp is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(sig[:32], pub, msg), "little") % _L
    return _pt_eq(_pt_mul(s, _B), _pt_add(rp, _pt_mul(k, a)))


def derive_test_keys() -> dict[str, dict[str, Any]]:
    """Re-derive the suite's TEST keys from the published recipe."""
    keys = {}
    for role in KEY_ROLES:
        seed = hashlib.sha256((f"in-toto-aee-test-key/{role}/v1").encode()).digest()
        pub = ed25519_public_key(seed)
        keys[role] = {
            "seed": seed,
            "public": pub,
            "keyid": sha256_hex(pub),
        }
    return keys


# ---------------------------------------------------------------------------
# Reference verifier (Rail R): GATE 0 -> GATE 1 -> recompute -> tier
# ---------------------------------------------------------------------------


def _statement_strict_fault(raw: bytes) -> bool:
    """Whole-statement strict pass (RFC 7493 I-JSON): report a fault the later
    decoded-value checks cannot see, anywhere in the statement JSON at any
    depth, not only inside record payloads. Mirrors the Go rail's
    ParseStatement promotion (aee/types.go).

    Two faults are unrecoverable one layer later, because every downstream
    check reads decoded Python strings:

      - a duplicate member, which json.loads keeps the last of, silently;
      - a string whose bytes are not Unicode scalar values, which json.loads
        turns into a lone surrogate or which the UTF-8 decode below rejects.

    The second is what makes GATE 0's observationVocabulary rules sound. They
    compare decoded strings and recompute the digest from them, so they cannot
    tell an unpaired "\\ud800" escape from a legitimate BMP scalar; without
    this gate that escape reached the BMP-only check and passed, and two
    distinct escapes arrived as one string and were reported as a duplicate the
    producer never wrote. Two of those checks cannot even run on a lone
    surrogate -- the UTF-16 sort key and the canonical re-serialization both
    raise UnicodeEncodeError -- so the fault surfaced as a traceback rather
    than a verdict.

    A bounds failure is promoted with them: an incomplete strict pass rules
    nothing out, so padding a statement past the parse bounds, or nesting one
    member deeper than the cap, must not skip the two checks above.

    Faults the payload parser already owns are NOT promoted here: the
    safe-integer profile is scoped to canonicalized content, and a statement
    that is not parseable JSON at all is reported by the caller's own parse.
    """
    if len(raw) > MAX_PARSE_BYTES:
        return True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return True
    if _max_json_depth(text) > MAX_PARSE_DEPTH:
        return True

    found = False

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal found
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            found = True
        return dict(pairs)

    try:
        json.loads(text, object_pairs_hook=hook)
    except (ValueError, RecursionError):
        # Bytes that are not a parseable JSON text at all are a malformed
        # statement, which is the same answer the Go rail and both consumer
        # rails give. This case is reachable on its own: a raw character below
        # U+0020 inside a string is well-formed UTF-8 that JSON forbids, so it
        # never gets as far as the string scan below, which needs syntactic
        # validity to know where the literals are.
        return True
    if found:
        return True
    try:
        check_string_scalars(raw)
    except StringNotScalarError:
        return True
    return False


class Outcome:
    def __init__(self) -> None:
        self.codes: list[str] = []
        self.result: str | None = None
        self.tiers_with_key: list[str] | None = None
        self.tiers_without_key: list[str] | None = None

    @property
    def verdict(self) -> str:
        return "invalid" if self.codes else "valid"

    def add(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)


def _is_hex64_lower(v: Any) -> bool:
    return isinstance(v, str) and bool(HEX64_RE.match(v))


def _digest_of(obj: Any) -> Any:
    if isinstance(obj, dict):
        d = obj.get("digest")
        if isinstance(d, dict):
            return d.get("sha256")
    return None


def _sorted_no_dupes(values: list[Any]) -> bool:
    """Ascending by UTF-16 code unit, with no duplicates.

    The same canonicality rule the observation vocabulary arrays carry, applied
    to the three arrays 0.7 adds. It reuses this file's UTF-16 sort key rather
    than Python's code-point comparison, because the two orders differ on
    supplementary-plane strings and a rail that sorted the wrong way would
    accept an array the specification calls malformed.
    """
    keys = [_utf16_sort_key(v) for v in values]
    return all(a < b for a, b in zip(keys, keys[1:], strict=False))


def _attack_id_array_ok(values: Any, declared: set[str]) -> TypeGuard[list[str]]:
    """The shared shape rule for aeeAssessedAttacks and aeeObservedAttacks.

    Duplicate-free, sorted ascending by UTF-16 code unit, every entry an attack
    identifier the carried manifest declares. The EMPTY array satisfies it: on
    the seal that is the honest value a substrate holding no probe-to-record
    correspondence carries, and it is required rather than omissible so the
    control is not escapable by omission.
    """
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        return False
    if not _sorted_no_dupes(values):
        return False
    return all(v in declared for v in values)


def _commitment_array_ok(values: Any) -> bool:
    """The shape rule for aeePayloadCommitment: duplicate-free, sorted ascending
    by UTF-16 code unit, non-empty, every entry lowercase 64-hex."""
    if not isinstance(values, list) or not values:
        return False
    if not all(_is_hex64_lower(v) for v in values):
        return False
    return _sorted_no_dupes(values)


def _expected_payloads_ok(expected: Any, declared: set[str]) -> bool:
    """The shape rule for corpus.manifest.expectedPayloads.

    Every key an attack identifier the same manifest's classes declares, every
    array non-empty, sorted ascending by UTF-16 code unit, duplicate-free, and
    every entry lowercase 64-hex. A manifest violating any of these is
    malformed, which is a GATE 0 fault and never a row-level one: nothing on a
    row can repair a manifest whose pre-image is already a run binding input.
    """
    if not isinstance(expected, dict):
        return False
    for attack, values in expected.items():
        if not isinstance(attack, str) or attack not in declared:
            return False
        if not _commitment_array_ok(values):
            return False
    return True


def observed_set_digest(views: list[RecordView]) -> str:
    """The value a seal's aeeObservedSet commits to.

    SHA-256 of the RFC 8785 canonicalization of the duplicate-free array, sorted
    ascending by UTF-16 code unit, of the lowercase 64-hex leaf hashes of every
    interception and examination record, where a leaf hash is
    H(0x00 || the record's DSSE PAE bytes) -- the same leaf construction
    batchRoot uses.

    A record whose payload does not decode, does not parse as strict I-JSON, or
    carries no readable aeeKind contributes nothing, because a verifier cannot
    classify the kind of a record it cannot read. The specification names that
    outcome where it defines the member: such a statement is invalid on the
    recompute without the verifier ever learning why.
    """
    leaves = sorted(
        {
            hashlib.sha256(b"\x00" + rv.pae).hexdigest()
            for rv in views
            if rv.pae is not None and rv.kind in ("interception", "examination")
        }
    )
    return sha256_hex(jcs_dumps(leaves))


# The run-binding construction this rail implements. A record declaring any
# other version covers nothing: the spec forbids attempting more than one
# construction, so there is no version-1 path left in this file to fall back to.
BINDING_VERSION = "2"

# The closed registry of substrate-authoritative egress postures. An absent,
# non-string or unregistered value makes the statement malformed, fail-closed.
EGRESS_POSTURES = frozenset({"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"})


def posture_preimage_digest(env: dict[str, Any]) -> str:
    """The version-2 networkPosture input: the canonical digest of the CARRIED
    object, never of its own `digest` member.

    Binding the member's digest, which is what version 1 did, leaves the
    `posture` string beside it unsigned, and the posture configuration that
    digest is taken over travels nowhere in the statement, so nothing could ever
    have compared the string against it. Hashing the object puts the string, its
    pinned digest and every further member a producer carries there inside the
    comparison every record already runs.

    A non-object, absent or otherwise, contributes the empty string, exactly as
    an absent digest member does elsewhere in this file: those statements are
    already malformed on their own codes, and inventing a second failure here
    would only mask the first. The same reasoning covers a canonicalizer error:
    a lone surrogate or an unsafe integer inside the object is caught by the
    I-JSON profile at GATE 0, so this returns the empty string and lets that
    code be the one the reader sees.
    """
    raw = env.get("networkPosture")
    if not isinstance(raw, dict):
        return ""
    try:
        return sha256_hex(jcs_dumps(raw))
    except (JcsError, TypeError, ValueError):
        return ""


def binding_preimage(env: dict[str, Any], subject_sha: Any) -> dict[str, Any] | None:
    """The eight-member version-2 pre-image object, or None when a member the
    construction reads verbatim is absent.

    The ``networkPosture`` MEMBER below does not carry the environment member's
    own digest. It carries ``posture_preimage_digest``, the RFC 8785 canonical
    digest of the whole carried object, which is a different 64-hex value from
    the one ``aeePostureDigest`` holds. The member name is the specification's
    (the pre-image member list in the wire profile's run binding section) and
    cannot move without naming a new binding version, as the same section says;
    the function name beside it is ours and says which digest this is.
    """
    try:
        return {
            "aeeBindingVersion": BINDING_VERSION,
            "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
            "corpus": env["corpus"]["digest"]["sha256"],
            "networkPosture": posture_preimage_digest(env),
            "observationVocabulary": env["observationVocabulary"]["digest"]["sha256"],
            "runEntropy": env["runEntropy"]["digest"]["sha256"],
            "subject": subject_sha,
            "substrate": env["substrate"]["digest"]["sha256"],
        }
    except (KeyError, IndexError, TypeError):
        return None


def _timestamp_ok(v: Any) -> bool:
    """Whether a value is carried under the predicate's Timestamp field type.

    The type requires RFC 3339 in the UTC timezone; the predicate pins the two
    choices that type leaves open
    (spec:req-fields-precedent-informative-reserved-members-inside@535994a66179a0d9), and the two
    are checked separately
    because they are separate rules. The pattern carries the case half: an
    uppercase separator and zone designator, never the lowercase `t` and `z`
    RFC 3339 also admits. The pattern accepts any numeric offset, so the zone
    half is the test below, and it reads the parsed offset rather than the
    literal suffix: a suffix test spelled `endswith("Z", "+00:00", "-00:00")`
    admits exactly the same strings and would also reject a lowercase `z`, so
    it would quietly stand in for the case rule and leave that rule untested.

    Both timestamps the predicate carries run through this one function. The
    zone rule used to be written on armedAt alone and applied at that call site
    alone, so issuedAt admitted `+05:00` while the same instant was refused a
    few fields away, and the case rule was written on neither field, so this
    rail accepted a lowercase designator four sibling rails rejected.
    """
    if not isinstance(v, str) or not RFC3339_RE.match(v):
        return False
    key = _rfc3339_key(v)
    return key is not None and key.utcoffset() == timedelta(0)


def _rfc3339_key(v: str) -> datetime | None:
    """Comparable key for a carried Timestamp."""
    s = v.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


METHOD_ORDER = {"reconstructed": 0, "intercepted": 1}

# The result vocabulary, in the order the recompute takes its minimum over.
RESULT_ORDER = {"fail": 0, "degraded": 1, "pass_indirect": 2, "pass": 3}


class RecordView:
    """A decoded observation record: PAE bytes always; payload object only
    when it passes the strict parse."""

    def __init__(self, idx: int, rec: Any):
        self.idx = idx
        self.raw = rec
        self.payload_type = rec.get("payloadType") if isinstance(rec, dict) else None
        self.payload_bytes: bytes | None = None
        self.pae: bytes | None = None
        self.payload: dict[str, Any] | None = None
        self.payload_error: str | None = None
        self.decode_err: bool = False
        if isinstance(rec, dict) and isinstance(rec.get("payload"), str):
            try:
                self.payload_bytes = strict_b64decode(rec["payload"])
            except (binascii.Error, ValueError):
                self.payload_bytes = None
                self.decode_err = True
        if self.payload_bytes is not None and isinstance(self.payload_type, str):
            self.pae = pae(self.payload_type, self.payload_bytes)
        if self.payload_bytes is not None:
            try:
                self.payload = strict_payload_parse(self.payload_bytes)
            except IJsonError as e:
                self.payload_error = e.code
        media_ok = isinstance(self.payload_type, str) and self.payload_type.endswith("+json")
        self.media_ok = media_ok
        # How many DSSE signature entries the record carries, and nothing about
        # whether any of them verifies. A record is a DSSE envelope and the spec
        # requires its signatures member to carry at least one entry, so an
        # absent member and an empty array are the same fault: zero entries.
        # Counting needs no key material, which is why the count lives here with
        # the byte-pure facts and the verification lives at the tier.
        sigs = rec.get("signatures") if isinstance(rec, dict) else None
        self.signature_count = len(sigs) if isinstance(sigs, list) else 0

    @property
    def kind(self) -> Any:
        return self.payload.get("aeeKind") if self.payload else None

    @property
    def method(self) -> Any:
        return self.payload.get("aeeMethod") if self.payload else None


@dataclass
class _VerifyState:
    """Mutable holder for the locals shared across ``verify``'s ordered checks.

    Each ``_check_*`` method reads and writes these fields and appends codes to
    the ``Outcome``; the field types mirror the loosely-typed originals.
    """

    stmt: Any
    pred: Any = None
    result: Any = None
    issued_at: Any = None
    env: dict[str, Any] = field(default_factory=dict)
    vocab: dict[str, Any] | None = None
    labels: list[Any] | None = None
    caught: list[Any] | None = None
    corpus: Any = None
    manifest_classes: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = field(default_factory=list)
    has_substrate: bool = False
    coverage: Any = None
    fail_closed_rows: set[int] = field(default_factory=set)
    has_records: bool = False
    views: list[RecordView] = field(default_factory=list)
    derived_binding: str | None = None
    pinned_posture: Any = None
    row_covering: dict[int, list[RecordView]] = field(default_factory=dict)
    # The attack identifiers the carried corpus.manifest.classes declares, and
    # the optional per-attack expectation map beside them. Two record kinds
    # carry arrays of the first from 0.7, and the attribution rule reads the
    # second, so both are derived once where the corpus is read.
    declared_attacks: set[str] = field(default_factory=set)
    expected_payloads: Any = None


class ReferenceVerifier:
    def __init__(self, pinned_pubs: list[bytes]):
        self.pinned_pubs = pinned_pubs

    # -- record cover validity -------------------------------------------

    def _arming_ok(
        self,
        rv: RecordView,
        pinned_posture: Any,
        issued_at: Any,
        declared_attacks: set[str],
    ) -> bool:
        p = rv.payload or {}
        armed = p.get("armedAt")
        if not _timestamp_ok(armed):
            return False
        if _timestamp_ok(issued_at):
            # armed/issued_at each passed _timestamp_ok above, so both are
            # strings here; an absent/None timestamp yields a None key and is
            # skipped for ordering exactly as a malformed one is (never crash,
            # never silently accept -- absence was already rejected above).
            a = _rfc3339_key(armed) if isinstance(armed, str) else None
            b = _rfc3339_key(issued_at) if isinstance(issued_at, str) else None
            if a is not None and b is not None and a > b:
                return False
        if p.get("aeePostureDigest") != pinned_posture:
            return False
        if p.get("aeeMethod") != "intercepted":
            return False
        # Read-first binding-version declaration: an explicit aeeBindingVersion
        # the verifier does not implement makes the arming record cover nothing,
        # distinguishably from a run-binding digest mismatch. Absent defaults to
        # the implemented version; the derivation is unchanged.
        #
        # The constant was the literal "1" here for as long as version 2 has been
        # the implemented construction, so this rail refused an arming record
        # declaring the version it actually derives while every other rail
        # accepted it. No vector carries the member, which is why a five-rail
        # divergence sat in the reference implementation unseen.
        bv = p.get("aeeBindingVersion")
        if bv is not None and bv != BINDING_VERSION:
            return False
        if not self._arming_chain_ok(p):
            return False
        # aeeAssessedAttacks is required on the kind from 0.7. The SUBSET
        # comparison against the carried coverage is a statement rule and lives
        # in _check_commitments; what the kind requires is that the array is
        # there and well formed.
        return _attack_id_array_ok(p.get("aeeAssessedAttacks"), declared_attacks)

    _CHAIN_SCOPE_VOCAB = frozenset({"subject", "corpus", "networkPosture"})

    @staticmethod
    def _arming_chain_ok(p: dict[str, Any]) -> bool:
        """Syntax of the optional run-chaining members an arming payload MAY
        carry (aeeRunSeq / aeePrevRunBinding / aeeChainScope): aeeRunSeq is a
        positive safe-range integer; aeeChainScope is a duplicate-free array of
        tokens from the closed vocabulary {subject, corpus, networkPosture},
        sorted in observationVocabulary.labels canonical order (UTF-16
        code-unit; for the ASCII vocabulary this is plain codepoint order),
        required whenever aeeRunSeq is present; aeePrevRunBinding is a lowercase
        64-hex string, present exactly when aeeRunSeq is greater than 1. A
        chain member present without aeeRunSeq is rejected fail-closed.
        Syntax-checked here in the reserved-member walk; nothing else
        normative reads the members."""
        has_seq = "aeeRunSeq" in p
        has_prev = "aeePrevRunBinding" in p
        has_scope = "aeeChainScope" in p
        if not has_seq:
            return not has_prev and not has_scope
        seq = p.get("aeeRunSeq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            return False
        scope = p.get("aeeChainScope")
        if not isinstance(scope, list):
            return False
        if any(tok not in ReferenceVerifier._CHAIN_SCOPE_VOCAB for tok in scope):
            return False
        # Canonical order is UTF-16 code-unit, the single sort predicate every rail
        # uses (and the same _utf16_sort_key the vocabulary array check applies). For
        # the current ASCII vocabulary this coincides with code-point order, but
        # sorting by the shared key keeps this rule correct if a non-BMP token is
        # ever registered rather than silently diverging from the other rails.
        if sorted(scope, key=_utf16_sort_key) != scope or len(set(scope)) != len(scope):
            return False
        if seq == 1:
            return not has_prev
        prev = p.get("aeePrevRunBinding")
        return isinstance(prev, str) and bool(HEX64_RE.match(prev))

    def _sealed_ok(
        self,
        rv: RecordView,
        pinned_posture: Any,
        arming_postures: list[str],
        declared_attacks: set[str],
    ) -> bool:
        p = rv.payload or {}
        if p.get("aeeStillArmed") is not True:
            return False
        drops = p.get("aeeDropCount")
        if not isinstance(drops, int) or isinstance(drops, bool) or drops < 0:
            return False
        if drops > 0:
            bound = p.get("aeeDropBound")
            if not isinstance(bound, int) or isinstance(bound, bool):
                return False
            if drops > bound:
                return False
        posture = p.get("aeePostureDigest")
        if posture != pinned_posture:
            return False
        # The two sealed posture equalities are JOINTLY enforced. The spec lines
        # are cited once, from the Go rail that implements the same rule
        # (aee/validity.go evaluateKind, sealed branch); this comment points there
        # rather than repeating the citation. The ledger that made repeating one
        # costly keyed citations positionally as file::symbol#N, so a seventh token
        # in this file renumbered every later one; the anchor form carries its own
        # digest inline and has no positional key, so that cost is gone and this
        # comment stays only because pointing at the rail is the clearer place.
        # the seal's posture must equal the pinned networkPosture digest AND every
        # referenced arming record's posture claim. This rail enforced only the
        # first for as long as the rule has existed, while the Go, TypeScript,
        # standalone-Python and server rails all enforced both -- a four-against-one
        # divergence in the REFERENCE implementation, and invisible because no
        # vector forced the rule. `v7f35f318b31ca92a` forces it now:
        # it carries a second arming record whose posture differs, which is the only
        # shape that reaches this equality, because with one arming record the
        # pinned-posture check above always fires first.
        for arming_posture in arming_postures:
            if posture != arming_posture:
                return False
        if p.get("aeeMethod") != "intercepted":
            return False
        return self._sealed_commitments_ok(p, declared_attacks)

    @staticmethod
    def _sealed_commitments_ok(p: dict[str, Any], declared_attacks: set[str]) -> bool:
        """The two members 0.7 requires of the sealed kind.

        The equality of aeeObservedSet against the recompute and the caught-row
        obligation of aeeObservedAttacks are STATEMENT rules and live in
        _check_commitments; what the kind requires is only that both are there
        in the shapes it names. The EMPTY attack array satisfies it, which is
        deliberate: a substrate holding no probe-to-record correspondence
        declares that on the wire rather than by omission.
        """
        if not _is_hex64_lower(p.get("aeeObservedSet")):
            return False
        return _attack_id_array_ok(p.get("aeeObservedAttacks"), declared_attacks)

    def _examination_ok(self, rv: RecordView) -> bool:
        return (rv.payload or {}).get("aeeMethod") == "reconstructed"

    def _record_verifies(self, rv: RecordView) -> bool:
        if rv.pae is None or not isinstance(rv.raw, dict):
            return False
        sigs = rv.raw.get("signatures")
        if not isinstance(sigs, list):
            return False
        for sig in sigs:
            if not isinstance(sig, dict) or not isinstance(sig.get("sig"), str):
                continue
            try:
                sig_bytes = strict_b64decode(sig["sig"])
            except (binascii.Error, ValueError):
                continue
            for pub in self.pinned_pubs:
                if ed25519_verify(pub, rv.pae, sig_bytes):
                    return True
        return False

    # -- main entry -------------------------------------------------------

    def verify(self, stmt: Any, raw: bytes | None = None) -> Outcome:
        out = Outcome()
        # Statement-wide strict I-JSON: a duplicate member, or a string whose
        # bytes are not Unicode scalar values, anywhere in the statement JSON
        # is a malformed statement. Both are checked from the raw bytes, because
        # the pre-parsed dict has already collapsed repeats and substituted for
        # the ill-formed strings. raw is None for internally-built clean dicts.
        if raw is not None and _statement_strict_fault(raw):
            out.add("statement-malformed")
            return out
        st = _VerifyState(stmt=stmt)
        if self._check_statement_type(st, out):
            return out
        self._check_gate0_wellformed(st, out)
        self._check_vocabulary(st, out)
        self._check_corpus(st, out)
        self._check_rows_setup(st, out)
        self._check_subject_cardinality(st, out)
        self._check_coverage(st, out)
        self._check_per_row_statements(st, out)
        self._check_substrate_binding_inputs(st, out)
        self._check_fail_closed_rows(st, out)
        self._check_records(st, out)
        self._check_run_binding(st, out)
        self._check_gate1_coverage(st, out)
        self._check_commitments(st, out)
        self._check_result_recompute(st, out)
        if out.codes:
            return out  # invalid: no result, no tiers (behavior assertion 2)
        self._check_gate2_tiers(st, out)
        return out

    def _check_statement_type(self, st: _VerifyState, out: Outcome) -> bool:
        stmt = st.stmt
        if not isinstance(stmt, dict):
            out.add("statement-type-unsupported")
            return True

        if stmt.get("_type") != STATEMENT_TYPE:
            out.add("statement-type-unsupported")
        if stmt.get("predicateType") != AEE_PREDICATE_TYPE:
            out.add("predicate-type-unsupported")

        # The three empty predicate states are ONE input (spec/v1/statement.md):
        # an absent member, "predicate": null and "predicate": {} decode to the
        # empty predicate object. json.loads hands this rail None for the first
        # two indistinguishably -- which is itself the argument for the rule --
        # and both used to exit here with predicate-type-unsupported, a code
        # about the TYPE URI, while "{}" went on to earn the five codes the
        # empty predicate actually fails on. So the spelling decided the reason,
        # and two of the three spellings were told their predicate type was
        # unsupported when the type was the one member they carried correctly.
        pred = stmt.get("predicate")
        if pred is None:
            pred = {}
        if not isinstance(pred, dict):
            # Present and neither an object nor null: a different fault, and it
            # keeps its own code. The equivalence class is the three empty
            # states, not every ill-typed value.
            out.add("predicate-type-unsupported")
            return True
        st.pred = pred
        return False

    # ---- GATE 0: statement well-formedness ------------------------------

    def _check_gate0_wellformed(self, st: _VerifyState, out: Outcome) -> None:
        pred = st.pred
        if "does_not_assert" in pred:
            out.add("member-spelling")

        result = pred.get("result")
        if result not in RESULT_ORDER:
            out.add("result-vocabulary")
        st.result = result

        issued_at = pred.get("issuedAt")
        if issued_at is None:
            out.add("issued-at-missing")
        elif not _timestamp_ok(issued_at):
            out.add("issued-at-malformed")
        st.issued_at = issued_at

        env = pred.get("observationEnvironment")
        env = env if isinstance(env, dict) else {}
        for member in ("substrate", "corpus", "catchPolicy", "networkPosture"):
            if member not in env:
                out.add("environment-incomplete")
        st.env = env
        vocab = env.get("observationVocabulary")
        if not isinstance(vocab, dict):
            out.add("vocabulary-missing")
            vocab = None
        st.vocab = vocab
        # The posture registry is closed and its violation is a malformed
        # statement, not a fail-closed row: nothing on a row carries it. The
        # check runs only when the member is present, so an absent
        # networkPosture keeps reporting environment-incomplete alone rather
        # than gaining a second code for the same absence. Membership is tested
        # against a frozenset, which raises on an unhashable value, so the
        # posture is normalized to a hashable stand-in first: a posture holding
        # a list is not a registered value and must report that rather than
        # taking the rail down.
        posture = env.get("networkPosture")
        if isinstance(posture, dict):
            declared = posture.get("posture")
            if not isinstance(declared, str) or declared not in EGRESS_POSTURES:
                out.add("posture-vocabulary")

    def _check_vocabulary(self, st: _VerifyState, out: Outcome) -> None:
        vocab = st.vocab
        labels: list[Any] | None = None
        caught: list[Any] | None = None
        if vocab is not None:
            labels = vocab.get("labels")
            caught = vocab.get("caught")
            if not self._vocab_shape_ok(labels, caught):
                out.add("vocabulary-not-canonical")
            self._vocab_check_pairs(out, vocab, labels, caught)
            if not isinstance(labels, list) or not isinstance(caught, list):
                labels, caught = None, None
        st.labels = labels
        st.caught = caught

    @staticmethod
    def _vocab_shape_ok(labels: Any, caught: Any) -> bool:
        for arr in (labels, caught):
            if not isinstance(arr, list) or not all(isinstance(x, str) for x in arr):
                return False
            # Sortedness is by UTF-16 code unit (RFC 8785 section 3.2.3), the
            # same comparator member-name canonicalization uses, and every
            # entry must be BMP-only: a supplementary-plane vocabulary entry
            # makes the statement malformed, the same handling as
            # non-canonical bytes.
            if sorted(arr, key=_utf16_sort_key) != arr or len(set(arr)) != len(arr):
                return False
            if not _all_bmp(arr):
                return False
        return True

    def _vocab_check_pairs(self, out: Outcome, vocab: Any, labels: Any, caught: Any) -> None:
        if not (isinstance(labels, list) and isinstance(caught, list)):
            return
        if not set(caught) <= set(labels):
            out.add("vocabulary-caught-not-subset")
        expect = sha256_hex(jcs_dumps({"caught": caught, "labels": labels}))
        if _digest_of(vocab) != expect:
            out.add("vocabulary-digest-mismatch")

    def _check_corpus(self, st: _VerifyState, out: Outcome) -> None:  # noqa: C901 -- one guarded branch per independent manifest member; see docs/complexity-rationales.toml
        env = st.env
        corpus = env.get("corpus")
        st.corpus = corpus
        manifest_classes: dict[str, Any] | None = None
        if isinstance(corpus, dict):
            manifest = corpus.get("manifest")
            classes = manifest.get("classes") if isinstance(manifest, dict) else None
            if manifest is None:
                # An ABSENT manifest is environment-incomplete, matching the Go
                # rail's explicit branch (aee/statement.go:249-251,
                # `len(c.ManifestRaw) == 0`). This rail previously fell straight
                # through and emitted nothing, so dropping corpus.manifest
                # produced verdict "valid" here and "invalid" on Go -- the second
                # reference-rail divergence found by the same forcing pass that
                # found the sealed-posture one, and invisible for the same reason:
                # no vector forced it. `v03547f8918e0d7dc` does now.
                out.add("environment-incomplete")
            if isinstance(manifest, dict):
                self._corpus_digest(out, corpus, manifest)
                self._corpus_declares_attack(out, classes)
            if isinstance(classes, dict):
                manifest_classes = classes
                self._corpus_dupes(out, classes)
                st.declared_attacks = {
                    aid
                    for ids in classes.values()
                    if isinstance(ids, list)
                    for aid in ids
                    if isinstance(aid, str)
                }
            if isinstance(manifest, dict) and "expectedPayloads" in manifest:
                expected = manifest["expectedPayloads"]
                if _expected_payloads_ok(expected, st.declared_attacks):
                    st.expected_payloads = expected
                else:
                    out.add("manifest-expected-payloads-malformed")
        st.manifest_classes = manifest_classes

    @staticmethod
    def _corpus_digest(out: Outcome, corpus: Any, manifest: Any) -> None:
        try:
            expect = sha256_hex(jcs_dumps(manifest))
            if _digest_of(corpus) != expect:
                out.add("corpus-digest-mismatch")
        except JcsError:
            out.add("corpus-digest-mismatch")

    @staticmethod
    def _corpus_declares_attack(out: Outcome, classes: Any) -> None:
        """The manifest MUST declare at least one attack identifier across all
        of its classes
        (spec:req-fields-coverage-bound-assessedclasses-array-class@be2e39f3e7439e24).

        A corpus with no adversarial inputs is not an adversarial corpus, so
        this sits with well-formedness and not with scoring: scoring it would
        concede that a zero-attack run is a legitimate statement that merely
        scores badly.

        What it closes is a total bypass of the substrate rather than a lie
        about a run. Zero declared attack identifiers means zero rows; zero
        rows means zero `basis: substrate` rows; and with no substrate row the
        predicate permits runEntropy, observationRecords and batchRoot all to
        be absent. Every structure that would have required a substrate
        signature drops out, and coverage integrity then compares an empty
        union of row attack ids against an empty union of manifest attack ids
        and passes vacuously, so the statement reaches a valid verdict and a
        pass result with no substrate behind it at all.

        The count is over attack identifiers and not over classes: a manifest
        carrying a real class name with an empty id array
        (``{"classes": {"XA": []}}``) declares no attacks just as an empty
        classes object does, and reads far more plausibly. A manifest that
        DOES declare an identifier is untouched here, which is what leaves the
        honest fully-skipped run -- every class disclosed under
        coverage.outOfScope, no rows, result degraded -- valid.
        """
        declared = 0
        if isinstance(classes, dict):
            for ids in classes.values():
                declared += len(ids) if isinstance(ids, list) else 0
        if declared == 0:
            out.add("corpus-manifest-no-attacks")

    @staticmethod
    def _corpus_dupes(out: Outcome, classes: dict[Any, Any]) -> None:
        seen: set[str] = set()
        for ids in classes.values():
            for aid in ids if isinstance(ids, list) else []:
                if aid in seen:
                    out.add("manifest-duplicate-attack")
                seen.add(aid)

    def _check_rows_setup(self, st: _VerifyState, out: Outcome) -> None:
        # attackResults is a required member
        # (spec:req-fields-row-per-executed-attack-attackid-2@8177bcb6a7441371)
        # and its ABSENCE is a malformed statement, which the Go rail has always
        # reported and this
        # one silently coerced to an empty row list. No vector exercised an
        # absent attackResults, so the two rails disagreed on the one member
        # whose absence a reader is most likely to hit -- it is what an empty
        # predicate is missing -- with every gate green. Presence with the wrong
        # JSON type is a different fault and keeps its own code, which is the
        # arm the Go rail also leaves to the member's own type check.
        if "attackResults" not in st.pred:
            out.add("statement-malformed")
        rows = st.pred.get("attackResults")
        rows = rows if isinstance(rows, list) else []
        rows = [r for r in rows if isinstance(r, dict)]
        st.rows = rows
        st.has_substrate = any(r.get("basis") == "substrate" for r in rows)

    # coverage integrity at attack granularity

    def _check_coverage(self, st: _VerifyState, out: Outcome) -> None:
        coverage = st.pred.get("coverage")
        st.coverage = coverage
        manifest_classes = st.manifest_classes
        if not isinstance(coverage, dict):
            out.add("coverage-missing")
            return
        if manifest_classes is None:
            return
        assessed = coverage.get("assessedClasses")
        assessed = assessed if isinstance(assessed, list) else []
        oos = coverage.get("outOfScope")
        oos = oos if isinstance(oos, dict) else {}
        routed = coverage.get("routedElsewhere")
        routed = routed if isinstance(routed, dict) else {}
        if not self._coverage_partition_ok(manifest_classes, assessed, oos, routed):
            out.add("coverage-incomplete")
        self._coverage_check_rows(st, out, manifest_classes, assessed)

    @staticmethod
    def _coverage_partition_ok(
        manifest_classes: dict[str, Any],
        assessed: list[Any],
        oos: dict[str, Any],
        routed: dict[str, Any],
    ) -> bool:
        # Coverage MUST be an exhaustive, disjoint partition of the
        # manifest's classes across assessedClasses/outOfScope/
        # routedElsewhere, each a real manifest class
        # (spec:req-fields-networkposture-posture-vocabulary-closed-four-2@591aef9c088d9164):
        # without this a whole class is silently dropped from all three
        # sets (or a fabricated class pads assessedClasses).
        acct: dict[str, int] = {}
        for _c in assessed:
            acct[_c] = acct.get(_c, 0) + 1
        for _c in oos:
            acct[_c] = acct.get(_c, 0) + 1
        for _c in routed:
            acct[_c] = acct.get(_c, 0) + 1
        return all(n == 1 and c in manifest_classes for c, n in acct.items()) and all(
            acct.get(c, 0) == 1 for c in manifest_classes
        )

    @staticmethod
    def _coverage_index(
        manifest_classes: dict[str, Any], assessed: list[Any]
    ) -> tuple[dict[Any, Any], set[Any]]:
        attack_class: dict[Any, Any] = {}
        for cls, ids in manifest_classes.items():
            for aid in ids if isinstance(ids, list) else []:
                attack_class.setdefault(aid, cls)
        expected_ids: set[Any] = set()
        for cls in assessed:
            _mc = manifest_classes.get(cls)
            for aid in _mc if isinstance(_mc, list) else []:
                expected_ids.add(aid)
        return attack_class, expected_ids

    def _coverage_check_rows(
        self,
        st: _VerifyState,
        out: Outcome,
        manifest_classes: dict[str, Any],
        assessed: list[Any],
    ) -> None:
        attack_class, expected_ids = self._coverage_index(manifest_classes, assessed)
        # No two rows may carry the same attackId
        # (spec:req-fields-typing-discipline-predicate-commits-stated@22ef77d9eb2d99d7): one row per
        # executed attack is a well-formedness invariant. Detected BEFORE the
        # row_ids set is built, because the set-equality check below silently
        # collapses duplicates.
        row_ids = set()
        for r in st.rows:
            aid = r.get("attackId")
            if aid in row_ids:
                out.add("statement-malformed")
            row_ids.add(aid)
            if aid not in attack_class:
                out.add("row-attack-unknown")
            elif attack_class[aid] not in assessed:
                out.add("coverage-incomplete")
        if expected_ids - {i for i in row_ids if i in attack_class}:
            out.add("coverage-incomplete")

    # per-row statement checks

    def _check_per_row_statements(self, st: _VerifyState, out: Outcome) -> None:
        rows = st.rows
        labels = st.labels
        caught = st.caught
        for r in rows:
            # Row members are strictly typed: a member present with a
            # non-string JSON value is a malformed statement (a different
            # altitude than an ABSENT basis/method, which is a fail-closed
            # row, or an absent actualLayer, which has its own code).
            for member in ("attackId", "containmentObserved", "basis", "method", "actualLayer"):
                if member in r and not isinstance(r[member], str):
                    out.add("statement-malformed")
        for r in rows:
            if "actualLayer" not in r:
                out.add("malformed-missing-actual-layer")
        if labels is not None and caught is not None:
            for r in rows:
                lab = r.get("containmentObserved")
                if (
                    lab in labels
                    and lab not in caught
                    and "actualLayer" in r
                    and r.get("actualLayer") != "none"
                ):
                    out.add("clean-row-layer-not-none")

    # substrate-carrying statements: binding inputs

    def _check_subject_cardinality(self, st: _VerifyState, out: Outcome) -> None:
        # subject MUST contain exactly one entry on a statement of ANY basis
        # (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530). The six
        # binding-digest-input requirement stays
        # substrate-scoped (_check_substrate_binding_inputs).
        subject = st.stmt.get("subject")
        subject = subject if isinstance(subject, list) else []
        if len(subject) != 1:
            out.add("subject-cardinality")

    def _check_substrate_binding_inputs(self, st: _VerifyState, out: Outcome) -> None:
        if not st.has_substrate:
            return
        stmt = st.stmt
        env = st.env
        subject = stmt.get("subject")
        subject = subject if isinstance(subject, list) else []
        subj_digest = _digest_of(subject[0]) if subject else None
        if subject and subj_digest is None:
            out.add("subject-sha256-missing")
        if "runEntropy" not in env:
            out.add("run-entropy-missing")
        self._binding_digest_canonical(out, env, subj_digest)

    @staticmethod
    def _binding_digest_canonical(out: Outcome, env: dict[str, Any], subj_digest: Any) -> None:
        for val in (
            subj_digest,
            _digest_of(env.get("substrate")),
            _digest_of(env.get("corpus")),
            _digest_of(env.get("catchPolicy")),
            _digest_of(env.get("networkPosture")),
            _digest_of(env.get("runEntropy")),
        ):
            if val is not None and not _is_hex64_lower(val):
                out.add("digest-not-canonical")

    # fail-closed substrate rows are invalid (cannot satisfy class-match)

    def _check_fail_closed_rows(self, st: _VerifyState, out: Outcome) -> None:
        rows = st.rows
        labels = st.labels
        fail_closed_rows: set[int] = set()
        for i, r in enumerate(rows):
            lab_bad = labels is not None and r.get("containmentObserved") not in labels
            basis_bad = r.get("basis") not in ("substrate", "artifact")
            method_bad = r.get("method") not in ("intercepted", "reconstructed")
            # attribution joined basis and method at 0.7, and joins them HERE
            # rather than in a rule of its own, because the specification states
            # the three closed row vocabularies as one rule with one consequence.
            attribution_bad = r.get("attribution") not in ("pinned", "paired")
            if lab_bad or basis_bad or method_bad or attribution_bad:
                fail_closed_rows.add(i)
                if r.get("basis") == "substrate":
                    out.add("fail-closed-substrate-row")
        st.fail_closed_rows = fail_closed_rows

    # ---- statement-level record checks ----------------------------------

    def _check_records(self, st: _VerifyState, out: Outcome) -> None:
        pred = st.pred
        records = pred.get("observationRecords")
        has_records = isinstance(records, list) and len(records) > 0
        views: list[RecordView] = []
        if isinstance(records, list) and records:
            views = [RecordView(i, rec) for i, rec in enumerate(records)]
            # Envelope shape before payload bytes, mirroring Go
            # validity.go:137-143: every record's signatures member MUST carry
            # at least one entry
            # (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5), and an
            # absent member is the
            # same zero as an empty array. The check is a count and proves
            # nothing about the entries it counts -- fabricated signature bytes
            # satisfy it and are caught only by verification at the tier -- but
            # the zero case is otherwise invisible here, because signatures sit
            # outside the PAE pre-image and so outside batchRoot: stripping them
            # all leaves the root, the validity verdict and the result
            # unchanged, and only the derived tier drops. A consumer gating on
            # result alone therefore admitted an entirely unsigned attestation.
            if any(v.signature_count == 0 for v in views):
                out.add("record-signatures-empty")
            if any(v.decode_err for v in views):
                # Mirror Go checkRecordsStatementLevel: a record whose payload is not
                # strict base64 is record-undecodable, and the BATCH ROOT check
                # is then skipped on both rails. That record contributes no
                # leaf, so a root recomputed without it would be a root over a
                # leaf set no producer committed to, and reporting
                # batch-root-mismatch for it would name a fault the statement
                # does not have.
                #
                # The DUPLICATE scan is not skipped, and it used to be. Both
                # rails guarded it with the batch root, so one record failing
                # base64 suppressed both; the code sets are compared by
                # intersection, so a statement carrying a duplicate beside an
                # undecodable record reported the decode failure and dropped
                # duplicate-record entirely, on every rail at once. The records
                # that decoded still carry whatever duplicate they carried, and
                # v7622b2c58c2e272d is the statement that
                # asks.
                out.add("record-undecodable")
            else:
                self._records_batch_root(out, pred, views)
            self._records_duplicates(out, views)
        elif pred.get("batchRoot") is not None:
            out.add("batch-root-orphaned")
        st.has_records = has_records
        st.views = views

    @staticmethod
    def _records_batch_root(out: Outcome, pred: Any, views: list[RecordView]) -> None:
        root = pred.get("batchRoot")
        if root is None:
            out.add("batch-root-missing")
        elif all(v.pae is not None for v in views):
            if merkle_root_hex([v.pae for v in views if v.pae is not None]) != root:
                out.add("batch-root-mismatch")
        else:
            out.add("batch-root-mismatch")

    @staticmethod
    def _records_duplicates(out: Outcome, views: list[RecordView]) -> None:
        seen_leaves: set[bytes] = set()
        for v in views:
            if v.decode_err:
                # Skipped rather than keyed on the raw record. Two records that
                # do not decode contribute the same absent leaf, so calling them
                # duplicates of each other would be a finding about this loop
                # rather than about the statement. Go skips them for the same
                # reason, in checkRecordsStatementLevel; keying them on raw bytes
                # here instead would make the two rails disagree about a
                # statement neither could repair.
                continue
            key = v.pae if v.pae is not None else jcs_dumps_safe(v.raw)
            if key in seen_leaves:
                out.add("duplicate-record")
            seen_leaves.add(key)

    # ---- run binding derivation -----------------------------------------

    def _check_run_binding(self, st: _VerifyState, out: Outcome) -> None:
        derived_binding = None
        if st.has_substrate:
            stmt = st.stmt
            env = st.env
            try:
                subject0 = stmt["subject"][0]
                vals = binding_preimage(env, subject0["digest"]["sha256"])
                if vals is not None and all(isinstance(v, str) for v in vals.values()):
                    derived_binding = sha256_hex(jcs_dumps(vals))
            except (KeyError, IndexError, TypeError):
                derived_binding = None  # member codes already emitted
        st.derived_binding = derived_binding

    # ---- GATE 1: per-substrate-row coverage validity --------------------

    def _check_gate1_coverage(self, st: _VerifyState, out: Outcome) -> None:
        pinned_posture = _digest_of(st.env.get("networkPosture"))
        st.pinned_posture = pinned_posture
        # An out-of-range observationRefs index is a structural integrity fault
        # on ANY row, regardless of basis and including rows nothing normative
        # reads (fail-closed, independent of any gate). Reserved for statements
        # where records exist; with no records the records-absent precedence
        # owns the reject. Negative indexes stay the substrate ref-malformed
        # path's concern.
        if st.has_records:
            self._check_refs_in_range(st, out)
        row_covering: dict[int, list[RecordView]] = {}
        for i, r in enumerate(st.rows):
            self._gate1_row(st, out, i, r, pinned_posture, row_covering)
        st.row_covering = row_covering

    def _check_refs_in_range(self, st: _VerifyState, out: Outcome) -> None:
        n = len(st.views)
        for r in st.rows:
            refs = r.get("observationRefs")
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if isinstance(ref, bool) or not isinstance(ref, int):
                    continue  # non-integer refs are the ref-malformed path's concern
                if ref >= n:
                    out.add("ref-out-of-range")
                    return

    def _gate1_row(
        self,
        st: _VerifyState,
        out: Outcome,
        i: int,
        r: dict[str, Any],
        pinned_posture: Any,
        row_covering: dict[int, list[RecordView]],
    ) -> None:
        if r.get("basis") != "substrate" or i in st.fail_closed_rows:
            return
        if not st.has_records:
            out.add("records-absent")
            return
        refs = r.get("observationRefs")
        if not isinstance(refs, list) or len(refs) == 0:
            out.add("refs-empty")
            # an uncovered caught row is the immediate consequence
            lab = r.get("containmentObserved")
            if st.caught is not None and lab in st.caught:
                out.add("caught-row-uncovered")
            return
        ref_views = self._gate1_resolve_refs(st, out, refs)
        if ref_views is None:
            return

        # payload validity of every referenced record
        self._gate1_check_payloads(st, out, ref_views)

        # class-match + kind constraints
        covering = self._gate1_class_match(st, out, r, ref_views, pinned_posture)
        row_covering[i] = covering

        # method cap: weakest signed aeeMethod across covering records
        self._gate1_method_cap(out, r, covering)

    def _gate1_resolve_refs(
        self, st: _VerifyState, out: Outcome, refs: list[Any]
    ) -> list[RecordView] | None:
        views = st.views
        ref_views: list[RecordView] = []
        refs_ok = True
        for ref in refs:
            if isinstance(ref, bool) or not isinstance(ref, int) or ref < 0:
                out.add("ref-malformed")
                refs_ok = False
            elif ref >= len(views):
                out.add("ref-out-of-range")
                refs_ok = False
            else:
                ref_views.append(views[ref])
        if not refs_ok and not ref_views:
            return None
        return ref_views

    def _gate1_check_payloads(
        self, st: _VerifyState, out: Outcome, ref_views: list[RecordView]
    ) -> None:
        derived_binding = st.derived_binding
        for rv in ref_views:
            self._gate1_check_payload(out, rv, derived_binding)

    @staticmethod
    def _gate1_check_payload(out: Outcome, rv: RecordView, derived_binding: str | None) -> None:
        if not rv.media_ok:
            out.add("payload-media-type")
        if rv.payload_error is not None:
            out.add(rv.payload_error)
            return
        if rv.payload is None:
            out.add("payload-not-canonical")
            return
        missing = [m for m in ("aeeRunBinding", "aeeKind", "aeeMethod") if m not in rv.payload]
        if missing:
            out.add("payload-missing-reserved")
        if (
            derived_binding is not None
            and "aeeRunBinding" in rv.payload
            and rv.payload["aeeRunBinding"] != derived_binding
        ):
            out.add("run-binding-mismatch")

    # Kinds that cover nothing whatever their payload carries. The two the
    # document registers as non-covering report under their own names, because
    # a citation of a kind that covers nothing by registration and a citation
    # of a kind this rail has never heard of are different producer errors with
    # different fixes, and telling the first to upgrade its verifier does not
    # help it.
    _REGISTERED_NONCOVERING = {
        "moat-drop": "moat-drop-covers-nothing",
        "uncommitted-observation": "uncommitted-observation-covers-nothing",
    }
    _COVERING_KINDS = ("interception", "arming", "sealed", "examination")

    @classmethod
    def _covers_nothing(cls, usable: list[RecordView]) -> str | None:
        """The code for the first resolved record whose KIND covers nothing.

        Reference order rather than a ranking between the registered kinds and
        the unrecognized one: the document states no precedence, neither can be
        made to cover, and the value is a diagnostic rather than a verdict.
        """
        for rv in usable:
            registered = cls._REGISTERED_NONCOVERING.get(rv.kind or "")
            if registered is not None:
                return registered
            if rv.kind not in cls._COVERING_KINDS:
                return "record-kind-unknown-covers-nothing"
        return None

    @staticmethod
    def _uncovered_code(covers_nothing: str | None, specific: str) -> str:
        return covers_nothing if covers_nothing is not None else specific

    def _gate1_class_match(
        self,
        st: _VerifyState,
        out: Outcome,
        r: dict[str, Any],
        ref_views: list[RecordView],
        pinned_posture: Any,
    ) -> list[RecordView]:
        usable = [rv for rv in ref_views if rv.payload is not None and rv.media_ok]
        covers_nothing = self._covers_nothing(usable)

        lab = r.get("containmentObserved")
        method = r.get("method")
        if method == "reconstructed":
            return self._gate1_cover_reconstructed(out, usable, covers_nothing)
        if st.caught is not None and lab in st.caught:
            return self._gate1_cover_caught(out, usable, covers_nothing)
        return self._gate1_cover_clean(st, out, usable, covers_nothing, pinned_posture)

    def _gate1_cover_reconstructed(
        self, out: Outcome, usable: list[RecordView], covers_nothing: str | None
    ) -> list[RecordView]:
        exams = [rv for rv in usable if rv.kind == "examination"]
        good = [rv for rv in exams if self._examination_ok(rv)]
        if not exams:
            out.add(self._uncovered_code(covers_nothing, "reconstructed-row-uncovered"))
        elif not good:
            out.add("examination-covers-nothing")
        return good

    def _gate1_cover_caught(
        self, out: Outcome, usable: list[RecordView], covers_nothing: str | None
    ) -> list[RecordView]:
        inters = [rv for rv in usable if rv.kind == "interception"]
        if not inters:
            out.add(self._uncovered_code(covers_nothing, "caught-row-uncovered"))
            return inters
        # aeePayloadCommitment is required on the kind from 0.7. ABSENT takes
        # the missing-reserved code every other absent reserved member takes;
        # PRESENT-but-malformed takes its own, because a producer told its
        # record is missing a value the record plainly carries has been told
        # the wrong thing about its own record.
        good = []
        for rv in inters:
            values = (rv.payload or {}).get("aeePayloadCommitment")
            if values is None:
                out.add("payload-missing-reserved")
            elif not _commitment_array_ok(values):
                out.add("payload-commitment-malformed")
            else:
                good.append(rv)
        return good

    def _gate1_cover_clean(
        self,
        st: _VerifyState,
        out: Outcome,
        usable: list[RecordView],
        covers_nothing: str | None,
        pinned_posture: Any,
    ) -> list[RecordView]:
        good_arm = self._gate1_clean_arm(st, out, usable, covers_nothing, pinned_posture)
        good_seal = self._gate1_clean_seal(st, out, usable, covers_nothing, pinned_posture)
        return good_arm + good_seal

    def _gate1_clean_arm(
        self,
        st: _VerifyState,
        out: Outcome,
        usable: list[RecordView],
        covers_nothing: str | None,
        pinned_posture: Any,
    ) -> list[RecordView]:
        issued_at = st.issued_at
        armings = [rv for rv in usable if rv.kind == "arming"]
        good_arm = [
            rv
            for rv in armings
            if self._arming_ok(rv, pinned_posture, issued_at, st.declared_attacks)
        ]
        if not armings:
            out.add(self._uncovered_code(covers_nothing, "clean-row-uncovered"))
        elif not good_arm:
            out.add("arming-covers-nothing")
        return good_arm

    def _gate1_clean_seal(
        self,
        st: _VerifyState,
        out: Outcome,
        usable: list[RecordView],
        covers_nothing: str | None,
        pinned_posture: Any,
    ) -> list[RecordView]:
        sealeds = [rv for rv in usable if rv.kind == "sealed"]
        # Collected from EVERY referenced arming record, not only the ones that
        # pass _arming_ok, matching the Go rail (aee/validity.go:518-527). A
        # malformed arming record still makes a posture claim, and a seal that
        # contradicts it is contradicting something the producer asserted.
        arming_postures = [
            posture
            for rv in usable
            if rv.kind == "arming"
            for posture in [(rv.payload or {}).get("aeePostureDigest")]
            if isinstance(posture, str)
        ]
        good_seal = [
            rv
            for rv in sealeds
            if self._sealed_ok(rv, pinned_posture, arming_postures, st.declared_attacks)
        ]
        if not sealeds:
            out.add(self._uncovered_code(covers_nothing, "clean-row-uncovered"))
        elif not good_seal:
            out.add("sealed-covers-nothing")
        return good_seal

    def _gate1_method_cap(
        self, out: Outcome, r: dict[str, Any], covering: list[RecordView]
    ) -> None:
        if not covering:
            return
        method = r.get("method")
        # the comprehension only admits records whose method is a key
        # of METHOD_ORDER, so index directly -- min never sees a None.
        methods = [METHOD_ORDER[rv.method] for rv in covering if rv.method in METHOD_ORDER]
        if methods and method in METHOD_ORDER:
            if METHOD_ORDER[method] > min(methods):
                out.add("method-cap-exceeded")

    # ---- result recompute (pure function of carried rows) ---------------

    # ---- the coverage validity requirements 0.7 adds --------------------
    #
    # They sit apart from the per-row gate above for the reason the
    # specification states in the sentence that introduces them: they hold on
    # the STATEMENT, or on every row rather than only on a basis: substrate
    # row. The per-row gate returns early on any row that is not substrate, so
    # a rule written there would silently acquire that scope.
    #
    # They run LAST, after the per-row gate, because they describe a
    # consequence rather than a cause: a row whose refs are emptied leaves the
    # record it used to resolve orphaned, and the code a reader wants first is
    # the one naming what the producer did.

    def _check_commitments(self, st: _VerifyState, out: Outcome) -> None:
        self._commit_clean_row_contradicted(st, out)
        self._commit_interception_orphaned(st, out)
        self._commit_attribution(st, out)
        if not st.has_substrate or not st.has_records:
            return
        self._commit_observed_set(st, out)
        self._commit_sealed_present(st, out)
        self._commit_carried_cover(st, out)
        self._commit_seal_attacks(st, out)
        self._commit_assessed_subset(st, out)

    @staticmethod
    def _resolved_views(st: _VerifyState, r: dict[str, Any]) -> list[RecordView]:
        """The in-range records one row resolves. A malformed refs member
        resolves nothing here: ref-malformed owns that fault."""
        refs = r.get("observationRefs")
        if not isinstance(refs, list):
            return []
        return [
            st.views[ref]
            for ref in refs
            if not isinstance(ref, bool)
            and isinstance(ref, int)
            and 0 <= ref < len(st.views)
        ]

    def _commit_clean_row_contradicted(self, st: _VerifyState, out: Outcome) -> None:
        """A clean row resolves no observationRefs index to an interception
        record. Stated over EVERY row, so the loop reads no basis: the
        contradiction does not depend on the vantage the row declares."""
        if st.labels is None or st.caught is None:
            return
        for r in st.rows:
            lab = r.get("containmentObserved")
            if lab not in st.labels or lab in st.caught:
                continue
            if any(rv.kind == "interception" for rv in self._resolved_views(st, r)):
                out.add("clean-row-contradicted")
                return

    def _commit_interception_orphaned(self, st: _VerifyState, out: Outcome) -> None:
        """Every carried interception record is resolved by at least one
        observationRefs index on a CAUGHT row. One record MAY be resolved by
        several rows, so the test is existence and never a count."""
        if st.caught is None or not st.has_records:
            return
        resolved: set[int] = set()
        for r in st.rows:
            if r.get("containmentObserved") not in st.caught:
                continue
            resolved.update(rv.idx for rv in self._resolved_views(st, r))
        for rv in st.views:
            if rv.kind == "interception" and rv.idx not in resolved:
                out.add("interception-record-orphaned")
                return

    def _commit_observed_set(self, st: _VerifyState, out: Outcome) -> None:
        """aeeObservedSet on every carried sealed record equals the recompute.

        A seal whose member is absent or is not lowercase 64-hex is NOT
        reported here: that record covers nothing by its own kind's
        constraints, which is a different fault with a different code, and
        reporting both would give one mutation two codes.
        """
        want: str | None = None
        for rv in st.views:
            if rv.kind != "sealed" or not isinstance(rv.payload, dict):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            got = rv.payload.get("aeeObservedSet")
            if not _is_hex64_lower(got):
                continue
            if want is None:
                want = observed_set_digest(st.views)
            if got != want:
                out.add("observed-set-mismatch")
                return

    def _commit_sealed_present(self, st: _VerifyState, out: Outcome) -> None:
        """A statement carrying at least one basis: substrate row carries at
        least one sealed record satisfying every constraint of its kind and
        binding to this run, whether or not a row resolves an index to it.

        Unconditional at 0.7: a rule conditioned on the presence of the record
        it constrains is a rule a producer switches off by omission, and the
        statements it was switched off on were exactly the statements a record
        deletion works against.
        """
        arming_postures = [
            posture
            for rv in st.views
            if rv.kind == "arming"
            for posture in [(rv.payload or {}).get("aeePostureDigest")]
            if isinstance(posture, str)
        ]
        for rv in st.views:
            if rv.kind != "sealed" or not isinstance(rv.payload, dict) or not rv.media_ok:
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            if self._sealed_ok(rv, st.pinned_posture, arming_postures, st.declared_attacks):
                return
        out.add("sealed-record-absent")

    # The reserved members a record must carry before any rule can read it.
    # Named here rather than inline because the statement-level rule below and
    # the per-row payload check share the list, and two copies of it would be
    # free to disagree about which members are reserved.
    _RESERVED_MEMBERS = ("aeeRunBinding", "aeeKind", "aeeMethod")

    def _commit_carried_cover(self, st: _VerifyState, out: Outcome) -> None:
        """Every carried record that binds to this run and whose aeeKind names
        a covering kind satisfies every constraint of that kind, whether or not
        any row resolves an index to it.

        The universal partner of _commit_sealed_present above, over the same
        records on the same terms. That one asks whether a valid sealed record
        is PRESENT and stops at the first one it finds; this asks whether an
        invalid record of any covering kind is carried beside it.

        Both readings were producer-selected before this. A substrate signs a
        sealed record with aeeStillArmed false, the producer carries it, points
        the row at a second seal, and the statement reads valid / pass with the
        record that says otherwise sitting in observationRecords and committed
        inside batchRoot. The same gap held arming open through a second arming
        record, examination through an unreferenced one, and interception
        through a caught row whose basis the per-row gate returns early on.

        The candidate set is the one _commit_sealed_present admits: a record
        that decodes and parses, carries the reserved members, has a +json
        media type, and binds to this run. Records outside it are making no
        claim about this run or are not readable at all, and reaching that
        state needs a substrate-signed payload EDITED, which breaks the
        record's signature and is refused at the tier.
        """
        for rv in st.views:
            if not isinstance(rv.payload, dict) or not rv.media_ok:
                continue
            if any(m not in rv.payload for m in self._RESERVED_MEMBERS):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            if rv.kind not in self._COVERING_KINDS:
                continue
            code = self._carried_record_fault(rv, st)
            if code is not None:
                out.add(code)

    def _carried_record_fault(self, rv: RecordView, st: _VerifyState) -> str | None:
        """The kind's own failure code for a carried record that does not
        satisfy its kind, or None when it does.

        Never a new code. A reader who resolves a defective record from a row
        and a reader who finds it carried beside the rows have found the same
        fault in the same record, and a second spelling would oblige a third
        party to implement two names for one condition.

        arming_postures is empty for the same reason _commit_sealed_present
        passes nothing: the seal-against-arming posture equality is stated over
        the arming records a ROW resolves, and a statement-level rule has no
        row. The pinned-posture half is checked here as it is there.
        """
        if rv.kind == "sealed":
            ok = self._sealed_ok(rv, st.pinned_posture, [], st.declared_attacks)
            return None if ok else "sealed-covers-nothing"
        if rv.kind == "arming":
            ok = self._arming_ok(rv, st.pinned_posture, st.issued_at, st.declared_attacks)
            return None if ok else "arming-covers-nothing"
        if rv.kind == "examination":
            return None if self._examination_ok(rv) else "examination-covers-nothing"
        # interception. ABSENT aeePayloadCommitment takes the missing-reserved
        # code every other absent reserved member takes; PRESENT-but-malformed
        # takes its own, exactly as the per-row path splits them.
        payload = rv.payload or {}
        if "aeePayloadCommitment" in payload and not _commitment_array_ok(
            payload["aeePayloadCommitment"]
        ):
            return "payload-commitment-malformed"
        if rv.method not in METHOD_ORDER or "aeePayloadCommitment" not in payload:
            return "payload-missing-reserved"
        return None

    def _commit_seal_attacks(self, st: _VerifyState, out: Outcome) -> None:
        """For every identifier the seal names in aeeObservedAttacks the
        statement carries a row with that attackId whose containmentObserved is
        in the carried caught set.

        The rule reads in ONE direction. A seal naming an attack obliges a
        caught row; a seal omitting one licenses nothing, and in particular
        does not oblige a clean row. That is what makes a lower bound sound
        without asking the substrate to resolve every ambiguous case.
        """
        if st.caught is None:
            return
        caught_ids = {
            r.get("attackId")
            for r in st.rows
            if r.get("containmentObserved") in st.caught
        }
        for rv in st.views:
            if rv.kind != "sealed" or not isinstance(rv.payload, dict):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            attacks = rv.payload.get("aeeObservedAttacks")
            if not _attack_id_array_ok(attacks, st.declared_attacks):
                continue
            if any(a not in caught_ids for a in attacks):
                out.add("observed-attack-uncaught")
                return

    def _commit_assessed_subset(self, st: _VerifyState, out: Outcome) -> None:
        """The union of the manifest identifiers for the carried
        coverage.assessedClasses is a SUBSET of the arming record's
        aeeAssessedAttacks.

        A subset and not an equality. An equality would refuse the honest run
        that declared two classes, lost one part-way and disclosed the loss,
        and would buy, against the withdrawal it appears to catch, only the
        version of that withdrawal that leaves the arming record in place.
        """
        cov = st.coverage if isinstance(st.coverage, dict) else {}
        assessed_classes = cov.get("assessedClasses")
        if not isinstance(assessed_classes, list) or not isinstance(
            st.manifest_classes, dict
        ):
            return
        assessed: set[str] = set()
        for cls in assessed_classes:
            ids = st.manifest_classes.get(cls)
            if isinstance(ids, list):
                assessed.update(a for a in ids if isinstance(a, str))
        for rv in st.views:
            if rv.kind != "arming" or not isinstance(rv.payload, dict):
                continue
            if rv.payload.get("aeeRunBinding") != st.derived_binding:
                continue
            declared = rv.payload.get("aeeAssessedAttacks")
            if not _attack_id_array_ok(declared, st.declared_attacks):
                continue
            if not assessed <= set(declared):
                out.add("assessed-set-exceeds-declaration")
                return

    def _commit_attribution(self, st: _VerifyState, out: Outcome) -> None:
        """A row declaring attribution: pinned carries the binding it claims,
        in the three parts the specification writes it in.

        The EXISTENCE part is checked first because it is the part the other
        two are vacuous without: a universally quantified rule over an empty
        set is true, so a producer that deletes the interception records keeps
        the stronger label unless something asks whether any remain.
        """
        expected_map = st.expected_payloads if isinstance(st.expected_payloads, dict) else {}
        for r in st.rows:
            if r.get("attribution") != "pinned":
                continue
            resolved = self._resolved_views(st, r)
            inters = [rv for rv in resolved if rv.kind == "interception"]
            if not inters:
                out.add("attribution-pinned-recordless")
                return
            expected = expected_map.get(r.get("attackId"))
            if not isinstance(expected, list) or not expected:
                out.add("attribution-unpinnable")
                return
            for rv in inters:
                values = (rv.payload or {}).get("aeePayloadCommitment")
                if not isinstance(values, list):
                    # Absent or wrong-typed: the record covers nothing by its
                    # own kind's constraints, and that is the fault reported.
                    continue
                if not any(v in expected for v in values):
                    out.add("attribution-pin-unmatched")
                    return

    def _check_result_recompute(self, st: _VerifyState, out: Outcome) -> None:
        """The recompute is TOTAL and runs on every parseable predicate.

        The specification defines `result` as "a total, deterministic,
        severity-independent function of the predicate" (spec:req-fields-fail-degraded-pass-indirect-pass@1496facaec24f2da). Total
        is the operative word: the function is defined on every predicate in
        its domain, so it answers rather than declines, and a member the
        predicate does not carry contributes the fail-closed reading of its
        own axis. An absent or unreadable `observationVocabulary` therefore
        yields EMPTY carried label and caught sets, which places every row's
        label outside the carried labels and contributes `fail`; an absent or
        empty `attackResults` yields zero rows, over which no condition holds.

        This rail used to guard on
        ``labels is not None and caught is not None and rows`` and emit
        nothing at all when the guard failed, while the Go rail built the empty
        sets and proceeded (`aee/recompute.go`, `Recompute`). The two answered
        differently over identical bytes, and the divergence was a VERDICT and
        not merely a code: a statement carrying `attackResults: []`, a coverage
        map that accounts for every manifested attack, and a declared `result`
        the recompute does not produce was INVALID on the Go rail
        (`result-recompute-mismatch`) and VALID here -- this rail handing a
        consumer a result token the predicate's own definition never derives.
        No vector carried that shape, so no run could see it.
        """
        recomputed = self._recompute(
            st.rows,
            st.labels if st.labels is not None else [],
            st.caught if st.caught is not None else [],
            st.coverage,
        )
        # An unknown result token can never equal the recompute, which only
        # ever returns a member of the ordered vocabulary.
        if st.result not in RESULT_ORDER or recomputed != st.result:
            out.add("result-recompute-mismatch")

    # ---- GATE 2: evidence tier per key policy ---------------------------

    def _check_gate2_tiers(self, st: _VerifyState, out: Outcome) -> None:
        out.result = st.result
        out.tiers_with_key = self._tiers(st.rows, st.row_covering, with_keys=True)
        out.tiers_without_key = self._tiers(st.rows, st.row_covering, with_keys=False)

    @staticmethod
    def _recompute(
        rows: list[dict[str, Any]],
        labels: list[Any],
        caught: list[Any],
        coverage: Any,
    ) -> str:
        """The minimum, under fail < degraded < pass_indirect < pass, of three
        independent conditions over the carried bytes and nothing else.

        INDIRECT, the third, reads the DECLARED basis and method of every clean
        row and never the evidence tier: the tier is key-relative, so a result
        that read it would not be recomputable. An unattested substrate clean
        row therefore still reaches pass here, by design.
        """
        forces_fail = False
        indirect = False
        for r in rows:
            lab = r.get("containmentObserved")
            if lab not in labels or lab in caught:
                forces_fail = True
            elif r.get("basis") not in ("substrate", "artifact"):
                forces_fail = True
            elif r.get("method") not in ("intercepted", "reconstructed"):
                forces_fail = True
            elif r.get("attribution") not in ("pinned", "paired"):
                # attribution enters the recompute through this arm and NOWHERE
                # else. A row declaring paired is not a weaker RESULT, it is a
                # weaker binding between the row and the records that cover it.
                forces_fail = True
            elif r.get("basis") != "substrate" or r.get("method") != "intercepted":
                indirect = True
        cov = coverage if isinstance(coverage, dict) else {}
        candidates = [
            "fail" if forces_fail else "pass",
            "degraded" if (cov.get("outOfScope") or cov.get("routedElsewhere")) else "pass",
            "pass_indirect" if indirect else "pass",
        ]
        return min(candidates, key=RESULT_ORDER.__getitem__)

    def _tiers(
        self,
        rows: list[dict[str, Any]],
        row_covering: dict[int, list[RecordView]],
        with_keys: bool,
    ) -> list[str]:
        tiers = []
        for i, r in enumerate(rows):
            if r.get("basis") == "artifact":
                tiers.append("declared")
                continue
            if not with_keys or not self.pinned_pubs:
                tiers.append("unattested")
                continue
            covering = row_covering.get(i, [])
            if covering and all(self._record_verifies(rv) for rv in covering):
                tiers.append("attested")
            else:
                tiers.append("unattested")
        return tiers


def jcs_dumps_safe(obj: Any) -> bytes:
    try:
        return jcs_dumps(obj)
    except JcsError:
        return repr(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# Second-fault-absence self-checks (single-fault discipline, machine-checked)
# ---------------------------------------------------------------------------

# Single source of truth: each failure code declares its report gate stage
# and the second-fault families it belongs to (a code may belong to more than
# one, e.g. environment-incomplete). CODE_STAGE and the _*_FAULT_CODES sets are
# DERIVED below so a new code is declared in exactly one place.
_CODE_REGISTRY: dict[str, tuple[str, tuple[str, ...]]] = {
    "statement-malformed": ("gate0", ()),
    "statement-type-unsupported": ("gate0", ()),
    "predicate-type-unsupported": ("gate0", ()),
    "member-spelling": ("gate0", ()),
    "result-vocabulary": ("gate0", ()),
    "issued-at-missing": ("gate0", ()),
    "issued-at-malformed": ("gate0", ()),
    "environment-incomplete": ("gate0", ("corpus", "binding")),
    # A binding-family fault: the posture object is a binding input under
    # version 2, so a statement carrying an unregistered posture has had that
    # object rewritten and its records rebound, which is the second-fault
    # assertion this family exempts.
    "posture-vocabulary": ("gate0", ("binding",)),
    "vocabulary-missing": ("gate0", ("vocab",)),
    "vocabulary-not-canonical": ("gate0", ("vocab",)),
    "vocabulary-caught-not-subset": ("gate0", ("vocab",)),
    "vocabulary-digest-mismatch": ("gate0", ("vocab",)),
    "corpus-digest-mismatch": ("gate0", ("corpus",)),
    "manifest-duplicate-attack": ("gate0", ("corpus",)),
    # Not a corpus-family fault: a manifest that declares no attack identifier
    # still digests to whatever the statement carries, so the corpus-digest
    # second-fault assertion must keep running against these vectors and prove
    # the emptied manifest was re-digested rather than left stale.
    "corpus-manifest-no-attacks": ("gate0", ()),
    "coverage-missing": ("gate0", ()),
    "coverage-incomplete": ("gate0", ()),
    "row-attack-unknown": ("gate0", ()),
    "malformed-missing-actual-layer": ("gate0", ()),
    "clean-row-layer-not-none": ("gate0", ()),
    "subject-cardinality": ("gate0", ("binding",)),
    "subject-sha256-missing": ("gate0", ("binding",)),
    "run-entropy-missing": ("gate0", ("binding",)),
    "digest-not-canonical": ("gate0", ("binding",)),
    "fail-closed-substrate-row": ("gate0", ()),
    # Not a root-family fault: signatures are outside the PAE pre-image, so a
    # record with none still recomputes the same leaf and the same batchRoot,
    # and the second-fault check must keep asserting that the root recomputes.
    "record-signatures-empty": ("gate0", ()),
    "record-undecodable": ("gate0", ("root",)),
    "batch-root-missing": ("gate0", ("root", "binding")),
    "batch-root-mismatch": ("gate0", ("root",)),
    "batch-root-orphaned": ("gate0", ("root",)),
    "duplicate-record": ("gate0", ("root",)),
    "records-absent": ("gate1", ("root", "binding")),
    "refs-empty": ("gate1", ("root", "binding")),
    "ref-malformed": ("gate1", ("root", "binding")),
    "ref-out-of-range": ("gate1", ("root", "binding")),
    "payload-not-canonical": ("gate1", ("binding",)),
    "payload-not-ijson": ("gate1", ("binding",)),
    "payload-media-type": ("gate1", ("binding",)),
    "payload-missing-reserved": ("gate1", ("binding",)),
    "run-binding-mismatch": ("gate1", ("binding",)),
    "method-cap-exceeded": ("gate1", ()),
    "caught-row-uncovered": ("gate1", ()),
    "reconstructed-row-uncovered": ("gate1", ()),
    "clean-row-uncovered": ("gate1", ()),
    "arming-covers-nothing": ("gate1", ()),
    "sealed-covers-nothing": ("gate1", ()),
    "examination-covers-nothing": ("gate1", ()),
    "record-kind-unknown-covers-nothing": ("gate1", ()),
    "moat-drop-covers-nothing": ("gate1", ()),
    "uncommitted-observation-covers-nothing": ("gate1", ()),
    "result-recompute-mismatch": ("recompute", ()),
}

CODE_STAGE = {code: stage for code, (stage, _fams) in _CODE_REGISTRY.items()}


def _fault_family(name: str) -> set[str]:
    return {c for c, (_s, fams) in _CODE_REGISTRY.items() if name in fams}


_ROOT_FAULT_CODES = _fault_family("root")
_VOCAB_FAULT_CODES = _fault_family("vocab")
_CORPUS_FAULT_CODES = _fault_family("corpus")
_BINDING_FAULT_CODES = _fault_family("binding")


def second_fault_absence(stmt: Any, expected_codes: set[str]) -> list[str]:
    """Return a list of second-fault findings (empty = clean)."""
    findings: list[str] = []
    if not isinstance(stmt, dict):
        return findings
    pred = stmt.get("predicate")
    if not isinstance(pred, dict):
        return findings
    env = pred.get("observationEnvironment")
    env = env if isinstance(env, dict) else {}
    _sfa_batch_root(pred, expected_codes, findings)
    _sfa_vocabulary(env, expected_codes, findings)
    _sfa_corpus(env, expected_codes, findings)
    _sfa_binding(stmt, pred, env, expected_codes, findings)
    return findings


def _sfa_batch_root(pred: dict[str, Any], expected_codes: set[str], findings: list[str]) -> None:
    # (i) batch root recomputes unless a root-family fault is expected
    records = pred.get("observationRecords")
    root = pred.get("batchRoot")
    if (
        not (expected_codes & _ROOT_FAULT_CODES)
        and isinstance(records, list)
        and records
        and isinstance(root, str)
    ):
        _sfa_root_recompute(records, root, findings)


def _sfa_root_recompute(records: list[Any], root: str, findings: list[str]) -> None:
    views = [RecordView(i, rec) for i, rec in enumerate(records)]
    if all(v.pae is not None for v in views):
        if merkle_root_hex([v.pae for v in views if v.pae is not None]) != root:
            findings.append("second-fault: batchRoot does not recompute")
    else:
        findings.append("second-fault: undecodable record payload")


def _sfa_vocabulary(env: dict[str, Any], expected_codes: set[str], findings: list[str]) -> None:
    # (ii) vocabulary digest verifies unless a vocabulary fault is expected
    vocab = env.get("observationVocabulary")
    if not (expected_codes & _VOCAB_FAULT_CODES) and isinstance(vocab, dict):
        labels, caught = vocab.get("labels"), vocab.get("caught")
        if isinstance(labels, list) and isinstance(caught, list):
            try:
                expect = sha256_hex(jcs_dumps({"caught": caught, "labels": labels}))
                if _digest_of(vocab) != expect:
                    findings.append("second-fault: vocabulary digest mismatch")
            except JcsError:
                findings.append("second-fault: vocabulary not canonicalizable")
            except UnicodeEncodeError:
                # A byte-level vector: a label carries bytes that are not a
                # well-formed sequence of Unicode scalar values, so there is no
                # canonical pre-image to recompute a digest over. The statement
                # is malformed before any vocabulary rule applies, which is the
                # single fault under test, so the second-fault check does not
                # apply rather than failing. This is the harness's own instance
                # of the bug the vectors exist to catch: code that recomputes a
                # digest from decoded strings cannot run on bytes that never
                # decoded.
                pass


def _sfa_corpus(env: dict[str, Any], expected_codes: set[str], findings: list[str]) -> None:
    # (iii) corpus digest verifies unless a corpus fault is expected
    corpus = env.get("corpus")
    if not (expected_codes & _CORPUS_FAULT_CODES) and isinstance(corpus, dict):
        manifest = corpus.get("manifest")
        if isinstance(manifest, dict):
            try:
                if _digest_of(corpus) != sha256_hex(jcs_dumps(manifest)):
                    findings.append("second-fault: corpus digest mismatch")
            except JcsError:
                findings.append("second-fault: corpus manifest not canonicalizable")


def _sfa_binding(
    stmt: dict[str, Any],
    pred: dict[str, Any],
    env: dict[str, Any],
    expected_codes: set[str],
    findings: list[str],
) -> None:
    # (iv) referenced record bindings equal the derived binding unless a
    # binding-family fault is expected
    if expected_codes & _BINDING_FAULT_CODES:
        return
    rows = pred.get("attackResults")
    rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    if not any(r.get("basis") == "substrate" for r in rows):
        return
    records = pred.get("observationRecords")
    derived = _sfa_derived_binding(stmt, env)
    if derived is not None and isinstance(records, list):
        views = [RecordView(i, rec) for i, rec in enumerate(records)]
        _sfa_binding_scan(rows, views, derived, findings)


def _sfa_derived_binding(stmt: dict[str, Any], env: dict[str, Any]) -> str | None:
    try:
        vals = binding_preimage(env, stmt["subject"][0]["digest"]["sha256"])
        if vals is None:
            return None
        return sha256_hex(jcs_dumps(vals))
    except (KeyError, IndexError, TypeError, JcsError):
        return None


def _sfa_binding_scan(
    rows: list[dict[str, Any]],
    views: list[RecordView],
    derived: str,
    findings: list[str],
) -> None:
    for r in rows:
        for ref in r.get("observationRefs") or []:
            if isinstance(ref, int) and not isinstance(ref, bool) and 0 <= ref < len(views):
                p = views[ref].payload
                if p is not None and p.get("aeeRunBinding") != derived:
                    findings.append("second-fault: record binding != derived binding")
                    break


# ---------------------------------------------------------------------------
# External rail
# ---------------------------------------------------------------------------


class VerifierNotRun(Exception):
    """A verifier was named and this harness cannot run it.

    There is deliberately no fallback from this. The harness used to probe the
    named executable for the predicate type URI and, when the probe failed, run
    the corpus on its own reference rail and print that rail's totals under the
    caller's request. A verifier that rejected everything, a file without the
    execute bit, a path that did not exist and every command found through PATH
    all produced a full pass and exit 0, and the composite action
    turned that into a green job for a verifier that never started. Whether the
    named command speaks this predicate is for the corpus to find out by running
    it, never for the harness to guess from its bytes.
    """


def resolve_verifier(setting: str) -> list[str]:
    """The argv prefix that runs the named verifier, or ``VerifierNotRun``.

    The setting is a COMMAND LINE, not a path: it is split with shlex and the
    first token is the executable, resolved the way a shell would -- through
    PATH when it carries no directory separator, relative to the working
    directory when it does. A ``.py`` first token that is a readable file is run
    with this interpreter, so it needs no execute bit.
    """
    try:
        parts = shlex.split(setting)
    except ValueError as e:
        raise VerifierNotRun(f"the command line {setting!r} does not parse: {e}") from None
    if not parts:
        raise VerifierNotRun("the verifier setting is empty")
    exe = parts[0]
    if exe.endswith(".py") and os.path.isfile(exe):
        return [sys.executable, *parts]
    if os.sep in exe or (os.altsep is not None and os.altsep in exe):
        if not os.path.isfile(exe):
            raise VerifierNotRun(f"{exe!r} is not a file")
        if not os.access(exe, os.X_OK):
            raise VerifierNotRun(f"{exe!r} is not executable")
        return parts
    if shutil.which(exe) is None:
        raise VerifierNotRun(f"{exe!r} was not found on PATH")
    return parts


EXTERNAL_KEYS_ENV = "AEE_SUBSTRATE_KEYS"


def _external_env(keys_path: str | None) -> dict[str, str]:
    """The child environment for one external-rail pass.

    The variable is REMOVED rather than emptied for the no-key pass, so a rail
    cannot mistake an empty string for a path it should try to open and cannot
    tell the two passes apart by anything other than presence.
    """
    env = dict(os.environ)
    env.pop(EXTERNAL_KEYS_ENV, None)
    if keys_path is not None:
        env[EXTERNAL_KEYS_ENV] = keys_path
    return env


# The report members a rail MAY emit, and the ones every comparison in this
# harness reads back.
#
# ABSENT AND EMPTY ARE DIFFERENT ANSWERS, and keeping them apart is the repair
# this block exists for. A member missing from the report, or present as JSON
# null, is ABSENT: the rail did not establish it, and a comparison holding an
# expectation for it has been handed nothing. A member present as an empty list
# is an ANSWER -- an empty one -- which a comparison can and must fail on its
# merits. Folding the two together is how a rail that never emitted a tier
# column passed every tier expectation in the corpus: the evaluator skipped the
# comparison it was handed nothing for, and a skipped comparison reads exactly
# like a satisfied one in every report this suite prints.
REPORT_MEMBERS = ("codes", "result", "tiers", "primaryCode")

# The type each member must have when it is present at all. A rail emitting
# ``"tiers": "attested"`` has not reported a tier column; it has reported
# something a comparison would coerce on the way past, so the shape is checked
# before anything is compared rather than after something has been concluded.
MEMBER_TYPES: dict[str, type] = {
    "verdict": str,
    "codes": list,
    "result": str,
    "tiers": list,
    "primaryCode": str,
}


def absent_members(parsed: dict[str, Any] | None) -> list[str]:
    """The report members the rail did not establish, missing and null alike."""
    if parsed is None:
        return list(REPORT_MEMBERS)
    return [m for m in REPORT_MEMBERS if parsed.get(m) is None]


def member_type_errors(parsed: dict[str, Any], name: str) -> list[str]:
    """Every present member whose type the rail contract does not allow."""
    out: list[str] = []
    for member, want in MEMBER_TYPES.items():
        value = parsed.get(member)
        if value is None:
            continue
        if not isinstance(value, want):
            out.append(
                f"external-output-member-type: {name}: {member} must be "
                f"{want.__name__}, the rail reported {value!r}"
            )
        elif isinstance(value, list) and not all(isinstance(x, str) for x in value):
            out.append(
                f"external-output-member-type: {name}: {member} must be a list of "
                f"strings, the rail reported {value!r}"
            )
    return out


def external_failure(errors: list[str]) -> dict[str, Any]:
    """One invocation that produced no usable report.

    The verdict is ``error`` rather than a guess read off the exit status, and
    the fault is CARRIED rather than printed and dropped. An invocation fault
    that reaches the evaluator as an absent field is indistinguishable from a
    rail that answered; carried as an error it fails the vector under its own
    name, which is the difference between a report saying the rail is broken and
    one saying the rail disagreed about a result.
    """
    return {
        "verdict": "error",
        "codes": [],
        "result": None,
        "tiers": None,
        "primaryCode": None,
        "absent": list(REPORT_MEMBERS),
        "errors": errors,
    }


def run_external(
    cmd: list[str], vector_path: str, keys_path: str | None, label: str
) -> dict[str, Any]:
    name = f"{os.path.basename(vector_path)} ({label})"
    try:
        proc = subprocess.run(
            cmd + [vector_path],
            capture_output=True,
            timeout=120,
            env=_external_env(keys_path),
        )
    except subprocess.TimeoutExpired:
        # A hung external verifier must not kill the whole suite run: report a
        # non-verdict for this vector so the loop continues.
        print(f"external verifier timed out on {name}", file=sys.stderr)
        # It started and did not exit, so it answered nothing: not counted
        # among the vectors the verifier ran on.
        return {
            **external_failure(
                [f"external-verifier-timeout: {name}: the rail did not terminate"]
            ),
            "ran": False,
        }
    except OSError as e:
        # Covers a missing, non-executable, or otherwise unrunnable --verifier.
        print(f"external verifier could not run on {name}: {e}", file=sys.stderr)
        return {
            **external_failure([f"external-verifier-unrunnable: {name}: {e}"]),
            "ran": False,
        }
    # Surface the external verifier's own diagnostics rather than swallowing
    # them: captured stderr is otherwise invisible when a run misbehaves.
    stderr_txt = proc.stderr.decode("utf-8", "replace").strip()
    if stderr_txt:
        print(f"external verifier stderr on {name}:\n{stderr_txt}", file=sys.stderr)
    return {**parse_external(proc, name, keys_path), "ran": True}


def parse_external(
    proc: subprocess.CompletedProcess[bytes], name: str, keys_path: str | None
) -> dict[str, Any]:
    """One invocation's stdout, held to the rail contract before it is read.

    The contract puts the verdict in the EXIT STATUS and the codes and the
    recomputed result in JSON on the last line of stdout. Every refusal below
    used to be a silent fallback to the exit status, which is the same thing as
    scoring a rail on a report it never wrote.
    """
    exit_verdict = "valid" if proc.returncode == 0 else "invalid"
    lines = [ln for ln in proc.stdout.decode("utf-8", "replace").splitlines() if ln.strip()]
    if not lines:
        return external_failure(
            [
                f"external-output-absent: {name}: the rail wrote no report line, so "
                f"only its exit status ({proc.returncode}) said anything and every "
                "member this suite compares is unestablished"
            ]
        )
    try:
        parsed = json.loads(lines[-1])
    except ValueError as e:
        # This was `except ValueError: pass`. The parse failure then vanished and
        # the verdict stood on the exit status alone, so a rail emitting broken
        # JSON was scored as a rail that had answered.
        return external_failure(
            [
                f"external-output-malformed-json: {name}: the last stdout line does "
                f"not parse as JSON ({e}); the harness reads that line as the whole "
                "report, so nothing the rail computed was received"
            ]
        )
    if not isinstance(parsed, dict):
        return external_failure(
            [
                f"external-output-not-an-object: {name}: the report line parsed as "
                f"{type(parsed).__name__}, and a report is an object"
            ]
        )
    type_errors = member_type_errors(parsed, name)
    if type_errors:
        return external_failure(type_errors)
    return external_record(parsed, name, exit_verdict, keys_path)


def external_record(
    parsed: dict[str, Any], name: str, exit_verdict: str, keys_path: str | None
) -> dict[str, Any]:
    """The rail's own report, once it has been proven to be one.

    A rail MAY restate the verdict in its JSON. When no consumer key policy was
    supplied, the two channels must agree.

    This line used to read ``parsed.get("verdict", verdict)``, which let the
    JSON silently overrule the exit status. Nothing then compared them, so a
    rail whose exit status is meaningless -- returning zero on every refusal --
    scored full marks as long as its JSON said the right thing, and the suite
    reported a conformant checker where it had only ever seen half a conformant
    checker. Picking a winner is what hid it.

    WHY THE CHECK IS SCOPED TO THE NO-POLICY CASE, which is a narrower claim
    than it first looks and is worth stating exactly. Two published contracts
    disagree here. The rail contract says the verdict is in the exit status. The
    shipped CLI documents, in its own source, that WITH a consumer policy the
    exit status is the admission result -- deliberately, so a result-only
    consumer cannot read a valid-but-not-admitted statement as admissible -- and
    binds to validity alone only when no policy is supplied. Both are internally
    coherent and they cannot both hold, which is the same shape as the
    ``-json``/last-line collision this harness already carries a gate for.
    Requiring agreement under a pinned key would fail two accept vectors for a
    divergence the CLI documents on purpose; requiring it nowhere returns to the
    defect above. So it is enforced where the contract is unambiguous, and the
    contradiction is recorded for a decision rather than settled here by
    whichever side this file happens to sit on.
    """
    reported = parsed.get("verdict")
    if reported is not None and reported != exit_verdict and keys_path is None:
        return external_failure(
            [
                f"external-verdict-contradicts-exit-status: {name}: the rail "
                f"reported {reported!r} in its JSON and {exit_verdict!r} in its "
                "exit status, and with no consumer policy supplied the two "
                "channels state the same thing"
            ]
        )
    return {
        "verdict": reported if reported is not None else exit_verdict,
        "codes": parsed.get("codes") or [],
        "result": parsed.get("result"),
        "tiers": parsed.get("tiers"),
        # OPTIONAL, and the only field a rail may omit without losing a
        # comparison: the condition the rail COMMITS to when several hold.
        # Nothing in the reject contract reads it, because that contract compares
        # code sets and says so. The indeterminate families read it, because a
        # rail that reports every condition has declined to answer the question
        # they ask, and a rail that names one has answered it.
        "primaryCode": parsed.get("primaryCode"),
        "absent": absent_members(parsed),
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Suite runner
# ---------------------------------------------------------------------------

GATE_NAMES = ("gate0", "gate1", "recompute", "tier", "self-check")


def load_manifest(suite_dir: str) -> dict[str, Any] | None:
    path = os.path.join(suite_dir, "MANIFEST.json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
        return data


def manifest_index(manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    if not manifest:
        return idx
    vectors = manifest.get("vectors") or manifest.get("index") or []
    if isinstance(vectors, dict):
        for vid, entry in vectors.items():
            if isinstance(entry, dict):
                idx[vid] = entry
    elif isinstance(vectors, list):
        for entry in vectors:
            if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                idx[entry["id"]] = entry
    return idx


# The vector kinds this file actually scores. Nothing is selected by it:
# evaluate_vector routes accept and indeterminate to their own contracts and
# everything else to the reject contract, so a kind the corpus grows and this
# rail does not know would be replayed under somebody else's rules with every
# column green. It is the coverage claim this rail makes about itself, checked
# against the MANIFEST by manifest_closure below.
REPLAYED_KINDS = ("accept", "indeterminate", "reject")

# The directories under the suite root that carry no conformance vectors in any
# encoding, and so are the only ones exempt from having to be a MANIFEST kind.
# Sorted, because the set is printed in a refusal.
#
#   - keys/ holds the published test-key derivation recipe and no vectors; the
#     keys themselves are derived from that recipe rather than committed.
#   - __pycache__/ is a gitignored artifact of running the generators in the
#     tree. It is absent in CI, which is why nothing here requires an entry to
#     correspond to a directory that exists.
SUITE_NON_VECTOR_DIRS = ("__pycache__", "keys", ".build")


def flat_layout(idx: dict[str, Any]) -> str:
    """The single directory every vector is declared under.

    A REQUIREMENT rather than a detection, and there is no per-verdict fallback
    behind it. A directory named for the verdict told a rail the answer before
    it opened the file -- measured over the whole path it predicted accept from
    reject perfectly -- so reading one is not a compatibility nicety, it is
    reading the defect. A corpus that still has one is refused by name.
    """
    dirs = set()
    for entry in idx.values():
        rel = entry.get("file")
        if not isinstance(rel, str) or "/" not in rel:
            raise SystemExit(
                "a MANIFEST row declares no file under a directory, so this rail "
                "would have to derive a path from the vector's kind -- which is "
                "the derivation the flat layout exists to remove."
            )
        dirs.add(rel.split("/", 1)[0])
    if len(dirs) != 1:
        raise SystemExit(
            f"the MANIFEST spreads its vectors over {sorted(dirs)}. This rail "
            "reads one flat directory of content-addressed statements; a corpus "
            "sorted into a directory per verdict is the retired layout and is "
            "not read."
        )
    only = dirs.pop()
    if only in REPLAYED_KINDS:
        raise SystemExit(
            f"the MANIFEST declares its vectors under {only!r}, which is a verdict "
            "name. That layout tells a rail the answer before it reads the "
            "statement and is not supported."
        )
    return only


def manifest_kinds(idx: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """The MANIFEST's vector identifiers, grouped by the kind each row declares.

    A row declaring no kind lands under the empty string, which is in no
    REPLAYED_KINDS entry and no directory name, so it is refused by name rather
    than silently read out of whichever directory a default would have picked.
    """
    listed: dict[str, list[str]] = {}
    for vid, entry in idx.items():
        kind = entry.get("kind")
        listed.setdefault(kind if isinstance(kind, str) else "", []).append(vid)
    for ids in listed.values():
        ids.sort()
    return listed


def discover_vectors(suite_dir: str, kinds: Sequence[str]) -> list[tuple[str, str]]:
    """Return (kind, path) pairs sorted by file name, over the kinds given.

    The kinds come from the MANIFEST, in the order it first mentions each,
    rather than from a literal here. Three directory names were hardcoded until
    a fourth arrived: a kind the corpus grew was walked by nothing, replayed by
    nothing, and counted in no total, while every gate stayed green -- the same
    blind spot the Go runner was hardened against after an indeterminate/
    directory was vendored and exercised by nothing. Any directory the MANIFEST
    does not name as a kind is now refused by manifest_closure instead of being
    quietly skipped.
    """
    # Every vector this suite declares, read from the file each MANIFEST row
    # names. The kind comes from the row, never from the path: a path that
    # carried the kind would be answering the question this corpus exists to
    # ask.
    manifest = load_manifest(suite_dir)
    entries = (manifest or {}).get("vectors") or (manifest or {}).get("index") or []
    if not entries:
        raise SystemExit(f"{suite_dir}/MANIFEST.json declares no vectors to replay")
    flat_layout({str(e.get("id")): e for e in entries})
    found: list[tuple[str, str]] = []
    for entry in entries:
        rel = entry.get("file")
        kind = entry.get("kind")
        if not isinstance(rel, str) or not isinstance(kind, str):
            raise SystemExit(
                f"MANIFEST row {entry.get('id')!r} declares no file or no kind"
            )
        found.append((kind, os.path.join(suite_dir, rel)))
    return found


def vector_files_in(directory: str) -> list[str]:
    """The vector identifiers a directory holds, or an empty list if absent."""
    if not os.path.isdir(directory):
        return []
    return sorted(
        os.path.splitext(name)[0]
        for name in os.listdir(directory)
        if name.endswith(".json")
    )


class Evaluation(NamedTuple):
    """One vector's judgement, with the two surfaces kept apart.

    ``reasons`` are NORMATIVE conformance failures: the verdict, the result, the
    tier columns, the behaviour assertions, the self-check. ``parity`` is the
    MEASURED reason-code comparison. ``vectors/MANIFEST.json`` says which is
    which in its own words -- "a rail conforms when its verdict, and for an
    accepted statement its result token, match this manifest", and of the codes,
    "a differing code is a reason-parity datum rather than a failure. Report
    that parity as its own figure."

    Until this split existed the two arrived in one undifferentiated list, so a
    report could not say the sentence the manifest asks for. A rail with its own
    reason vocabulary and a perfect verdict record read, in every figure this
    suite printed, exactly like a rail that admitted statements it should have
    refused.

    ``ok`` still counts both, and that is deliberate rather than an oversight.
    The forcing measurement (`scripts/forcing-gate.py`) reads this status to ask
    what the corpus obliges a rail to implement, and several rules are forced
    only through the code a rail reports; making parity non-fatal would silently
    shrink that measurement in the same change that separated the reporting. The
    separation is in the REPORT, where the manifest asks for it; whether parity
    also stops binding the exit status is a measurement decision that needs the
    forcing baseline re-derived beside it, and is recorded rather than taken
    here.
    """

    ok: bool
    gates: dict[str, str]
    reasons: list[str]
    parity: list[str]


def evaluate_vector(
    kind: str,
    entry: dict[str, Any] | None,
    observed: dict[str, Any],
    self_check_findings: list[str] | None,
) -> tuple[bool, dict[str, str], list[str]]:
    """Return (pass, per-gate status, reasons), reasons and parity together.

    The three-value shape every caller outside this file uses. Callers that
    need the two surfaces apart -- the report writer, and anything quoting the
    manifest's conformance sentence -- call ``evaluate_vector_detailed``.
    """
    ev = evaluate_vector_detailed(kind, entry, observed, self_check_findings)
    return ev.ok, ev.gates, [*ev.reasons, *ev.parity]


def evaluate_vector_detailed(
    kind: str,
    entry: dict[str, Any] | None,
    observed: dict[str, Any],
    self_check_findings: list[str] | None,
) -> Evaluation:
    """Score one vector against its manifest entry."""
    reasons: list[str] = []
    parity: list[str] = []
    gates = {g: "-" for g in GATE_NAMES}
    expected = (entry or {}).get("expected") or {}
    if declared_exclusion(expected) is not None:
        # A member whose property the specification cannot express is NOT
        # EXERCISED: no gate is scored, and the row says why. Before this the
        # field was written into manifests and read by nothing, so an
        # unmeasurable member was replayed as though an answer were required.
        return Evaluation(True, gates, reasons, parity)
    exp_verdict = expected.get("verdict") or ("valid" if kind == "accept" else "invalid")
    obs_verdict = observed["verdict"]
    obs_codes = set(observed.get("codes") or [])

    established = _eval_establishment(observed, exp_verdict, gates, reasons)
    # Cross-check the observed verdict against the manifest's declared verdict
    # (falling back to the directory-derived expectation). This strengthens the
    # per-kind checks below by also catching a manifest whose declared verdict
    # disagrees with the vector's accept/reject placement. It is skipped when the
    # verdict was never established, because "the rail said the wrong thing" and
    # "the rail said nothing this harness could read" are different findings and
    # the second one is already reported above under its own name.
    if established and obs_verdict != exp_verdict:
        reasons.append(f"verdict: manifest declares {exp_verdict!r}, observed {obs_verdict!r}")

    if kind == "accept":
        _eval_accept(expected, observed, obs_verdict, obs_codes, gates, reasons)
    elif kind == "indeterminate":
        _eval_indeterminate(
            expected, observed, obs_verdict, obs_codes, self_check_findings, gates, reasons
        )
    else:
        _eval_reject(
            expected,
            observed,
            obs_verdict,
            obs_codes,
            self_check_findings,
            gates,
            reasons,
            parity,
        )

    ok = not (reasons or parity)
    return Evaluation(ok, gates, reasons, parity)


def _eval_establishment(
    observed: dict[str, Any],
    exp_verdict: str,
    gates: dict[str, str],
    reasons: list[str],
) -> bool:
    """The gate that reads no reason code: was there an answer to compare at all?

    Every other check in this file asks whether the rail's answer MATCHES. This
    one asks whether the rail gave one, and it is deliberately independent of
    the codes a rail did or did not report, because the defect it closes was
    exactly a vector passing on the strength of comparisons that never ran.

    Returns whether the verdict was established, so the caller can report a
    disagreement rather than restating the absence in different words.
    """
    for err in observed.get("errors") or []:
        reasons.append(f"rail invocation: {err}")
    obs_verdict = observed.get("verdict")
    established = obs_verdict in ("valid", "invalid")
    if not established:
        gates["gate0"] = "FAIL"
        reasons.append(
            f"verdict-not-established: the vector expects {exp_verdict!r} and the "
            f"rail's verdict could not be established (observed {obs_verdict!r}). A "
            "verdict that cannot be established is never a pass, whatever the rail "
            "did or did not report alongside it."
        )
    obs_without = observed.get("verdict_without_key")
    if established and obs_without is not None and obs_without != obs_verdict:
        gates["gate0"] = "FAIL"
        reasons.append(
            f"verdictWithoutKey: the rail reports {obs_verdict!r} under the pinned "
            f"key and {obs_without!r} without one. Validity is byte-pure and never "
            "consults a consumer key policy, so the two passes cannot disagree "
            "about it; a rail whose validity moves with the key policy has answered "
            "a different question from the one this corpus asks."
        )
    return established


def declared_exclusion(expected: dict[str, Any]) -> str | None:
    """The reason a manifest entry declares it cannot be scored, or None.

    ``expected.unmeasurableBecause`` is the declared exclusion of the v0.1
    per-check record: such a member is reported not-exercised with this text
    as its cause, and the pair table rejects any other state for it.
    """
    reason = expected.get("unmeasurableBecause")
    return reason if isinstance(reason, str) and reason else None


def readings_of(entry: dict[str, Any] | None) -> dict[str, str]:
    """The declared readings of an indeterminate vector, or an empty map."""
    expected = (entry or {}).get("expected") or {}
    declared = expected.get("readings")
    return {str(k): str(v) for k, v in declared.items()} if isinstance(declared, dict) else {}


def _eval_indeterminate(
    expected: dict[str, Any],
    observed: dict[str, Any],
    obs_verdict: Any,
    obs_codes: set[Any],
    self_check_findings: list[str] | None,
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    """Per-member half of the indeterminate contract: verdict and CLOSURE.

    The verdict is determined and is checked exactly as a reject vector's. The
    condition is not, so what is checked here is that the rail's answer is one
    the corpus DECLARED somebody could give: its codes must intersect the union
    of this member's predicted conditions. An answer outside that union is a
    failure and not an invitation to widen the union -- widening is how a
    two-answer expectation becomes a set that any answer satisfies, which is the
    thing this bucket exists so that nobody has to do.

    Coherence across the family is the other half and cannot be asked here,
    because it is a property of several members' answers at once. It runs over
    the finished rows in family_coherence_failures.
    """
    predicted = {str(v) for v in (expected.get("readings") or {}).values()}
    if obs_verdict != "invalid":
        gates["gate0"] = gates["gate1"] = gates["recompute"] = "FAIL"
        reasons.append("expected invalid, observed valid")
    else:
        gates["gate0"] = "PASS"
        if predicted and not (predicted & obs_codes):
            gates["gate0"] = "FAIL"
            reasons.append(
                f"no declared reading's condition observed: the readings predict "
                f"{sorted(predicted)}, the rail reported {sorted(obs_codes)}. A "
                "condition no declared reading predicts is an undeclared reading: "
                "add it to the family by name with its argument, never by widening "
                "the set."
            )
        if observed.get("result") is not None or observed.get("tiers_with_key"):
            gates["recompute"] = "FAIL"
            reasons.append("invalid vector emitted a result or tiers")
    if self_check_findings is not None:
        gates["self-check"] = "FAIL" if self_check_findings else "PASS"
        reasons.extend(self_check_findings)


def _answers(
    row: dict[str, Any], reading: str, idx: dict[str, dict[str, Any]], committed: bool
) -> bool:
    """Does this member's answer match what ``reading`` predicts for it?

    Two strengths, and which one applies is the rail's own choice rather than
    this harness's. A rail that publishes ``primaryCode`` has named the one
    condition it reports when several hold, so the reading must predict exactly
    that. A rail that publishes only a code set has not answered the question
    these families ask -- reporting every condition is a legitimate response to a
    statement carrying several -- so membership is all that can be asked, and
    such a rail is compatible with every reading and is reported as committing to
    none. Inferring a primary from the set's order is the one thing not done
    here: the reject contract states that order carries nothing, and a harness
    that read order anyway would be enforcing a rule the corpus tells rails to
    ignore.
    """
    predicted = readings_of(idx.get(str(row["id"]))).get(reading)
    observed: dict[str, Any] = row.get("observed") or {}
    if committed:
        return predicted == observed.get("primaryCode")
    return predicted in {str(c) for c in (observed.get("codes") or [])}


def family_coherence_failures(
    idx: dict[str, dict[str, Any]], rows_out: list[dict[str, Any]]
) -> tuple[list[str], list[str]]:
    """Coherence half of the indeterminate contract, plus the reading it records.

    A rail may take any declared reading of a family. What it may not do is
    answer one member under one reading and another member under a different
    one: the specification leaves the condition open, it does not license a rail
    whose reported condition turns on incidental structure. So the requirement is
    that at least ONE declared reading predicts, for every member of the family,
    a condition the rail actually reported.

    Returns (notes, failures). The notes name the reading each family matched,
    which is the whole reason the bucket exists: two rails that agree on every
    verdict and disagree here have, until now, had nowhere for that disagreement
    to show up.
    """
    families: dict[str, list[dict[str, Any]]] = {}
    for row in rows_out:
        if row.get("kind") != "indeterminate":
            continue
        entry = idx.get(str(row["id"]))
        family = str(((entry or {}).get("expected") or {}).get("family") or "")
        if family:
            families.setdefault(family, []).append(row)

    notes: list[str] = []
    failures: list[str] = []
    for family, members in sorted(families.items()):
        declared = sorted(readings_of(idx.get(str(members[0]["id"]))))
        committed = all(m.get("observed", {}).get("primaryCode") for m in members)
        matched = [
            name
            for name in declared
            if all(_answers(m, name, idx, committed) for m in members)
        ]
        if matched:
            how = (
                "the reading the rail committed to"
                if committed and len(matched) == 1
                else "compatible with the rail's reported code set, which commits "
                "to no single reading"
            )
            notes.append(
                f"indeterminate family {family}: {', '.join(matched)} -- {how} "
                f"({len(members)} member(s))"
            )
            continue
        failures.append(
            f"indeterminate family {family}: no declared reading explains the "
            "rail's answers across the family. Per member: "
            + "; ".join(
                f"{m['id']} -> "
                + str(
                    m.get("observed", {}).get("primaryCode")
                    if committed
                    else sorted(m.get("observed", {}).get("codes") or [])
                )
                for m in members
            )
            + f". Declared readings: {declared}. Either answer is admissible; "
            "answering two members under different readings is not, because the "
            "reported condition is then a function of incidental structure rather "
            "than of a policy the rail applies."
        )
    return notes, failures


def _eval_accept(
    expected: dict[str, Any],
    observed: dict[str, Any],
    obs_verdict: Any,
    obs_codes: set[Any],
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    for g in ("gate0", "gate1", "recompute", "tier"):
        gates[g] = "PASS"
    if obs_verdict != "valid":
        # gate0 falls FIRST, before the per-code attribution below, and that
        # order is the fix rather than a tidy-up. A rail that refuses an accept
        # vector while reporting no code at all left this loop with nothing to
        # iterate, so every gate column stayed on the PASS pre-set above while
        # the vector failed: a row reading PASS PASS PASS PASS beside a FAIL
        # status, in the table this suite publishes as its evidence.
        gates["gate0"] = "FAIL"
        for code in obs_codes:
            gates[CODE_STAGE.get(code, "gate0")] = "FAIL"
        reasons.append(f"expected valid, observed invalid with codes {sorted(obs_codes)}")
    exp_result = expected.get("result")
    if obs_verdict == "valid" and exp_result is not None:
        if observed.get("result") != exp_result:
            gates["recompute"] = "FAIL"
            reasons.append(
                "result: expected {!r}, observed {!r}".format(exp_result, observed.get("result"))
            )
    _eval_accept_tiers(expected, observed, gates, reasons)


def _eval_accept_tiers(
    expected: dict[str, Any],
    observed: dict[str, Any],
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    """The tier columns, and the rule that a tier never moves the result.

    THE DEFECT THIS CLOSES. Both comparisons below used to run only when the
    rail had reported something to compare -- ``obs_tiers is not None`` on the
    columns, ``not in (None, result)`` on the assertion. An expectation compared
    against nothing cannot fail, so a rail that emitted no ``tiers`` member
    passed all six pinned tier expectations in the corpus, including the only
    statement the corpus makes of GATE 2's no-TOFU rule, by staying silent. The
    row printed PASS with no reason under it, which is the strongest thing this
    report can say and it was being said about a comparison that never happened.

    An ABSENT column is now a failure in its own words, and an EMPTY column is a
    mismatch in its own words. Those are different findings: a rail that derives
    an empty tier column has answered and is wrong, a rail that reports no
    column has not answered, and a reader deciding whether to trust a rail needs
    to know which.
    """
    absent = set(observed.get("absent") or ())
    for field_name, obs_key in (
        ("tierWithPinnedKey", "tiers_with_key"),
        ("tierWithoutKey", "tiers_without_key"),
    ):
        exp_tiers = expected.get(field_name)
        if exp_tiers is None:
            continue
        if obs_key in absent:
            gates["tier"] = "FAIL"
            reasons.append(
                f"{field_name}: not established -- the rail reported no {obs_key} "
                f"member, so the expectation {list(exp_tiers)} was compared against "
                "nothing. An unanswered column is a failure and never a skipped check."
            )
            continue
        obs_tiers = observed.get(obs_key)
        if list(exp_tiers) != list(obs_tiers or []):
            gates["tier"] = "FAIL"
            reasons.append(f"{field_name}: expected {exp_tiers}, observed {obs_tiers}")
    _eval_tier_result_invariance(observed, gates, reasons)


def _eval_tier_result_invariance(
    observed: dict[str, Any],
    gates: dict[str, str],
    reasons: list[str],
) -> None:
    """Behaviour assertion 1: deriving a tier never alters the result.

    The assertion needs BOTH results to have been reported. Reading a missing
    no-key result as agreement is how a rail that answers one pass and not the
    other satisfied an assertion nobody had checked it against.
    """
    if observed.get("tiers_with_key") is None or observed.get("result") is None:
        return
    if "result_without_key" in set(observed.get("absent") or ()):
        gates["tier"] = "FAIL"
        reasons.append(
            "resultWithoutKey: not established -- the rail reported a result and a "
            "tier column under the pinned key and no result at all without one, so "
            "the assertion that tier derivation never alters the result was checked "
            "against nothing."
        )
        return
    if observed.get("result_without_key") != observed["result"]:
        gates["tier"] = "FAIL"
        reasons.append(
            "tier derivation altered the result: {!r} under the pinned key, {!r} "
            "without one".format(observed["result"], observed.get("result_without_key"))
        )


def _eval_reject(
    expected: dict[str, Any],
    observed: dict[str, Any],
    obs_verdict: Any,
    obs_codes: set[Any],
    self_check_findings: list[str] | None,
    gates: dict[str, str],
    reasons: list[str],
    parity: list[str],
) -> None:
    exp_codes = set(expected.get("codes") or [])
    if obs_verdict != "invalid":
        gates["gate0"] = gates["gate1"] = gates["recompute"] = "FAIL"
        reasons.append("expected invalid, observed valid")
    else:
        _eval_reject_stages(exp_codes, obs_codes, gates, parity)
        # behavior assertion 2: invalid emits no result and no tiers
        if observed.get("result") is not None or observed.get("tiers_with_key"):
            gates["recompute"] = "FAIL"
            reasons.append("invalid vector emitted a result or tiers")
    if self_check_findings is not None:
        if self_check_findings:
            gates["self-check"] = "FAIL"
            reasons.extend(self_check_findings)
        else:
            gates["self-check"] = "PASS"


def _eval_reject_stages(
    exp_codes: set[Any],
    obs_codes: set[Any],
    gates: dict[str, str],
    parity: list[str],
) -> None:
    """REASON PARITY, which the manifest calls measured and not normative.

    ``vectors/MANIFEST.json`` states the comparison surface itself: a rail
    conforms on its verdict and, for an accepted statement, its result token,
    and "the codes on a reject entry are the reference verifier's own
    vocabulary, not the specification's ... a differing code is a reason-parity
    datum rather than a failure. Report that parity as its own figure."

    So the finding below goes into ``parity`` and not into ``reasons``, and the
    report carries the two as separate figures. It still binds the run's exit
    status -- see ``Evaluation`` for why that is a measurement decision rather
    than a reporting one -- but a reader can now tell a rail that admitted a
    statement it should have refused from a rail that refused it and said so in
    its own words.
    """
    stage = "gate0"
    if not exp_codes:
        gates[stage] = "PASS"
        return
    hit = exp_codes & obs_codes
    if not hit:
        parity.append(
            f"no expected code observed: expected {sorted(exp_codes)}, observed {sorted(obs_codes)}"
        )
    # Group expected codes by gate stage; a stage is PASS iff ANY of
    # its expected codes was observed, matching the disjunctive
    # "no expected code observed" reason above (several coverage
    # codes are conditional alternates in the generator, so a vector
    # legitimately declares more than one and emits one). Iterating
    # the set directly let a later unobserved code overwrite an
    # earlier PASS, making the sub-status depend on PYTHONHASHSEED.
    stage_hit: dict[str, bool] = {}
    for code in exp_codes:
        st = CODE_STAGE.get(code, "gate0")
        stage_hit[st] = stage_hit.get(st, False) or (code in obs_codes)
    for st, seen in stage_hit.items():
        gates[st] = "PASS" if seen else "FAIL"


def write_pinned_key_policy(keys: dict[str, dict[str, Any]], directory: str) -> str:
    """Write the suite's pinned TEST substrate observation key as a consumer key
    policy file and return its path.

    This is the object the external rail's ``AEE_SUBSTRATE_KEYS`` points at. It
    is derived here rather than committed, for the same reason the keys
    themselves are derived: a checked-in public key is one more thing that can
    drift from the recipe that makes it. TEST KEY ONLY -- it proves nothing.
    """
    path = os.path.join(directory, "pinned-test-keys.json")
    entry = keys[PINNED_ROLE]
    body = {
        "substrateObservationKeys": [
            {"keyid": entry["keyid"], "publicKeyHex": entry["public"].hex()}
        ]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(body, f)
        f.write("\n")
    return path


#: The one suite the reference rail below implements. Every other suite in the
#: tree is judged by a reader of its own: two of them ship in this package, and
#: the rest are read by ``aee-verify <corpus-dir>`` (the Go readers in
#: ``corpora/``, which CI runs over every committed corpus).
REFERENCE_SUITE = "adversarial-execution-evidence-conformance"


def _run_non_reference_suite(
    manifest: dict[str, Any] | None,
    suite_dir: str,
    external_cmd: list[str] | None,
    report_path: str,
    rail_note: str,
) -> int | None:
    """Judge or refuse a corpus the reference rail does not implement.

    Returns None only for the reference suite (and for a directory with no
    MANIFEST, which the rail reads by its accept/reject layout). Every other
    suite is either judged by this package's own reader for it or REFUSED BY
    NAME with exit 2, the contract ``corpora.Judge`` keeps in Go. Running the
    AEE reference rail over another predicate's corpus printed that rail's
    failures as though they were a verdict on the corpus: the same substitution
    as replacing a named verifier, pointed the other way.

    A named verifier still runs against any suite whose manifest the generic
    evaluator reads, because the verifier under test is the caller's. The
    receipt-signature corpus writes its own external-verifier contract, so a
    named verifier runs over it through that contract. The other two suites with
    readers here define none, so a named verifier is refused on them rather
    than silently not asked.
    """
    suite = manifest.get("suite") if manifest is not None else None
    if suite is None or suite == REFERENCE_SUITE:
        return None
    own_reader = suite in (w3creport.SUITE, observedeffect.SUITE, receiptsignature.SUITE)
    if not own_reader and external_cmd is not None:
        return None
    if external_cmd is not None and suite == receiptsignature.SUITE:
        return receiptsignature.run_external(suite_dir, external_cmd, report_path, rail_note)
    if external_cmd is not None:
        return refuse_verifier(
            f"the verifier {shlex.join(external_cmd)!r} {DID_NOT_RUN}: the corpus "
            f"{suite!r} is judged only by this package's own reader and has no "
            "external-verifier contract"
        )
    if not own_reader:
        print(
            f"corpus {suite!r} has no reader in this package: the reference rail "
            f"implements {REFERENCE_SUITE!r} only, so nothing was judged. Judge it "
            f"with `aee-verify {suite_dir}`, or name a verifier with "
            "--verifier.",
            file=sys.stderr,
        )
        return 2
    if suite == receiptsignature.SUITE:
        rs_judged = receiptsignature.judge(suite_dir)
        sys.stdout.write(receiptsignature.render(rs_judged, receiptsignature.SUITE))
        return 0 if rs_judged.ok() else 1
    if suite == w3creport.SUITE:
        # The W3C per-check report corpus is judged by its own validator, in
        # the same words the Go reader prints, so the two rails can be diffed.
        judged = w3creport.judge(suite_dir)
        sys.stdout.write(w3creport.render(judged, w3creport.SUITE))
        return 0 if judged.ok() else 1
    # Same arrangement for the Observed Effect corpus: a predicate of its own
    # gets a reader of its own, and the printed lines are the ones
    # corpora/observedeffect.go prints from Go.
    oe_judged = observedeffect.judge(suite_dir)
    sys.stdout.write(observedeffect.render(oe_judged, observedeffect.SUITE))
    return 0 if oe_judged.ok() else 1


def run_suite(args: argparse.Namespace) -> int:
    suite_dir = os.path.abspath(args.vectors)
    if not os.path.isdir(suite_dir):
        print(f"suite directory not found: {args.vectors}", file=sys.stderr)
        return 2

    # Resolved before anything is judged, so a named verifier that cannot run
    # stops the harness here instead of reaching a branch that never calls it.
    try:
        external_cmd, rail_note = _run_rail_selection(args)
    except VerifierNotRun as e:
        return refuse_verifier(str(e))

    manifest = load_manifest(suite_dir)
    judged_own = _run_non_reference_suite(
        manifest,
        suite_dir,
        external_cmd,
        _report_path(args),
        rail_note,
    )
    if judged_own is not None:
        return judged_own
    idx = manifest_index(manifest)
    # The kinds to walk come from the MANIFEST when there is one, so a kind the
    # corpus grows is replayed rather than skipped by a literal that predates
    # it. Without a MANIFEST there is nothing to derive them from and the rail
    # falls back to the kinds it scores, which is the only case where the set
    # is a literal.
    kinds = list(manifest_kinds(idx)) if manifest is not None else list(REPLAYED_KINDS)
    vectors = discover_vectors(suite_dir, kinds)
    report_base = os.path.dirname(suite_dir) or "."

    if not vectors:
        rel = os.path.relpath(suite_dir, report_base)
        print(
            f"no vectors found under {rel} (the kind directories {kinds} are "
            "empty or missing); nothing to run"
        )
        return 2

    keys = derive_test_keys()
    pinned = [keys[PINNED_ROLE]["public"]]
    ref_with = ReferenceVerifier(pinned)
    ref_without = ReferenceVerifier([])

    rows_out: list[dict[str, Any]] = []
    failures = 0
    with tempfile.TemporaryDirectory(prefix="agent-evidence-vectors-keys-") as tmp:
        keys_path = write_pinned_key_policy(keys, tmp)
        for kind, path in vectors:
            row, failed = _run_process_vector(
                kind, path, idx, external_cmd, ref_with, ref_without, report_base, keys_path
            )
            if failed:
                failures += 1
            rows_out.append(row)

    # manifest-to-disk closure, both ways per kind, plus the directory set and
    # the manifest's own counts block
    suite_notes, note_failures = _run_manifest_closure(manifest, idx, suite_dir, rows_out)
    failures += note_failures
    executed, short = verifier_execution(external_cmd, rows_out)
    suite_notes.extend(short)
    failures += len(short)

    # The cross-member half of the indeterminate contract. A failure is written
    # onto every member of the family as well as into the suite notes: the
    # profile is what fails, no one member of it is at fault on its own, and a
    # totals line reading "0 fail" beside a non-zero exit is the shape of report
    # this repository exists to stop shipping.
    coherence_notes, coherence_failures = family_coherence_failures(idx, rows_out)
    suite_notes.extend(coherence_notes)
    suite_notes.extend(coherence_failures)
    if coherence_failures:
        for row in rows_out:
            if row.get("kind") == "indeterminate":
                row["status"] = "FAIL"
                # Coherence is a normative property of the family, so it moves
                # the conformance column with the status. A row whose status
                # said FAIL while its conformance column still said PASS would
                # be the split reporting a contradiction rather than a finding.
                row["conformance"] = "FAIL"
                row["reasons"] = [*row["reasons"], *coherence_failures]
                row["conformanceReasons"] = [
                    *row["conformanceReasons"], *coherence_failures
                ]
                row["gates"]["gate0"] = "FAIL"
        failures += len(coherence_failures)

    # Suite-level refusals -- closure, the directory set, the counts block --
    # belong to no one vector, so they are carried in the totals in their own
    # right. Reported only through the exit status they produce a table reading
    # "0 fail" beside a non-zero exit, which is the shape of report this
    # repository exists to stop shipping.
    suite_refusals = failures - sum(1 for r in rows_out if r["status"] == "FAIL")
    report, report_path = _run_write_report(
        args, suite_dir, report_base, external_cmd, rail_note, suite_notes, rows_out,
        max(suite_refusals, 0), executed,
    )
    args.report_written = report_path
    _run_print_table(report, rows_out, suite_notes, rail_note, report_path, report_base)
    return _run_exit_status(failures, executed)


def _run_exit_status(failures: int, executed: int | None) -> int:
    """0 clean, 1 any check failed, 2 when the named verifier answered nothing."""
    if executed == 0:
        # Nothing the named verifier said reached a single vector, so this run
        # is the "did not run" case rather than a failing census.
        print(f"the named verifier {DID_NOT_RUN} on any vector")
        return 2
    return 1 if failures else 0


def _run_rail_selection(args: argparse.Namespace) -> tuple[list[str] | None, str]:
    """Resolve --verifier (or AEE_EXTERNAL_VERIFIER) to an argv prefix.

    Returns ``(None, note)`` only when no verifier was named at all. A named
    verifier either resolves or raises ``VerifierNotRun``; an empty setting is a
    named verifier that cannot run, not an absent one.
    """
    verifier = args.verifier
    if verifier is None:
        verifier = os.environ.get("AEE_EXTERNAL_VERIFIER")
    if verifier is None:
        return None, "no external verifier supplied; using the reference rail"
    try:
        argv = resolve_verifier(verifier)
    except VerifierNotRun as e:
        reason = f"the verifier {verifier!r} {DID_NOT_RUN}: {e}"
        raise VerifierNotRun(reason) from None
    return argv, f"external verifier: {verifier}"


DID_NOT_RUN = "did NOT run"


def refuse_verifier(reason: str) -> int:
    """Say the named verifier did not run, on both streams, and exit 2."""
    msg = f"{reason}\nno vector was checked and no report was written."
    print(msg)
    print(msg, file=sys.stderr)
    return 2


def verifier_execution(
    external_cmd: list[str] | None, rows_out: list[dict[str, Any]]
) -> tuple[int | None, list[str]]:
    """How many vectors the named verifier answered, and the refusal when short.

    A vector counts only when BOTH of its invocations started and exited. The
    count is published beside the totals, so a reader never has to infer from a
    pass count which program produced it.
    """
    if external_cmd is None:
        return None, []
    executed = sum(1 for r in rows_out if r.get("verifierRan"))
    total = len(rows_out)
    if executed == total and total > 0:
        return executed, []
    return executed, [
        f"the verifier {shlex.join(external_cmd)!r} ran on {executed} of {total} "
        f"vectors; {total - executed} were never answered by it"
    ]


# How one pass's report members are named once the two passes are merged. The
# no-key pass contributes exactly two members, because exactly two comparisons
# read it; its codes and its primary code are not consumed by anything, and
# listing them as unestablished would be noise a reader has to learn to skip.
WITH_KEY_MEMBER = {
    "codes": "codes",
    "result": "result",
    "tiers": "tiers_with_key",
    "primaryCode": "primaryCode",
}
WITHOUT_KEY_MEMBER = {"tiers": "tiers_without_key", "result": "result_without_key"}


def observe_external(external_cmd: list[str], path: str, keys_path: str) -> dict[str, Any]:
    """Drive an external rail over one vector under BOTH key policies.

    One invocation cannot answer both tier questions, and for several revisions
    the harness only asked one: it recorded ``tiers_without_key: None`` for every
    external run, and the evaluator skips a tier column it was handed nothing
    for. So ``ok-024``'s ``tierWithoutKey`` -- the corpus's only statement of
    GATE 2's no-TOFU rule, that an unpinned consumer derives ``unattested`` and
    never infers the substrate root from the predicate -- was compared against
    nothing on every rail but this file's own, while reading in the MANIFEST as
    a requirement on all of them.

    The byte-pure facts (verdict, codes, result) are read from the pinned-key
    pass. The no-key pass contributes its tier column and its result, which is
    also what puts a third-party rail under the assertion that tier derivation
    never alters ``result``.

    BOTH INVOCATIONS ARE NOW KEPT WHOLE. This function used to take four values
    out of the two passes and drop everything else, including the no-key pass's
    verdict and the fact that the invocation had failed at all. A no-key pass
    that timed out, would not run, or contradicted itself arrived at the
    evaluator as ``tiers_without_key: None``, and the evaluator skipped a column
    it was handed nothing for -- so a broken invocation and a rail that answered
    correctly produced identical rows. The merged record carries every field's
    ESTABLISHMENT (``absent``) and every invocation fault (``errors``), labelled
    by the pass that produced it, so an unanswered question fails under its own
    name instead of vanishing into a skipped comparison.
    """
    with_key = run_external(external_cmd, path, keys_path, "pinned-key")
    without_key = run_external(external_cmd, path, None, "no-key")
    # Only the members a comparison in this file actually reads are carried
    # forward per pass: the pinned-key pass supplies the byte-pure facts, and
    # the no-key pass supplies exactly two -- its tier column and its result.
    absent = [WITH_KEY_MEMBER[m] for m in with_key["absent"] if m in WITH_KEY_MEMBER]
    absent += [
        WITHOUT_KEY_MEMBER[m] for m in without_key["absent"] if m in WITHOUT_KEY_MEMBER
    ]
    errors = [f"pinned-key: {e}" for e in with_key["errors"]]
    errors += [f"no-key: {e}" for e in without_key["errors"]]
    return {
        "verdict": with_key["verdict"],
        "verdict_without_key": without_key["verdict"],
        "codes": with_key["codes"],
        "primaryCode": with_key["primaryCode"],
        "result": with_key["result"],
        "tiers_with_key": with_key["tiers"],
        "tiers_without_key": without_key["tiers"],
        "result_without_key": without_key["result"],
        "absent": sorted(absent),
        "errors": errors,
        "ran": bool(with_key.get("ran")) and bool(without_key.get("ran")),
    }


def _run_observe(
    external_cmd: list[str] | None,
    ref_with: ReferenceVerifier,
    ref_without: ReferenceVerifier,
    path: str,
    stmt: Any,
    raw: bytes | None,
    keys_path: str,
) -> dict[str, Any]:
    if external_cmd is not None:
        return observe_external(external_cmd, path, keys_path)
    o_with = ref_with.verify(stmt, raw)
    o_without = ref_without.verify(stmt, raw)
    return {
        "verdict": o_with.verdict,
        "codes": o_with.codes,
        # This rail appends codes in detection order, so its first code is the
        # deterministic primary the README names as the contract. Publishing it
        # here rather than inferring it in the evaluator keeps the inference to
        # the one rail whose ordering is defined; an external rail says so
        # itself or is recorded as having declined to.
        "primaryCode": o_with.codes[0] if o_with.codes else None,
        "result": o_with.result,
        "tiers_with_key": o_with.tiers_with_key,
        "tiers_without_key": o_without.tiers_without_key,
        "result_without_key": o_without.result,
        # This rail is held to the same establishment rule as an external one,
        # and it is held to it through the same field rather than through an
        # exemption. It computes every member on every statement, so a None here
        # means the rail derived nothing -- an invalid statement carries no
        # result and no tier column -- and that is exactly what "absent" says. A
        # rail that got its own answers exempted from the check the corpus
        # applies to everybody else would be measuring the others against a
        # standard it does not meet.
        "absent": sorted(_reference_absent(o_with, o_without)),
        "errors": [],
        # The no-key pass's verdict, which used to be discarded. Validity is
        # byte-pure: it does not consult a consumer key policy, so the two
        # passes cannot disagree about it, and a rail whose validity moves with
        # the key policy has answered a different question from the one the
        # corpus asks.
        "verdict_without_key": o_without.verdict,
    }


def _reference_absent(o_with: Outcome, o_without: Outcome) -> list[str]:
    """The members the reference rail established nothing for on one statement."""
    absent: list[str] = []
    if not o_with.codes:
        absent.append("codes")
        absent.append("primaryCode")
    if o_with.result is None:
        absent.append("result")
    if o_with.tiers_with_key is None:
        absent.append("tiers_with_key")
    if o_without.tiers_without_key is None:
        absent.append("tiers_without_key")
    if o_without.result is None:
        absent.append("result_without_key")
    return absent


def _load_statement(raw: bytes) -> tuple[Any, bool]:
    """Parse a vector file for the harness, reporting whether the parse was
    faithful. Returns (value, faithful).

    A byte-level vector carries its fault in the ENCODING or in a character JSON
    forbids, so there is no faithful Python value to produce. The verifier does
    not need one: it is handed the raw bytes and rejects them in the
    statement-wide strict pass before any decoded string is read. Everything the
    harness does with the value afterwards -- recomputing digests, checking that
    no second fault crept in -- is meaningful only on a faithful parse, so the
    flag is what those checks key on rather than guessing from the content.

    Where a lenient decode still yields JSON, it is returned: that is exactly
    the substitution a lenient rail performs, so if the strict pass ever stopped
    rejecting these bytes the lossy value would flow onward and the vector would
    fail, which is the outcome it exists to force. Where even that fails, there
    is no value at all and the verifier answers from the bytes alone.
    """
    try:
        return json.loads(raw.decode("utf-8")), True
    except (UnicodeDecodeError, ValueError):
        pass
    try:
        return json.loads(raw.decode("utf-8", "replace")), False
    except ValueError:
        return None, False


def _run_process_vector(
    kind: str,
    path: str,
    idx: dict[str, dict[str, Any]],
    external_cmd: list[str] | None,
    ref_with: ReferenceVerifier,
    ref_without: ReferenceVerifier,
    report_base: str,
    keys_path: str,
) -> tuple[dict[str, Any], bool]:
    vid = os.path.splitext(os.path.basename(path))[0]
    entry = idx.get(vid)
    rel = os.path.relpath(path, report_base)
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_STATEMENT_BYTES + 1)
        if len(raw) > MAX_STATEMENT_BYTES:
            raise ValueError(f"statement exceeds {MAX_STATEMENT_BYTES} bytes")
        stmt, faithful = _load_statement(raw)
    except (OSError, ValueError, RecursionError) as e:
        return {
            "id": vid,
            "file": rel,
            "kind": kind,
            "status": "FAIL",
            "gates": {g: "FAIL" for g in GATE_NAMES},
            "reasons": [f"vector unreadable: {e}"],
            "verifierRan": False if external_cmd is not None else None,
        }, True

    observed = _run_observe(external_cmd, ref_with, ref_without, path, stmt, raw, keys_path)

    self_check = None
    if kind in ("reject", "indeterminate") and faithful:
        # The second-fault check recomputes derived commitments from the parsed
        # statement, so it is meaningful only when the parse was faithful. On a
        # byte-level vector the value above is a lossy reconstruction and every
        # digest recomputed from it would mismatch for the substitution rather
        # than for a second fault.
        expected = (entry or {}).get("expected") or {}
        # A precedence-pin vector carries a second fault on purpose, because
        # which of two conditions a rail must report can only be asked of a
        # statement carrying both. Its expected-code set stays a single code so
        # the pin still discriminates, and the deliberate companion faults are
        # declared separately. Only the declared ones are exempted, so an
        # UNdeclared second fault in the same vector still fails this check.
        exp_codes = set(expected.get("codes") or [])
        exp_codes |= set(expected.get("alsoCarries") or [])
        # An indeterminate member carries one fault per declared reading, all of
        # them on purpose, so the union of the predicted conditions is its
        # exemption key. Anything beyond that union is still an undeclared second
        # fault, and it would hand a rail an answer the readings do not cover.
        exp_codes |= {str(v) for v in (expected.get("readings") or {}).values()}
        self_check = second_fault_absence(stmt, exp_codes)

    ev = evaluate_vector_detailed(kind, entry, observed, self_check)
    row = {
        "id": vid,
        "file": rel,
        "kind": kind,
        "status": "PASS" if ev.ok else "FAIL",
        # The manifest's own two figures, kept apart. "conformance" is the
        # sentence the manifest defines -- verdict, and for an accepted
        # statement its result -- plus the tier columns and behaviour assertions
        # it states as requirements. "reasonParity" is the measured code
        # comparison, which is a datum about two vocabularies and not a claim
        # about conformance. A report carrying only "status" cannot say which of
        # the two a rail failed, and those are opposite findings.
        "conformance": "PASS" if not ev.reasons else "FAIL",
        "reasonParity": _parity_status(kind, ev.parity),
        "gates": ev.gates,
        "observed": {
            "verdict": observed["verdict"],
            "verdictWithoutKey": observed.get("verdict_without_key"),
            "codes": observed["codes"],
            "primaryCode": observed.get("primaryCode"),
            "result": observed["result"],
            # What the rail did NOT establish, which is the field the tier and
            # result comparisons now key on. Published because a reader deciding
            # whether to trust a census needs to see how much of it the rail
            # actually answered.
            "absent": observed.get("absent") or [],
            "errors": observed.get("errors") or [],
        },
        "expected": (entry or {}).get("expected"),
        # A declared exclusion, when the manifest entry carries one: the row
        # was not scored, and the v0.1 emitter reports it not-exercised with
        # this as its cause.
        "declaredExclusion": declared_exclusion((entry or {}).get("expected") or {}),
        "inManifest": entry is not None,
        # Whether the named verifier started and exited on BOTH key-policy
        # passes of this vector. Null on the reference rail.
        "verifierRan": observed.get("ran") if external_cmd is not None else None,
        "reasons": [*ev.reasons, *ev.parity],
        "conformanceReasons": ev.reasons,
        "reasonParityFindings": ev.parity,
    }
    return row, (not ev.ok)


def _parity_status(kind: str, parity: list[str]) -> str:
    """The parity column: only a reject vector states a code expectation."""
    if parity:
        return "FAIL"
    return "PASS" if kind == "reject" else "-"


def _closure_kind_coverage(listed: dict[str, list[str]]) -> list[str]:
    """The kinds the MANIFEST declares against the kinds this rail scores."""
    failures: list[str] = []
    for kind in sorted(listed):
        if kind not in REPLAYED_KINDS:
            failures.append(
                f"MANIFEST lists {listed[kind]} under kind {kind!r}, which no contract in "
                "this rail scores; evaluate_vector would read them under the reject "
                "contract. Add the contract and name the kind in REPLAYED_KINDS -- naming "
                "it alone is the same absence with a green tick on it"
            )
    for kind in REPLAYED_KINDS:
        if not listed.get(kind):
            failures.append(
                f"REPLAYED_KINDS names kind {kind!r} that the MANIFEST no longer carries, "
                "so the contract for it runs over nothing and asserts nothing"
            )
    return failures


def _closure_flat(
    suite_dir: str, idx: dict[str, dict[str, Any]], listed: dict[str, list[str]],
    flat: str
) -> tuple[list[str], dict[str, str]]:
    """Rows against files for a suite whose vectors share one directory."""
    failures: list[str] = []
    unlisted: dict[str, str] = {}
    held = set(vector_files_in(os.path.join(suite_dir, flat)))
    for kind in sorted(listed):
        if kind not in REPLAYED_KINDS:
            continue
        for vid in listed[kind]:
            declared = idx[vid].get("file")
            if not isinstance(declared, str) or not declared:
                failures.append(f"MANIFEST row {vid} declares no file")
                continue
            if not os.path.isfile(os.path.join(suite_dir, declared)):
                failures.append(
                    f"MANIFEST row {vid} declares file {declared!r}, which is "
                    "not on disk"
                )
    for vid in sorted(held):
        if not any(vid in listed[k] for k in listed):
            unlisted[vid] = flat
            failures.append(
                f"{flat}/{vid}.json is committed and named by no MANIFEST row, "
                "so it is replayed by nothing"
            )
    return failures, unlisted


def _closure_both_directions(
    suite_dir: str, idx: dict[str, dict[str, Any]], listed: dict[str, list[str]]
) -> tuple[list[str], dict[str, str]]:
    """Per kind, the MANIFEST rows against the vector files on disk, both ways.

    Returns the refusals and, for the identifiers a MANIFEST row does not
    name, the kind directory each was found in -- the caller marks those rows
    FAIL rather than leaving a totals line reading zero failures beside a
    non-zero exit.
    """
    # Every vector is checked against the file its MANIFEST row DECLARES. There
    # is no kind directory to derive a path from, and deriving one is what a
    # rail must stop doing once the layout stops naming the answer.
    return _closure_flat(suite_dir, idx, listed, flat_layout(idx))


def _closure_directories(
    suite_dir: str, listed: dict[str, list[str]], idx: dict[str, Any]
) -> list[str]:
    """Every directory under the suite root is a MANIFEST kind or a declared
    non-vector directory.

    The rule is set equality against SUITE_NON_VECTOR_DIRS, not "holds files
    this rail recognises as vectors". Asking whether a directory held any .json
    decides the question by file extension, so a directory carrying the same
    corpus in another encoding passes silently AND contributes to no per-kind
    count, which is the pair of blind spots that lets an unreplayed set look
    like an absent one.
    """
    failures: list[str] = []
    flat = flat_layout(idx)
    for name in sorted(os.listdir(suite_dir)):
        if not os.path.isdir(os.path.join(suite_dir, name)):
            continue
        if name in listed:
            continue
        if name == flat:
            continue  # the one directory every vector is declared to live in
        if name not in SUITE_NON_VECTOR_DIRS:
            failures.append(
                f"{name}/ is named by no MANIFEST kind and is not one of the suite's "
                f"declared non-vector directories {list(SUITE_NON_VECTOR_DIRS)}, so "
                "whatever it carries is replayed by nothing. Add the kind to the MANIFEST "
                "or name the directory in SUITE_NON_VECTOR_DIRS"
            )
            continue
        held = vector_files_in(os.path.join(suite_dir, name))
        if held:
            failures.append(
                f"{name}/ is declared to hold no vectors and holds {len(held)} vector file(s)"
            )
    return failures


def _counts_against_rows(
    suite_dir: str, counts: Any, listed: dict[str, list[str]], flat: str
) -> list[str]:
    """The counts block against the rows, and the rows against the directory."""
    failures: list[str] = []
    for kind in sorted(listed):
        if kind not in REPLAYED_KINDS:
            continue
        # One directory holds every kind, so a per-kind count cannot be read off
        # it. The rows carry the kind, and the TOTAL below is still grounded in
        # the directory, so the chain is unbroken: counts against rows, rows
        # against files.
        held = len(listed[kind])
        where = "the MANIFEST rows"
        if kind not in counts:
            failures.append(
                f"MANIFEST counts declares no entry for kind {kind!r}, which "
                f"{len(listed[kind])} row(s) carry"
            )
        elif counts[kind] != held:
            failures.append(
                f"MANIFEST counts[{kind!r}] is {counts[kind]}; {where} holds "
                f"{held} vector(s)"
            )
    total_files = len(vector_files_in(os.path.join(suite_dir, flat)))
    total_rows = sum(len(v) for v in listed.values())
    if total_files != total_rows:
        failures.append(
            f"{flat}/ holds {total_files} vector file(s) and the MANIFEST "
            f"carries {total_rows} row(s)"
        )
    return failures


def _closure_counts(
    suite_dir: str, counts: Any, listed: dict[str, list[str]],
    idx: dict[str, Any]
) -> list[str]:
    """The MANIFEST's own counts block against the tree.

    The block is a third copy of a number the rows and the files each already
    carry, so it is checked against the other two rather than trusted or
    ignored: a published corpus size that only ever agrees with itself is a
    cache nothing invalidates.
    """
    if counts is None:
        return ["MANIFEST carries no counts block, so the size it publishes is derived by nothing"]
    if not isinstance(counts, dict):
        return [f"MANIFEST counts is {type(counts).__name__}, not an object"]
    failures: list[str] = []
    flat = flat_layout(idx)
    failures.extend(_counts_against_rows(suite_dir, counts, listed, flat))
    for kind in sorted(counts):
        if kind not in listed:
            failures.append(
                f"MANIFEST counts declares kind {kind!r} that no MANIFEST row carries"
            )
    return failures


def manifest_closure(
    suite_dir: str, manifest: dict[str, Any], idx: dict[str, dict[str, Any]]
) -> tuple[list[str], dict[str, str]]:
    """Assert that the MANIFEST and the vector files on disk name each other
    exactly, in both directions and per kind.

    The replay is driven by the directories the MANIFEST names, so on its own it
    can only ever report on what it happened to walk: a .json committed into a
    vector directory with no MANIFEST row was scored against a verdict derived
    from its directory name, counted in the printed total, and reported as a
    note beside exit 0 -- and that total is the number the published corpus size
    derives from. Comparing the two listings is what makes "every vector was
    replayed, and only those" a measured claim rather than an assumption about
    whoever last regenerated the suite. The Go runner has refused the same tree
    by name since the directory blind spot was closed there.
    """
    listed = manifest_kinds(idx)
    failures = _closure_kind_coverage(listed)
    direction_failures, unlisted = _closure_both_directions(suite_dir, idx, listed)
    failures.extend(direction_failures)
    failures.extend(_closure_directories(suite_dir, listed, idx))
    failures.extend(
        _closure_counts(suite_dir, manifest.get("counts"), listed, idx)
    )
    return failures, unlisted


def _run_manifest_closure(
    manifest: dict[str, Any] | None,
    idx: dict[str, dict[str, Any]],
    suite_dir: str,
    rows_out: list[dict[str, Any]],
) -> tuple[list[str], int]:
    suite_notes: list[str] = []
    if manifest is None:
        suite_notes.append(
            "MANIFEST.json not found: expectations inferred from directory "
            "names only (verdict-level checks; no code, tier, or self-check "
            "exemption data)"
        )
        return suite_notes, 0
    failures, unlisted = manifest_closure(suite_dir, manifest, idx)
    # A closure failure attributable to one vector is written onto that vector
    # as well as into the suite notes, because a totals line reading "0 fail"
    # beside a non-zero exit is the shape of report this repository exists to
    # stop shipping.
    for row in rows_out:
        kind = unlisted.get(row["id"])
        if kind is None or row["kind"] != kind:
            continue
        row["status"] = "FAIL"
        row["conformance"] = "FAIL"
        row["reasons"] = [*row["reasons"], "no MANIFEST row names this file"]
        row["conformanceReasons"] = [
            *row["conformanceReasons"], "no MANIFEST row names this file"
        ]
        row["gates"]["gate0"] = "FAIL"
    suite_notes.extend(failures)
    return suite_notes, len(failures)


def _report_path(args: argparse.Namespace) -> str:
    """Where the report goes: --report, else beside this file."""
    return str(args.report) if args.report else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "conformance-report.json"
    )


def _run_write_report(
    args: argparse.Namespace,
    suite_dir: str,
    report_base: str,
    external_cmd: list[str] | None,
    rail_note: str,
    suite_notes: list[str],
    rows_out: list[dict[str, Any]],
    suite_refusals: int,
    executed: int | None,
) -> tuple[dict[str, Any], str]:
    report: dict[str, Any] = {
        "suite": os.path.relpath(suite_dir, report_base),
        "predicateType": AEE_PREDICATE_TYPE,
        "rail": "external" if external_cmd else "reference",
        "railNote": rail_note,
        # Which program answered, and on how many vectors. Null on the
        # reference rail. A consumer holds the executed count to the vector
        # count; the composite action does, and fails the job on any gap.
        "verifier": None
        if external_cmd is None
        else {
            "command": shlex.join(external_cmd),
            "vectorsExecuted": executed,
            "vectors": len(rows_out),
        },
        "pinnedTestKeyRole": PINNED_ROLE,
        "totals": {
            "vectors": len(rows_out),
            "pass": sum(1 for r in rows_out if r["status"] == "PASS"),
            "fail": sum(1 for r in rows_out if r["status"] == "FAIL"),
            # The manifest's two figures, reported separately because the
            # manifest says to: a rail conforms on verdict and result, and a
            # differing reason code is a parity datum about two vocabularies.
            # "conform" is therefore the number a rail may quote about itself;
            # "reasonParityMismatch" is the number that says how far its
            # vocabulary sits from this corpus's, and neither substitutes for
            # the other.
            "conform": sum(1 for r in rows_out if r.get("conformance") == "PASS"),
            "reasonParityMismatch": sum(
                1 for r in rows_out if r.get("reasonParity") == "FAIL"
            ),
            "suiteRefusals": suite_refusals,
            # Rows a declared exclusion kept out of the score. Counted so a
            # total that reads "all pass" says how many of its members were
            # never asked.
            "notExercised": sum(1 for r in rows_out if r.get("declaredExclusion")),
        },
        "comparisonSurface": {
            "normative": ["verdict", "result", "tierWithPinnedKey", "tierWithoutKey"],
            "measured": ["codes"],
            "note": (
                "A vector's conformance column is its verdict, its result token "
                "where the manifest declares one, both tier columns where it "
                "declares them, and the behaviour assertions. Its reasonParity "
                "column is the code comparison, which vectors/MANIFEST.json calls "
                "a datum rather than a failure. The status column still counts "
                "both, so the exit code has not moved."
            ),
        },
        "notes": suite_notes,
        "gateColumns": list(GATE_NAMES),
        "vectors": rows_out,
    }
    report_path = _report_path(args)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=False)
        f.write("\n")
    return report, report_path


def _run_print_table(
    report: dict[str, Any],
    rows_out: list[dict[str, Any]],
    suite_notes: list[str],
    rail_note: str,
    report_path: str,
    report_base: str,
) -> None:
    # stdout coverage table (gate x vector)
    print(f"rail: {report['rail']}  ({rail_note})")
    gate_cols = " ".join(f"{g:<10}" for g in GATE_NAMES)
    header = f"{'vector':<42} {'status':<6} {gate_cols}"
    print(header)
    print("-" * len(header))
    for r in rows_out:
        row_gates = " ".join(f"{r['gates'][g]:<10}" for g in GATE_NAMES)
        print(f"{r['id'][:42]:<42} {r['status']:<6} {row_gates}")
        if r["status"] == "FAIL":
            for reason in r["reasons"]:
                print(f"    ! {reason}")
    for note in suite_notes:
        print(f"note: {note}")
    t = report["totals"]
    refusals = ""
    if t.get("suiteRefusals"):
        refusals = f", {t['suiteRefusals']} suite-level refusal(s)"
    parity = ""
    if t.get("reasonParityMismatch"):
        parity = (
            f"; {t['conform']} of {t['vectors']} conform, "
            f"{t['reasonParityMismatch']} reason-parity mismatch(es)"
        )
    print(
        f"totals: {t['vectors']} vectors, {t['pass']} pass, {t['fail']} fail{refusals}"
        f"{parity}; report written to {shown_path(report_path, report_base)}"
    )
    verifier = report.get("verifier")
    if verifier is not None:
        ran, total = verifier["vectorsExecuted"], verifier["vectors"]
        line = f"verifier: {verifier['command']} ran on {ran} of {total} vectors"
        if ran != total:
            line += f"; MISMATCH: {total - ran} vector(s) were never answered by it"
        print(line)


# ---------------------------------------------------------------------------
# Built-in self-test: synthetic statements exercising the reference rail
# ---------------------------------------------------------------------------


def _selftest_build(keys: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Build a minimal valid substrate statement with arming + sealed +
    interception records signed by the derived test key."""

    def d(s: str) -> str:  # synthetic digest for the self-test statement
        return sha256_hex(s.encode())

    labels = ["example_label_a", "example_label_b"]
    caught = ["example_label_a"]
    manifest = {"classes": {"XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"]}}
    env: dict[str, Any] = {
        "substrate": {"name": "example-substrate", "digest": {"sha256": d("substrate")}},
        "corpus": {
            "name": "example-corpus",
            "uri": "pkg:example/corpus@1",
            "digest": {"sha256": sha256_hex(jcs_dumps(manifest))},
            "manifest": manifest,
        },
        "catchPolicy": {"digest": {"sha256": d("catch-policy-doc")}},
        "networkPosture": {"posture": "sinkhole", "digest": {"sha256": d("posture")}},
        "observationVocabulary": {
            "digest": {"sha256": sha256_hex(jcs_dumps({"caught": caught, "labels": labels}))},
            "labels": labels,
            "caught": caught,
        },
        "runEntropy": {"digest": {"sha256": d("run-start")}},
    }
    subject: list[dict[str, Any]] = [
        {"name": "example-agent-bundle", "digest": {"sha256": d("subject")}}
    ]
    binding = sha256_hex(jcs_dumps(binding_preimage(env, subject[0]["digest"]["sha256"])))
    ptype = "application/vnd.example.aee-observation.v1+json"
    seed = keys[PINNED_ROLE]["seed"]
    keyid = keys[PINNED_ROLE]["keyid"]

    def record(payload_obj: dict[str, Any]) -> dict[str, Any]:
        payload = jcs_dumps(payload_obj)
        sig = ed25519_sign(seed, pae(ptype, payload))
        return {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": ptype,
            "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}],
        }

    posture = env["networkPosture"]["digest"]["sha256"]
    rec_arming = record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "arming",
            "aeeMethod": "intercepted",
            "armedAt": "2025-12-31T23:59:00Z",
            "aeePostureDigest": posture,
            # Required on the kind from 0.7, and it must cover every identifier
            # the assessed classes name, or the statement is invalid on
            # assessed-set-exceeds-declaration.
            "aeeAssessedAttacks": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"],
        }
    )
    rec_intercept = record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "interception",
            "aeeMethod": "intercepted",
            # Required on the kind from 0.7. Its VALUES only have to resolve
            # against corpus.manifest.expectedPayloads on a row declaring
            # attribution: pinned, and neither row here does, so the shape rule
            # is the whole obligation: non-empty, sorted, duplicate-free,
            # lowercase 64-hex.
            "aeePayloadCommitment": [d("synthetic-payload")],
            "producerNote": "synthetic",
        }
    )
    # The seal commits to the interception set, so it is built AFTER the record
    # it commits to. The commitment is the same construction observed_set_digest
    # recomputes: the sorted, duplicate-free array of H(0x00 || PAE) over every
    # interception and examination record. Nothing here is circular, because the
    # sealed record is not itself a member of that set.
    intercept_pae = pae(
        rec_intercept["payloadType"], base64.b64decode(rec_intercept["payload"])
    )
    observed_leaves = sorted({hashlib.sha256(b"\x00" + intercept_pae).hexdigest()})
    rec_sealed = record(
        {
            "aeeRunBinding": binding,
            "aeeKind": "sealed",
            "aeeMethod": "intercepted",
            "aeeStillArmed": True,
            "aeeDropCount": 0,
            "aeePostureDigest": posture,
            "aeeObservedAttacks": ["XA-EXAMPLE-1"],
            "aeeObservedSet": sha256_hex(jcs_dumps(observed_leaves)),
        }
    )
    records = [rec_arming, rec_sealed, rec_intercept]
    leaves = [pae(r["payloadType"], base64.b64decode(r["payload"])) for r in records]
    stmt = {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": AEE_PREDICATE_TYPE,
        "predicate": {
            "result": "fail",
            "observationEnvironment": env,
            "coverage": {
                "assessedClasses": ["XA"],
                "outOfScope": {},
                "routedElsewhere": {},
            },
            "attackResults": [
                {
                    "attackId": "XA-EXAMPLE-1",
                    "containmentObserved": "example_label_a",
                    "basis": "substrate",
                    "method": "intercepted",
                    # paired, not pinned: the stronger label additionally
                    # obliges corpus.manifest.expectedPayloads and an
                    # aeePayloadCommitment on every resolved interception
                    # record, which is a surface of its own. What this statement
                    # needs from attribution is a value the closed vocabulary
                    # admits, because at 0.7 an absent one is fail-closed.
                    "attribution": "paired",
                    "actualLayer": "example.layer-a",
                    "observationRefs": [2],
                },
                {
                    "attackId": "XA-EXAMPLE-2",
                    "containmentObserved": "example_label_b",
                    "basis": "substrate",
                    "method": "intercepted",
                    "attribution": "paired",
                    "actualLayer": "none",
                    "observationRefs": [0, 1],
                },
            ],
            "observationRecords": records,
            "batchRoot": merkle_root_hex(leaves),
            "issuedAt": "2026-01-01T00:00:00Z",
        },
    }
    return stmt


def self_test() -> int:
    keys = derive_test_keys()
    ref = ReferenceVerifier([keys[PINNED_ROLE]["public"]])
    ref_nokey = ReferenceVerifier([])
    base = _selftest_build(keys)
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        checks.append((name, cond, detail))

    # Ed25519 known-answer test: the pure-Python RFC 8032 implementation must
    # reproduce a reference signature computed by the `cryptography` library for
    # a fixed seed and message (regenerate the expected value from cryptography
    # if this vector ever changes).
    _kat_seed = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    _kat_msg = b"aee-conformance ed25519 known-answer test"
    _kat_pub = bytes.fromhex("79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
    _kat_sig = bytes.fromhex(
        "fb6b33be7173edac6bbecc0c916806fa15e58360924d26b9c60466f491193f2b"
        "3aba43873d55404a43649ca8534736ca92941456ac379899dc443f9c2a03f607"
    )
    check(
        "ed25519 known-answer (RFC 8032, vs cryptography)",
        ed25519_sign(_kat_seed, _kat_msg) == _kat_sig
        and ed25519_verify(_kat_pub, _kat_msg, _kat_sig),
        "hand-rolled signature must match the reference",
    )

    # Comparator pin, mirrored from the Go rail's unit pin: a
    # supplementary-plane string orders BEFORE a BMP private-use code point
    # under UTF-16 code units and AFTER it under code points. With the
    # BMP-only profile enforced no corpus vector can probe this divergence,
    # so this is the only layer where the comparator's order stays
    # expressible; reverting the sort key to code-point order turns it red.
    check(
        "utf-16 code-unit comparator (supplementary before private-use)",
        sorted(["\ue000", "\U0001f600"], key=_utf16_sort_key) == ["\U0001f600", "\ue000"],
        "sort key must compare 16-bit code units, not code points",
    )

    o = ref.verify(base)
    check(
        "base statement valid",
        o.verdict == "valid" and o.result == "fail",
        f"codes={o.codes} result={o.result}",
    )
    check(
        "tiers with pinned key",
        o.tiers_with_key == ["attested", "attested"],
        str(o.tiers_with_key),
    )
    o2 = ref_nokey.verify(base)
    check(
        "tiers without key",
        o2.tiers_without_key == ["unattested", "unattested"],
        str(o2.tiers_without_key),
    )
    check(
        "tier never alters result",
        o2.result == o.result,
        f"{o2.result} vs {o.result}",
    )

    def mutate(fn: Callable[[dict[str, Any]], object]) -> Outcome:
        s = json.loads(json.dumps(base))
        fn(s)
        return ref.verify(s)

    def add_astral_label(s: dict[str, Any]) -> None:
        # Supplementary-plane label with the digest recomputed and sortedness
        # intact under both orders: the BMP-only rule is the only violation.
        v = s["predicate"]["observationEnvironment"]["observationVocabulary"]
        v["labels"] = [*v["labels"], "\U0001f600"]
        v["digest"]["sha256"] = sha256_hex(
            jcs_dumps({"caught": v["caught"], "labels": v["labels"]})
        )

    m = mutate(add_astral_label)
    check(
        "supplementary-plane vocabulary entry rejected (BMP-only profile)",
        m.verdict == "invalid" and "vocabulary-not-canonical" in m.codes,
        str(m.codes),
    )

    # Supplementary-plane member NAME in a covering payload covers nothing;
    # a supplementary-plane VALUE stays legal. Checked at the payload-parse
    # layer, where the covering-payload analysis reads it.
    bad_name = jcs_dumps({"aeeKind": "interception", "zz\U0001f600": "x"})
    try:
        strict_payload_parse(bad_name)
        bmp_name_rejected = False
        bmp_name_detail = "parse accepted a supplementary-plane member name"
    except IJsonError as e:
        bmp_name_rejected = e.code == "payload-not-canonical"
        bmp_name_detail = e.code
    check(
        "supplementary-plane payload member name rejected (BMP-only profile)",
        bmp_name_rejected,
        bmp_name_detail,
    )
    ok_value = jcs_dumps({"aeeKind": "interception", "note": "\U0001f600"})
    try:
        strict_payload_parse(ok_value)
        bmp_value_ok = True
        bmp_value_detail = ""
    except IJsonError as e:
        bmp_value_ok = False
        bmp_value_detail = e.code
    check(
        "supplementary-plane payload member VALUE stays legal",
        bmp_value_ok,
        bmp_value_detail,
    )

    m = mutate(lambda s: s["predicate"].__setitem__("result", "pass"))
    check(
        "carried pass on fail recompute",
        m.verdict == "invalid" and "result-recompute-mismatch" in m.codes,
        str(m.codes),
    )
    m = mutate(lambda s: s["predicate"].__setitem__("batchRoot", "0" * 64))
    check(
        "tampered batch root",
        "batch-root-mismatch" in m.codes,
        str(m.codes),
    )
    m = mutate(
        lambda s: s["predicate"]["observationEnvironment"]["observationVocabulary"][
            "labels"
        ].reverse()
    )
    check(
        "unsorted vocabulary labels",
        "vocabulary-not-canonical" in m.codes,
        str(m.codes),
    )
    m = mutate(lambda s: s["predicate"]["attackResults"][0].__setitem__("observationRefs", [0]))
    check(
        "caught row referencing arming only",
        "caught-row-uncovered" in m.codes,
        str(m.codes),
    )
    m = mutate(lambda s: s["predicate"]["attackResults"][0].__setitem__("method", "examined"))
    check(
        "unknown method on substrate row",
        "fail-closed-substrate-row" in m.codes,
        str(m.codes),
    )
    m = mutate(lambda s: s["predicate"]["observationEnvironment"].pop("runEntropy"))
    check(
        "missing runEntropy",
        "run-entropy-missing" in m.codes and "run-binding-mismatch" not in m.codes,
        str(m.codes),
    )
    m = mutate(lambda s: s["predicate"]["attackResults"][1].__setitem__("observationRefs", [7]))
    check("ref out of range", "ref-out-of-range" in m.codes, str(m.codes))

    # The duplicate scan and the batch-root check shared one guard on both
    # rails, so one record failing base64 suppressed both and a statement
    # carrying a duplicate beside an undecodable record reported the decode
    # failure alone. The corpus asks this over committed bytes at
    # v7622b2c58c2e272d; it is asked here as well because
    # the harness compares reject expectations by intersecting code sets, and
    # both conditions sit in one expected set, so replaying that vector passes
    # whether or not the duplicate is ever looked for. This is where the rail's
    # own claim to emit the SET of every failure it detects is checked.
    def duplicate_beside_undecodable(s: dict[str, Any]) -> None:
        recs = s["predicate"]["observationRecords"]
        recs.append(json.loads(json.dumps(recs[0])))
        recs.append({**recs[0], "payload": "@@@not base64@@@"})

    m = mutate(duplicate_beside_undecodable)
    check(
        "a duplicate is still found beside a record that does not decode",
        "record-undecodable" in m.codes and "duplicate-record" in m.codes,
        str(m.codes),
    )

    # The trap the shared guard was avoiding, and the reason the scan skips the
    # records that never decoded rather than keying them on their raw bytes: two
    # records that do not decode contribute the same absent leaf, so reading
    # them as duplicates of each other would be a finding about the scan. The Go
    # rail skips them, and a divergence here would be one no vector could
    # repair.
    def two_undecodable_records(s: dict[str, Any]) -> None:
        broken = {**s["predicate"]["observationRecords"][0], "payload": "@@@nope@@@"}
        recs = s["predicate"]["observationRecords"]
        recs.append(json.loads(json.dumps(broken)))
        recs.append(json.loads(json.dumps(broken)))

    m = mutate(two_undecodable_records)
    check(
        "two records that do not decode are not duplicates of each other",
        "record-undecodable" in m.codes and "duplicate-record" not in m.codes,
        str(m.codes),
    )

    dup_raw = (
        b'{"_type":"https://in-toto.io/Statement/v1","_type":"x",'
        b'"subject":[],"predicateType":"p","predicate":{}}'
    )
    o_dup = ref.verify({}, dup_raw)
    check(
        "statement-wide duplicate member rejected",
        o_dup.verdict == "invalid" and "statement-malformed" in o_dup.codes,
        f"codes={o_dup.codes}",
    )

    def wrong_signer(s: dict[str, Any]) -> None:
        seed = keys["wrong-signer-test"]["seed"]
        rec = s["predicate"]["observationRecords"][2]
        sig = ed25519_sign(seed, pae(rec["payloadType"], base64.b64decode(rec["payload"])))
        rec["signatures"] = [
            {
                "keyid": keys["wrong-signer-test"]["keyid"],
                "sig": base64.b64encode(sig).decode(),
            }
        ]

    s = json.loads(json.dumps(base))
    wrong_signer(s)
    o3 = ref.verify(s)
    check(
        "wrong-signer record: valid but unattested (signature failure is a "
        "tier outcome, never a failure code)",
        o3.verdict == "valid" and o3.tiers_with_key == ["unattested", "attested"],
        f"verdict={o3.verdict} tiers={o3.tiers_with_key} codes={o3.codes}",
    )

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print("{}  {}{}".format("PASS" if ok else "FAIL", name, f"  [{detail}]" if not ok else ""))
    print(f"self-test: {len(checks)} checks, {len(failed)} failed")
    return 1 if failed else 0


# ---------------------------------------------------------------------------


def shown_path(path: str, base: str) -> str:
    """A path as printed: relative to the suite's parent when it sits under it.

    Installed from the wheel, the suite's parent is site-packages and a report
    in the working directory is a chain of `..` from there, so a path that
    would leave the base is printed as given.
    """
    rel = os.path.relpath(path, base)
    return path if rel.startswith(os.pardir) else rel


def installed_layout() -> bool:
    """True when this module runs from the wheel rather than a checkout."""
    return os.path.isdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpora"))


def corpora_root() -> str:
    """Where the corpora live relative to this file, in either layout.

    Installed from the wheel, this module sits at
    ``agent_evidence_vectors/run_vectors.py`` and the corpora are packaged
    beside it under ``corpora/``. In a checkout it sits at
    ``packaging/run_vectors.py`` and the corpora are siblings of ``packaging/``.
    The installed layout is checked first because a checkout never carries a
    ``corpora/`` directory, so the two cannot be confused.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    if installed_layout():
        return os.path.join(here, "corpora")
    return os.path.normpath(os.path.join(here, os.pardir))


def shipped_corpora() -> list[str]:
    """Every corpus directory carrying a MANIFEST.json, by name, sorted.

    Read from disk rather than from a literal so that a corpus added to the
    repository is listed the moment it lands, and one removed stops being
    offered the moment it goes.
    """
    root = corpora_root()
    found = []
    for name in os.listdir(root):
        if name == "vectors" or name.startswith("vectors-"):
            if os.path.isfile(os.path.join(root, name, "MANIFEST.json")):
                found.append(name)
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent-evidence-vectors",
        description="AEE v0.7 conformance vector harness (differential when an "
        "external verifier is named, which then always runs; self-contained otherwise)",
    )
    parser.add_argument(
        "--vectors",
        default=None,
        help="suite directory containing MANIFEST.json, accept/, reject/ "
        "(overrides --corpus; default: the shipped corpus --corpus names)",
    )
    parser.add_argument(
        "--corpus",
        default="vectors",
        help="name of a shipped corpus directory to replay (default: vectors, the "
        "Adversarial Execution Evidence corpus this rail judges; see --list-corpora)",
    )
    parser.add_argument(
        "--list-corpora",
        action="store_true",
        help="print the shipped corpus names, one per line, and exit",
    )
    parser.add_argument(
        "--verifier",
        default=None,
        help="command line for an external verifier to run differentially, e.g. "
        "'./aee-verify -json' (also read from AEE_EXTERNAL_VERIFIER); it always "
        "runs, and a verifier that cannot be started exits 2 rather than falling "
        f"back to the reference rail; the key policy is handed to it in ${EXTERNAL_KEYS_ENV}",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="output path for conformance-report.json",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the built-in reference-rail self-test and exit",
    )
    parser.add_argument(
        "--emit-w3c-report",
        default=None,
        metavar="PATH",
        help="after the replay, also write the v0.1 per-check report of the W3C "
        "public-agent-conformance group, crosswalked from conformance-report.json",
    )
    args = parser.parse_args()
    if args.list_corpora:
        for name in shipped_corpora():
            print(name)
        return 0
    if args.self_test:
        return self_test()
    if args.vectors is None:
        args.vectors = os.path.join(corpora_root(), args.corpus)
    if args.report is None and installed_layout():
        # Beside this file is site-packages when the wheel is installed, and a
        # report written there is one nobody finds. The working directory is
        # where a relying party's CI looks for it.
        args.report = "conformance-report.json"
    args.report_written = None
    status = run_suite(args)
    if args.emit_w3c_report is not None:
        if args.report_written is None:
            # Reading whatever report sits at the path would emit a v0.1 report
            # for a run that never happened, from a file an earlier run left.
            print(
                f"v0.1 per-check report NOT written to {args.emit_w3c_report}: this "
                "run wrote no conformance report to crosswalk from",
                file=sys.stderr,
            )
            return status or 2
        _emit_w3c(args)
    return status


def _emit_w3c(args: argparse.Namespace) -> None:
    """Write the v0.1 report beside the harness report, from the harness report."""
    with open(args.report_written, encoding="utf-8") as handle:
        harness = json.load(handle)
    with open(args.emit_w3c_report, "w", encoding="utf-8") as handle:
        json.dump(w3creport.emit(harness), handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"v0.1 per-check report written to {args.emit_w3c_report}")


if __name__ == "__main__":
    sys.exit(main())
