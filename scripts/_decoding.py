#!/usr/bin/env python3
"""Decode the encoded spans a text-matching guard cannot see through.

WHY THIS MODULE EXISTS. Every identity guard in this repository matches TEXT.
Signed statements are the product, and a signed statement carries its payload
base64-encoded, so a forbidden first-party string inside a payload is invisible
to a text match while sitting in a file we publish. That was measured, not
argued: a range carrying 31 statement files whose signed payloads each held a
forbidden host produced 31 findings, 20 of them naming plain-text files and NONE
naming anything under `statements/`. The push was refused only because a
plain-text copy of the same string happened to sit in the generator beside the
encoded ones. Had the generator read that string from a variable, the guard
would have passed a real leak.

Base64 is not a variant spelling a wider pattern can reach, which is what
separates this from the underscore that once defeated a word-boundary match. The
only way to match it is to decode it, so that is what this does: every encoded
span a line carries is decoded, every level of nesting is followed, and the
caller applies its own rules to what comes back as well as to the raw text.

WHAT IS TREATED AS A CARRIER, and why each one is plausible here.

  base64   both alphabets, padded or not. A DSSE envelope's `payload` is
           standard base64; a JWS-shaped field and anything that has travelled
           through a URL is the URL-safe alphabet; producers that strip `=`
           are common enough that requiring padding would be the whole gap
           again one character narrower.
  hex      a digest field is hex and decodes to noise, but hex is also how this
           repository's own guards hold the strings they forbid, so a string
           encoded the way the guard encodes it is exactly the shape that
           would be missed.
  percent  a URL-encoded fragment inside a JSON string value, which is how a
           host reaches a document that is otherwise escaped.

NESTING. A bundle holds an envelope, an envelope holds a statement, a statement
holds a field that may itself be encoded, so decoding once is not enough. Each
decoded result is fed back in up to `MAX_DEPTH` levels, and the layers crossed
are reported so a reader knows where the string actually sits, and is not told
only which file it was in.

A NESTED JSON DOCUMENT IS ONE OF THOSE LAYERS, and for a while it was the one
this module could see and would not follow. A corpus holds its members as
strings, so an envelope arriving as a member is a JSON document held inside
another JSON document -- not base64, not hex, not percent-encoded, so no decode
applies to it and the walk used to stop at the outer level with the candidate
offered and discarded. Measured: an envelope that on its own yields one view
and finds the host yielded ZERO views once embedded as `$[0].bundle`, and a
34 KB corpus returned nothing while the host sat in 19 places. A string that
parses as a document is now walked as one, under the same depth cap and a cycle
guard, so `$[0].bundle -> json $.payload -> base64` reads all the way through.

WHAT KEEPS THIS CHEAP. Decoding is attempted only on spans long enough to carry
anything, a decode is kept only when it yields printable UTF-8 (which discards
every digest, key and image blob without the caller ever seeing it), and one
budget caps the number of decodes and the total decoded size per input. A guard
slow enough to be worth skipping is a guard that gets skipped, and a guard that
explodes on a binary file is a guard that gets disabled.

Nothing here prints, and nothing here decides. The caller owns the rules and
owns whether a decoded string is ever echoed -- these guards withhold the text
they match on purpose, because printing it reproduces the leak into a CI log.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import urllib.parse
from collections.abc import Iterator
from typing import Any

# A span shorter than this cannot be a base64-encoded carrier worth chasing: the
# shortest string these guards forbid is seven characters, which encodes to
# twelve, and a threshold at twelve matches almost every identifier in a source
# file. Sixteen is the smallest value that keeps ordinary code quiet, and a
# JSON string VALUE is delimited and never guessed at, so it is chased from
# eight and the gap the threshold leaves is only in unstructured prose.
MIN_SPAN = 16
MIN_VALUE = 8

# Four levels reaches a bundle holding an envelope holding a statement holding
# one more encoded field. A fifth level has never been observed and every level
# multiplies the work.
MAX_DEPTH = 4

# Per input, not per file: at most this many decodes are kept and at most this
# many decoded characters are produced. A large binary blob yields neither,
# because it is not printable, but a file of concatenated base64 would otherwise
# grow the work without bound.
#
# MAX_OUTPUT IS THE REAL BOUND AND THE COUNT IS ONLY A PROXY FOR IT, which is
# why the count is loose. A count caps a number of ITEMS, so it is a claim about
# how the input happens to be chunked, and repacking the same bytes makes it go
# stale without a word: 128 was sized against one envelope per input, and the
# moment envelopes arrive packed as members of one corpus it is a cap on
# MEMBERS. Measured at 128, a corpus of 100 envelopes reported 64 of its 100
# hosts and a corpus of 100 bundles reported 42 -- the module stopped looking
# two thirds of the way through and returned a short list that reads exactly
# like a thorough one. Raised to 1024, both report every host, a 400-member
# corpus costs 208 ms against 43 ms, and a 300 KB random-base64 blob is
# unchanged because it keeps nothing and its cost is the regex scan. Bytes, not
# items, are what a pre-send gate can afford to bound on.
MAX_DECODES = 1024
MAX_OUTPUT = 1 << 19

# A span that is only a prefix of a longer run would decode to a truncation, so
# the runs are matched greedily and whole.
BASE64_SPAN = re.compile(rf"[A-Za-z0-9+/_-]{{{MIN_SPAN},}}={{0,2}}")
HEX_SPAN = re.compile(rf"(?:[0-9a-fA-F]{{2}}){{{MIN_SPAN // 2},}}")
PERCENT_SPAN = re.compile(r"(?:[A-Za-z0-9._~/:-]*%[0-9a-fA-F]{2})+[A-Za-z0-9._~/:-]*")

# The JSON key immediately before a span, so a finding inside a diff line can
# name the field it sits in even though one line of a pretty-printed file is not
# itself parseable JSON.
KEY_BEFORE = re.compile(r"\"([A-Za-z_][A-Za-z0-9_.-]*)\"\s*:\s*\"?$")

# Enough of the decoded bytes must be printable for the result to be text at
# all. Below this it is a digest, a key or an image, and feeding it to a rule
# only costs time.
PRINTABLE_FLOOR = 0.9


# EVERY ENCODED SPAN THIS REPOSITORY'S OWN GUARDS HOLD AS RULE MATERIAL.
#
# One list, not one per guard, because the guards read each other's
# source: the tracked-content scan reads every tracked file, so the history
# scanner's word list is an input to it, and a per-guard list would leave each
# guard refusing the other's rules. Each guard checks that its own spans appear
# here and refuses to run if they do not, so the list cannot fall behind a rule
# it is supposed to cover. See `material` for why the exemption is the literal
# and not the file.
GUARD_SPANS: tuple[str, ...] = (
    "67657470726f62697479",
    "70726f62697479",
    "6d617463686c6f636b",
    "6d63705b2d5f205d746573745b2d5f205d746f6f6c6b6974",
    "70726f626974796169",
)


def material(*spans: str) -> frozenset[str]:
    """Digest the exact encoded spans a guard holds as its OWN rule material.

    AN IDENTITY GUARD IN A PUBLIC REPOSITORY CANNOT BE SELF-CONSISTENT UNDER
    DECODING, and this function is the whole answer to that. A guard that
    matches a term has to hold the term, and holding it in any decodable form
    makes the guard's own source a carrier of exactly what it forbids. The
    guards here hold theirs hex-encoded so that a text match reads past them,
    which worked until this module began decoding: the first run of the fixed
    scanner refused the scanner's own commit, naming the line its word list is
    built from.

    The escape is NOT a path exemption. A path exemption stops being about the
    literal the moment the literal moves, and it is an open door for every other
    string in the same file. The escape is the literal itself: a guard hands in
    the exact spans it holds, and a decode of exactly one of those spans is not
    reported. Because the set is derived from the same tuple the rules are built
    from, it cannot go stale, it cannot be widened by editing a list of files,
    and every other encoded span -- in that file, in that line, one character
    different -- is still decoded and still matched.
    """
    return frozenset(hashlib.sha256(span.encode("utf-8")).hexdigest() for span in spans)


GUARD_MATERIAL = material(*GUARD_SPANS)


class Budget:
    """The cap on one input's decoding. Shared across every level of nesting."""

    def __init__(self) -> None:
        self.decodes = 0
        self.output = 0

    def take(self, decoded: str) -> bool:
        """Account for one kept decode, or refuse because the input is spent."""
        if self.decodes >= MAX_DECODES or self.output + len(decoded) > MAX_OUTPUT:
            return False
        self.decodes += 1
        self.output += len(decoded)
        return True


def _text(raw: bytes) -> str | None:
    """`raw` as text, or None when it is not printable UTF-8."""
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\t\n\r")
    if printable < PRINTABLE_FLOOR * len(decoded):
        return None
    return decoded


def _base64(span: str) -> str | None:
    """`span` decoded under whichever alphabet accepts it, padding supplied."""
    body = span.rstrip("=")
    if len(body) % 4 == 1:
        return None  # no base64 encoding has this length
    padded = body + "=" * (-len(body) % 4)
    for translate in (str.maketrans("", ""), str.maketrans("-_", "+/")):
        try:
            raw = base64.b64decode(padded.translate(translate), validate=True)
        except (binascii.Error, ValueError):
            continue
        text = _text(raw)
        if text is not None:
            return text
    return None


def _hexadecimal(span: str) -> str | None:
    try:
        raw = bytes.fromhex(span)
    except ValueError:
        return None
    return _text(raw)


def _percent(span: str) -> str | None:
    """`span` percent-decoded, via BYTES and never via `unquote`.

    `unquote(..., errors="strict")` raises on an escape that is not valid UTF-8,
    and an uncaught raise here stops the whole scan: the first full-tree run
    after this module was added died on one such escape after 1.6 seconds and
    printed nothing, which is a guard reporting no findings because it never
    looked. Decoding to bytes and handing them to `_text` gives a percent span
    the same treatment every other carrier gets -- not text, not a carrier.
    """
    if "%" not in span:
        return None
    text = _text(urllib.parse.unquote_to_bytes(span))
    return text if text is not None and text != span else None


def decodings(value: str) -> Iterator[tuple[str, str]]:
    """Every way `value` decodes, as (encoding name, decoded text)."""
    for name, decode, floor in (
        ("base64", _base64, MIN_VALUE),
        ("hex", _hexadecimal, MIN_VALUE),
        ("percent-encoding", _percent, 4),
    ):
        if len(value) < floor:
            continue
        decoded = decode(value)
        if decoded is not None and decoded != value:
            yield name, decoded


def _json_strings(node: Any, path: str) -> Iterator[tuple[str, str]]:
    """Every string value in a parsed document, with its key path."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _json_strings(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _json_strings(value, f"{path}[{index}]")


def _parsed(text: str) -> Any | None:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        return None


def _spans(text: str) -> Iterator[tuple[str, str]]:
    """Every encoded-looking run in unstructured text, with the key before it."""
    seen: set[str] = set()
    for pattern in (BASE64_SPAN, HEX_SPAN, PERCENT_SPAN):
        for found in pattern.finditer(text):
            span = found.group(0)
            if span in seen:
                continue  # the three patterns overlap; one run is one candidate
            seen.add(span)
            key = KEY_BEFORE.search(text[: found.start()])
            yield (f"${'.' + key.group(1) if key else ''}", span)


def candidates(text: str) -> Iterator[tuple[str, str]]:
    """Every (key path, encoded value) pair `text` offers.

    A document that parses as JSON is walked, because a key path names where a
    string sits far better than an offset does. Anything else -- one line of a
    pretty-printed file, a commit message, a decoded payload that is not itself
    JSON -- is scanned for encoded-looking runs.
    """
    document = _parsed(text)
    if document is None:
        yield from _spans(text)
        return
    for path, value in _json_strings(document, "$"):
        if len(value) >= MIN_VALUE:
            yield path, value


def _descend(
    layer: str,
    text: str,
    depth: int,
    found: list[tuple[str, str]],
    budget: Budget,
    exempt: frozenset[str],
    chain: frozenset[str],
) -> bool:
    """Record one layer's text as a view and walk what it reveals.

    False means the input's budget is spent and the caller must stop, which is
    the same contract the budget always had: a guard that keeps going past its
    cap is a guard slow enough to be worth skipping.

    THE CYCLE GUARD IS THE `chain`, which carries the digest of every text
    already open on this path from the input downwards. Depth alone bounds a
    chain that keeps producing NEW text; it does not stop a payload that
    re-produces one of its own ancestors, which would then be walked again at
    every remaining level for no new finding. Skipping a text already on the
    path costs one digest and cannot lose anything, because the identical text
    was walked where it first appeared and its findings are already recorded.
    """
    if not budget.take(text):
        return False
    found.append((layer, text))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if digest not in chain:
        _walk(text, f"{layer} ", depth + 1, found, budget, exempt, chain | {digest})
    return True


def _walk(
    text: str,
    prefix: str,
    depth: int,
    found: list[tuple[str, str]],
    budget: Budget,
    exempt: frozenset[str],
    chain: frozenset[str],
) -> None:
    """Every layer `text` offers, recorded and then followed one level deeper.

    A NESTED JSON DOCUMENT IS A CARRIER IN ITS OWN RIGHT, and treating it as one
    is what this second branch does. `candidates` parses a document and hands
    back its string VALUES, so an envelope that arrives as a member of a corpus
    -- one JSON document held as a string inside another -- was offered to the
    rules as an opaque string and then dropped, because it is not base64, not
    hex and not percent-encoded, so `decodings` yielded nothing and the walk
    stopped at the outer level. Measured: the same envelope that yields one view
    and one found host on its own yielded ZERO views once embedded as
    `$[0].bundle` in a corpus array, and on a 34 KB corpus the module returned
    nothing at all while the host sat in 19 places. The candidate was offered
    and discarded, which is the worst shape a guard can have -- it looked.

    THE NESTED DOCUMENT IS RECORDED AS A VIEW AND NOT ONLY WALKED, because
    unescaping is itself a decoding and this is where the CARRIER's escapes
    resolve. A carrier may hold the nested document with a name written
    `\\u0065xample.invalid`, which is legal JSON, invisible to a text match over
    the raw bytes, and restored to `e` by the one parse that produced this
    value -- so the view carries a plain name the file does not. That is
    measured, and it is the whole reason for recording: `views` over such a
    carrier returns one view whose text holds the name while `HOST in raw` is
    false. The layer name also makes a reader's path complete, which a walked
    but unrecorded layer would leave with a gap in the middle.

    WHAT THIS DOES NOT REACH, so nobody reads the case above as more than it
    is. The escape has to belong to the CARRIER. A `\\u` escape applied by the
    nested document's own producer survives into this view unresolved, and it
    resolves only when that document is parsed one level down -- where the name
    lands in a plain string VALUE, and a plain value is offered to `decodings`,
    decodes as nothing and is never recorded. So a name hidden by a unicode
    escape one level below its carrier is still missed, and so is the same
    escape in a top-level document with no nesting at all. That gap is older
    than this branch and is not narrowed by it; closing it means recording a
    parsed value whose unescaping changed its bytes, which is a different rule
    with a false-positive profile of its own (every string holding a newline
    differs from its carrier) and is not decided here.
    """
    if depth >= MAX_DEPTH:
        return
    for path, value in candidates(text):
        if hashlib.sha256(value.encode("utf-8")).hexdigest() in exempt:
            continue  # a guard's own rule material; see `material`
        for name, decoded in decodings(value):
            if not _descend(f"{prefix}{path} -> {name}", decoded,
                             depth, found, budget, exempt, chain):
                return
        if _parsed(value) is not None and not _descend(
                f"{prefix}{path} -> json", value,
                depth, found, budget, exempt, chain):
            return


def views(text: str, exempt: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    """Every decoded view of `text`, as (layers crossed, decoded text).

    The layers read left to right from the outside in, so a caller can print
    where a string sits: `$.payload -> base64 $.predicateType` says the hit is
    in the `predicateType` member of the JSON that the envelope's base64
    `payload` decodes to, and `$[0].bundle -> json $.payload -> base64` says the
    same envelope arrived as one member of a corpus.

    `exempt` holds digests from `material`: the exact spans the calling guard
    carries as its own rule material, which are skipped and never decoded.

    The input's own digest seeds the cycle guard, so a document that embeds
    itself verbatim is followed once and not again.
    """
    found: list[tuple[str, str]] = []
    seed = hashlib.sha256(text.encode("utf-8")).hexdigest()
    _walk(text, "", 0, found, Budget(), exempt, frozenset({seed}))
    return found
