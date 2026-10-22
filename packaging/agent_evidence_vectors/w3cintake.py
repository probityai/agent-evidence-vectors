"""Intake criteria for a submitted conformance result, W3C public-agent-conformance.

The criteria are the group's: version 2 as posted to the list on 2026-10-13
(archive 2026Oct/0067), with the five wording deltas the editor accepted inside
the 48-hour objection window that followed it (2026Oct/0070 deltas 1 to 4,
2026Oct/0075 delta 5) and the explicit field 2026Oct/0073 announced for the
consolidated v2.1 text. Every rejection ground below is a sentence of those
messages; ``vectors-w3c-intake/MANIFEST.json`` binds each identifier to its
sentence by sha256, and the corpus holds at least one record that must pass
and one a careless intake reader would admit and that must be refused, for
every ground.

Three things live here, stdlib-only, for the reason ``w3creport.py`` gives: a
relying party runs it with nothing installed.

1. A CHECKER for an intake record: ``rejections(record, root=None)`` returns
   the sorted identifiers the record is refused under, an empty list for a
   record that is admitted. The checks that need bytes on disk (member pins,
   the both-way inventory against the package, the native output carried
   unaltered, the anchor, helper and checker-source pins) run only when
   ``root`` names the directory the record's paths are relative to;
   ``ROOT_GROUNDS`` lists them and the command line says which ran.
2. A JUDGE for the corpus: ``judge(directory)`` reads
   ``vectors-w3c-intake/MANIFEST.json`` and says of every member whether the
   checker refuses it under exactly the ground the manifest expects. Its
   printed form is byte-identical to what ``aee-verify <dir>`` prints from the
   Go reader in ``corpora/w3cintake.go``.
3. A COMMAND LINE: ``python -m agent_evidence_vectors.w3cintake record.json
   [--root DIR]``, exit 0 admitted, 1 refused, 2 unreadable.

The criteria name no implementation (criterion 13). The identifiers and the
vectors are the shared test: any intake reader conforms by refusing every
reject member under the ground it names and admitting every accept member.
This module is one reader that does.

What is the group's and what is ours. The rules are the group's. The text
states rules and fixes no field names, so the record shape is ours, and where
v0.1 of the per-check report already named something this record reuses the
name: a per-case line is a v0.1 check (``check``, ``state`` from the five v0.1
states), a carried or referenced observation uses v0.1's ``carried`` and
``reference``, the two anchor failure kinds are v0.1's causes
``availability-failure`` and ``integrity-failure``, and the canonicalization
identifier is drawn from v0.1's digest-encoding set (``jcs-sha256``). The
fields below are ours, each carrying a rule the group stated without a field:

- ``boundary.member-locations`` (criterion 2(iii) as amended): where members
  of a package declared complete live, as directory (empty for the package
  root itself), suffix and recursion, so
  "an unexpected member inside a package declared complete" is decidable and
  "a file outside that package" is not part of the claim.
- ``selector.language`` = ``id-glob`` (criterion 3): ``*`` matches any run of
  characters, every other character matches itself, over the manifest's ids.
  ``selector.require`` is ``exactly-one`` or ``at-least-one``.
- ``exit-rule`` (criterion 4): ``zero-iff-every-check-passes`` makes the exit
  code one more value compared against the recount; ``undeclared`` carries it
  without a comparison.
- ``refusal-verdicts`` and ``refusals`` (criterion 4 with delta 5): the native
  verdicts that are refusals, and per refusal its rule and its inputs, each
  input naming material inside the record: ``member:<id>``, ``check:<id>``,
  ``aggregate`` or ``exit-code``.
- ``native.format`` = ``corpus-result-json-v1`` (criterion 5): the one-line
  JSON object ``aee-verify -json <corpus>`` prints, ``members`` of ``id``,
  ``kind`` and ``findings``; the summary is the text it prints without
  ``-json``. In this format a member passes exactly when it carries no
  finding, so a per-case state is recounted from its own native line.
- ``carry`` (criterion 6): ``carried``, ``referenced`` or ``absent``.
- ``artifacts`` (criterion 6 with 2026Oct/0090 and 0091): every file of the
  package that is neither a member nor the manifest, pinned by its bytes, with
  ``consumed`` either ``consumed`` or ``unconsumed`` and the evidence that
  decides it: the swap-and-re-pin test of 0091 (replace the file's bytes, move
  every pin that covers it, rerun the checker) as the native result before and
  after, and for an unconsumed file the grounds that refuse its swap while its
  pin stays (``refused-by``). An artifact is consumed exactly when the two
  native results differ, so opening a file is not consuming it.
- ``anchor.kind`` = ``digest-list-line`` (criterion 7): a line of a digest
  list naming the corpus digest and the manifest path, the form
  ``release/CORPUS-DIGESTS.txt`` takes. ``signed-digest-list`` is the same
  line in a list that carries a detached signature: ``signature`` names the
  signature file, the public key file and its sha256, and the scheme
  (``ed25519``, RFC 8032 over the list's exact bytes, the signature base64 in
  its file, the key an Ed25519 SubjectPublicKeyInfo in PEM). The reader
  verifies the signature; locating the line is not checking the anchor. A
  signature or key that does not resolve is an availability failure, and one
  that resolves and does not verify, or a key that is not the pinned one, is an
  integrity failure.
- ``anchor.routine-file`` (criterion 9): the file a ``corpus-routine`` digest's
  routine lives in, when the routine is code. A named routine whose file does
  not resolve under the root leaves the anchor digest's input undeclared.
- ``checker.revision`` (criterion 8): ``git-commit`` (40 or 64 hex digits) or
  ``source-listing``, a digest over the checker's source files, recomputable
  from the bytes.
- ``specification-readers`` (criterion 8, the field 0073 announced): the
  readers written from the specification that have run against the suite,
  an empty list when none has.
- serializations (criterion 9): ``bytes`` (the exact file bytes),
  ``sha256-listing-v1`` (SHA-256 over ``<sha256>  <path>\\n`` lines sorted by
  path, the ``sha256sum`` form) and ``corpus-routine`` (a corpus's own digest
  routine, named in ``routine``).
- ``byte-identity`` and ``replay-stability`` (criterion 10): two objects;
  ``replay-stability.state`` is ``stable``, ``varies`` or ``not-measured``;
  ``ordering`` is ``emission-order``, ``sorted`` or ``hash-order``, the last
  needing ``seed``.
- ``faults`` and ``relaxed-controls`` (criterion 11): ``native-claim`` and
  ``isolation-claim`` are recomputed from the paired baseline and relaxed
  results.
- ``scope.does-not-claim`` (criterion 12): the four limits as tokens.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
from typing import Any, TypeGuard

SUITE = "w3c-intake-v2-conformance"
FORMAT = "public-agent-conformance/intake-record/v2"

#: Ground identifiers, minted by the corpus. The sentence each binds to is in
#: vectors-w3c-intake/MANIFEST.json and the corpus's INDEX.md.
G = {n: f"W3C-I-{n:03d}" for n in range(1, 49)}

#: The grounds that read bytes on disk and run only under a root.
ROOT_GROUNDS = (G[2], G[3], G[8], G[19], G[23], G[24], G[25], G[26], G[28], G[33])

#: v0.1's five states, reused for a per-case line, a fault result and the two
#: halves of a relaxed control.
STATES = ("pass", "fail", "inconclusive", "not-exercised", "void")
SELECTOR_LANGUAGES = ("id-glob",)
SELECTOR_REQUIRE = ("exactly-one", "at-least-one")
EXIT_RULES = ("zero-iff-every-check-passes", "undeclared")
INPUT_LITERALS = ("aggregate", "exit-code")
NATIVE_FORMATS = ("corpus-result-json-v1",)
CARRY = ("carried", "referenced", "absent")
CONSUMED = ("consumed", "unconsumed")
CONSUMPTION_TESTS = ("swap-and-re-pin",)
ANCHOR_KINDS = ("digest-list-line", "signed-digest-list")
SIGNATURE_SCHEMES = ("ed25519",)
ANCHOR_FAILURES = ("availability-failure", "integrity-failure")
#: A verdict for an anchor failure is any state but pass: an anchor that does
#: not resolve, or resolves to other bytes, never passes.
ANCHOR_VERDICTS = ("fail", "inconclusive", "not-exercised", "void")
REVISION_KINDS = ("git-commit", "source-listing")
RELATIONSHIPS = ("same-implementation", "reference-derived", "written-from-specification")
#: v0.1's digest-encoding set; the encodings this reader implements.
ENCODINGS = ("jcs-sha256",)
BYTES, LISTING, ROUTINE = "bytes", "sha256-listing-v1", "corpus-routine"
SERIALIZATIONS = (BYTES, LISTING, ROUTINE)
REPLAY_STATES = ("stable", "varies", "not-measured")
ORDERINGS = ("emission-order", "sorted", "hash-order")
EXPOSURE = ("visible", "hidden")
NATIVE_CLAIMS = ("unchanged", "changed")
ISOLATION_CLAIMS = ("isolates", "does-not-isolate")
SCOPE_LIMITS = (
    "whole-attack-surface",
    "implementation-ranking",
    "threats-outside-corpus",
    "action-occurred-or-authority",
)

NO_WEAKENING: frozenset[str] = frozenset()


# --------------------------------------------------------------------------
# Small readers. Every field is read defensively: a field of the wrong type is
# the ground for that field, never an exception.
# --------------------------------------------------------------------------


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _obj(value: Any) -> TypeGuard[dict[str, Any]]:
    return isinstance(value, dict)


def _str(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _strs(value: Any) -> bool:
    return isinstance(value, list) and all(_str(v) for v in value)


def _hex(value: Any, lengths: tuple[int, ...] = (64,)) -> bool:
    return (
        isinstance(value, str)
        and len(value) in lengths
        and all(c in "0123456789abcdef" for c in value)
    )


def _field(obj: Any, key: str) -> Any:
    return obj.get(key) if _obj(obj) else None


def _list(obj: Any, key: str) -> list[Any]:
    value = _field(obj, key)
    return value if isinstance(value, list) else []


def listing_digest(entries: list[tuple[str, str]]) -> str:
    """sha256-listing-v1: SHA-256 over ``<sha256>  <path>\\n`` sorted by path."""
    lines = "".join(f"{digest}  {path}\n" for path, digest in sorted(entries))
    return sha(lines.encode("utf-8"))


def glob_match(pattern: str, text: str) -> bool:
    """id-glob: ``*`` matches any run of characters, anything else itself."""
    p = t = 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(pattern) and pattern[p] == "*":
            star, mark = p, t
            p += 1
        elif p < len(pattern) and pattern[p] == text[t]:
            p += 1
            t += 1
        elif star >= 0:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def safe_path(rel: Any) -> bool:
    """A record path: relative, forward slashes, no empty or dot segments."""
    if not _str(rel) or rel.startswith("/") or "\\" in rel:
        return False
    return all(part not in ("", ".", "..") for part in rel.split("/"))


def _read(root: str, rel: Any) -> bytes | None:
    if not safe_path(rel):
        return None
    path = os.path.join(root, *rel.split("/"))
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        return handle.read()


def _walk(root: str, rel: str, suffix: str, recursive: bool) -> list[str]:
    """Files under root/rel ending in suffix, as record paths, sorted.

    A rel that is not a record path lists nothing, so a manifest root such as
    ``..`` cannot walk outside the directory the operator named.
    """
    if not safe_path(rel):
        return []
    base = os.path.join(root, *rel.split("/"))
    if not os.path.isdir(base):
        return []
    found: list[str] = []
    if recursive:
        for current, dirs, files in os.walk(base):
            dirs.sort()
            for name in files:
                full = os.path.join(current, name)
                found.append(os.path.relpath(full, root).replace(os.sep, "/"))
    else:
        for name in os.listdir(base):
            if os.path.isfile(os.path.join(base, name)):
                found.append(rel + "/" + name)
    return sorted(f for f in found if f.endswith(suffix))


def source_listing(root: str, paths: list[str]) -> str | None:
    """The sha256-listing-v1 digest over every file a revision's paths name."""
    entries: list[tuple[str, str]] = []
    for rel in paths:
        if not safe_path(rel):
            return None
        full = os.path.join(root, *rel.split("/"))
        if os.path.isfile(full):
            files = [rel]
        elif os.path.isdir(full):
            files = _walk(root, rel, "", True)
        else:
            return None
        for name in files:
            body = _read(root, name)
            if body is None:
                return None
            entries.append((name, sha(body)))
    return listing_digest(entries)


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032), verification only, so a signed anchor is checked with
# nothing installed. Decoding follows Go's crypto/ed25519, which the twin
# reader in corpora/w3cintake.go calls: the public key's y is taken modulo p,
# and the signature's R is compared as bytes against the recomputed point, so
# both readers accept and refuse the same signatures.
# --------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_Point = tuple[int, int, int, int]
#: The DER prefix of an Ed25519 SubjectPublicKeyInfo: SEQUENCE, the algorithm
#: identifier 1.3.101.112, and a 33-byte BIT STRING holding the 32-byte key.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _point_add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(scalar: int, point: _Point) -> _Point:
    result: _Point = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _recover_x(y: int, sign: int) -> int | None:
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = (_P - x) % _P
    return x


def _decode_point(encoded: bytes) -> _Point | None:
    value = int.from_bytes(encoded, "little")
    y = (value & ((1 << 255) - 1)) % _P
    x = _recover_x(y, value >> 255)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _encode_point(point: _Point) -> bytes:
    inverse = pow(point[2], _P - 2, _P)
    x, y = point[0] * inverse % _P, point[1] * inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE_X = _recover_x(_BASE_Y, 0) or 0
BASE_POINT: _Point = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 section 5.1.7, cofactorless, R compared as bytes."""
    if len(public) != 32 or len(signature) != 64:
        return False
    point = _decode_point(public)
    if point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    negated: _Point = ((_P - point[0]) % _P, point[1], point[2], (_P - point[3]) % _P)
    recomputed = _point_add(_point_mul(s, BASE_POINT), _point_mul(k, negated))
    return _encode_point(recomputed) == signature[:32]


def ed25519_public_key(pem: bytes) -> bytes | None:
    """The 32-byte key of a PEM ``PUBLIC KEY`` block holding an Ed25519 SPKI."""
    lines = pem.decode("ascii", "replace").strip("\n").split("\n")
    if len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or (
        lines[-1] != "-----END PUBLIC KEY-----"
    ):
        return None
    der = _base64("".join(lines[1:-1]).encode("ascii", "replace"))
    if der is None or len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        return None
    return der[len(ED25519_SPKI_PREFIX):]


def _base64(text: bytes) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def signature_bytes(body: bytes) -> bytes | None:
    """A detached signature file: standard base64 of 64 bytes, trailing newlines allowed."""
    decoded = _base64(body.rstrip(b"\n"))
    return decoded if decoded is not None and len(decoded) == 64 else None


# --------------------------------------------------------------------------
# The grounds. Each function adds the identifiers it finds to ``out``; a
# ground in ``weaken`` is never added, which is how the mutation test removes
# one check at a time.
# --------------------------------------------------------------------------


class Findings:
    """Grounds found, each with the details that explain it."""

    def __init__(self, weaken: frozenset[str]) -> None:
        self.weaken = weaken
        self.found: dict[str, list[str]] = {}

    def add(self, ground: str, detail: str) -> None:
        if ground in self.weaken:
            return
        self.found.setdefault(ground, []).append(detail)


def _manifest_ids(record: dict[str, Any]) -> list[str] | None:
    ids = _field(record.get("manifest"), "ids")
    return ids if _strs(ids) else None


def _member_ids(record: dict[str, Any]) -> list[str]:
    return [m["id"] for m in _list(record, "members") if _obj(m) and _str(m.get("id"))]


def _member_files(record: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for member in _list(record, "members"):
        for pin in _list(member, "files"):
            if _obj(pin) and _str(pin.get("path")) and _hex(pin.get("sha256")):
                out.append((pin["path"], pin["sha256"]))
    return out


def _artifact_files(record: dict[str, Any]) -> list[tuple[str, str]]:
    """The artifacts' pins, the files of the package that are neither members nor manifest."""
    return [
        (item["path"], item["sha256"])
        for item in _list(record, "artifacts")
        if _obj(item) and safe_path(item.get("path")) and _hex(item.get("sha256"))
    ]


def _pins(record: dict[str, Any], f: Findings) -> None:
    """Criterion 1: every member pinned; the corpus digest over members and manifest."""
    _member_pins(record, f)
    _corpus_digest(record, f)


def _member_pins(record: dict[str, Any], f: Findings) -> None:
    members: Any = record.get("members")
    ids = _manifest_ids(record) or []
    if not isinstance(members, list):
        f.add(G[1], "the record carries no members list")
        members = []
    for i, member in enumerate(members):
        files = _field(member, "files")
        if not _str(_field(member, "id")) or not isinstance(files, list) or not files:
            f.add(G[1], f"members[{i}] names no id or pins no file")
            continue
        for pin in files:
            if not (_obj(pin) and _str(pin.get("path")) and _hex(pin.get("sha256"))):
                f.add(G[1], f"members[{i}] carries a pin without a path and a sha256")
    pinned = set(_member_ids(record))
    for mid in ids:
        if mid not in pinned:
            f.add(G[1], f"manifest id {mid} is pinned by no member")


def _corpus_digest(record: dict[str, Any], f: Findings) -> None:
    manifest: Any = record.get("manifest")
    digest: Any = record.get("corpus-digest")
    if not (_str(_field(manifest, "path")) and _hex(_field(manifest, "sha256"))):
        f.add(G[2], "the manifest is not pinned, so no corpus digest can cover it")
        return
    if not _obj(digest) or not _hex(digest.get("sha256")):
        f.add(G[2], "the record declares no corpus digest")
        return
    if digest.get("serialization") != LISTING:
        return  # an undeclared serialization keeps the digest outside the record (I-033)
    entries = (
        _member_files(record) + _artifact_files(record) + [(manifest["path"], manifest["sha256"])]
    )
    recomputed = listing_digest(entries)
    if recomputed != digest["sha256"]:
        f.add(G[2], f"corpus digest {digest['sha256']} and the listing recomputes {recomputed}")


def _pins_on_disk(record: dict[str, Any], root: str, f: Findings) -> None:
    for path, digest in _member_files(record):
        body = _read(root, path)
        if body is None:
            f.add(G[3], f"{path} does not resolve under the root")
        elif sha(body) != digest:
            f.add(G[3], f"{path} hashes to {sha(body)}, pinned {digest}")
    manifest: Any = record.get("manifest")
    path, digest = _field(manifest, "path"), _field(manifest, "sha256")
    if _str(path) and _hex(digest):
        body = _read(root, path)
        if body is None or sha(body) != digest:
            f.add(G[2], f"the manifest {path} does not match its pin, so the corpus digest "
                        "does not cover these bytes")
    for path, digest in _artifact_files(record):
        body = _read(root, path)
        if body is None or sha(body) != digest:
            f.add(G[2], f"the artifact {path} does not match its pin, so the corpus digest "
                        "does not cover these bytes")


def _manifest(record: dict[str, Any], f: Findings) -> None:
    """Criterion 2: a closed manifest of unique identifiers, closing the pins."""
    manifest: Any = record.get("manifest")
    ids = _manifest_ids(record)
    if not _obj(manifest) or manifest.get("closed") is not True or ids is None:
        f.add(G[4], "the record carries no closed manifest of identifiers")
        return
    if len(set(ids)) != len(ids):
        f.add(G[4], "the manifest repeats an identifier")
    members = _member_ids(record)
    if len(set(members)) != len(members):
        f.add(G[4], "two members carry one identifier")
    for mid in members:
        if mid not in ids:
            f.add(G[4], f"member {mid} is pinned and the manifest does not close over it")


def _boundary(record: dict[str, Any], f: Findings) -> list[dict[str, Any]] | None:
    """Delta 1: the boundary is declared before the check."""
    boundary: Any = record.get("boundary")
    locations = _field(boundary, "member-locations")
    ok = (
        _obj(boundary)
        and safe_path(boundary.get("root"))
        and isinstance(boundary.get("complete"), bool)
        and isinstance(locations, list)
        and len(locations) > 0
    )
    if ok:
        for loc in locations:
            if not (
                _obj(loc)
                and (loc.get("dir") == "" or safe_path(loc.get("dir")))
                and isinstance(loc.get("suffix"), str)
                and isinstance(loc.get("recursive"), bool)
            ):
                ok = False
    if not ok:
        f.add(G[9], "the record declares no boundary: root, complete and member-locations")
        return None
    return list(locations)


def _boundary_on_disk(
    record: dict[str, Any], locations: list[dict[str, Any]], root: str, f: Findings
) -> None:
    """Delta 1: an unexpected member inside a package declared complete."""
    boundary = record["boundary"]
    if boundary.get("complete") is not True:
        return
    pinned = {path for path, _ in _member_files(record)}
    base = boundary["root"]
    for loc in locations:
        rel = base + "/" + loc["dir"] if loc["dir"] else base
        for path in _walk(root, rel, loc["suffix"], loc["recursive"]):
            if path not in pinned:
                f.add(G[8], f"{path} sits inside the package declared complete "
                            "and no member pins it")


def _selection(record: dict[str, Any], f: Findings) -> list[str] | None:
    """Criterion 3: which members, by what expression, how many matched."""
    selector: Any = record.get("selector")
    ids = _manifest_ids(record)
    selected = _field(selector, "selected")
    matched = _field(selector, "matched")
    if not (
        _obj(selector)
        and selector.get("language") in SELECTOR_LANGUAGES
        and isinstance(selector.get("expression"), str)
        and selector.get("require") in SELECTOR_REQUIRE
        and isinstance(selected, list)
        and all(_str(s) for s in selected)
        and _int(matched)
    ):
        f.add(G[10], "the record does not name the selection, its expression and its count")
        return None
    if ids is None:
        return None
    recomputed = [i for i in ids if glob_match(selector["expression"], i)]
    if sorted(recomputed) != sorted(selected):
        f.add(G[10], f"the expression selects {len(recomputed)} member(s) and the record "
                     f"lists {len(selected)} other ones")
    if matched != len(selected):
        f.add(G[10], f"the record says {matched} matched and lists {len(selected)}")
    count = len(recomputed)
    if count == 0:
        f.add(G[11], "the selection resolves to no member")
    elif selector["require"] == "exactly-one" and count > 1:
        f.add(G[12], f"exactly one member is required and the selection matches {count}")
    return recomputed


def _checks(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in _list(record, "checks") if _obj(c) and _str(c.get("check"))]


def _population(record: dict[str, Any], declared: list[str] | None, f: Findings) -> None:
    """Criterion 2 (i) to (iii) and delta 1: the returned population both ways."""
    if declared is None:
        declared = _manifest_ids(record)
    if declared is None:
        return
    returned = [c["check"] for c in _checks(record)]
    seen: set[str] = set()
    for rid in returned:
        if rid in seen:
            f.add(G[6], f"{rid} is returned twice")
        seen.add(rid)
    for mid in declared:
        if mid not in seen:
            f.add(G[5], f"{mid} is in the declared population and missing from the result")
    for rid in sorted(seen):
        if rid not in declared:
            f.add(G[7], f"{rid} is returned and sits outside the declared population")


def _carried_result(record: dict[str, Any], f: Findings) -> bool:
    """Criterion 4: per-case lines, aggregate line and exit code all carried."""
    checks: Any = record.get("checks")
    aggregate: Any = record.get("aggregate")
    counts = _field(aggregate, "counts")
    ok = (
        isinstance(checks, list)
        and all(
            _obj(c) and _str(c.get("check")) and c.get("state") in STATES for c in checks
        )
        and _obj(aggregate)
        and _str(aggregate.get("line"))
        and _int(aggregate.get("total"))
        and _obj(counts)
        and all(_int(v) for v in counts.values())
        and _int(record.get("exit-code"))
        and record.get("exit-rule") in EXIT_RULES
    )
    if not ok:
        f.add(G[13], "the per-case lines, the aggregate line and the exit code are not all carried")
    return ok


def _verdict(check: dict[str, Any]) -> str | None:
    verdict = _field(check.get("native"), "verdict")
    return verdict if _str(verdict) else None


def _recount(record: dict[str, Any], f: Findings) -> None:
    """Criterion 4: recount from the per-case records, never the printed line."""
    checks = record["checks"]
    aggregate = record["aggregate"]
    if aggregate["total"] != len(checks):
        f.add(G[14], f"the aggregate prints {aggregate['total']} and the per-case lines "
                     f"recount {len(checks)}")
    recount: dict[str, int] = {}
    for check in checks:
        verdict = _verdict(check)
        if verdict is not None:
            recount[verdict] = recount.get(verdict, 0) + 1
    if aggregate["counts"] != recount:
        f.add(G[14], f"the aggregate prints {_render_counts(aggregate['counts'])} and the "
                     f"per-case lines recount {_render_counts(recount)}")
    every_pass = all(c["state"] == "pass" for c in checks)
    if record["exit-rule"] == "zero-iff-every-check-passes" and (
        (record["exit-code"] == 0) != every_pass
    ):
        f.add(G[14], f"exit code {record['exit-code']} and the per-case lines "
                     f"{'all pass' if every_pass else 'do not all pass'}")
    state = "pass" if every_pass else "fail"
    if record.get("state") != state:
        f.add(G[15], f"the record states {record.get('state')!r} and the per-case lines "
                     f"recount {state!r}")
    for check in checks:
        reasons = _field(check.get("native"), "reasons")
        if isinstance(reasons, list) and (check["state"] == "pass") != (not reasons):
            f.add(G[15], f"{check['check']} states {check['state']!r} beside a native line "
                         f"carrying {len(reasons)} finding(s)")


def _refusals(record: dict[str, Any], f: Findings) -> None:
    """Criterion 4 and delta 5: each refusal names its rule and inputs in the record."""
    verdicts: Any = record.get("refusal-verdicts")
    refusals: Any = record.get("refusals")
    if not _strs(verdicts) or not isinstance(refusals, list):
        f.add(G[16], "the record declares no refusal verdicts and no refusals list")
        return
    named: dict[str, dict[str, Any]] = {}
    for item in refusals:
        if _obj(item) and _str(item.get("check")):
            named[item["check"]] = item
    members = set(_member_ids(record))
    returned = {c["check"] for c in _checks(record)}
    for check in _checks(record):
        refused = _verdict(check) in verdicts or check.get("state") == "fail"
        if not refused:
            continue
        item = named.get(check["check"])
        rule, inputs = _field(item, "rule"), _field(item, "inputs")
        if not (_str(rule) and _strs(inputs) and inputs):
            f.add(G[16], f"{check['check']} is a refusal without its decision rule and inputs")
            continue
        for ref in inputs:
            kind, _, name = ref.partition(":")
            inside = (
                ref in INPUT_LITERALS
                or (kind == "member" and name in members)
                or (kind == "check" and name in returned)
            )
            if not inside:
                f.add(G[17], f"{check['check']} is recomputed from {ref}, "
                             "which is not in the pinned record bytes")


def _native(record: dict[str, Any], f: Findings) -> None:
    """Criterion 5: native verdicts, reasons and process status carried."""
    native: Any = record.get("native")
    status = _field(_field(native, "process-status"), "exit-code")
    if not (
        _obj(native)
        and native.get("format") in NATIVE_FORMATS
        and _str(native.get("cases"))
        and (native.get("summary") is None or _str(native.get("summary")))
        and _int(status)
    ):
        f.add(G[18], "the record carries no native format, case output and process status")
        return
    for check in _checks(record):
        reasons = _field(check.get("native"), "reasons")
        if _verdict(check) is None or not isinstance(reasons, list) or not all(
            isinstance(r, str) for r in reasons
        ):
            f.add(G[18], f"{check['check']} carries no native verdict and reasons")
    if _int(record.get("exit-code")) and status != record["exit-code"]:
        f.add(G[19], f"the native process status is {status} and the record carries "
                     f"exit code {record['exit-code']}")


def _observation(record: dict[str, Any], oid: Any) -> dict[str, Any] | None:
    for item in _list(record, "observations"):
        if _obj(item) and item.get("id") == oid:
            return item
    return None


def _observed_bytes(record: dict[str, Any], oid: Any, root: str) -> bytes | None:
    item = _observation(record, oid)
    if item is None:
        return None
    if item.get("carry") == "carried":
        carried: Any = item.get("carried")
        return carried.encode("utf-8") if isinstance(carried, str) else None
    reference: Any = item.get("reference")
    if item.get("carry") != "referenced" or not _obj(reference):
        return None
    body = _read(root, reference.get("path"))
    if body is None or sha(body) != reference.get("sha256"):
        return None
    return body


def _count(value: str) -> int | None:
    """A count as the summary prints it: one to eighteen ASCII digits."""
    if not 0 < len(value) <= 18 or any(c not in "0123456789" for c in value):
        return None
    return int(value)


def parse_summary(text: str) -> tuple[str, int, dict[str, int]] | None:
    """The text ``aee-verify <corpus>`` prints: members, counts by kind, verdict.

    Lines are split on newline only, and a count is ASCII digits only, so every
    reader of this format reads the same bytes the same way.
    """
    total: int | None = None
    counts: dict[str, int] = {}
    line = None
    for raw in text.split("\n"):
        if raw.startswith("members: "):
            total = _count(raw[len("members: "):])
            if total is None:
                return None
        elif raw.startswith("  ") and ": " in raw:
            kind, _, value = raw[2:].partition(": ")
            number = _count(value)
            if number is None:
                return None
            counts[kind] = number
        elif raw.startswith("verdict: "):
            line = raw
    if total is None or line is None:
        return None
    return line, total, counts


def _native_on_disk(record: dict[str, Any], root: str, f: Findings) -> None:
    """Criterion 5: the carried lines are the native output, byte for byte."""
    native: Any = record.get("native")
    if not _obj(native) or native.get("format") not in NATIVE_FORMATS:
        return
    body = _observed_bytes(record, native.get("cases"), root)
    document: Any = None
    if body is not None:
        try:
            document = json.loads(body)
        except ValueError:
            document = None
    members = _field(document, "members")
    if not isinstance(members, list):
        f.add(G[19], "the native case output does not resolve to its pinned bytes")
        return
    native_lines = []
    for m in members:
        reasons = _field(m, "findings")
        native_lines.append(
            (_field(m, "id"), _field(m, "kind"), reasons if reasons is not None else [])
        )
    carried_lines = [
        (c.get("check"), _field(c.get("native"), "verdict"), _field(c.get("native"), "reasons"))
        for c in _list(record, "checks")
        if _obj(c)
    ]
    if _canonical(native_lines) != _canonical(carried_lines):
        f.add(G[19], "the carried per-case lines differ from the native case output")
    summary: Any = native.get("summary")
    if summary is None:
        return
    text = _observed_bytes(record, summary, root)
    parsed = parse_summary(text.decode("utf-8", "replace")) if text is not None else None
    aggregate: Any = record.get("aggregate")
    if parsed is None:
        f.add(G[19], "the native summary does not resolve to its pinned bytes")
        return
    line, total, counts = parsed
    carried_counts = _field(aggregate, "counts")
    if (
        _field(aggregate, "line") != line
        or not _int(_field(aggregate, "total"))
        or aggregate["total"] != total
        or not _obj(carried_counts)
        or not all(_int(v) for v in carried_counts.values())
        or carried_counts != counts
    ):
        f.add(G[19], "the carried aggregate line differs from the native summary")


def _observations(record: dict[str, Any], f: Findings) -> None:
    """Criterion 6: one of three carry states per observation."""
    observations: Any = record.get("observations")
    if not isinstance(observations, list):
        f.add(G[20], "the record declares no observations list")
        return
    ids: set[str] = set()
    for i, item in enumerate(observations):
        carry = _field(item, "carry")
        if not _str(_field(item, "id")) or carry not in CARRY or item["id"] in ids:
            f.add(G[20], f"observations[{i}] states no carry from {', '.join(CARRY)}")
            continue
        ids.add(item["id"])
        if carry == "referenced":
            reference: Any = item.get("reference")
            if not (_obj(reference) and safe_path(reference.get("path"))
                    and _hex(reference.get("sha256"))):
                f.add(G[20], f"observations[{i}] is referenced by no digest")
        elif carry == "carried" and "carried" not in item:
            f.add(G[21], f"observations[{i}] is declared inline and is not present")


def _native_result(value: Any) -> bool:
    """One complete native result: the digest of the checker's case output and its exit code."""
    return _obj(value) and _hex(value.get("sha256")) and _int(value.get("exit-code"))


def _artifact_shape(item: Any) -> bool:
    evidence = _field(item, "evidence")
    return (
        _obj(item)
        and safe_path(item.get("path"))
        and _hex(item.get("sha256"))
        and item.get("consumed") in CONSUMED
        and _obj(evidence)
        and evidence.get("test") in CONSUMPTION_TESTS
        and _native_result(evidence.get("baseline"))
        and _native_result(evidence.get("swapped"))
    )


def _names_grounds(value: Any) -> bool:
    known = set(G.values())
    return isinstance(value, list) and len(value) > 0 and all(
        isinstance(v, str) and v in known for v in value
    )


def _artifacts(record: dict[str, Any], f: Findings) -> None:
    """Criterion 6 with 0090 and 0091: whether a check consumed each file of the package."""
    artifacts: Any = record.get("artifacts")
    if not isinstance(artifacts, list):
        f.add(G[46], "the record states no artifacts list, so whether a check read each "
                     "file of the package is unsaid")
        return
    members = {path for path, _ in _member_files(record)}
    manifest_path = _field(record.get("manifest"), "path")
    seen: set[str] = set()
    for i, item in enumerate(artifacts):
        if not _artifact_shape(item):
            f.add(G[46], f"artifacts[{i}] states no consumed state from {', '.join(CONSUMED)} "
                         "with the swap-and-re-pin evidence that decides it")
            continue
        path = item["path"]
        if path in seen or path in members or path == manifest_path:
            f.add(G[46], f"artifacts[{i}] {path} is listed twice, or is a member or the "
                         "manifest rather than another file of the package")
            continue
        seen.add(path)
        evidence = item["evidence"]
        before, after = evidence["baseline"], evidence["swapped"]
        changed = (before["sha256"], before["exit-code"]) != (after["sha256"], after["exit-code"])
        state = "consumed" if changed else "unconsumed"
        if item["consumed"] != state:
            f.add(G[47], f"{path} is declared {item['consumed']} and its swap with every pin "
                         f"moved {'changes' if changed else 'leaves unchanged'} the complete "
                         "native result")
            continue
        if state == "unconsumed" and not _names_grounds(evidence.get("refused-by")):
            f.add(G[48], f"{path} enters no check's verdict and the record does not say which "
                         "ground refused its swap")


def _anchor(record: dict[str, Any], f: Findings) -> None:
    """Criterion 7: an anchor that tells availability from integrity, with verdicts."""
    anchor: Any = record.get("anchor")
    reference = _field(anchor, "reference")
    verdicts = _field(anchor, "verdicts")
    manifest_path = _field(record.get("manifest"), "path")
    ok = (
        _obj(anchor)
        and anchor.get("kind") in ANCHOR_KINDS
        and _obj(reference)
        and _str(reference.get("uri"))
        and safe_path(reference.get("path"))
        and _hex(anchor.get("sha256"))
        and _str(anchor.get("manifest"))
        and anchor.get("manifest") == manifest_path
        and _obj(verdicts)
        and all(verdicts.get(k) in ANCHOR_VERDICTS for k in ANCHOR_FAILURES)
    )
    if not ok:
        f.add(G[22], "the anchor does not carry a reference, a digest for the manifest it "
                     "anchors, and a non-passing verdict for each failure")
    elif anchor.get("kind") == "signed-digest-list" and not _signature_declared(anchor):
        f.add(G[22], "the anchor is a signed digest list and does not name its signature "
                     "file, its key file and pin, and a scheme this reader verifies")


def _signature_declared(anchor: dict[str, Any]) -> bool:
    signature: Any = anchor.get("signature")
    return (
        _obj(signature)
        and safe_path(signature.get("path"))
        and safe_path(signature.get("key"))
        and _hex(signature.get("key-sha256"))
        and signature.get("scheme") in SIGNATURE_SCHEMES
    )


def _binds(line: str, digest: Any, manifest: Any) -> bool:
    """A digest-list line binding the digest to the manifest path: fields split on spaces."""
    fields = [field for field in line.split(" ") if field]
    return (
        not line.startswith("#")
        and len(fields) >= 2
        and fields[0] == digest
        and fields[1] == manifest
    )


def _anchor_on_disk(record: dict[str, Any], root: str, f: Findings) -> None:
    anchor: Any = record.get("anchor")
    path = _field(_field(anchor, "reference"), "path")
    if not safe_path(path):
        return
    body = _read(root, path)
    if body is None:
        f.add(G[23], f"availability-failure: the anchor {path} does not resolve")
        return
    want, manifest = anchor.get("sha256"), anchor.get("manifest")
    lines = body.decode("utf-8", "replace").split("\n")
    if not any(_binds(line, want, manifest) for line in lines):
        f.add(G[24], f"integrity-failure: {path} resolves and carries no line binding "
                     f"{want} to {manifest}")
        return
    pinned = _read(root, manifest) if _str(manifest) else None
    declared: Any = None
    if pinned is not None:
        try:
            declared = json.loads(pinned).get("corpusDigest")
        except (ValueError, AttributeError):
            declared = None
    if declared != want:
        f.add(G[24], f"integrity-failure: the anchored digest {want} is not the digest "
                     f"{manifest} declares")
    if anchor.get("kind") == "signed-digest-list" and _signature_declared(anchor):
        _signature_on_disk(anchor, path, body, root, f)


def _signature_on_disk(
    anchor: dict[str, Any], path: str, body: bytes, root: str, f: Findings
) -> None:
    """The signed list's own check: the signature over its exact bytes, under the pinned key."""
    signature = anchor["signature"]
    raw = _read(root, signature["path"])
    pem = _read(root, signature["key"])
    if raw is None:
        f.add(G[23], f"availability-failure: the signature {signature['path']} does not resolve")
    if pem is None:
        f.add(G[23], f"availability-failure: the key {signature['key']} does not resolve")
    if raw is None or pem is None:
        return
    if sha(pem) != signature["key-sha256"]:
        f.add(G[24], f"integrity-failure: the key {signature['key']} hashes to {sha(pem)}, "
                     f"pinned {signature['key-sha256']}")
        return
    public = ed25519_public_key(pem)
    decoded = signature_bytes(raw)
    if public is None or decoded is None:
        f.add(G[24], f"integrity-failure: {signature['key']} is not an Ed25519 public key or "
                     f"{signature['path']} is not a 64-byte signature in base64")
    elif not ed25519_verify(public, body, decoded):
        f.add(G[24], f"integrity-failure: the signature {signature['path']} over {path} does "
                     f"not verify under {signature['key']}")


def _routine_on_disk(record: dict[str, Any], root: str, f: Findings) -> None:
    """Criterion 9: a digest routine named by its file is a routine that is here."""
    anchor: Any = record.get("anchor")
    routine_file = _field(anchor, "routine-file")
    if safe_path(routine_file) and _read(root, routine_file) is None:
        f.add(G[33], f"the anchor digest's routine names {routine_file}, which does not "
                     "resolve under the root, so its input serialization cannot be read")


def _offered_digests(record: dict[str, Any]) -> list[tuple[str, bool]]:
    """Every digest the record offers as evidence, and whether it declares its input."""
    anchor: Any = record.get("anchor")
    checker: Any = record.get("checker")
    revision = _field(checker, "revision")
    offered = [
        ("the member pins", record.get("pin-serialization") == BYTES),
        ("the corpus digest", _field(record.get("corpus-digest"), "serialization") == LISTING),
    ]
    if _obj(anchor):
        routine_file = anchor.get("routine-file")
        offered.append(("the anchor digest", anchor.get("serialization") == ROUTINE
                        and _str(anchor.get("routine"))
                        and (routine_file is None or safe_path(routine_file))))
        signature = anchor.get("signature")
        if anchor.get("kind") == "signed-digest-list" and _obj(signature):
            offered.append(("the anchor key pin", signature.get("serialization") == BYTES))
    for i, item in enumerate(_list(record, "artifacts")):
        offered.append((f"artifacts[{i}]", _field(item, "serialization") == BYTES))
    if _field(revision, "kind") == "source-listing":
        offered.append(("the checker source listing",
                        _field(revision, "serialization") == LISTING))
    for key in ("dependencies", "helpers"):
        for i, item in enumerate(_list(checker, key)):
            offered.append((f"{key}[{i}]", _field(item, "serialization") == BYTES))
    for item in _list(record, "observations"):
        reference = _field(item, "reference")
        if _field(item, "carry") == "referenced" and _obj(reference):
            offered.append((f"observation {item.get('id')}",
                            reference.get("serialization") == BYTES))
    return offered


def _serializations(record: dict[str, Any], f: Findings) -> None:
    """Criterion 9: every digest offered as evidence declares its input serialization."""
    undeclared = [name for name, declared in _offered_digests(record) if not declared]
    for name in undeclared:
        f.add(G[33], f"{name}: the digest declares no input serialization from "
                     f"{', '.join(SERIALIZATIONS)}")
    canonical = _field(record.get("canonicalization"), "encoding")
    if canonical not in ENCODINGS:
        f.add(G[32], f"the canonicalization {canonical!r} is not one this reader implements")


def _checker(record: dict[str, Any], f: Findings) -> None:
    """Criterion 8 as amended: revision, command, runtime, helpers, relationship."""
    checker: Any = record.get("checker")
    revision = _field(checker, "revision")
    kind = _field(revision, "kind")
    pinned = (kind == "git-commit" and _hex(revision.get("value"), (40, 64))) or (
        kind == "source-listing"
        and _strs(revision.get("paths"))
        and len(revision["paths"]) > 0
        and all(safe_path(p) for p in revision["paths"])
        and _hex(revision.get("sha256"))
    )
    commands = _field(checker, "commands")
    if not (pinned and _strs(commands) and commands):
        f.add(G[25], "the checker is not named by an immutable revision and the exact command")
    runtime = _field(checker, "runtime")
    dependencies = _field(checker, "dependencies")
    if not (
        _obj(runtime)
        and _str(runtime.get("name"))
        and _str(runtime.get("version"))
        and isinstance(dependencies, list)
        and all(_obj(d) and safe_path(d.get("path")) and _hex(d.get("sha256"))
                for d in dependencies)
    ):
        f.add(G[26], "the checker's runtime and dependencies are not named")
    helpers = _field(checker, "helpers")
    if not isinstance(helpers, list) or not all(
        _obj(h) and _str(h.get("uri")) and _hex(h.get("sha256")) for h in helpers
    ):
        f.add(G[27], "a helper acquired at run time is not named by URI and content digest")
    readers = [checker] + [r for r in _list(record, "non-author-runs")]
    for i, reader in enumerate(readers):
        where = "the checker" if i == 0 else f"non-author-runs[{i - 1}]"
        relationship = _field(reader, "relationship")
        if relationship not in RELATIONSHIPS:
            f.add(G[29], f"{where} states no relationship to the reference implementation")
            continue
        shared = _field(reader, "shared-verification-code")
        if not _strs(shared):
            f.add(G[30], f"{where} identifies no shared verification code, not even none")
        elif relationship == "written-from-specification" and shared:
            f.add(G[30], f"{where} is written from the specification and shares {shared[0]}")
        elif relationship == "same-implementation" and not shared:
            f.add(G[30], f"{where} is the same implementation and names no shared code")
    readers_field: Any = record.get("specification-readers")
    if not isinstance(readers_field, list) or not all(
        _obj(r) and _str(r.get("reader")) for r in readers_field
    ):
        f.add(G[31], "the record does not say, as a field, which readers written from the "
                     "specification have run")


def _checker_on_disk(record: dict[str, Any], root: str, f: Findings) -> None:
    checker: Any = record.get("checker")
    revision = _field(checker, "revision")
    if _field(revision, "kind") == "source-listing" and _strs(revision.get("paths")):
        recomputed = source_listing(root, revision["paths"])
        if recomputed != revision.get("sha256"):
            f.add(G[25], f"the checker source recomputes {recomputed}, "
                         f"the record names {revision.get('sha256')}")
    for dep in _list(checker, "dependencies"):
        if _obj(dep) and safe_path(dep.get("path")):
            body = _read(root, dep["path"])
            if body is None or sha(body) != dep.get("sha256"):
                f.add(G[26], f"the dependency pin {dep['path']} does not match")
    for helper in _list(checker, "helpers"):
        if not _obj(helper):
            continue
        body = _read(root, helper["path"]) if safe_path(helper.get("path")) else None
        if body is None:
            f.add(G[28], f"the helper {helper.get('uri')} does not resolve")
        elif sha(body) != helper.get("sha256"):
            f.add(G[28], f"the helper {helper.get('uri')} resolves to other bytes")


def _replay(record: dict[str, Any], f: Findings) -> None:
    """Criterion 10 as amended: identity and stability apart; ordering and seed."""
    identity: Any = record.get("byte-identity")
    stability: Any = record.get("replay-stability")
    state = _field(stability, "state")
    runs = _field(stability, "runs")
    files = len(_member_files(record))
    well_formed = (
        _obj(identity)
        and _int(identity.get("pins"))
        and identity["pins"] == files
        and _obj(stability)
        and state in REPLAY_STATES
        and isinstance(runs, list)
        and all(_obj(r) and _str(r.get("process")) and _hex(r.get("sha256")) for r in runs)
        and (state == "not-measured" or len(runs) >= 2)
    )
    if not well_formed:
        f.add(G[34], "byte identity and replay stability are not recorded as separate claims")
        return
    if not runs:
        return
    ordering: Any = stability.get("ordering")
    if ordering not in ORDERINGS or (ordering == "hash-order" and not _str(stability.get("seed"))):
        f.add(G[35], "a digested stream declares no ordering, or hash order without its seed")
    digests = {r["sha256"] for r in runs}
    if len(digests) > 1 and state == "stable":
        f.add(G[36], f"the runs produced {len(digests)} different outputs and the record "
                     "states stable")
    if len(digests) > 1 and state == "varies" and not _str(stability.get("cause")):
        f.add(G[37], "the output varies across processes and no cause is declared")


def _fault_separation(record: dict[str, Any], f: Findings) -> None:
    """Criterion 11 as amended."""
    if record.get("exposure") not in EXPOSURE:
        f.add(G[38], "the record does not state whether the expected answers were visible")
    _faults(record, f)
    _relaxed_controls(record, f)


def _faults(record: dict[str, Any], f: Findings) -> None:
    faults: Any = record.get("faults")
    returned = {c["check"] for c in _checks(record)}
    if not isinstance(faults, list):
        f.add(G[39], "the record keeps no separate fault results")
        faults = []
    for i, fault in enumerate(faults):
        fid = _field(fault, "id")
        if not _str(fid) or not _str(_field(fault, "injected")):
            f.add(G[39], f"faults[{i}] names no fault")
        elif fid in returned:
            f.add(G[39], f"fault {fid} is counted among the reproduction checks")
        if _field(_field(fault, "result"), "state") not in STATES:
            f.add(G[40], f"faults[{i}] carries no result of its own")


def _control_result(value: Any) -> bool:
    return _obj(value) and value.get("state") in STATES and _strs(value.get("grounds"))


def _relaxed_controls(record: dict[str, Any], f: Findings) -> None:
    controls: Any = record.get("relaxed-controls")
    if not isinstance(controls, list):
        f.add(G[41], "the record declares no relaxed-controls list")
        return
    for i, control in enumerate(controls):
        baseline, relaxed = _field(control, "baseline"), _field(control, "relaxed")
        if not (
            _str(_field(control, "relaxed-check"))
            and _control_result(relaxed)
            and _control_result(baseline)
        ):
            f.add(G[41], f"relaxed-controls[{i}] is not paired with its baseline")
            continue
        unchanged = (
            baseline["state"] == relaxed["state"]
            and sorted(baseline["grounds"]) == sorted(relaxed["grounds"])
        )
        native_claim: Any = control.get("native-claim")
        if native_claim not in NATIVE_CLAIMS or (native_claim == "unchanged") != unchanged:
            f.add(G[42], f"relaxed-controls[{i}] claims {native_claim!r} and the complete native "
                         f"result is {'unchanged' if unchanged else 'changed'}")
        isolates = relaxed["state"] == "pass" and not relaxed["grounds"]
        isolation_claim: Any = control.get("isolation-claim")
        if isolation_claim not in ISOLATION_CLAIMS or (isolation_claim == "isolates") != isolates:
            f.add(G[43], f"relaxed-controls[{i}] claims {isolation_claim!r} and another ground "
                         f"{'does not' if isolates else 'can still'} reject the object")


def _scope(record: dict[str, Any], f: Findings) -> None:
    """Criterion 12."""
    scope: Any = record.get("scope")
    establishes = _field(scope, "establishes")
    leaves = _field(scope, "leaves-open")
    if not (_strs(establishes) and establishes and _strs(leaves) and leaves):
        f.add(G[44], "the record does not state what the suite establishes and leaves open")
        establishes = establishes if _strs(establishes) else []
    disclaimed = _field(scope, "does-not-claim")
    disclaimed = disclaimed if _strs(disclaimed) else []
    for limit in SCOPE_LIMITS:
        if limit not in disclaimed or limit in establishes:
            f.add(G[45], f"the record does not keep the limit {limit}")


def evaluate(
    record: Any, root: str | None = None, weaken: frozenset[str] = NO_WEAKENING
) -> dict[str, list[str]]:
    """Every ground the record is refused under, with what found it."""
    f = Findings(weaken)
    if not _obj(record) or record.get("format") != FORMAT:
        # Not an intake record at all: every ground stands, because nothing
        # the criteria ask for can be read from it.
        for ground in G.values():
            f.add(ground, f"the document does not declare format '{FORMAT}'")
        return f.found
    _pins(record, f)
    _manifest(record, f)
    locations = _boundary(record, f)
    declared = _selection(record, f)
    _population(record, declared, f)
    if _carried_result(record, f):
        _recount(record, f)
    _refusals(record, f)
    _native(record, f)
    _observations(record, f)
    _artifacts(record, f)
    _anchor(record, f)
    _checker(record, f)
    _serializations(record, f)
    _replay(record, f)
    _fault_separation(record, f)
    _scope(record, f)
    if root is not None:
        _pins_on_disk(record, root, f)
        if locations is not None:
            _boundary_on_disk(record, locations, root, f)
        _native_on_disk(record, root, f)
        _anchor_on_disk(record, root, f)
        _routine_on_disk(record, root, f)
        _checker_on_disk(record, root, f)
    return f.found


def rejections(
    record: Any, root: str | None = None, weaken: frozenset[str] = NO_WEAKENING
) -> list[str]:
    """The sorted grounds a record is refused under; empty when it is admitted."""
    return sorted(evaluate(record, root, weaken))


# --------------------------------------------------------------------------
# The judge, over vectors-w3c-intake/.
# --------------------------------------------------------------------------

ID_FIELDS = ("kind", "family", "requirements", "root", "tree", "record", "expected")
KINDS = ("accept", "reject")


def _canonical(value: Any) -> bytes:
    """The bytes a member identifier is taken over: sorted keys, no spaces, ASCII.

    Every value a member carries is a string, an integer, a boolean, null, a
    list or an object, so this is the RFC 8785 form of it as well.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def identify(document: dict[str, Any]) -> str:
    """v and the first 16 hex digits of SHA-256 over the member's ID_FIELDS."""
    return "v" + sha(_canonical({k: document.get(k) for k in ID_FIELDS}))[:16]


def tree_digest(directory: str, rel: str) -> str:
    """sha256-listing-v1 over every file under a member's root, paths relative to it."""
    entries = []
    for path in _walk(directory, rel, "", True):
        body = _read(directory, path)
        entries.append((path[len(rel) + 1:], sha(body or b"")))
    return listing_digest(entries)


def _list_text(values: list[str]) -> str:
    return "[" + ", ".join(values) + "]"


def _render_counts(counts: Any) -> str:
    if not isinstance(counts, dict):
        return "{}"
    return "{" + ", ".join(f"{k}={counts[k]}" for k in sorted(counts)) + "}"


class Judged:
    """One corpus, judged: members with their findings, and corpus findings."""

    def __init__(self) -> None:
        self.members: list[tuple[str, str, list[str]]] = []
        self.findings: list[str] = []

    def ok(self) -> bool:
        return not self.findings and all(not f for _, _, f in self.members)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, kind, _ in self.members:
            counts[kind] = counts.get(kind, 0) + 1
        return counts


def _requirement(directory: str, row: dict[str, Any], out: list[str]) -> None:
    rid = row.get("id")
    path = os.path.join(directory, *str(row.get("vendored")).split("/"))
    if not os.path.isfile(path):
        out.append(f"{rid}: names a vendored file {row.get('vendored')} that is not here")
        return
    with open(path, "rb") as handle:
        text = handle.read().decode("utf-8")
    sentence = row.get("sentence")
    if not isinstance(sentence, str) or any(ord(ch) > 0x7F for ch in sentence):
        out.append(f"{rid}: the pinned sentence is not ASCII")
        return
    if sha(sentence.encode("utf-8")) != row.get("sentenceDigest"):
        out.append(f"{rid}: the pinned sentence digest does not recompute from the sentence")
    index = text.find(sentence)
    if index < 0:
        out.append(f"{rid}: quotes a sentence the vendored copy no longer carries")
        return
    if text.find(sentence, index + 1) >= 0:
        out.append(
            f"{rid}: quotes a sentence that appears more than once, so it identifies nothing"
        )
    line = text.count("\n", 0, index) + 1
    if line != row.get("line"):
        out.append(f"{rid}: records line {row.get('line')} and the sentence sits on line {line}")


def _vendored(directory: str, manifest: dict[str, Any], out: list[str]) -> None:
    pins = manifest.get("specVendored") or {}
    for key in sorted(pins):
        pin = pins[key]
        body = _read(directory, pin.get("path"))
        if body is None:
            out.append(f"the vendored file for {key} {pin.get('path')} is missing")
        elif sha(body) != pin.get("sha256"):
            out.append(
                f"the vendored file for {key} {pin.get('path')} does not match its pinned digest"
            )


def _entry_vocabulary(
    manifest: dict[str, Any], entry: dict[str, Any], known: set[str], out: list[str]
) -> list[str]:
    """The manifest entry, read against the manifest: kind, family, grounds, expectation."""
    if entry.get("kind") not in KINDS:
        out.append(f"declares kind {entry.get('kind')}")
    if entry.get("family") not in (manifest.get("families") or {}):
        out.append(f"cites family {entry.get('family')} the manifest does not define")
    requirements = entry.get("requirements") or []
    for rid in requirements:
        if rid not in known:
            out.append(f"cites requirement {rid} the manifest does not carry")
    if not requirements:
        out.append("cites no requirement, so a specification change cannot tell it broke")
    return _entry_expectation(entry, requirements, out)


def _entry_expectation(entry: dict[str, Any], requirements: Any, out: list[str]) -> list[str]:
    expected = entry.get("expected") or {}
    rejects = expected.get("rejects")
    if expected.get("verdict") != entry.get("kind"):
        out.append("expects a verdict that is not its kind")
    if not isinstance(rejects, list):
        out.append("declares no rejects list")
        return []
    if entry.get("kind") == "accept" and rejects:
        out.append("is an accept member that expects a rejection")
    if entry.get("kind") == "reject" and len(rejects) != 1:
        out.append("is a reject member that does not name exactly one ground")
    for rid in rejects:
        if rid not in requirements:
            out.append(f"expects rejection under {rid} and does not cite it")
    return [str(r) for r in rejects]


def _load_document(directory: str, entry: dict[str, Any], out: list[str]) -> Any:
    body = _read(directory, entry.get("file"))
    if body is None:
        out.append("the manifest names a vector file that does not exist")
        return None
    try:
        document = json.loads(body)
    except ValueError:
        # The parser's own message is not repeated: it differs between readers,
        # and the line the two rails print must be the same bytes.
        out.append("the vector file does not parse")
        return None
    if not _obj(document):
        out.append("the vector file is not a JSON object")
        return None
    for field in ("kind", "family", "requirements", "expected", "root"):
        if document.get(field) != entry.get(field):
            out.append(f"the vector file and the manifest disagree about {field}")
    if document.get("id") != entry.get("id"):
        out.append("the vector file carries a different identifier")
    if identify(document) != entry.get("id"):
        out.append("identifier does not recompute from the member's own bytes")
    return document


def _member_root(directory: str, document: dict[str, Any], out: list[str]) -> str | None:
    """The directory a member's record is judged under, or None for a record alone."""
    rel = document.get("root")
    if rel is None:
        if document.get("tree") is not None:
            out.append("the member carries a tree digest and no root")
        return None
    if not safe_path(rel) or not os.path.isdir(os.path.join(directory, *rel.split("/"))):
        out.append(f"the member names a root {rel} that is not a directory here")
        return ""
    if tree_digest(directory, rel) != document.get("tree"):
        out.append("the tree under the member's root does not match its tree digest")
    return os.path.join(directory, *rel.split("/"))


def _member(
    directory: str,
    manifest: dict[str, Any],
    entry: dict[str, Any],
    known: set[str],
    weaken: frozenset[str],
) -> list[str]:
    out: list[str] = []
    want = sorted(_entry_vocabulary(manifest, entry, known, out))
    document = _load_document(directory, entry, out)
    if document is None:
        return out
    root = _member_root(directory, document, out)
    if root == "":
        return out
    observed = rejections(document.get("record"), root, weaken)
    if observed != want:
        out.append(f"the checker refuses under {_list_text(observed)} and the manifest "
                   f"expects {_list_text(want)}")
    return out


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """sha256-listing-v1 over every member file and every file under a member's root."""
    entries: list[tuple[str, str]] = []
    roots: set[str] = set()
    for entry in manifest.get("vectors", []):
        body = _read(root, entry.get("file"))
        if body is not None:
            entries.append((entry["file"], sha(body)))
        if _str(entry.get("root")):
            roots.add(entry["root"])
    for rel in sorted(roots):
        for path in _walk(root, rel, "", True):
            entries.append((path, sha(_read(root, path) or b"")))
    return listing_digest(entries)


def judge(directory: str, weaken: frozenset[str] = NO_WEAKENING) -> Judged:
    """Judge every member; ``weaken`` removes grounds, for the mutation test."""
    with open(os.path.join(directory, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    judged = Judged()
    known: set[str] = set()
    for row in manifest.get("requirements", []):
        if row.get("id") in known:
            judged.findings.append(f"{row.get('id')}: duplicate requirement identifier")
        known.add(row.get("id"))
        _requirement(directory, row, judged.findings)
    seen: set[str] = set()
    entries: list[dict[str, Any]] = manifest.get("vectors", [])
    for entry in entries:
        findings: list[str] = []
        if entry.get("id") in seen:
            findings.append("duplicate identifier")
        seen.add(str(entry.get("id")))
        findings.extend(_member(directory, manifest, entry, known, weaken))
        mid, kind = entry.get("id"), entry.get("kind")
        judged.members.append(
            (mid if isinstance(mid, str) else "", kind if isinstance(kind, str) else "", findings)
        )
    judged.findings.extend(_corpus(directory, manifest, known, entries))
    return judged


def _corpus(
    directory: str, manifest: dict[str, Any], known: set[str], entries: list[dict[str, Any]]
) -> list[str]:
    out: list[str] = []
    accepting: dict[str, int] = {}
    rejecting: dict[str, int] = {}
    for entry in entries:
        target = accepting if entry.get("kind") == "accept" else rejecting
        for rid in entry.get("requirements") or []:
            target[rid] = target.get(rid, 0) + 1
    if missing := sorted(r for r in known if r not in accepting):
        out.append(f"grounds no accept member passes: {_list_text(missing)}")
    if missing := sorted(r for r in known if r not in rejecting):
        out.append(f"grounds no reject member is refused under: {_list_text(missing)}")
    families = manifest.get("families") or {}
    used = {e.get("family") for e in entries}
    if unused := sorted(set(families) - used):
        out.append(f"families declared and carried by no member: {_list_text(unused)}")
    _vendored(directory, manifest, out)
    measured = {"accept": 0, "reject": 0}
    for entry in entries:
        if entry.get("kind") in measured:
            measured[entry["kind"]] += 1
    if manifest.get("counts") != measured:
        out.append(f"counts disagree: manifest {_render_counts(manifest.get('counts'))}, "
                   f"measured {_render_counts(measured)}")
    if corpus_digest(manifest, directory) != manifest.get("corpusDigest"):
        out.append("corpusDigest does not match the vector files on disk")
    return out


def render(judged: Judged, suite: str) -> str:
    """The same lines the Go reader prints, so the two rails can be diffed."""
    lines = [f"suite: {suite}", f"members: {len(judged.members)}"]
    counts = judged.counts()
    for kind in sorted(counts):
        lines.append(f"  {kind}: {counts[kind]}")
    failed = 0
    for member_id, _, findings in judged.members:
        if not findings:
            continue
        failed += 1
        for finding in findings:
            lines.append(f"FAIL {member_id}: {finding}")
    for finding in judged.findings:
        lines.append(f"FAIL corpus: {finding}")
    if judged.ok():
        lines.append("verdict: every member behaves as MANIFEST.json declares")
    else:
        lines.append(
            f"verdict: {failed} member(s) and {len(judged.findings)} "
            "corpus-level claim(s) do not hold"
        )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Command line.
# --------------------------------------------------------------------------


def explain(record: Any, root: str | None) -> str:
    """What a reader prints for one record: what ran, and every ground with its cause."""
    found = evaluate(record, root)
    lines = []
    if root is None:
        lines.append("bytes on disk: not read (no --root); not run: " + ", ".join(ROOT_GROUNDS))
    else:
        lines.append(f"bytes on disk: read under {root}; run: " + ", ".join(ROOT_GROUNDS))
    for ground in sorted(found):
        for detail in found[ground]:
            lines.append(f"REFUSE {ground}: {detail}")
    if found:
        lines.append(f"verdict: refused under {_list_text(sorted(found))}")
    else:
        lines.append("verdict: admitted, no intake rejection ground applies")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="w3cintake",
        description="check an intake record for a submitted conformance result, "
        "or judge vectors-w3c-intake/",
    )
    parser.add_argument("record", help="an intake record, or with --judge a corpus directory")
    parser.add_argument("--root", help="the directory the record's paths are relative to")
    parser.add_argument("--judge", action="store_true", help="judge a corpus directory")
    parser.add_argument(
        "--member",
        action="store_true",
        help="the file is a member of vectors-w3c-intake: check the record it carries, "
        "under the root it names",
    )
    args = parser.parse_args(argv)
    if args.judge:
        judged = judge(args.record)
        sys.stdout.write(render(judged, SUITE))
        return 0 if judged.ok() else 1
    try:
        with open(args.record, "rb") as handle:
            record = json.loads(handle.read())
    except (OSError, ValueError) as exc:
        print(f"w3cintake: {args.record} cannot be read as JSON: {exc}", file=sys.stderr)
        return 2
    if args.member:
        rel = _field(record, "root")
        if rel is not None and args.root is None:
            if not safe_path(rel):
                print(f"w3cintake: the member names an unsafe root {rel!r}", file=sys.stderr)
                return 2
            corpus = os.path.dirname(os.path.dirname(os.path.abspath(args.record)))
            args.root = os.path.join(corpus, *rel.split("/"))
        record = _field(record, "record")
    if args.root is not None and not os.path.isdir(args.root):
        print(f"w3cintake: --root {args.root} is not a directory", file=sys.stderr)
        return 2
    sys.stdout.write(explain(record, args.root))
    return 1 if rejections(record, args.root) else 0


if __name__ == "__main__":
    raise SystemExit(main())
