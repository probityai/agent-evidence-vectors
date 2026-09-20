"""The Observed Effect predicate, and the corpus that holds its conformance set.

A mutation interval observed from a vantage the observed party does not control:
the state root before, the state root after, the path scope the observation
covered, and the digest of the authority under which mutation was permitted. The
interval is not the contribution; binding it to independently observed execution
is. ``spec/predicates/observed-effect.md`` is the normative definition.

Two things live here, and both are stdlib-only for the reason the whole rail is:
a relying party runs it with nothing installed.

1. A VERIFIER: ``verify(raw, policy)`` judges one DSSE envelope and returns the
   verdict, the single first refusal code, and the tier it RECOMPUTED. Every rule
   the predicate states is one function, registered in ``RULES`` in the order it
   runs, under the same name the Go rail's ``RuleNames()`` gives it.
2. A JUDGE for the corpus: ``judge(directory)`` reads
   ``vectors-observed-effect/MANIFEST.json`` and says of every member whether this
   rail reaches the verdict and the code the manifest declares, plus the claims
   that belong to no single member. Its printed form is the lines
   ``aee-verify <dir>`` prints from ``corpora/observedeffect.go``, so the two can
   be diffed.

Before this module the corpus was judged by nothing the harness runs: the rail
refused all forty-nine members with ``predicate-type-unsupported``, because the
reference verifier it reaches for is the one for a DIFFERENT predicate, and the
corpus was excluded from the wheel for exactly that reason. A corpus a harness
cannot judge and a corpus a harness finds clean are one exit status apart, which
is the shape of report this repository exists to stop shipping.

This is the third statement of these rules, after
``vectors-observed-effect/check_vectors.py`` and ``observedeffect/rules.go``.
Neither is imported here, so the three can be diffed member by member and a
defect in one does not travel; what this file does NOT claim is to have been
written blind, because it was written with both of them open, and the rule set
and its order came from reading them alongside the specification. The
independence that is real is the independence that matters at run time: three
implementations, no shared code, and a corpus that scores all three. Rule ORDER
is load-bearing -- the manifest names one code per reject member and that code is
the FIRST refusal -- so reordering ``RULES`` changes published answers.

The parser is this module's own for the same reason the Go rail wrote its own:
``run_vectors.py`` canonicalizes and bounds input for the Adversarial Execution
Evidence predicate, and a shared parser would move this predicate's refusals
whenever that one's moved. The one thing borrowed from the rail is its Ed25519,
which is the single implementation in this distribution and must stay so.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import importlib
import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

if __package__ in (None, ""):
    # Run as a script from a checkout: make the package importable by name, and
    # put the rail's directory on the path so the Ed25519 borrowed below resolves.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUITE = "observed-effect-conformance"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# --------------------------------------------------------------------------
# Closed vocabularies. Fail closed on an unknown value: a verifier that ignores
# a value it does not know has read a record it does not understand as one that
# conforms.
# --------------------------------------------------------------------------

TIERS = frozenset({"voluntary", "authoritative"})
MUTATIONS = frozenset({"observed", "none"})
HASH_ALGORITHMS = frozenset({"sha256", "sha1"})
VANTAGES = frozenset({"below-observed", "peer", "self"})
BASE_RESOLUTIONS = frozenset({"supplied", "recorded-parent", "empty-tree"})
READ_STATES = frozenset({"bytes-read", "no-bytes-read", "unavailable"})
AGREEMENTS = frozenset({"agree", "disagree", "one-sided"})
#: How the evidence in this record ARRIVED, which is a different question from
#: where the producer stood. Three values are the sibling vocabulary's;
#: first-hand is this registry's own, for a producer that observed somebody
#: else's execution itself.
ORIGINS = frozenset({"self", "first-hand", "third-party-control-plane", "log-import"})
#: The two origins that hold somebody else's record. An importer has no quote to
#: present, so it may not claim a hardware-rooted runtime.
IMPORT_ORIGINS = frozenset({"third-party-control-plane", "log-import"})

#: A scope carrying one of these is a pattern, and a pattern is resolved by
#: whoever reads it. The universal scope is the literal "/".
GLOB_METACHARACTERS = frozenset("*?[]{}!")
#: I-JSON's safe-integer bound. The producer side refuses to ENCODE past it; a
#: hostile rail does not use our encoder, so the verifier refuses to CONSUME
#: past it too.
IJSON_LIMIT = 2**53
#: RFC 3339, UTC, Z designator, no fractional second. The ordering rules compare
#: strings, which is sound for exactly one grammar. The regular expression fixes
#: the shape and the parse below fixes the calendar, because 2026-13-01T00:00:00Z
#: matches the shape and names no day.
TIMESTAMP_GRAMMAR = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: The object name of the empty tree per hash algorithm: the terminal case of
#: base resolution, and what makes beforeRoot unconditionally required rather
#: than optional-when-unknown. Computed from the preimage rather than stated as a
#: literal, so the corpus check below compares two computations and not a
#: constant against the value that produced it. ``usedforsecurity=False`` is what
#: keeps this importable where the library refuses sha1 outright: the empty
#: tree's object name is an identifier, and nothing here signs with it.
EMPTY_TREE = {
    "sha1": hashlib.sha1(b"tree 0\x00", usedforsecurity=False).hexdigest(),
    "sha256": hashlib.sha256(b"tree 0\x00").hexdigest(),
}

#: The one blob this corpus's read rows point at, restated here rather than read
#: out of the thing being judged. A reader that took the bytes from the corpus
#: would agree with it by construction; stated, the digest check in ``_corpus``
#: says so when the corpus starts narrating different bytes, instead of the
#: range-preimage rule quietly skipping every row for want of a blob.
NARRATED_BLOB = b"port: 8080\nmode: strict\n" * 8

#: The reference rail, which owns the one Ed25519 implementation in this
#: distribution. Its import name depends on where the code is installed: a
#: top-level module in a checkout, where ``packaging/`` is on the path; a member
#: of this package in the wheel, where it sits at
#: ``agent_evidence_vectors/run_vectors.py``; and ``__main__`` when the harness
#: is run as a script, which is how every gate in this repository drives it.
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
#: A candidate has to carry both, so a ``__main__`` that is somebody else's
#: program is passed over rather than mistaken for the rail.
_RAIL_PRIMITIVES = ("ed25519_verify", "pae")


def _rail() -> Any:
    """The rail module, resolved at call time rather than on import.

    The rail imports THIS module to dispatch the suite to it, so importing the
    rail from here at module level would be a cycle whose outcome depends on
    which side was imported first: the primitives sit below that import in the
    rail's file and would not exist yet. Every already-loaded name is tried
    before any import is attempted, because a checkout that runs the rail as a
    script holds it under ``__main__``, and importing ``run_vectors`` there would
    load and execute a second copy of the module already running.
    """
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, name_) for name_ in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, name_) for name_ in _RAIL_PRIMITIVES):
            return module
    raise ImportError(
        "the reference rail is importable as neither "
        f"{_RAIL_NAMES[0]} nor {_RAIL_NAMES[1]}, so the Ed25519 verification and the "
        "DSSE pre-authentication encoding this module borrows from it are unavailable"
    )


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    return bool(_rail().ed25519_verify(public_key, message, signature))


def _pae(payload_type: str, payload: bytes) -> bytes:
    return bytes(_rail().pae(payload_type, payload))


class Malformed(Exception):
    """A defect in the carried bytes. Stage one; no trust input reaches it."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Invalid(Exception):
    """A coherent statement whose claims its own rules refuse. Stage two."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Policy:
    """What a consumer brings to a verification.

    Nothing here is read from the record: a record that carried its own expected
    predicate type, or its own key, would be grading its own homework. Blobs are
    the blobs this consumer holds; a verifier holding none treats a range digest
    as an opaque commitment, which is why the predicate calls three of the four
    read bindings checkable rather than four.
    """

    predicate_type: str
    observer_public_key: str
    blobs: dict[str, bytes] = field(default_factory=dict)


@dataclass
class Report:
    """One verification.

    ``codes`` carries the single first refusal, which is what the corpus pins: a
    verifier reporting every rule a record breaks would make the expectation
    depend on rule order in a second way. ``derived_tier`` is the tier
    RECOMPUTED from the record, never the tier the record claims, and is empty
    where the statement was refused before the recompute could run.
    """

    verdict: str
    codes: list[str]
    derived_tier: str = ""

    @property
    def independently_observed(self) -> bool:
        """The one bit a consumer may read as evidence that somebody other than
        the observed party watched this interval.

        Derived here rather than stored, which is the vocabulary's prohibition
        made unbypassable: a verifier MUST NOT read a voluntary attestation as
        evidence that its content corresponds to any independently observed
        fact, and here it cannot, because there is no field to copy one into. A
        refused record establishes nothing about what was observed whatever tier
        its fields would have derived, so the verdict is part of the condition.
        """
        return self.verdict == "valid" and self.derived_tier == "authoritative"


@dataclass
class _State:
    """One statement under verification, plus what the recompute filled in."""

    statement: dict[str, Any]
    predicate: dict[str, Any]
    policy: Policy
    derived_tier: str = ""


# --------------------------------------------------------------------------
# Shared readings. Each is a rule's predicate, pulled out only where more than
# one rule states it.
# --------------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a repeated member name at any depth.

    Nothing in the json module refuses one: the last spelling of a repeated key
    wins silently, so two rails reading one set of bytes can disagree about what
    the record says while both report a clean parse.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise Malformed("duplicate-member")
        seen.add(key)
    return dict(pairs)


def _required(obj: Any, *names: str) -> None:
    """Refuse an absent member, naming it. No member has a default and no
    verifier may supply one, so a shape that cannot carry members at all is the
    same refusal rather than a shape nobody described."""
    for name in names:
        if not isinstance(obj, dict) or name not in obj:
            raise Malformed(f"required-member-absent:{name}")


def _lower_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value != ""
        and all(character in "0123456789abcdef" for character in value)
    )


def _path_normalized(value: Any, allow_trailing_slash: bool) -> bool:
    """Absolute, with no empty, dot or dot-dot segment.

    Without this, /srv/app/../../../etc/shadow starts with /srv/app/ and a write
    to /etc/shadow travels as in-scope under a scope of /srv/app/.
    """
    if not isinstance(value, str) or not value.startswith("/"):
        return False
    body = value[1:]
    if body.endswith("/"):
        if not allow_trailing_slash:
            return False
        body = body[:-1]
    if body == "":
        return True
    return all(segment not in ("", ".", "..") for segment in body.split("/"))


def _under(path: Any, scope: Any) -> bool:
    """Containment at a segment boundary, never by string prefix.

    /srv/application-secrets/id_ed25519 starts with /srv/app and is not under it.
    """
    if not isinstance(path, str) or not isinstance(scope, str):
        return False
    prefix = scope if scope.endswith("/") else scope + "/"
    return path == scope.rstrip("/") or path.startswith(prefix)


def _in_scope(pred: dict[str, Any], path: Any) -> bool:
    return any(_under(path, scope) for scope in pred["pathScope"])


def _timestamp_ok(value: Any) -> bool:
    if not isinstance(value, str) or not TIMESTAMP_GRAMMAR.match(value):
        return False
    try:
        datetime.datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return True


def _commitment(pred: dict[str, Any]) -> dict[str, Any] | None:
    """The prior commitment, or None where the record carries none.

    A member that is present and is not an object is read as absent, so the rule
    that requires a commitment refuses it by name instead of a later rule failing
    on a shape nobody described.
    """
    carried = pred["observation"].get("priorCommitment")
    return carried if isinstance(carried, dict) else None


def _canonical_string_map(members: dict[str, str]) -> bytes:
    """RFC 8785 for the one shape this predicate signs over: a flat object of
    string members.

    The prior commitment's preimage is that shape and nothing else here is
    canonicalized, so a general canonicalizer would be surface nothing exercises.
    Member names sort by UTF-16 code unit, which is Section 3.2.3, and the
    strings carry no HTML escaping, because an escaped less-than sign is a
    different byte string and would not verify against a rail that wrote the
    character.
    """
    body = ",".join(
        json.dumps(name, ensure_ascii=False, separators=(",", ":"))
        + ":"
        + json.dumps(members[name], ensure_ascii=False, separators=(",", ":"))
        for name in sorted(members, key=lambda name: name.encode("utf-16-be"))
    )
    return ("{" + body + "}").encode("utf-8")


def _commitment_preimage(state: _State, commitment: dict[str, Any]) -> bytes:
    """The four members the commitment digest and signature are taken over.

    Four, not two: authorityDigest is in it so an observer cannot select a
    permissive authority after the interval closed, and intervalId is in it so
    one signed commitment cannot serve two intervals that share a before-root.
    Both were open while the preimage carried only the before-root and the nonce.
    """
    pred = state.predicate
    return _canonical_string_map(
        {
            "authorityDigest": pred["authorityDigest"],
            "beforeRoot": pred["interval"]["beforeRoot"],
            "intervalId": pred["intervalId"],
            "witnessNonce": commitment["witnessNonce"],
        }
    )


#: The facts a statement determines about ITSELF. For these the observed side of
#: a dual value is not a matter of report and a verifier recomputes it: the
#: member the predicate offers as the one that catches a lying producer was a
#: free string, so a record carrying two writes could declare writes.count
#: observed as 7 and agree with itself.
SELF_DERIVABLE: dict[str, Callable[[dict[str, Any]], str]] = {
    "writes.count": lambda pred: str(len(pred["writes"])),
    "reads.count": lambda pred: str(len(pred["reads"])),
    "pathScope.count": lambda pred: str(len(pred["pathScope"])),
    "interval.beforeRoot": lambda pred: pred["interval"]["beforeRoot"],
    "interval.afterRoot": lambda pred: pred["interval"]["afterRoot"],
    "authorityDigest": lambda pred: pred["authorityDigest"],
}


# --------------------------------------------------------------------------
# The rules. One function per rule the predicate states.
# --------------------------------------------------------------------------


def _rule_ijson_integers(state: _State) -> None:
    """No integer at or above 2**53 anywhere in the statement, at any depth.

    A number carrying a fraction or an exponent is a float and the bound is
    stated over integers, so a float is exempt. The producer side refuses to
    encode past the bound and nothing refused it on the way in, so a byteRange of
    9007199254740993 was accepted and two rails read two different numbers out of
    one set of bytes.
    """

    def walk(node: Any) -> None:
        if isinstance(node, bool):
            return
        if isinstance(node, int):
            if abs(node) >= IJSON_LIMIT:
                raise Malformed("integer-not-ijson-safe")
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(state.statement)


def _rule_predicate_type(state: _State) -> None:
    """The statement says which predicate its fields belong to, and the policy
    says which one this consumer routes. A policy carrying no type refuses every
    statement, because a verifier that accepts any predicate type has stopped
    checking which predicate it is reading.
    """
    expected = state.policy.predicate_type
    if not expected or state.statement.get("predicateType") != expected:
        raise Malformed("predicate-type-unexpected")


def _rule_required_members(state: _State) -> None:
    """No member has a default, and no verifier may supply one."""
    pred = state.predicate
    _required(
        pred,
        "intervalId",
        "tier",
        "mutation",
        "hashAlgorithm",
        "interval",
        "pathScope",
        "authorityDigest",
        "observation",
        "reads",
        "writes",
        "dualValues",
        "doesNotAssert",
        "issuedAt",
    )
    _required(
        pred["interval"], "beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"
    )
    _required(pred["observation"], "vantage", "coverage", "observedSigners", "origin")


def _rule_closed_vocabularies(state: _State) -> None:
    """Fail closed on an unknown value in any closed vocabulary. A tier that is
    the number 3 is refused for carrying an unknown tier, which is where the
    refusal belongs, rather than for a shape nobody described."""
    pred = state.predicate
    for value, known, code in (
        (pred["tier"], TIERS, "tier-unknown"),
        (pred["mutation"], MUTATIONS, "mutation-unknown"),
        (pred["hashAlgorithm"], HASH_ALGORITHMS, "hash-algorithm-unknown"),
        (pred["observation"]["vantage"], VANTAGES, "vantage-unknown"),
        (pred["observation"]["origin"], ORIGINS, "origin-unknown"),
    ):
        if not isinstance(value, str) or value not in known:
            raise Malformed(code)


def _rule_timestamp_grammar(state: _State) -> None:
    """Every timestamp is RFC 3339 UTC with Z and no fractional second.

    The ordering rules below compare strings, and two records defeated that while
    the grammar was open: an offset of -05:00 sorted an hour-late commitment
    before the interval it was meant to precede, and a fractional second sorted
    an identical instant strictly before itself.
    """
    pred = state.predicate
    for member in ("openedAt", "sealedAt"):
        if not _timestamp_ok(pred["interval"][member]):
            raise Malformed(f"timestamp-not-utc-basic:interval.{member}")
    if not _timestamp_ok(pred["issuedAt"]):
        raise Malformed("timestamp-not-utc-basic:issuedAt")
    commitment = _commitment(pred)
    if commitment is not None and "committedAt" in commitment:
        if not _timestamp_ok(commitment["committedAt"]):
            raise Malformed("timestamp-not-utc-basic:priorCommitment.committedAt")


def _rule_interval_order(state: _State) -> None:
    """The ordering the fixed grammar above makes checkable by comparing
    strings, and the one the issuance has to respect: a record cannot be issued
    before the interval it reports was sealed."""
    interval = state.predicate["interval"]
    if interval["openedAt"] >= interval["sealedAt"]:
        raise Malformed("interval-not-ordered")
    if state.predicate["issuedAt"] < interval["sealedAt"]:
        raise Malformed("issued-before-sealed")


def _rule_base_vocabulary(state: _State) -> None:
    """Resolution is ordered -- supplied, then the authority's recorded parent,
    then the empty tree -- and a value outside the three is a fourth resolution
    nobody defined."""
    if state.predicate["interval"]["baseResolution"] not in BASE_RESOLUTIONS:
        raise Malformed("base-resolution-unknown")


def _rule_empty_tree_constant(state: _State) -> None:
    """empty-tree requires the constant for the DECLARED algorithm, not either
    one. The terminal case has a value, so there is no case in which a producer
    may leave the base out."""
    interval = state.predicate["interval"]
    if interval["baseResolution"] != "empty-tree":
        return
    if interval["beforeRoot"] != EMPTY_TREE[state.predicate["hashAlgorithm"]]:
        raise Malformed("empty-tree-constant-wrong-algorithm")


def _rule_path_scope_literal(state: _State) -> None:
    """A scope is a literal path. A pattern is resolved by whoever reads it, so
    two readers of one record can disagree about what it covered."""
    for entry in state.predicate["pathScope"]:
        if not isinstance(entry, str) or not entry.startswith("/"):
            raise Malformed("path-scope-not-absolute")
        if GLOB_METACHARACTERS & set(entry):
            raise Malformed("path-scope-glob-metacharacter")


def _rule_paths_normalized(state: _State) -> None:
    """Every path in the statement is absolute and normalized. A scope may end in
    a separator and a row's path may not, because a row names a file."""
    pred = state.predicate
    for entry in pred["pathScope"]:
        if not _path_normalized(entry, allow_trailing_slash=True):
            raise Malformed("path-scope-not-normalized")
    for row in list(pred["reads"]) + list(pred["writes"]):
        if not isinstance(row, dict) or not _path_normalized(row.get("path"), False):
            raise Malformed("path-not-normalized")


def _rule_mutation_coherence(state: _State) -> None:
    """A record whose own carried evidence refutes its own claim is malformed.

    A verifier that reads the claim and does not recompute over the rows accepts
    a record that says both things at once.
    """
    pred = state.predicate
    interval = pred["interval"]
    if pred["mutation"] == "none":
        if pred["writes"]:
            raise Malformed("mutation-contradicted-by-writes")
        if interval["beforeRoot"] != interval["afterRoot"]:
            raise Malformed("mutation-none-with-moved-root")
    elif not pred["writes"]:
        raise Malformed("mutation-observed-without-writes")


def _rule_write_chain(state: _State) -> None:
    """The ordered composition must carry beforeRoot to afterRoot. A chain that
    stops short is a record whose rows do not add up to its own claim."""
    interval = state.predicate["interval"]
    writes = state.predicate["writes"]
    if not writes:
        return
    cursor = interval["beforeRoot"]
    for row in writes:
        _required(row, "path", "preStateDigest", "postStateDigest", "inScope")
        if row["preStateDigest"] != cursor:
            raise Malformed("write-chain-broken")
        cursor = row["postStateDigest"]
    if cursor != interval["afterRoot"]:
        raise Malformed("write-chain-does-not-reach-after-root")


def _rule_subject_binding(state: _State) -> None:
    """The subject is the interval's after-state, and nothing else.

    This is the rule whose absence made every other rule optional: a consumer
    gates on the subject digest, and while nothing bound it to the interval a
    record could carry an honest, fully authoritative interval beside a subject
    naming an artifact the interval never produced.
    """
    pred = state.predicate
    subject = state.statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1:
        raise Malformed("subject-not-a-single-member")
    member = subject[0]
    _required(member, "name", "digest")
    digest = member["digest"]
    algorithm = pred["hashAlgorithm"]
    if not isinstance(digest, dict) or set(digest) != {algorithm}:
        raise Malformed("subject-digest-algorithm-mismatch")
    if digest[algorithm] != pred["interval"]["afterRoot"]:
        raise Malformed("subject-not-the-after-root")


def _rule_read_bindings(state: _State) -> None:
    """What a read row carries, and what it may not carry.

    A row that read no bytes carrying a range is a row claiming a reading it says
    it did not take, and a range of zero bytes proves that a path existed while
    reading as proof that its contents were seen.
    """
    for row in state.predicate["reads"]:
        _required(row, "path", "preStateDigest", "blobDigest", "readState")
        if row["readState"] not in READ_STATES:
            raise Malformed("read-state-unknown")
        if row["readState"] != "bytes-read":
            if "byteRange" in row or "rangeDigest" in row:
                raise Malformed("read-state-carries-range")
            continue
        _required(row, "byteRange", "rangeDigest")
        _check_byte_range(row["byteRange"])


def _check_byte_range(span: Any) -> None:
    _required(span, "start", "end")
    start, end = span["start"], span["end"]
    if isinstance(start, bool) or isinstance(end, bool):
        raise Malformed("byte-range-not-integer")
    if not isinstance(start, int) or not isinstance(end, int):
        raise Malformed("byte-range-not-integer")
    if start < 0:
        raise Malformed("byte-range-negative")
    if end <= start:
        raise Malformed("byte-range-empty")


def _rule_range_preimage(state: _State) -> None:
    """rangeDigest binds blob length and both offsets, never the range bytes
    alone.

    A verifier holding the blob recomputes this. One that does not holds the
    range digest as an opaque commitment and cannot check it, which is why the
    predicate calls three of the four read bindings checkable rather than four.
    """
    for row in state.predicate["reads"]:
        if row.get("readState") != "bytes-read":
            continue
        blob = state.policy.blobs.get(row["blobDigest"])
        if blob is None:
            continue
        start, end = row["byteRange"]["start"], row["byteRange"]["end"]
        if end > len(blob):
            raise Malformed("range-digest-preimage-wrong")
        preimage = b"%d\x00%d\x00%d\x00" % (len(blob), start, end) + blob[start:end]
        if row["rangeDigest"] != hashlib.sha256(preimage).hexdigest():
            raise Malformed("range-digest-preimage-wrong")


def _rule_read_chain(state: _State) -> None:
    """A read's pre-state must be a state this interval actually passed
    through, which is the before-root or the post-state of one of its writes."""
    pred = state.predicate
    reachable = {pred["interval"]["beforeRoot"]}
    for row in pred["writes"]:
        reachable.add(row["postStateDigest"])
    for row in pred["reads"]:
        if row["preStateDigest"] not in reachable:
            raise Malformed("read-pre-state-not-in-interval")


def _rule_empty_tree_holds_no_bytes(state: _State) -> None:
    """Nothing can be read out of the empty tree.

    The terminal case of base resolution is the strongest thing a producer can
    claim about the past -- there was nothing before -- and a record that claims
    it and then reads 64 bytes from a file at that root has said both.
    """
    pred = state.predicate
    before = pred["interval"]["beforeRoot"]
    if before != EMPTY_TREE[pred["hashAlgorithm"]]:
        return
    for row in pred["reads"]:
        if row.get("readState") == "bytes-read" and row.get("preStateDigest") == before:
            raise Malformed("bytes-read-from-the-empty-tree")


def _rule_coverage_coherence(state: _State) -> None:
    """A record that declares complete coverage and then names a gap inside the
    scope it says it covered has said both."""
    pred = state.predicate
    coverage = pred["observation"]["coverage"]
    _required(coverage, "scopeComplete", "gaps")
    if not coverage["scopeComplete"]:
        return
    for gap in coverage["gaps"]:
        if _in_scope(pred, gap):
            raise Malformed("coverage-self-contradictory")


def _rule_coverage_gaps_named(state: _State) -> None:
    """An incomplete observation says WHERE it was blind.

    The tier recompute's coverage clause reads "every gap names a path outside
    pathScope", which an empty gaps list satisfies vacuously, so a record could
    admit it did not cover its own scope, name no gap, and still grade
    authoritative. The blind spot is where the writes went.
    """
    coverage = state.predicate["observation"]["coverage"]
    if not coverage["scopeComplete"] and not coverage["gaps"]:
        raise Malformed("coverage-incomplete-without-gaps")


def _rule_origin_carries_the_vantage(state: _State) -> None:
    """Only a producer that observed the execution itself may claim to have stood
    below it.

    Without the origin member there was no place in the record where an importer
    had to say it imported, so a record assembled from another vendor's exported
    log could be emitted as a first-hand below-observed observation and no field
    contradicted it. The lie was not a false value anywhere; it was a claim the
    format had no slot to refuse.
    """
    observation = state.predicate["observation"]
    if observation["vantage"] == "below-observed" and observation["origin"] != "first-hand":
        raise Malformed("origin-cannot-carry-below-observed-vantage")


def _rule_import_origin_platform(state: _State) -> None:
    """A record holding somebody else's log may not claim a hardware-rooted
    runtime.

    An importer has no quote to present: whatever the exporting platform
    measured, the importing party cannot produce the evidence for it. So an
    origin of third-party-control-plane or log-import declares a software-only
    platform and a verifier refuses anything else, absence included. The sibling
    vocabulary registers this beside the origin enum as a MUST and nothing
    enforced it, so half of the origin rule was a sentence in a registry with no
    verifier behind it.
    """
    observation = state.predicate["observation"]
    if observation["origin"] not in IMPORT_ORIGINS:
        return
    runtime = observation.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("platform") != "software-only":
        raise Malformed("import-origin-requires-software-only-platform")


def _rule_prior_commitment_present(state: _State) -> None:
    """A below-observed vantage requires a prior commitment.

    The Fields section says so and nothing enforced it, so a record could carry
    the independence claim with nothing behind it. Refusing it here is what makes
    the tier recompute's commitment clause unreachable, which is why that clause
    is gone rather than kept as a sentence.
    """
    observation = state.predicate["observation"]
    if observation["vantage"] == "below-observed" and _commitment(state.predicate) is None:
        raise Malformed("prior-commitment-absent-for-vantage")


def _rule_commitment_digest(state: _State) -> None:
    """The commitment digest recomputes from the four members it covers."""
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    _required(commitment, "committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig")
    recomputed = hashlib.sha256(_commitment_preimage(state, commitment)).hexdigest()
    if commitment["commitmentDigest"] != recomputed:
        raise Malformed("commitment-digest-mismatch")


def _rule_keyid_form(state: _State) -> None:
    """One spelling per key identifier, so the disjointness check below cannot be
    dodged by case.

    That check is the predicate's offline discriminator and it is a string
    comparison. An observed party that listed its own key uppercase in
    observedSigners and committed with it lowercase passed the discriminator with
    the same key on both sides.
    """
    observation = state.predicate["observation"]
    for keyid in observation["observedSigners"]:
        if not _lower_hex(keyid):
            raise Malformed("keyid-not-lowercase-hex")
    commitment = _commitment(state.predicate)
    if commitment is not None and not _lower_hex(commitment.get("keyid")):
        raise Malformed("keyid-not-lowercase-hex")


def _rule_agreement_derivable(state: _State) -> None:
    """The agreement is a function of the two carried values, never a claim."""
    for row in state.predicate["dualValues"]:
        _required(row, "fact", "observedValue", "reportedValue", "agreement")
        if row["agreement"] not in AGREEMENTS:
            raise Malformed("agreement-unknown")
        observed, reported = row["observedValue"], row["reportedValue"]
        if observed == "" and reported == "":
            # Neither side carries a value, so there is no comparison to declare.
            # This read as one-sided and let a record carry any number of dual
            # values that looked like cross-checks and asserted nothing.
            raise Malformed("dual-value-carries-no-value")
        if observed == "" or reported == "":
            derived = "one-sided"
        elif observed == reported:
            derived = "agree"
        else:
            derived = "disagree"
        if row["agreement"] != derived:
            raise Malformed("agreement-not-derivable")


def _rule_dual_value_recomputes(state: _State) -> None:
    """For a fact the statement determines about itself, the observed side is
    that fact and not a report of it."""
    for row in state.predicate["dualValues"]:
        derive = SELF_DERIVABLE.get(row["fact"])
        if derive is None:
            continue
        if row["observedValue"] != derive(state.predicate):
            raise Malformed("dual-value-not-recomputable")


def _rule_commitment_signature(state: _State) -> None:
    """The prior commitment is signed, and the signature is CHECKED.

    Stage two names this gate and nothing implemented it, so sixty-four zero
    bytes in sig produced an authoritative record. Checking it against the key
    the consumer anchored also narrows the two-key attack: the second key a
    self-observer commits with is no longer any key it likes, it is a key the
    consumer has to have anchored.
    """
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    try:
        signature = bytes.fromhex(commitment["sig"])
        public_key = bytes.fromhex(state.policy.observer_public_key)
    except (ValueError, TypeError) as exc:
        raise Malformed("commitment-signature-unreadable") from exc
    if len(public_key) != 32:
        raise Malformed("commitment-signature-unreadable")
    if not _ed25519_verify(public_key, _commitment_preimage(state, commitment), signature):
        raise Invalid("commitment-signature-invalid")


def _rule_commitment_order(state: _State) -> None:
    """The commitment precedes the interval. One made after the fact commits to
    nothing."""
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    if commitment["committedAt"] >= state.predicate["interval"]["openedAt"]:
        raise Invalid("commitment-not-prior")


def _rule_commitment_keyid_disjoint(state: _State) -> None:
    """The offline discriminator. Necessary, and the predicate says not
    sufficient."""
    observation = state.predicate["observation"]
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    if commitment["keyid"] in observation["observedSigners"]:
        raise Invalid("commitment-keyid-not-disjoint")


def _rule_write_scope(state: _State) -> None:
    """The in-scope label is derived from the path and the scope, never read as
    the producer's opinion of it, and an authoritative record's writes stay
    inside the scope it claims to have covered."""
    pred = state.predicate
    for row in pred["writes"]:
        covered = _in_scope(pred, row["path"])
        if covered != bool(row["inScope"]):
            raise Invalid("write-in-scope-mislabelled")
        if not covered and pred["tier"] == "authoritative":
            raise Invalid("write-outside-path-scope")


def _rule_tier_recompute(state: _State) -> None:
    """tier is recomputed, never read as a claim, and a mismatch is invalid
    rather than a silent downgrade: a caller that selected its own tier and got
    it quietly corrected learns nothing.

    There is no prior-commitment clause and no mutation-shape clause. Both were
    proved UNREACHABLE: a below-observed record with no commitment is already
    refused in stage one, a record whose vantage is anything else fails the
    vantage clause first, and a record whose mutation claim disagrees with its
    write set is already malformed. A clause no input can reach is a sentence,
    not a gate, and worse than absent -- it made the coherence rule look measured
    when nothing measured it.
    """
    pred = state.predicate
    observation = pred["observation"]
    coverage = observation["coverage"]
    clauses = {
        "authoritative-vantage-not-independent": observation["vantage"] == "below-observed",
        "authoritative-empty-path-scope": bool(pred["pathScope"]),
        "authoritative-coverage-incomplete": bool(coverage["scopeComplete"])
        or not any(_in_scope(pred, gap) for gap in coverage["gaps"]),
    }
    derived = "authoritative" if all(clauses.values()) else "voluntary"
    state.derived_tier = derived
    if pred["tier"] == derived:
        return
    if pred["tier"] == "authoritative":
        for code, held in clauses.items():
            if not held:
                raise Invalid(code)
    raise Invalid("tier-recompute-mismatch")


def _rule_authoritative_carries_rows(state: _State) -> None:
    """An authoritative record observed something.

    The non-empty path scope clause closed one spelling of the vacuous record. A
    scope of ["/"] with no reads and no writes is the same record, graded the
    strongest tier, asserting that nothing happened anywhere; a mutation of none
    is a positive claim about an interval and it needs a row to be a claim about
    anything.
    """
    pred = state.predicate
    if pred["tier"] != "authoritative":
        return
    if not pred["reads"] and not pred["writes"]:
        raise Invalid("authoritative-without-observed-rows")


Rule = Callable[[_State], None]

#: Ordered, because stage one precedes stage two and because the first refusal is
#: the code the manifest names. The names are the Go rail's, which exports the
#: same list from ``RuleNames()``, so the two orders can be diffed rather than
#: compared by eye.
RULES: tuple[tuple[str, Rule], ...] = (
    ("ijson-integers", _rule_ijson_integers),
    ("predicate-type", _rule_predicate_type),
    ("required-members", _rule_required_members),
    ("closed-vocabularies", _rule_closed_vocabularies),
    ("timestamp-grammar", _rule_timestamp_grammar),
    ("interval-order", _rule_interval_order),
    ("base-vocabulary", _rule_base_vocabulary),
    ("empty-tree-constant", _rule_empty_tree_constant),
    ("path-scope-literal", _rule_path_scope_literal),
    ("paths-normalized", _rule_paths_normalized),
    ("mutation-coherence", _rule_mutation_coherence),
    ("write-chain", _rule_write_chain),
    ("subject-binding", _rule_subject_binding),
    ("read-bindings", _rule_read_bindings),
    ("range-preimage", _rule_range_preimage),
    ("read-chain", _rule_read_chain),
    ("empty-tree-holds-no-bytes", _rule_empty_tree_holds_no_bytes),
    ("coverage-coherence", _rule_coverage_coherence),
    ("coverage-gaps-named", _rule_coverage_gaps_named),
    ("origin-carries-the-vantage", _rule_origin_carries_the_vantage),
    ("import-origin-platform", _rule_import_origin_platform),
    ("prior-commitment-present", _rule_prior_commitment_present),
    ("commitment-digest", _rule_commitment_digest),
    ("keyid-form", _rule_keyid_form),
    ("agreement-derivable", _rule_agreement_derivable),
    ("dual-value-recomputes", _rule_dual_value_recomputes),
    ("commitment-signature", _rule_commitment_signature),
    ("commitment-order", _rule_commitment_order),
    ("commitment-keyid-disjoint", _rule_commitment_keyid_disjoint),
    ("write-scope", _rule_write_scope),
    ("tier-recompute", _rule_tier_recompute),
    ("authoritative-carries-rows", _rule_authoritative_carries_rows),
)


def rule_names() -> list[str]:
    """The rules in the order they run, so a caller can report what it enforced.

    There is no exported way to turn one off: ``verify``'s ``disabled`` parameter
    is keyword-only and exists for a mutation sweep, and no flag or environment
    variable reaches it.
    """
    return [name for name, _ in RULES]


def predicate_type_from_spec(path: str) -> str:
    """Read the Type URI out of the document that DEFINES the predicate.

    Not a literal here and not taken from the corpus: the specification is the
    normative statement of what this predicate IS, so the manifest's declared
    type is compared against this value rather than trusted. It also keeps the
    one first-party host name in this repository confined to the documents that
    have to carry it.
    """
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("Type URI:"):
                return line.split(":", 1)[1].strip()
    raise ValueError(f"{path} states no Type URI line")


def verify(raw: bytes, policy: Policy, *, disabled: str | None = None) -> Report:
    """Judge one DSSE envelope carrying an Observed Effect statement.

    ``disabled`` names one rule to skip, which is how a mutation sweep asks
    whether that rule is load-bearing. Production verification never passes it.
    """
    try:
        envelope = json.loads(raw, object_pairs_hook=_no_duplicates)
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(payload, object_pairs_hook=_no_duplicates)
    except Malformed as exc:
        return Report("malformed", [exc.code])
    except Exception:
        return Report("malformed", ["not-parseable"])
    if not isinstance(statement, dict):
        return Report("malformed", ["not-parseable"])

    state = _State(statement=statement, predicate={}, policy=policy)
    refused = _apply_rules(state, disabled)
    if refused is not None:
        return refused
    return _verify_envelope(envelope, payload, state)


def _apply_rules(state: _State, disabled: str | None) -> Report | None:
    """Run stage one and stage two. Return a refusal, or None where every rule
    held."""
    try:
        if state.statement.get("_type") != STATEMENT_TYPE:
            raise Malformed("statement-type-unexpected")
        predicate = state.statement.get("predicate")
        if not isinstance(predicate, dict):
            raise Malformed("unhandled-shape:predicate")
        state.predicate = predicate
        for name, rule in RULES:
            if name != disabled:
                rule(state)
    except Malformed as exc:
        return Report("malformed", [exc.code], state.derived_tier)
    except Invalid as exc:
        return Report("invalid", [exc.code], state.derived_tier)
    except (KeyError, TypeError) as exc:
        # A shape no rule named. Reported under its own name rather than crashing
        # the replay, because a rail that dies on one member judges none of the
        # rest and a traceback is not a verdict.
        return Report("malformed", [f"unhandled-shape:{exc.__class__.__name__}"])
    return None


def _verify_envelope(envelope: dict[str, Any], payload: bytes, state: _State) -> Report:
    """The last gate, after every carried-bytes rule held."""
    try:
        signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
        public_key = bytes.fromhex(state.policy.observer_public_key)
    except Exception:
        return Report("malformed", ["envelope-signature-unreadable"], state.derived_tier)
    if len(public_key) != 32 or not isinstance(envelope.get("payloadType"), str):
        return Report("malformed", ["envelope-signature-unreadable"], state.derived_tier)
    message = _pae(envelope["payloadType"], payload)
    if not _ed25519_verify(public_key, message, signature):
        return Report("invalid", ["envelope-signature-invalid"], state.derived_tier)
    return Report("valid", [], state.derived_tier)


# --------------------------------------------------------------------------
# The corpus judge.
# --------------------------------------------------------------------------


class Judged:
    """One corpus, judged: members with their findings, and corpus findings.

    Restated here rather than shared with ``w3creport``. The Go side shares one
    renderer across every reader, and in Python the other copy belongs to a
    different specification's module; importing it would tie this predicate's
    reporting to that one's, which is the coupling the rules above are kept apart
    for. The lines are the same lines either way, which is the property that
    matters.
    """

    def __init__(self) -> None:
        self.members: list[tuple[str, str, list[str]]] = []
        self.findings: list[str] = []
        #: What the judgement could not reach, said out loud. A check that did not
        #: run must never print as one that passed.
        self.notes: list[str] = []

    def ok(self) -> bool:
        return not self.findings and all(not findings for _, _, findings in self.members)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, kind, _ in self.members:
            counts[kind] = counts.get(kind, 0) + 1
        return counts


def _policy(directory: str, manifest: dict[str, Any]) -> tuple[Policy, list[str], list[str]]:
    """What a consumer brings, and what could not be established about it.

    The Type URI comes out of the document that defines the predicate wherever
    that document is reachable, because a corpus supplying its own routing value
    would be grading its own homework. The wheel ships the corpora and not the
    specification, so there the manifest's value is routed and the substitution
    is printed: with the two equal by construction the cross-check in ``_corpus``
    is vacuous, and a vacuous check that prints nothing reads as one that passed.
    """
    declared = str(manifest.get("predicateType", ""))
    spec = manifest.get("predicateSpec")
    notes: list[str] = []
    findings: list[str] = []
    resolved = declared
    if not isinstance(spec, str) or not spec:
        findings.append(
            "the manifest names no predicateSpec, so the predicate type cannot be read "
            "out of the document that defines it"
        )
    else:
        try:
            resolved = predicate_type_from_spec(os.path.join(directory, os.pardir, spec))
        except OSError:
            notes.append(
                f"{spec} is not beside this corpus, so the manifest's own predicateType is "
                "what this run routed and nothing cross-checked it against the specification"
            )
        except ValueError as exc:
            findings.append(str(exc))
    blobs = {hashlib.sha256(NARRATED_BLOB).hexdigest(): NARRATED_BLOB}
    key = str(manifest.get("keys", {}).get("observer", {}).get("publicKey", ""))
    return Policy(resolved, key, blobs), notes, findings


def _judge_member(
    directory: str, entry: dict[str, Any], policy: Policy
) -> tuple[str, str, list[str]]:
    findings: list[str] = []
    identifier, kind = str(entry.get("id", "")), str(entry.get("kind", ""))
    path = os.path.join(directory, str(entry.get("file", "")))
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        return identifier, kind, [f"the vector body is unreadable: {exc}"]
    # The identifier is the first 16 hex characters of the member's own bytes, so
    # an edited vector cannot keep its name.
    recomputed = "v" + hashlib.sha256(raw).hexdigest()[:16]
    if recomputed != identifier:
        findings.append(
            f"file bytes hash to {recomputed} and the manifest calls this member {identifier}"
        )
    report = verify(raw, policy)
    if kind in ("accept", "reject"):
        findings.extend(_declared_findings(entry, report))
    elif kind == "indeterminate":
        findings.extend(_indeterminate_findings(entry, report))
    else:
        findings.append(
            f"the manifest lists this member under kind {kind!r}, which this rail does not "
            "replay. A kind nobody taught the rail about is refused by name rather than "
            "replayed as an accept."
        )
    return identifier, kind, findings


def _declared_findings(entry: dict[str, Any], report: Report) -> list[str]:
    slug = entry.get("slug")
    expected = entry.get("expected") or {}
    if report.verdict != expected.get("verdict"):
        return [
            f"{slug}: expected {expected.get('verdict')}, got {report.verdict} {report.codes}"
        ]
    codes = expected.get("codes") or []
    if codes and report.codes != codes:
        return [f"{slug}: expected codes {codes}, got {report.codes}"]
    return []


def _indeterminate_findings(entry: dict[str, Any], report: Report) -> list[str]:
    """A member the predicate states no rule for declares the readings a
    conforming verifier could take, and scoring either one wrong would be the
    corpus inventing a rule the predicate does not carry. A member declaring no
    reading is the other failure: no answer to it can be wrong."""
    readings = entry.get("readings") or []
    allowed = sorted({str(reading.get("verdict")) for reading in readings})
    if not allowed:
        return [
            f"{entry.get('slug')}: declared indeterminate and names no readings, so no "
            "answer can be wrong"
        ]
    if report.verdict not in allowed:
        return [
            f"{entry.get('slug')}: this rail took the reading {report.verdict!r}, which is "
            f"outside the declared set {allowed}"
        ]
    return []


def _corpus(directory: str, manifest: dict[str, Any], policy: Policy) -> list[str]:
    """The claims that belong to no single member."""
    out: list[str] = []
    if manifest.get("predicateType") != policy.predicate_type:
        out.append(
            f"the manifest's predicateType is not the Type URI "
            f"{manifest.get('predicateSpec')} states"
        )
    out.extend(_empty_tree_findings(manifest))
    if not _blob_is_named(directory, manifest, hashlib.sha256(NARRATED_BLOB).hexdigest()):
        out.append(
            "the blob this rail reconstructs is named by no read row, so the "
            "range-preimage rule was not exercised"
        )
    out.extend(_twin_findings(manifest))
    out.extend(_parent_findings(manifest))
    out.extend(_count_findings(directory, manifest))
    return out


def _empty_tree_findings(manifest: dict[str, Any]) -> list[str]:
    out: list[str] = []
    declared = manifest.get("emptyTree") or {}
    if not declared:
        return ["the manifest publishes no empty-tree constants, so nothing compared them"]
    for algorithm in sorted(declared):
        if algorithm not in EMPTY_TREE:
            out.append(
                f"the manifest declares an empty-tree constant for {algorithm} and this "
                "rail knows none"
            )
        elif declared[algorithm] != EMPTY_TREE[algorithm]:
            out.append(
                f"the manifest's {algorithm} empty-tree constant is not the one this rail "
                "computes"
            )
    return out


def _blob_is_named(directory: str, manifest: dict[str, Any], digest: str) -> bool:
    """Whether any member's payload actually names this digest.

    A check on the manifest's condition labels instead would be a check on a
    label: the corpus could narrate a different blob, the range-preimage rule
    would skip every row for want of it, and the label would still say the rule
    was exercised. The payloads are where the digest appears.
    """
    for entry in manifest.get("vectors", []):
        try:
            with open(os.path.join(directory, str(entry.get("file", ""))), "rb") as handle:
                envelope = json.load(handle)
            payload = base64.b64decode(envelope["payload"], validate=True)
        except Exception:
            continue
        if digest.encode("ascii") in payload:
            return True
    return False


def _twin_findings(manifest: dict[str, Any]) -> list[str]:
    """Every condition a reject member carries is also carried by a member that
    must be ACCEPTED, and every condition the manifest declares is exercised.

    Without the first, a verifier that refuses every input scores full marks;
    without the second, a declared condition can sit in the manifest with no
    member behind it and read as covered.
    """
    buckets: dict[str, set[str]] = {"accept": set(), "reject": set(), "indeterminate": set()}
    for entry in manifest.get("vectors", []):
        bucket = buckets.get(str(entry.get("kind")))
        if bucket is not None:
            bucket.update(entry.get("conditions") or [])
    accepted, rejected = buckets["accept"], buckets["reject"]
    indeterminate = buckets["indeterminate"]
    out: list[str] = []
    # A condition carried only by an indeterminate member is exempt from the twin
    # requirement by construction: the predicate states no rule for it, so there
    # is no implementation for a refuse-everything strategy to skip.
    for condition in sorted(rejected - accepted - indeterminate):
        out.append(
            f"condition {condition} is exercised only by reject members, so refusing "
            "everything scores full marks on it"
        )
    declared = set(manifest.get("conditions") or {})
    exercised = accepted | rejected | indeterminate
    for condition in sorted(declared - exercised):
        out.append(f"condition {condition} is declared and no member exercises it")
    for condition in sorted(exercised - declared):
        out.append(f"condition {condition} is used by a member and not declared")
    for condition in sorted(declared & accepted - rejected - indeterminate):
        out.append(
            f"condition {condition} has no reject member, so a verifier that implements "
            "nothing for it scores full marks"
        )
    return out


def _parent_findings(manifest: dict[str, Any]) -> list[str]:
    """Every reject member names the accept member it is one mutation from. A
    reject vector with no parent is a refusal nobody can reproduce."""
    identifiers = {str(entry.get("id")) for entry in manifest.get("vectors", [])}
    out: list[str] = []
    for entry in manifest.get("vectors", []):
        if entry.get("kind") != "reject":
            continue
        parent = entry.get("parent")
        if parent is None:
            out.append(f"{entry.get('id')}: a reject member names no parent")
        elif parent not in identifiers:
            out.append(f"{entry.get('id')}: parent {parent} is not a member")
    return out


def _count_findings(directory: str, manifest: dict[str, Any]) -> list[str]:
    out: list[str] = []
    measured: dict[str, int] = {}
    for entry in manifest.get("vectors", []):
        kind = str(entry.get("kind"))
        measured[kind] = measured.get(kind, 0) + 1
    if manifest.get("counts") != measured:
        out.append(f"counts declare {manifest.get('counts')} and the members are {measured}")
    recomputed = corpus_digest(manifest, directory)
    if manifest.get("corpusDigest") != recomputed:
        out.append(
            f"corpusDigest {str(manifest.get('corpusDigest'))[:12]} does not recompute "
            f"({recomputed[:12]})"
        )
    return out


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """SHA-256 over every member's bytes, concatenated in identifier order."""
    digest = hashlib.sha256()
    for entry in sorted(manifest.get("vectors", []), key=lambda entry: str(entry.get("id"))):
        path = os.path.join(root, str(entry.get("file", "")))
        if os.path.isfile(path):
            with open(path, "rb") as handle:
                digest.update(handle.read())
    return digest.hexdigest()


def judge(directory: str) -> Judged:
    with open(os.path.join(directory, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    judged = Judged()
    policy, notes, findings = _policy(directory, manifest)
    judged.notes.extend(notes)
    judged.findings.extend(findings)
    entries: list[dict[str, Any]] = manifest.get("vectors") or []
    if not entries:
        judged.findings.append("the manifest carries no vectors, so this run measured nothing")
        return judged
    seen: set[str] = set()
    for entry in entries:
        identifier, kind, member = _judge_member(directory, entry, policy)
        if identifier in seen:
            member.append("duplicate identifier")
        seen.add(identifier)
        judged.members.append((identifier, kind, member))
    judged.findings.extend(_corpus(directory, manifest, policy))
    return judged


def render(judged: Judged, suite: str) -> str:
    """The lines ``aee-verify`` prints from the Go reader, so the two rails can be
    diffed. A note is printed above the verdict and changes no exit status: it
    says what this run could not establish, which is neither a member's failure
    nor a corpus-level one."""
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
    for note in judged.notes:
        lines.append(f"note: {note}")
    if judged.ok():
        lines.append("verdict: every member behaves as MANIFEST.json declares")
    else:
        lines.append(
            f"verdict: {failed} member(s) and {len(judged.findings)} "
            "corpus-level claim(s) do not hold"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="observedeffect",
        description="judge vectors-observed-effect/ with the reference rail for the "
        "Observed Effect predicate",
    )
    parser.add_argument("directory", help="a corpus directory carrying MANIFEST.json")
    args = parser.parse_args(argv)
    judged = judge(args.directory)
    sys.stdout.write(render(judged, SUITE))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
