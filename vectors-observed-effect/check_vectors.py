#!/usr/bin/env python3
"""Reference verifier for the Observed Effect predicate, plus the corpus self-check.

    uv run --extra generators python vectors-observed-effect/check_vectors.py

Two jobs in one file, and they are separable on purpose.

`verify()` is the reference verifier: it implements every rule
spec/predicates/observed-effect.md states, one rule per function, registered in
RULES so that mutation_check.py can disable exactly one and see what stops being
refused. A rule whose removal changes no verdict measures nothing, and that is
the defect the sibling harness exists to catch.

`main()` is the corpus self-check: it asks whether the committed bytes BEHAVE as
MANIFEST.json claims. Every reject member must be refused with the specific code
it names and not some other one; every reject condition must also be carried by
a member that must be ACCEPTED, because a corpus of refusals gives full marks to
a verifier that refuses everything; every declared count must match; and the
corpus digest must recompute.

Nothing here imports gen_vectors.py. A checker that reused the generator's
construction would produce a corpus and then agree with it, and two independent
statements of one rule is the only arrangement in which this file can fail.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import sys
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from canonical import canonical_bytes  # noqa: E402
from digest import corpus_digest  # noqa: E402

GLOB_METACHARACTERS = set("*?[]{}!")
PREDICATE_SPEC_PATH = "spec/predicates/observed-effect.md"


def _predicate_type_from_spec() -> str:
    """Read the Type URI out of the predicate document that defines it.

    Not a literal here, and not imported from the generator either. The generator
    is what produced the corpus, so a checker that took the URI from there would
    agree with it by construction; the specification is the normative statement of
    what this predicate IS, so main()'s comparison of the manifest against this
    value is a comparison of the corpus against its own definition. It also keeps
    the one first-party host name in this public repository confined to the
    document that has to carry it.
    """
    spec = os.path.join(HERE, "..", PREDICATE_SPEC_PATH)
    with open(spec, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("Type URI:"):
                return line.split(":", 1)[1].strip()
    raise SystemExit(f"{PREDICATE_SPEC_PATH} states no Type URI line")


PREDICATE_TYPE = _predicate_type_from_spec()
#: RFC 3339, UTC, Z designator, no fractional second. The grammar is fixed so that
#: a lexical comparison of two timestamps IS a comparison of two instants. While it
#: was not, a commitment stamped 2026-09-18T20:00:00-05:00 sorted before an interval
#: that opened at 2026-09-19T00:00:00Z and was made an hour AFTER it.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
TIMESTAMP_MEMBERS = ("openedAt", "sealedAt")
#: Facts a statement can recompute about itself. dualValues is the one member the
#: predicate offers as catching a lying producer, and it caught nothing while the
#: observed side was a free string: writes.count could read 7 on a record carrying
#: two writes.
SELF_DERIVABLE: dict[str, Callable[[dict[str, Any]], str]] = {
    "writes.count": lambda p: str(len(p["writes"])),
    "reads.count": lambda p: str(len(p["reads"])),
    "pathScope.count": lambda p: str(len(p["pathScope"])),
    "interval.beforeRoot": lambda p: p["interval"]["beforeRoot"],
    "interval.afterRoot": lambda p: p["interval"]["afterRoot"],
    "authorityDigest": lambda p: p["authorityDigest"],
}
#: I-JSON's safe-integer bound. canonical.py refuses to ENCODE past it, which is
#: the producer side. A hostile rail does not use our encoder, so the verifier
#: refuses to CONSUME past it too.
IJSON_LIMIT = 2**53
BASE_RESOLUTIONS = {"supplied", "recorded-parent", "empty-tree"}
VANTAGES = {"below-observed", "peer", "self"}
#: How the evidence in this record ARRIVED, which is a different question from
#: where the producer stood. Three values are the sibling vocabulary's, borrowed
#: from the specification it crosswalks; first-hand is that registry's own, for a
#: producer that observed somebody else's execution itself.
ORIGINS = {"self", "first-hand", "third-party-control-plane", "log-import"}
TIERS = {"voluntary", "authoritative"}
MUTATIONS = {"observed", "none"}
READ_STATES = {"bytes-read", "no-bytes-read", "unavailable"}
AGREEMENTS = {"agree", "disagree", "one-sided"}
HASH_ALGORITHMS = {"sha256", "sha1"}
EMPTY_TREE = {
    "sha1": hashlib.sha1(b"tree 0\x00").hexdigest(),
    "sha256": hashlib.sha256(b"tree 0\x00").hexdigest(),
}


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


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise Malformed("duplicate-member")
        seen.add(key)
    return dict(pairs)


def _hex(value: Any, width: int) -> str:
    if not isinstance(value, str) or len(value) != width:
        raise Malformed("digest-malformed")
    if value != value.lower() or any(c not in "0123456789abcdef" for c in value):
        raise Malformed("digest-malformed")
    return value


def _lower_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value != ""
        and all(c in "0123456789abcdef" for c in value)
    )


def _path_normalized(value: Any, allow_trailing_slash: bool) -> bool:
    """Absolute, with no empty, dot or dot-dot segment.

    Without this, /srv/app/../../../etc/shadow starts with /srv/app/ and a write to
    /etc/shadow travels as in-scope under a scope of /srv/app/.
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


def _under(path: str, scope: str) -> bool:
    """Containment at a segment boundary, never by string prefix.

    /srv/application-secrets/id_ed25519 starts with /srv/app and is not under it.
    """
    prefix = scope if scope.endswith("/") else scope + "/"
    return path == scope.rstrip("/") or path.startswith(prefix)


def _timestamp(value: Any, code: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise Malformed(code)
    try:
        return datetime.datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise Malformed(code) from exc


def _required(obj: dict[str, Any], *names: str) -> None:
    for name in names:
        if name not in obj:
            raise Malformed(f"required-member-absent:{name}")


# ---------------------------------------------------------------------------
# The rules. One function per rule the predicate states. mutation_check.py
# replaces one of these with a no-op at a time.
# ---------------------------------------------------------------------------


def rule_ijson_integers(statement: dict[str, Any]) -> None:
    """No integer at or above 2**53 anywhere, at any depth.

    The Prerequisites section states this as a MUST and canonical.py enforces it on
    the way out. Nothing enforced it on the way in, so a byteRange of
    9007199254740993 was accepted and two rails read two different numbers from one
    set of bytes.
    """

    def walk(node: Any) -> None:
        if isinstance(node, bool):
            return
        if isinstance(node, int):
            if abs(node) >= IJSON_LIMIT:
                raise Malformed("integer-not-ijson-safe")
            return
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(statement)


def rule_predicate_type(statement: dict[str, Any]) -> None:
    """The statement must say which predicate these fields belong to."""
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise Malformed("predicate-type-unexpected")


def rule_subject_binding(statement: dict[str, Any]) -> None:
    """The subject is the interval's after-state, and nothing else.

    This is the rule whose absence made every other rule in this file optional: a
    consumer gates on the subject digest, and while nothing bound it to the
    interval, a record could carry an honest, fully authoritative interval beside a
    subject naming an artifact the interval never produced.
    """
    pred = statement["predicate"]
    subject = statement.get("subject")
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


def rule_required_members(pred: dict[str, Any]) -> None:
    """No member has a default, and no verifier may supply one."""
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


def rule_closed_vocabularies(pred: dict[str, Any]) -> None:
    """Fail-closed on an unknown value in any closed vocabulary."""
    if pred["tier"] not in TIERS:
        raise Malformed("tier-unknown")
    if pred["mutation"] not in MUTATIONS:
        raise Malformed("mutation-unknown")
    if pred["hashAlgorithm"] not in HASH_ALGORITHMS:
        raise Malformed("hash-algorithm-unknown")
    if pred["observation"]["vantage"] not in VANTAGES:
        raise Malformed("vantage-unknown")
    if pred["observation"]["origin"] not in ORIGINS:
        raise Malformed("origin-unknown")


def rule_timestamp_grammar(pred: dict[str, Any]) -> None:
    """Every timestamp is RFC 3339 UTC with Z and no fractional second.

    The ordering rules below compare strings. That is sound for exactly one
    grammar, and two records defeated it: an offset of -05:00 sorted an hour late
    commitment before the interval it was supposed to precede, and a fractional
    second sorted an identical instant strictly before itself.
    """
    interval = pred["interval"]
    for member in TIMESTAMP_MEMBERS:
        _timestamp(interval[member], f"timestamp-not-utc-basic:interval.{member}")
    _timestamp(pred["issuedAt"], "timestamp-not-utc-basic:issuedAt")
    commitment = pred["observation"].get("priorCommitment")
    if commitment is not None and "committedAt" in commitment:
        _timestamp(
            commitment["committedAt"],
            "timestamp-not-utc-basic:priorCommitment.committedAt",
        )


def rule_interval_order(pred: dict[str, Any]) -> None:
    interval = pred["interval"]
    if interval["openedAt"] >= interval["sealedAt"]:
        raise Malformed("interval-not-ordered")
    if pred["issuedAt"] < interval["sealedAt"]:
        raise Malformed("issued-before-sealed")


def rule_base_vocabulary(pred: dict[str, Any]) -> None:
    if pred["interval"]["baseResolution"] not in BASE_RESOLUTIONS:
        raise Malformed("base-resolution-unknown")


def rule_empty_tree_constant(pred: dict[str, Any]) -> None:
    """empty-tree requires the constant for the DECLARED algorithm, not either one."""
    interval = pred["interval"]
    if interval["baseResolution"] != "empty-tree":
        return
    if interval["beforeRoot"] != EMPTY_TREE[pred["hashAlgorithm"]]:
        raise Malformed("empty-tree-constant-wrong-algorithm")


def rule_path_scope_literal(pred: dict[str, Any]) -> None:
    for entry in pred["pathScope"]:
        if not isinstance(entry, str) or not entry.startswith("/"):
            raise Malformed("path-scope-not-absolute")
        if GLOB_METACHARACTERS & set(entry):
            raise Malformed("path-scope-glob-metacharacter")


def rule_paths_normalized(pred: dict[str, Any]) -> None:
    """Every path in the statement is an absolute normalized path."""
    for entry in pred["pathScope"]:
        if not _path_normalized(entry, allow_trailing_slash=True):
            raise Malformed("path-scope-not-normalized")
    for row in pred["reads"] + pred["writes"]:
        if not _path_normalized(row.get("path"), allow_trailing_slash=False):
            raise Malformed("path-not-normalized")


def rule_write_chain(pred: dict[str, Any]) -> None:
    """The ordered composition must carry beforeRoot to afterRoot."""
    interval = pred["interval"]
    writes = pred["writes"]
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


def rule_mutation_coherence(pred: dict[str, Any]) -> None:
    """A record whose own carried evidence refutes its own claim is malformed."""
    interval = pred["interval"]
    if pred["mutation"] == "none":
        if pred["writes"]:
            raise Malformed("mutation-contradicted-by-writes")
        if interval["beforeRoot"] != interval["afterRoot"]:
            raise Malformed("mutation-none-with-moved-root")
    else:
        if not pred["writes"]:
            raise Malformed("mutation-observed-without-writes")


def rule_read_bindings(pred: dict[str, Any]) -> None:
    for row in pred["reads"]:
        _required(row, "path", "preStateDigest", "blobDigest", "readState")
        if row["readState"] not in READ_STATES:
            raise Malformed("read-state-unknown")
        if row["readState"] != "bytes-read":
            if "byteRange" in row or "rangeDigest" in row:
                raise Malformed("read-state-carries-range")
            continue
        _required(row, "byteRange", "rangeDigest")
        rng = row["byteRange"]
        _required(rng, "start", "end")
        if not isinstance(rng["start"], int) or not isinstance(rng["end"], int):
            raise Malformed("byte-range-not-integer")
        if rng["start"] < 0:
            raise Malformed("byte-range-negative")
        if rng["end"] <= rng["start"]:
            raise Malformed("byte-range-empty")


def rule_range_preimage(pred: dict[str, Any], blobs: dict[str, bytes]) -> None:
    """rangeDigest binds blob length and both offsets, never the range bytes alone.

    A verifier that holds the blob recomputes this. A verifier that does not holds
    the range digest as an opaque commitment and cannot check it, which is why the
    predicate calls three of the four read bindings checkable rather than four.
    """
    for row in pred["reads"]:
        if row.get("readState") != "bytes-read":
            continue
        blob = blobs.get(row["blobDigest"])
        if blob is None:
            continue
        start, end = row["byteRange"]["start"], row["byteRange"]["end"]
        pre = (
            f"{len(blob)}\0".encode()
            + f"{start}\0".encode()
            + f"{end}\0".encode()
            + blob[start:end]
        )
        if row["rangeDigest"] != hashlib.sha256(pre).hexdigest():
            raise Malformed("range-digest-preimage-wrong")


def rule_read_chain(pred: dict[str, Any]) -> None:
    """A read's pre-state must be a state this interval actually passed through."""
    interval = pred["interval"]
    reachable = {interval["beforeRoot"]}
    for row in pred["writes"]:
        reachable.add(row["postStateDigest"])
    for row in pred["reads"]:
        if row["preStateDigest"] not in reachable:
            raise Malformed("read-pre-state-not-in-interval")


def rule_empty_tree_holds_no_bytes(pred: dict[str, Any]) -> None:
    """Nothing can be read out of the empty tree.

    The terminal case of base resolution is the strongest thing a producer can
    claim about the past: there was nothing before. A record that claims it and
    then reads 64 bytes from a file at that root has said both.
    """
    before = pred["interval"]["beforeRoot"]
    if before != EMPTY_TREE[pred["hashAlgorithm"]]:
        return
    for row in pred["reads"]:
        if row.get("readState") == "bytes-read" and row.get("preStateDigest") == before:
            raise Malformed("bytes-read-from-the-empty-tree")


def rule_coverage_coherence(pred: dict[str, Any]) -> None:
    coverage = pred["observation"]["coverage"]
    _required(coverage, "scopeComplete", "gaps")
    if not coverage["scopeComplete"]:
        return
    for gap in coverage["gaps"]:
        if any(_under(gap, scope) for scope in pred["pathScope"]):
            raise Malformed("coverage-self-contradictory")


def rule_coverage_gaps_named(pred: dict[str, Any]) -> None:
    """An incomplete observation says WHERE it was blind.

    Clause 4 of the tier recompute reads "every member of gaps names a path outside
    pathScope", and an empty gaps list satisfies that vacuously, so a record could
    admit that it did not cover its own scope, name no gap, and still grade
    authoritative. The blind spot is where the writes went.
    """
    coverage = pred["observation"]["coverage"]
    if not coverage["scopeComplete"] and not coverage["gaps"]:
        raise Malformed("coverage-incomplete-without-gaps")


def rule_origin_carries_the_vantage(pred: dict[str, Any]) -> None:
    """Only a producer that observed it itself may claim to have stood below.

    Without this member there was no place in the record where an importer had to
    say it imported, so a record assembled from another vendor's exported log
    could be emitted as a first-hand below-observed observation and no field in
    the statement contradicted it. The lie was not a false value anywhere; it was
    a claim the format had no slot to refuse.
    """
    obs = pred["observation"]
    if obs["vantage"] == "below-observed" and obs["origin"] != "first-hand":
        raise Malformed("origin-cannot-carry-below-observed-vantage")


def rule_prior_commitment_present(pred: dict[str, Any]) -> None:
    """priorCommitment is required where vantage is below-observed.

    The Fields section says so and nothing enforced it, so a record could carry the
    independence claim with nothing behind it and pass as voluntary. Refusing it
    here is what makes clause 2 of the tier recompute unreachable, and the clause is
    gone for that reason rather than kept as a sentence.
    """
    obs = pred["observation"]
    if obs["vantage"] == "below-observed" and obs.get("priorCommitment") is None:
        raise Malformed("prior-commitment-absent-for-vantage")


def rule_commitment_digest(pred: dict[str, Any]) -> None:
    commitment = pred["observation"].get("priorCommitment")
    if commitment is None:
        return
    _required(commitment, "committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig")
    # Four members, not two. authorityDigest is in the preimage so an observer
    # cannot select a permissive authority after the interval closed (attack A8);
    # intervalId is in it so one signed commitment cannot serve two intervals that
    # share a before-root (attack A9). Both were open while the preimage carried
    # only beforeRoot and the nonce.
    recomputed = hashlib.sha256(
        canonical_bytes(
            {
                "authorityDigest": pred["authorityDigest"],
                "beforeRoot": pred["interval"]["beforeRoot"],
                "intervalId": pred["intervalId"],
                "witnessNonce": commitment["witnessNonce"],
            }
        )
    ).hexdigest()
    if commitment["commitmentDigest"] != recomputed:
        raise Malformed("commitment-digest-mismatch")


def rule_agreement_derivable(pred: dict[str, Any]) -> None:
    for row in pred["dualValues"]:
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


def rule_dual_value_recomputes(pred: dict[str, Any]) -> None:
    """For a fact the statement can compute about itself, the observed side is that.

    dualValues is the member the predicate offers as the one that catches a lying
    producer without trusting anyone, and the observed side was a free string: a
    record carrying two writes could declare writes.count observed as 7 and agree
    with itself. A fact the carried bytes determine is not a matter of report.
    """
    for row in pred["dualValues"]:
        derive = SELF_DERIVABLE.get(row["fact"])
        if derive is None:
            continue
        if row["observedValue"] != derive(pred):
            raise Malformed("dual-value-not-recomputable")


def rule_keyid_form(pred: dict[str, Any]) -> None:
    """One spelling per key identifier, so a comparison cannot be dodged by case.

    The disjointness check below is the predicate's offline discriminator and it is
    a string comparison. An observed party that listed its own key uppercase in
    observedSigners and committed with it lowercase passed the discriminator with
    the same key on both sides.
    """
    obs = pred["observation"]
    for keyid in obs["observedSigners"]:
        if not _lower_hex(keyid):
            raise Malformed("keyid-not-lowercase-hex")
    commitment = obs.get("priorCommitment")
    if commitment is not None and not _lower_hex(commitment.get("keyid")):
        raise Malformed("keyid-not-lowercase-hex")


def rule_commitment_signature(pred: dict[str, Any], observer_public_key: str) -> None:
    """The prior commitment is signed, and the signature is CHECKED.

    Stage two in the Parsing Rules section names this gate and nothing implemented
    it, so sixty-four zero bytes in sig produced an authoritative record. Checking
    it against the key the consumer anchored also narrows attack A1: the second key
    a self-observer commits with is no longer any key it likes, it is a key the
    consumer has to have anchored.
    """
    commitment = pred["observation"].get("priorCommitment")
    if commitment is None:
        return
    body = {
        "authorityDigest": pred["authorityDigest"],
        "beforeRoot": pred["interval"]["beforeRoot"],
        "intervalId": pred["intervalId"],
        "witnessNonce": commitment["witnessNonce"],
    }
    try:
        signature = bytes.fromhex(commitment["sig"])
    except (ValueError, TypeError) as exc:
        raise Malformed("commitment-signature-unreadable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(observer_public_key)).verify(
            signature, canonical_bytes(body)
        )
    except InvalidSignature as exc:
        raise Invalid("commitment-signature-invalid") from exc


def rule_commitment_order(pred: dict[str, Any]) -> None:
    commitment = pred["observation"].get("priorCommitment")
    if commitment is None:
        return
    if commitment["committedAt"] >= pred["interval"]["openedAt"]:
        raise Invalid("commitment-not-prior")


def rule_commitment_keyid_disjoint(pred: dict[str, Any]) -> None:
    """The offline discriminator. Necessary, and the predicate says not sufficient."""
    obs = pred["observation"]
    commitment = obs.get("priorCommitment")
    if commitment is None:
        return
    if commitment["keyid"] in obs["observedSigners"]:
        raise Invalid("commitment-keyid-not-disjoint")


def rule_write_scope(pred: dict[str, Any]) -> None:
    for row in pred["writes"]:
        covered = any(_under(row["path"], scope) for scope in pred["pathScope"])
        if covered != bool(row["inScope"]):
            raise Invalid("write-in-scope-mislabelled")
        if not covered and pred["tier"] == "authoritative":
            raise Invalid("write-outside-path-scope")


def rule_tier_recompute(pred: dict[str, Any]) -> None:
    """tier is recomputed, never read as a claim. Failure is invalid, not a downgrade."""
    obs = pred["observation"]
    clauses = {
        "authoritative-vantage-not-independent": obs["vantage"] == "below-observed",
        "authoritative-empty-path-scope": bool(pred["pathScope"]),
        "authoritative-coverage-incomplete": bool(obs["coverage"]["scopeComplete"])
        or not any(
            _under(gap, scope)
            for gap in obs["coverage"]["gaps"]
            for scope in pred["pathScope"]
        ),
    }
    # The prior-commitment clause is gone for the same reason, and it went the same
    # way: rule_prior_commitment_present refuses a below-observed record with no
    # commitment in stage one, and a record whose vantage is anything else fails the
    # vantage clause first, so no input reached the commitment clause here.
    #
    # There is no mutation-shape clause here either, and its absence is deliberate. An
    # earlier draft carried one, and the mutation sweep proved it UNREACHABLE: any
    # record whose mutation claim disagrees with its write set is already malformed
    # under rule_mutation_coherence, which is stage one and runs first. A clause no
    # input can reach is a sentence, not a gate, and worse than absent: it made the
    # coherence rule look measured when nothing measured it.
    derived = "authoritative" if all(clauses.values()) else "voluntary"
    if pred["tier"] == derived:
        return
    if pred["tier"] == "authoritative":
        for code, held in clauses.items():
            if not held:
                raise Invalid(code)
    raise Invalid("tier-recompute-mismatch")


def rule_authoritative_carries_rows(pred: dict[str, Any]) -> None:
    """An authoritative record observed something.

    Attack A2 is recorded as closed by the non-empty pathScope clause. It was
    closed against one spelling: pathScope ["/"] with an empty reads and an empty
    writes is the same vacuous record, graded the strongest tier, asserting that
    nothing happened anywhere. mutation: none is a positive claim about an interval
    and it needs a row to be a claim about anything.
    """
    if pred["tier"] != "authoritative":
        return
    if not pred["reads"] and not pred["writes"]:
        raise Invalid("authoritative-without-observed-rows")


#: Rules whose input is the whole statement rather than the predicate, and the one
#: that needs the consumer's anchored key. The dispatch is by name because RULES is
#: what mutation_check.py disables one entry of.
STATEMENT_SCOPED = frozenset(
    {"rule_ijson_integers", "rule_predicate_type", "rule_subject_binding"}
)
BLOB_SCOPED = frozenset({"rule_range_preimage"})
KEY_SCOPED = frozenset({"rule_commitment_signature"})


#: Ordered because stage one precedes stage two, and because the first refusal is
#: the code the manifest names. Each entry is (condition-ish name, function).
RULES: list[tuple[str, Callable[..., None]]] = [
    ("rule_ijson_integers", rule_ijson_integers),
    ("rule_predicate_type", rule_predicate_type),
    ("rule_required_members", rule_required_members),
    ("rule_closed_vocabularies", rule_closed_vocabularies),
    ("rule_timestamp_grammar", rule_timestamp_grammar),
    ("rule_interval_order", rule_interval_order),
    ("rule_base_vocabulary", rule_base_vocabulary),
    ("rule_empty_tree_constant", rule_empty_tree_constant),
    ("rule_path_scope_literal", rule_path_scope_literal),
    ("rule_paths_normalized", rule_paths_normalized),
    ("rule_mutation_coherence", rule_mutation_coherence),
    ("rule_write_chain", rule_write_chain),
    ("rule_subject_binding", rule_subject_binding),
    ("rule_read_bindings", rule_read_bindings),
    ("rule_range_preimage", rule_range_preimage),
    ("rule_read_chain", rule_read_chain),
    ("rule_empty_tree_holds_no_bytes", rule_empty_tree_holds_no_bytes),
    ("rule_coverage_coherence", rule_coverage_coherence),
    ("rule_coverage_gaps_named", rule_coverage_gaps_named),
    ("rule_origin_carries_the_vantage", rule_origin_carries_the_vantage),
    ("rule_prior_commitment_present", rule_prior_commitment_present),
    ("rule_commitment_digest", rule_commitment_digest),
    ("rule_keyid_form", rule_keyid_form),
    ("rule_agreement_derivable", rule_agreement_derivable),
    ("rule_dual_value_recomputes", rule_dual_value_recomputes),
    ("rule_commitment_signature", rule_commitment_signature),
    ("rule_commitment_order", rule_commitment_order),
    ("rule_commitment_keyid_disjoint", rule_commitment_keyid_disjoint),
    ("rule_write_scope", rule_write_scope),
    ("rule_tier_recompute", rule_tier_recompute),
    ("rule_authoritative_carries_rows", rule_authoritative_carries_rows),
]


def pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (
        len(payload_type),
        payload_type.encode(),
        len(payload),
        payload,
    )


def verify(
    raw: bytes,
    observer_public_key: str,
    blobs: dict[str, bytes] | None = None,
    disabled: str | None = None,
) -> tuple[str, list[str]]:
    """Return (verdict, codes) for one vector file.

    `disabled` names one rule to skip, which is how mutation_check.py asks whether
    that rule is load-bearing. Production verification never passes it.
    """
    blobs = blobs or {}
    try:
        envelope = json.loads(raw, object_pairs_hook=_no_duplicates)
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(payload, object_pairs_hook=_no_duplicates)
    except Malformed as exc:
        return "malformed", [exc.code]
    except Exception:
        return "malformed", ["not-parseable"]

    refusal = _apply_rules(statement, blobs, disabled, observer_public_key)
    if refusal is not None:
        return refusal
    return _verify_envelope(envelope, payload, observer_public_key)


def _apply_rules(
    statement: dict[str, Any],
    blobs: dict[str, bytes],
    disabled: str | None,
    observer_public_key: str,
) -> tuple[str, list[str]] | None:
    """Run stage one and stage two. Return a refusal, or None where every rule held."""
    try:
        if statement["_type"] != "https://in-toto.io/Statement/v1":
            raise Malformed("statement-type-unexpected")
        pred = statement["predicate"]
        for name, fn in RULES:
            if name == disabled:
                continue
            if name in STATEMENT_SCOPED:
                fn(statement)
            elif name in BLOB_SCOPED:
                fn(pred, blobs)
            elif name in KEY_SCOPED:
                fn(pred, observer_public_key)
            else:
                fn(pred)
    except Malformed as exc:
        return "malformed", [exc.code]
    except Invalid as exc:
        return "invalid", [exc.code]
    except (KeyError, TypeError) as exc:  # a shape the rules did not name
        return "malformed", [f"unhandled-shape:{exc.__class__.__name__}"]
    return None


def _verify_envelope(
    envelope: dict[str, Any], payload: bytes, observer_public_key: str
) -> tuple[str, list[str]]:
    try:
        signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(observer_public_key)).verify(
            signature, pae(envelope["payloadType"], payload)
        )
    except InvalidSignature:
        return "invalid", ["envelope-signature-invalid"]
    except Exception:
        return "malformed", ["envelope-signature-unreadable"]
    return "valid", []


# ---------------------------------------------------------------------------
# Corpus self-check
# ---------------------------------------------------------------------------

FAILURES: list[str] = []

#: The one blob this corpus narrates, reconstructed here rather than imported, so
#: the range-preimage rule is checked against bytes this file states.
BLOB = b"port: 8080\nmode: strict\n" * 8
BLOBS = {hashlib.sha256(BLOB).hexdigest(): BLOB}


def check_member(manifest: dict[str, Any], entry: dict[str, Any]) -> None:
    path = os.path.join(HERE, entry["file"])
    with open(path, "rb") as fh:
        raw = fh.read()
    if hashlib.sha256(raw).hexdigest()[:16] != entry["id"][1:]:
        FAILURES.append(f"{entry['id']}: file bytes do not hash to the identifier")
    verdict, codes = verify(raw, manifest["keys"]["observer"]["publicKey"], BLOBS)

    if entry["kind"] == "indeterminate":
        allowed = {reading["verdict"] for reading in entry["readings"]}
        if verdict not in allowed:
            FAILURES.append(
                f"{entry['id']} ({entry['slug']}): reference verifier took the "
                f"reading {verdict!r}, which is outside the declared set {sorted(allowed)}"
            )
        return

    want = entry["expected"]
    if verdict != want["verdict"]:
        FAILURES.append(
            f"{entry['id']} ({entry['slug']}): expected {want['verdict']}, got {verdict} {codes}"
        )
        return
    if want["codes"] and codes != want["codes"]:
        FAILURES.append(
            f"{entry['id']} ({entry['slug']}): expected codes {want['codes']}, got {codes}"
        )


def check_twins(manifest: dict[str, Any]) -> None:
    """Every reject condition must also be carried by a member that must be accepted.

    Without this, a verifier that refuses every input scores full marks.
    """
    accept_conditions: set[str] = set()
    reject_conditions: set[str] = set()
    indeterminate_conditions: set[str] = set()
    buckets = {
        "accept": accept_conditions,
        "reject": reject_conditions,
        "indeterminate": indeterminate_conditions,
    }
    for entry in manifest["vectors"]:
        buckets[entry["kind"]].update(entry["conditions"])
    orphan_rejects = sorted(reject_conditions - accept_conditions)
    # A condition carried only by an indeterminate member is exempt from the twin
    # requirement by construction: the predicate states no rule for it, so there is
    # no implementation for a refuse-everything strategy to skip. It still has to be
    # declared, and it still may not be the ONLY exemption in the corpus without
    # being visible here.
    orphan_rejects = [c for c in orphan_rejects if c not in indeterminate_conditions]
    for condition in orphan_rejects:
        FAILURES.append(
            f"condition {condition} is exercised only by reject members, so refusing "
            "everything scores full marks on it"
        )
    declared = set(manifest["conditions"])
    exercised = accept_conditions | reject_conditions | indeterminate_conditions
    unexercised = sorted(declared - exercised)
    for condition in unexercised:
        FAILURES.append(f"condition {condition} is declared and no member exercises it")
    undeclared = sorted(exercised - declared)
    for condition in undeclared:
        FAILURES.append(f"condition {condition} is used by a member and not declared")
    no_reject = sorted(
        c
        for c in declared
        if c in accept_conditions
        and c not in reject_conditions
        and c not in indeterminate_conditions
    )
    for condition in no_reject:
        FAILURES.append(
            f"condition {condition} has no reject member, so a verifier that "
            "implements nothing for it scores full marks"
        )


def check_parents(manifest: dict[str, Any]) -> None:
    ids = {entry["id"] for entry in manifest["vectors"]}
    for entry in manifest["vectors"]:
        if entry["kind"] != "reject":
            continue
        if "parent" not in entry:
            FAILURES.append(f"{entry['id']}: a reject member names no parent")
        elif entry["parent"] not in ids:
            FAILURES.append(f"{entry['id']}: parent {entry['parent']} is not a member")


def check_counts(manifest: dict[str, Any]) -> None:
    actual = {"accept": 0, "reject": 0, "indeterminate": 0}
    for entry in manifest["vectors"]:
        actual[entry["kind"]] += 1
    if actual != manifest["counts"]:
        FAILURES.append(f"counts declare {manifest['counts']} and the members are {actual}")
    if manifest["predicateType"] != PREDICATE_TYPE:
        FAILURES.append(
            "the manifest's predicateType is not the URI this verifier enforces"
        )
    if manifest["emptyTree"] != EMPTY_TREE:
        FAILURES.append("the manifest's empty-tree constants are not the computed ones")
    recomputed = corpus_digest(manifest)
    if manifest["corpusDigest"] != recomputed:
        FAILURES.append(
            f"corpusDigest {manifest['corpusDigest'][:12]} does not recompute "
            f"({recomputed[:12]})"
        )


def main() -> None:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    for entry in manifest["vectors"]:
        check_member(manifest, entry)
    check_twins(manifest)
    check_parents(manifest)
    check_counts(manifest)

    if FAILURES:
        for failure in FAILURES:
            print("FAIL", failure)
        sys.exit(1)
    counts = manifest["counts"]
    print(
        f"OK {counts['accept']} accept, {counts['reject']} reject, "
        f"{counts['indeterminate']} indeterminate, "
        f"{len(manifest['conditions'])} conditions, "
        f"corpus {manifest['corpusDigest'][:12]}"
    )


if __name__ == "__main__":
    main()
