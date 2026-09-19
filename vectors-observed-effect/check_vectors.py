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
BASE_RESOLUTIONS = {"supplied", "recorded-parent", "empty-tree"}
VANTAGES = {"below-observed", "peer", "self"}
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


def _required(obj: dict[str, Any], *names: str) -> None:
    for name in names:
        if name not in obj:
            raise Malformed(f"required-member-absent:{name}")


# ---------------------------------------------------------------------------
# The rules. One function per rule the predicate states. mutation_check.py
# replaces one of these with a no-op at a time.
# ---------------------------------------------------------------------------


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
    _required(pred["observation"], "vantage", "coverage", "observedSigners")


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


def rule_coverage_coherence(pred: dict[str, Any]) -> None:
    coverage = pred["observation"]["coverage"]
    _required(coverage, "scopeComplete", "gaps")
    if not coverage["scopeComplete"]:
        return
    for gap in coverage["gaps"]:
        if any(gap.startswith(scope) for scope in pred["pathScope"]):
            raise Malformed("coverage-self-contradictory")


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
            derived = "one-sided"
        elif observed == "" or reported == "":
            derived = "one-sided"
        elif observed == reported:
            derived = "agree"
        else:
            derived = "disagree"
        if row["agreement"] != derived:
            raise Malformed("agreement-not-derivable")


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
        covered = any(row["path"].startswith(scope) for scope in pred["pathScope"])
        if covered != bool(row["inScope"]):
            raise Invalid("write-in-scope-mislabelled")
        if not covered and pred["tier"] == "authoritative":
            raise Invalid("write-outside-path-scope")


def rule_tier_recompute(pred: dict[str, Any]) -> None:
    """tier is recomputed, never read as a claim. Failure is invalid, not a downgrade."""
    obs = pred["observation"]
    clauses = {
        "authoritative-vantage-not-independent": obs["vantage"] == "below-observed",
        "authoritative-prior-commitment-absent": obs.get("priorCommitment") is not None,
        "authoritative-empty-path-scope": bool(pred["pathScope"]),
        "authoritative-coverage-incomplete": bool(obs["coverage"]["scopeComplete"])
        or not any(
            gap.startswith(scope)
            for gap in obs["coverage"]["gaps"]
            for scope in pred["pathScope"]
        ),
    }
    # There is no mutation-shape clause here, and its absence is deliberate. An
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


#: Ordered because stage one precedes stage two, and because the first refusal is
#: the code the manifest names. Each entry is (condition-ish name, function).
RULES: list[tuple[str, Callable[..., None]]] = [
    ("rule_required_members", rule_required_members),
    ("rule_closed_vocabularies", rule_closed_vocabularies),
    ("rule_interval_order", rule_interval_order),
    ("rule_base_vocabulary", rule_base_vocabulary),
    ("rule_empty_tree_constant", rule_empty_tree_constant),
    ("rule_path_scope_literal", rule_path_scope_literal),
    ("rule_mutation_coherence", rule_mutation_coherence),
    ("rule_write_chain", rule_write_chain),
    ("rule_read_bindings", rule_read_bindings),
    ("rule_range_preimage", rule_range_preimage),
    ("rule_read_chain", rule_read_chain),
    ("rule_coverage_coherence", rule_coverage_coherence),
    ("rule_commitment_digest", rule_commitment_digest),
    ("rule_agreement_derivable", rule_agreement_derivable),
    ("rule_commitment_order", rule_commitment_order),
    ("rule_commitment_keyid_disjoint", rule_commitment_keyid_disjoint),
    ("rule_write_scope", rule_write_scope),
    ("rule_tier_recompute", rule_tier_recompute),
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

    refusal = _apply_rules(statement, blobs, disabled)
    if refusal is not None:
        return refusal
    return _verify_envelope(envelope, payload, observer_public_key)


def _apply_rules(
    statement: dict[str, Any], blobs: dict[str, bytes], disabled: str | None
) -> tuple[str, list[str]] | None:
    """Run stage one and stage two. Return a refusal, or None where every rule held."""
    try:
        if statement["_type"] != "https://in-toto.io/Statement/v1":
            raise Malformed("statement-type-unexpected")
        pred = statement["predicate"]
        for name, fn in RULES:
            if name == disabled:
                continue
            if name == "rule_range_preimage":
                fn(pred, blobs)
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
