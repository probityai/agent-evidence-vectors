"""Generate the TRACE registry anchor cases, byte for byte.

Trees and audit paths are built with the RFC 6962 recursive split at the
largest power of two (MTH and PATH, RFC 6962 section 2.1), which shares no code
with the iterative section 5.1 replay the reader runs. A case that verifies
therefore verifies under two independent constructions of the same tree.

Run from the repository root: ``python3 vectors-trace-anchor/gen_vectors.py``.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SUITE = "trace-registry-anchor/v1"
SPEC = {
    "document": "spec/registry-anchor-v1.md",
    "repository": "https://github.com/agentrust-io/trace-spec",
    "commit": "95e160a8ef1c54081d987c6ce4dfcce121d9440b",
    "amendment": "https://github.com/agentrust-io/trace-spec/pull/533",
    "baseCommit": "6fb2570",
}
ANCHORED, REFUSED = "anchored", "refused"
LOG = "https://registry.example.org/anchors"


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def leaf_bytes(claim: dict[str, Any]) -> bytes:
    return json.dumps(claim, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def leaf_hash(claim: dict[str, Any]) -> bytes:
    return hashlib.sha256(b"\x00" + leaf_bytes(claim)).digest()


def node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node(mth(leaves[:k]), mth(leaves[k:]))


def path(m: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]


def h(digest: bytes) -> str:
    return "sha256:" + digest.hex()


def record(subject: str, iat: int, batch: str, **extra: Any) -> dict[str, Any]:
    """A small Trust-Record-shaped claim. ``signature`` is an opaque fixture
    string: section 5.2 says inclusion does not check the signature."""
    claim: dict[str, Any] = {
        "transparency": f"{LOG}/{batch}",
        "subject": subject,
        "iat": iat,
        "signature": f"fixture-signature-{subject}",
    }
    claim.update(extra)
    return claim


class Batch:
    """One anchored batch: its ordered claims, its tree, and its section 4 entry."""

    def __init__(self, batch_id: str, claims: list[dict[str, Any]],
                 leaves: list[bytes] | None = None) -> None:
        self.batch_id = batch_id
        self.claims = claims
        self.leaves = leaves if leaves is not None else [leaf_hash(c) for c in claims]
        self.root = mth(self.leaves)

    def entry(self, **override: Any) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": "2026-10-15T12:00:00Z",
            "merkle_root": h(self.root),
            "leaf_count": len(self.leaves),
            "producer": "trace-gateway/1.0.0",
            "batch_id": self.batch_id,
        }
        entry.update(override)
        return entry

    def receipt(self, index: int, carry: bool = True) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "leaf_index": index,
            "audit_path": [h(p) for p in path(index, self.leaves)],
        }
        if carry:
            receipt["merkle_root"] = h(self.root)
            receipt["leaf_count"] = len(self.leaves)
        return receipt


def batch(batch_id: str, size: int, **extra: Any) -> Batch:
    return Batch(batch_id, [record(f"{batch_id}-agent-{i}", 1792000000 + i, batch_id, **extra)
                            for i in range(size)])


def _member(member_id: str, case: dict[str, Any], decision: str, reason: str, rule: str,
            attack: str, amended: bool = False) -> dict[str, Any]:
    return {"id": member_id, "case": case, "decision": decision, "reason": reason,
            "rule": rule, "attack": attack, "dependsOnAmendment": amended}


def members() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    link = "included_link_unchecked"

    def accept(member_id: str, case: dict[str, Any], rule: str, attack: str,
               amended: bool = False) -> None:
        out.append(_member(member_id, case, ANCHORED, link, rule, attack, amended))

    def refuse(member_id: str, case: dict[str, Any], reason: str, rule: str, attack: str,
               amended: bool = False) -> None:
        out.append(_member(member_id, case, REFUSED, reason, rule, attack, amended))

    one = batch("b-one", 1)
    five = batch("b-five", 5)
    eight = batch("b-eight", 8)
    other_five = batch("b-other-five", 5)

    # Accepted controls: the verdict every rule below is measured against.
    accept("anchored-one-leaf",
           {"claim": one.claims[0], "receipt": one.receipt(0), "entry": one.entry()},
           "5.1", "control: a batch of one leaf has an empty audit path")
    accept("anchored-five-leaves-right-edge",
           {"claim": five.claims[4], "receipt": five.receipt(4), "entry": five.entry()},
           "3, 5.1", "control: the last leaf of an odd batch is promoted, never duplicated")
    accept("anchored-eight-leaves-interior",
           {"claim": eight.claims[5], "receipt": eight.receipt(5), "entry": eight.entry()},
           "5.1", "control: an interior leaf of a full batch")
    accept("anchored-proof-only-receipt",
           {"claim": five.claims[2], "receipt": five.receipt(2, carry=False),
            "entry": five.entry()},
           "5, 5.1, 6",
           "the proof in the exact section 5 shape, leaf_index and audit_path only, with the "
           "entry supplied: section 6 says only a root or count the receipt carries is checked "
           "against the entry, so a receipt that carries neither is complete", amended=True)
    signed = record("agent-ü", 1792000100, "b-signed", **{
        "policy": {"name": "Zürich egress", "\U0001f600": "astral key", "｡": "bmp key"},
        "signature": "eyJhbGciOiJFZERTQSJ9..fixture",
    })
    signed_batch = Batch("b-signed", [signed, *batch("b-signed", 2).claims])
    accept("anchored-non-ascii-signed-record",
           {"claim": signed, "receipt": signed_batch.receipt(0), "entry": signed_batch.entry()},
           "0, 1",
           "control for the canonicalization trap: non-ASCII strings are escaped and keys sort "
           "by code point, so a U+1F600 key follows a U+FF61 key here although UTF-16 order "
           "puts it first")
    big = record("agent-max", 9007199254740991, "b-max")
    big_batch = Batch("b-max", [big, *batch("b-max", 2).claims])
    accept("anchored-max-safe-integer",
           {"claim": big, "receipt": big_batch.receipt(0), "entry": big_batch.entry()},
           "1", "boundary control: 2^53 - 1 is the largest integer inside the profile")
    elsewhere = dict(five.claims[1])
    elsewhere["transparency"] = f"{LOG}/b-some-other-batch"
    moved = Batch("b-five-moved", [*five.claims[:1], elsewhere, *five.claims[2:]])
    accept("anchored-transparency-names-other-batch",
           {"claim": elsewhere, "receipt": moved.receipt(1), "entry": moved.entry()},
           "6",
           "the claim's transparency URI names a batch other than the entry supplied. Nothing "
           "defines the URI-to-entry link yet (trace-spec#448 finding 21), so the verdict is "
           "inclusion in the entry given, with the link stated unchecked. This member flips "
           "to refused once that link is defined", amended=True)

    # Receipt shape.
    refuse("receipt-absent", {"claim": five.claims[0], "entry": five.entry()},
           "receipt_absent", "5.1", "a URI and an entry, but no proof to replay")
    upper = five.receipt(3)
    upper["audit_path"][0] = upper["audit_path"][0].upper().replace("SHA256:", "sha256:")
    refuse("receipt-path-uppercase-hex",
           {"claim": five.claims[3], "receipt": upper, "entry": five.entry()},
           "receipt_malformed", "3, 5", "a sibling hash in uppercase hex, which section 3's "
           "lowercase form excludes; a decoder that accepts it accepts two spellings of one "
           "hash")
    two = batch("b-two", 2)
    boolean_index = two.receipt(1)
    boolean_index["leaf_index"] = True
    refuse("receipt-index-boolean",
           {"claim": two.claims[1], "receipt": boolean_index, "entry": two.entry()},
           "receipt_malformed", "5",
           "leaf_index is JSON true and the claim really is leaf 1: a verifier that lets a "
           "boolean stand for an integer accepts it")
    unprefixed = five.receipt(2)
    unprefixed["merkle_root"] = unprefixed["merkle_root"][len("sha256:"):]
    refuse("receipt-root-unprefixed",
           {"claim": five.claims[2], "receipt": unprefixed, "entry": five.entry()},
           "receipt_malformed", "3, 6",
           "the receipt carries the right root without its sha256: prefix; a verifier that "
           "ignores a carried root accepts it")

    # The entry, the input trace-spec#533 makes mandatory.
    refuse("entry-absent", {"claim": five.claims[1], "receipt": five.receipt(1)},
           "entry_absent", "6",
           "an honest, self-consistent receipt and no registry entry: before trace-spec#533 a "
           "suite replayed the proof against the root the receipt brought and passed it",
           amended=True)
    lone = record("agent-self-anchored", 1792000200, "b-never-anchored")
    self_receipt = {"leaf_index": 0, "audit_path": [], "merkle_root": h(leaf_hash(lone)),
                    "leaf_count": 1}
    refuse("self-anchored-no-entry", {"claim": lone, "receipt": self_receipt},
           "entry_absent", "6",
           "a record never anchored anywhere, with a one-leaf receipt whose root is its own "
           "leaf hash. Any record can write this receipt for itself", amended=True)
    refuse("entry-leaf-count-boolean",
           {"claim": one.claims[0], "receipt": one.receipt(0, carry=False),
            "entry": one.entry(leaf_count=True)},
           "entry_malformed", "4",
           "leaf_count is JSON true in a one-leaf batch: a verifier that lets a boolean stand "
           "for 1 accepts it")
    refuse("entry-producer-empty",
           {"claim": five.claims[0], "receipt": five.receipt(0), "entry": five.entry(producer="")},
           "entry_malformed", "4", "an entry naming no producer cannot be attributed")
    missing_ts = five.entry()
    del missing_ts["ts"]
    refuse("entry-missing-ts",
           {"claim": five.claims[0], "receipt": five.receipt(0), "entry": missing_ts},
           "entry_malformed", "4", "an entry without its anchoring time")

    # The receipt's own claims about the entry.
    refuse("self-anchored-with-real-entry",
           {"claim": lone, "receipt": self_receipt, "entry": five.entry()},
           "receipt_root_mismatch", "6",
           "the self-anchored receipt presented beside a genuine entry the record is not in. "
           "A suite that replays against the receipt's root, as trace-spec did before #533, "
           "passes a record that was never anchored", amended=True)
    lying_root = five.receipt(2)
    lying_root["merkle_root"] = h(other_five.root)
    refuse("receipt-root-lies",
           {"claim": five.claims[2], "receipt": lying_root, "entry": five.entry()},
           "receipt_root_mismatch", "6",
           "the proof replays to the entry's root, but the receipt names another batch's "
           "root: section 6 says to refuse when a carried root differs, not to ignore it",
           amended=True)
    sub = eight.leaves[:4]
    subtree = {"leaf_index": 1, "audit_path": [h(p) for p in path(1, sub)],
               "merkle_root": h(mth(sub)), "leaf_count": 4}
    refuse("receipt-subtree-root",
           {"claim": eight.claims[1], "receipt": subtree, "entry": eight.entry()},
           "receipt_root_mismatch", "6",
           "a receipt whose root is an interior node of the real tree, with a matching "
           "shortened count and path. It replays to its own root, so a suite that trusts the "
           "receipt's root passes it, although no entry commits to that node", amended=True)
    lying_count = five.receipt(2)
    lying_count["leaf_count"] = 6
    refuse("receipt-count-lies",
           {"claim": five.claims[2], "receipt": lying_count, "entry": five.entry()},
           "receipt_count_mismatch", "6",
           "the receipt says 6 leaves for a 5-leaf entry. Leaf 2's path replays to the same "
           "root under either count, so only the comparison with the entry catches it",
           amended=True)

    # Section 5.1 step 1.
    past_end = five.receipt(4)
    past_end["leaf_index"] = 5
    refuse("index-equals-count",
           {"claim": five.claims[4], "receipt": past_end, "entry": five.entry()},
           "index_out_of_range", "5.1 step 1", "leaf_index equal to leaf_count")
    negative = five.receipt(0)
    negative["leaf_index"] = -1
    refuse("index-negative",
           {"claim": five.claims[0], "receipt": negative, "entry": five.entry()},
           "index_out_of_range", "5.1 step 1", "a negative leaf_index")

    # Section 1 profile.
    with_float = record("agent-float", 1792000300, "b-float", score=0.5)
    float_batch = Batch("b-float", [with_float, *batch("b-float", 2).claims])
    refuse("claim-float",
           {"claim": with_float, "receipt": float_batch.receipt(0), "entry": float_batch.entry()},
           "claim_outside_profile", "1",
           "a non-integer number: the proof was built over the bytes Python writes for it, "
           "which another language's implementation of section 1 need not write")
    too_big = record("agent-2-53", 9007199254740992, "b-2-53")
    big_bad = Batch("b-2-53", [too_big, *batch("b-2-53", 2).claims])
    refuse("claim-integer-2-53",
           {"claim": too_big, "receipt": big_bad.receipt(0), "entry": big_bad.entry()},
           "claim_outside_profile", "1",
           "2^53, which a double-only implementation writes with the same bytes as 2^53 + 1")

    # Section 5.1 replay.
    signed_body = {k: v for k, v in five.claims[3].items() if k != "signature"}
    presig = Batch("b-presig", [*five.claims[:3], signed_body, *five.claims[4:]])
    refuse("pre-signature-anchored",
           {"claim": five.claims[3], "receipt": presig.receipt(3), "entry": presig.entry()},
           "proof_does_not_replay", "1",
           "the producer anchored the claim body before signing it; section 1 anchors the "
           "complete signed claim, signature included")
    truncated = eight.receipt(6)
    truncated["audit_path"] = truncated["audit_path"][:-1]
    refuse("truncated-path",
           {"claim": eight.claims[6], "receipt": truncated, "entry": eight.entry()},
           "proof_does_not_replay", "5.1 step 4", "the audit path with its root-side element cut")
    refuse("proof-only-receipt-other-batch",
           {"claim": other_five.claims[2], "receipt": other_five.receipt(2, carry=False),
            "entry": five.entry()},
           "proof_does_not_replay", "5.1, 6",
           "a section 5 receipt with no root or count, from a batch other than the entry's: "
           "carrying nothing to compare does not excuse the replay against the entry")
    return out


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                 for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return hashlib.sha256(_json(entries)).hexdigest()


def generate(target: Path = HERE) -> None:
    cases = target / "cases"
    if cases.exists():
        shutil.rmtree(cases)
    vectors = []
    for member in members():
        directory = cases / member["id"]
        directory.mkdir(parents=True)
        data = _json(member["case"])
        (directory / "case.json").write_bytes(data)
        vectors.append({
            "id": member["id"],
            "path": f"cases/{member['id']}",
            "files": {"case.json": hashlib.sha256(data).hexdigest()},
            "expected": {"decision": member["decision"], "reason": member["reason"]},
            "rule": member["rule"],
            "attack": member["attack"],
            "dependsOnAmendment": member["dependsOnAmendment"],
        })
    manifest = {
        "suite": SUITE,
        "specification": SPEC,
        "corpusDigest": hashlib.sha256(_json(vectors)).hexdigest(),
        "vectors": vectors,
    }
    verdict_words = [entry["expected"]["decision"] for entry in vectors]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (target / "MANIFEST.json").write_bytes(_json(manifest))


if __name__ == "__main__":
    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else HERE)
