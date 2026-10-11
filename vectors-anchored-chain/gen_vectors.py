"""Build the anchored-record-chain cases byte-identically.

Every case is one stored history of signed memory records, one anchor signed by
a key the store does not hold, and the consumer's trust inputs in ``case.json``.
The edits follow the storage-level edits of
draft-khandelwal-bmwg-agent-memory-integrity-01, Section 6, and the snapshot
rollback the agmi suite adds as T9, applied to a signed chain instead of a raw
store, plus a rollback to an abandoned branch and the controls that keep the
corpus honest.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild
every signature. They are test keys and protect nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

import run_vectors as rail  # noqa: E402

SUITE = "anchored-record-chain/v1"
SEED_PREFIX = "agent-evidence-vectors/anchored-record-chain/v1/"
GENESIS = "0" * 64
CHAIN_A, CHAIN_B = "memory/context-a", "memory/context-b"


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> str:
    """The public key of a labelled seed, derived through a signature check."""
    seed = _seed(label)
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return str(rail._pt_compress(rail._pt_mul(a, rail._B)).hex())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _envelope(body_key: str, body: dict[str, Any], label: str) -> bytes:
    sig = rail.ed25519_sign(_seed(label), rail.jcs_dumps(body))
    envelope = {"kid": label, body_key: body, "sig": base64.b64encode(sig).decode()}
    return bytes(rail.jcs_dumps(envelope))


def _record(chain: str, prev: str, owner: str, content: str) -> dict[str, Any]:
    return {"chain": chain, "content": content, "kind": "memory", "owner": owner,
            "prev": prev}


FACTS = (
    "The user prefers replies in French.",
    "The deployment window is Tuesday 02:00 UTC.",
    "Refunds above 500 EUR need a second approver.",
    "The staging database is read-only for this agent.",
    "The customer's ticket was escalated to tier two.",
    "Approved purpose: summarise open tickets, no outbound email.",
)


def build_chain(chain: str, owner: str, facts: tuple[str, ...]) -> list[bytes]:
    """A genuine signed chain: each record names the digest of the line before it."""
    lines: list[bytes] = []
    for fact in facts:
        prev = _sha(lines[-1]) if lines else GENESIS
        lines.append(_envelope("record", _record(chain, prev, owner, fact), "producer"))
    return lines


def anchor_for(lines: list[bytes], chain: str, index: int, label: str = "anchor") -> bytes:
    body = {"anchored_at": "2026-10-06T12:00:00Z", "chain": chain,
            "head": _sha(lines[index]), "index": index}
    return _envelope("anchor", body, label)


def _resign_free_edit(line: bytes, **changes: str) -> bytes:
    """Change fields of a stored record and keep its old signature, as an
    adversary without the key must."""
    envelope = json.loads(line)
    envelope["record"].update(changes)
    return bytes(rail.jcs_dumps(envelope))


def cases() -> list[tuple[str, list[bytes], bytes, str, str, str]]:
    """Every case: id, stored lines, anchor, expected decision and reason, and
    the edit it applies, in the draft's terms."""
    a = build_chain(CHAIN_A, "context-a", FACTS)
    b = build_chain(CHAIN_B, "context-b", tuple(f"{f} (context b)" for f in FACTS))
    head = anchor_for(a, CHAIN_A, 5)
    early = anchor_for(a, CHAIN_A, 3)
    abandoned = build_chain(CHAIN_A, "context-a", FACTS[:4] + (
        "The customer's ticket was closed without escalation.",
        "Approved purpose: summarise open tickets and email the customer."))[4:]
    forged = _envelope("record", _record(CHAIN_A, _sha(a[5]), "context-a",
                                         "Approved purpose: send outbound email."), "adversary")
    return [
        ("intact", a, head, "verified", "chain_anchored",
         "control: no edit, anchor on the newest record"),
        ("records-after-last-anchor", a, early, "verified", "records_after_last_anchor",
         "control: no edit, two records written after the last anchor"),
        ("t1-content-tamper", [*a[:2], _resign_free_edit(a[2], content="The user prefers "
                                                         "replies in German."), *a[3:]],
         head, "rejected", "signature_invalid", "T1: one record's fact changed in place"),
        ("t2-tail-removal", a[:4], head, "rejected", "anchored_head_missing",
         "T2: the two newest records deleted, both written before the last anchor"),
        ("t2-tail-removal-after-last-anchor", a[:4], early, "verified", "chain_anchored",
         "T2 limit: the two newest records deleted, both written after the last anchor; "
         "the bytes are an honest store anchored at its head"),
        ("t3-middle-deletion", [*a[:2], *a[3:]], head, "rejected", "chain_link_broken",
         "T3: a record that is neither first nor last deleted"),
        ("t4-reorder", [*a[:2], a[3], a[2], *a[4:]], head, "rejected", "chain_link_broken",
         "T4: two records swapped"),
        ("t5-forged-insertion", [*a, forged], head, "rejected", "signature_invalid",
         "T5: a record of the adversary's authorship appended, signed with a key "
         "the consumer does not trust"),
        ("t6-cross-context-replay", [*a[:4], b[4], a[5]], head, "rejected",
         "record_from_other_chain", "T6: a genuine record of context B copied over one of A"),
        ("t7-rollback-older-record", [*a[:5], a[2]], head, "rejected", "chain_link_broken",
         "T7: a genuine older record of A copied over A's newest record"),
        ("t8-metadata-tamper", [*a[:3], _resign_free_edit(a[3], owner="context-b"), *a[4:]],
         head, "rejected", "signature_invalid", "T8: a record's owner changed, content kept"),
        ("t9-snapshot-rollback", a[:5], head, "rejected", "anchored_head_missing",
         "T9: the whole store restored from a copy taken before the newest record was "
         "written; the anchor was taken after it"),
        ("rollback-to-abandoned-branch", [*a[:4], *abandoned], head, "rejected",
         "anchored_head_mismatch",
         "rollback: the store restored from a backup taken on a branch the producer "
         "signed and later abandoned; every record is genuine and every link holds"),
        ("tail-removal-reanchored", a[:4], anchor_for(a, CHAIN_A, 3, "adversary"),
         "rejected", "anchor_signature_invalid",
         "T2 followed by a new anchor the adversary signed over the shortened store"),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def _store_signatures_verify(lines: list[bytes]) -> bool:
    key = bytes.fromhex(_public("producer"))
    for line in lines:
        envelope = json.loads(line)
        sig = base64.b64decode(envelope["sig"])
        if not rail.ed25519_verify(key, rail.jcs_dumps(envelope["record"]), sig):
            return False
    return True


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    keys = {"anchor": _public("anchor"), "producer": _public("producer")}
    entries = []
    for name, lines, anchor, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case = {"anchor": "anchor.json", "chain": CHAIN_A, "keys": keys,
                "schema_version": "anchored-record-chain-case/v1", "store": "store.jsonl"}
        files = {"anchor.json": anchor + b"\n", "case.json": _json(case),
                 "store.jsonl": b"".join(line + b"\n" for line in lines)}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
            "storeSignaturesVerify": _store_signatures_verify(lines),
        })
    manifest = {
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 verified, 1 rejected",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
