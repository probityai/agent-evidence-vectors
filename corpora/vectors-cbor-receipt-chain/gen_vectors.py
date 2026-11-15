"""Build the cbor-receipt-chain cases byte-identically.

Every case is a stream of signed CBOR receipts, the consumer's trust inputs and the decision a reader must
reach. Each refusal changes an accepting control so the check it names is the first that fails. Receipts are
signed with keys derived from fixed public labels, which carry no trust outside this corpus, and the format
is the neutral profile in ``profile.json``. Every member is synthetic.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))
sys.path.insert(0, str(ROOT))

import receipt_builder as rb  # noqa: E402
from agent_evidence_vectors import cborreceiptchain as reader  # noqa: E402

SUITE = reader.SUITE
KEY, OTHER = rb.seed_key("corpus-signer"), rb.seed_key("corpus-unpinned")
PROFILE = rb.NEUTRAL
EARLIER = hashlib.sha256(b"earlier run").digest()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _link(receipt: bytes) -> bytes:
    return hashlib.sha256(receipt).digest()


def _run(key: Any, names: str, count: int, first_prev: bytes | None) -> list[bytes]:
    """``count`` linked receipts for distinct requests ``<names>0``, ``<names>1`` and so on."""
    out: list[bytes] = []
    prev = first_prev
    for i in range(count):
        out.append(rb.receipt(PROFILE, key, prev, request=f"{names}{i}"))
        prev = _link(out[-1])
    return out


def base() -> list[bytes]:
    return _run(KEY, "r", 6, None)


def _flip(r: list[bytes]) -> list[bytes]:
    return r[:3] + [r[3][:-1] + bytes([r[3][-1] ^ 1])] + r[4:]


def _resigned(r: list[bytes]) -> list[bytes]:
    return r[:3] + [rb.receipt(PROFILE, OTHER, _link(r[2]), request="r3")] + r[4:]


def _foreign(r: list[bytes]) -> list[bytes]:
    return r + _run(OTHER, "x", 3, _link(r[-1]))


def _dup(r: list[bytes]) -> list[bytes]:
    return r[:3] + [r[2]] + r[3:]


def _reissue(r: list[bytes]) -> list[bytes]:
    return r + [rb.receipt(PROFILE, KEY, _link(r[-1]), request="r0")]


def _denied_repeat(r: list[bytes]) -> list[bytes]:
    return r + [rb.receipt(PROFILE, KEY, _link(r[-1]), request="r0", outcome="deny")]


def _restart(r: list[bytes]) -> list[bytes]:
    return r[:4] + _run(KEY, "s", 2, None)


def _swap(r: list[bytes]) -> list[bytes]:
    return r[:2] + [r[3], r[2]] + r[4:]


def _garbage(r: list[bytes]) -> list[bytes]:
    return r[:2] + [b"\xa1\x01\x02"] + r[3:]


def _earlier_run(_: list[bytes]) -> list[bytes]:
    return _run(KEY, "r", 4, EARLIER)


KEEP = "full"
# id, what changes, edit, which stream the pinned head names (full, original or none), extra case members,
# expected (decision, reason)
CASES: list[tuple[str, str, Callable[[list[bytes]], list[bytes]], str, dict[str, Any], tuple[str, str]]] = [
    ("control-intact-anchored", "control: six receipts, head pinned", lambda r: r, KEEP, {},
     ("supported", "receipt_chain_holds")),
    ("control-first-prev-pinned", "control: a chain that continues an earlier run", _earlier_run, KEEP,
     {"first_prev": EARLIER.hex()}, ("supported", "receipt_chain_holds")),
    ("control-denied-request-repeats", "control: a denied request may be tried again", _denied_repeat,
     KEEP, {}, ("supported", "receipt_chain_holds")),
    ("unanchored-intact", "no head pinned: the stream may be a prefix", lambda r: r, "none", {},
     ("not_established", "head_not_anchored")),
    ("cut-tail-unanchored", "last receipt removed, no head pinned", lambda r: r[:-1], "none", {},
     ("not_established", "head_not_anchored")),
    ("cut-tail-anchored", "last receipt removed, head pinned", lambda r: r[:-1], "original", {},
     ("contradicted", "head_anchor")),
    ("restart-honest", "a new chain starts mid stream", _restart, KEEP, {},
     ("not_established", "chain_reset")),
    ("restart-hides-lost-tail", "a restart after a lost tail, head pinned to the true end", _restart,
     "original", {}, ("contradicted", "head_anchor")),
    ("no-effect-member", "the format records the decision only; an effect is required", lambda r: r,
     KEEP, {"require_effect": True}, ("not_established", "effect_not_recorded")),
    ("signature-flipped", "one signature byte flipped", _flip, KEEP, {}, ("contradicted", "signature")),
    ("receipt-malformed", "a line holds a map that is not a receipt", _garbage, KEEP, {},
     ("contradicted", "receipt_shape")),
    ("embedded-key-unpinned", "one record re-signed under a key the consumer never pinned", _resigned,
     KEEP, {}, ("contradicted", "signer_pinned")),
    ("foreign-key-extends", "an unpinned key appends its own chained receipts", _foreign, KEEP, {},
     ("contradicted", "signer_pinned")),
    ("duplicate-line", "one receipt appears twice", _dup, KEEP, {},
     ("contradicted", "no_duplicate_receipt")),
    ("reissued-authorization", "the same signed request is allowed by a second, linked receipt", _reissue,
     KEEP, {}, ("contradicted", "single_use")),
    ("first-receipt-dropped", "the first receipt removed", lambda r: r[1:], KEEP, {},
     ("contradicted", "chain_order")),
    ("middle-receipt-dropped", "a middle receipt removed", lambda r: r[:2] + r[3:], KEEP, {},
     ("contradicted", "chain_order")),
    ("receipts-swapped", "two receipts swapped", _swap, KEEP, {}, ("contradicted", "chain_order")),
]


def _case(receipts: list[bytes], original: list[bytes], pin: str, extra: dict[str, Any]) -> dict[str, Any]:
    case: dict[str, Any] = {"chain": "chain.jsonl", "profile": "../../profile.json",
                            "signer_keys": [rb.public_hex(KEY)], **extra}
    if pin != "none":
        pinned = receipts if pin == KEEP else original
        case.update(head=_sha(pinned[-1]), count=len(pinned))
    return case


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    if _sha((base_dir / "profile.json").read_bytes()) != manifest["profile"]["sha256"]:
        raise ValueError("profile digest mismatch")
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    (root / "profile.json").write_bytes(_json(PROFILE))
    entries = []
    for name, edit, transform, pin, extra, (decision, reason) in CASES:
        original = base()
        receipts = transform(original)
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        body, stream = _json(_case(receipts, original, pin, extra)), rb.stream(PROFILE, receipts)
        (directory / "case.json").write_bytes(body)
        (directory / "chain.jsonl").write_bytes(stream)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "case.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case says {expected}")
        entries.append({"edit": edit, "expected": expected,
                        "files": {"case.json": _sha(body), "chain.jsonl": _sha(stream)},
                        "id": name, "path": f"cases/{name}", "receipts": len(receipts)})
    words = [e["expected"]["decision"] for e in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {w: words.count(w) for w in sorted(set(words))},
        "profile": {"path": "profile.json", "sha256": _sha(_json(PROFILE))},
        "suite": SUITE,
        "synthetic": True,
        "vectors": entries,
        "verifierContract": "verifier case.json --json; exit 0 supported, 1 contradicted, "
        "3 not_established",
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
