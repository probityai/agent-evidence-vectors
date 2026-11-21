"""Build the empty-interval-statement cases byte-identically.

Every case is one revocation ledger (a hash-linked chain of signed events), one signed
statement from the ledger about one credential and one interval of it, and the
verifier's query and federation. The cases cover the five values of the
``revocation_establishment`` term: a recorded revocation, an interval that is provably
empty, a failed query, a ledger in a federation that has not been synchronised, and
every way a statement can fail to verify, which reads as the fallback ``undetermined``.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild every
signature. They are test keys and protect nothing.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import emptyinterval as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/empty-interval-statement/v1/"
LEDGER = "ledger/revocations-a"
CREDENTIAL = "cred-7"
FROM, TO = 2, 5
SIGNED_AT = "2026-11-20T09:00:00Z"
EVALUATED_AT = "2026-11-20T09:30:00Z"
SOURCE = {
    "note": (
        "Synthetic ledgers and statements. The five values are the revocation_establishment "
        "term of the vocabulary; the check order and reason tokens are this corpus's own."
    ),
    "source": "W3C public-agent-identity list, 2026, discussion of revocation freshness",
}


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> str:
    """The public key of a labelled seed, derived through the rail's curve arithmetic."""
    h = hashlib.sha512(_seed(label)).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return str(rail._pt_compress(rail._pt_mul(a, rail._B)).hex())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _envelope(body_key: str, body: dict[str, Any], label: str = "ledger") -> dict[str, Any]:
    sig = rail.ed25519_sign(_seed(label), rail.jcs_dumps(body))
    return {"kid": label, body_key: body, "sig": base64.b64encode(sig).decode()}


def _line(envelope: dict[str, Any]) -> bytes:
    return bytes(rail.jcs_dumps(envelope))


def event(index: int, kind: str, credential: str, prev: str) -> dict[str, Any]:
    """The body of one ledger event."""
    return {
        "credential": credential,
        "index": index,
        "kind": kind,
        "ledger": LEDGER,
        "prev": prev,
        "recordedAt": f"2026-11-1{index}T10:00:00Z",
    }


#: The events of the clean ledger: kind and credential at each position.
BASE = (
    ("issued", "cred-7"),
    ("issued", "cred-1"),
    ("rotated", "cred-1"),
    ("issued", "cred-9"),
    ("rotated", "cred-7"),
    ("issued", "cred-3"),
    ("issued", "cred-4"),
)


def ledger(rows: tuple[tuple[str, str], ...] = BASE, label: str = "ledger") -> list[bytes]:
    """A genuine chain: each event names the digest of the line before it."""
    lines: list[bytes] = []
    for index, (kind, credential) in enumerate(rows):
        prev = _sha(lines[-1]) if lines else reader.GENESIS
        lines.append(_line(_envelope("record", event(index, kind, credential, prev), label)))
    return lines


def with_row(index: int, kind: str, credential: str) -> tuple[tuple[str, str], ...]:
    """The clean rows with one position changed."""
    rows = list(BASE)
    rows[index] = (kind, credential)
    return tuple(rows)


def checkpoint(
    lines: list[bytes], index: int, label: str = "ledger", signed_at: str | None = SIGNED_AT
) -> dict[str, Any]:
    """A signed checkpoint over the line at ``index``."""
    body: dict[str, Any] = {"head": _sha(lines[index]), "index": index, "ledger": LEDGER}
    if signed_at is not None:
        body["signedAt"] = signed_at
    return _envelope("checkpoint", body, label)


def statement(
    lines: list[bytes],
    listed: list[int],
    cp: dict[str, Any] | None = None,
    label: str = "ledger",
    credential: str = CREDENTIAL,
) -> dict[str, Any]:
    """A signed statement about one credential and the interval ``FROM`` to ``TO``."""
    body = {
        "checkpoint": cp if cp is not None else checkpoint(lines, len(lines) - 1),
        "credential": credential,
        "fromIndex": FROM,
        "ledger": LEDGER,
        "listed": listed,
        "toIndex": TO,
    }
    return _envelope("statement", body, label)


def case_file(
    federation: dict[str, Any] | None = None, response: dict[str, Any] | None = None,
    has_statement: bool = True,
) -> dict[str, Any]:
    """The verifier's trust inputs: key, query, response and federation."""
    return {
        "federation": federation
        or {"ledger": "federation-a", "synchronisedWith": [], "verifier": "federation-a"},
        "keys": {"ledger": _public("ledger")},
        "ledger": "ledger.jsonl",
        "query": {
            "credential": CREDENTIAL,
            "evaluatedAt": EVALUATED_AT,
            "fromIndex": FROM,
            "ledger": LEDGER,
            "toIndex": TO,
        },
        "response": response or {"status": "ok"},
        "statement": "statement.json" if has_statement else None,
        "suite": SUITE,
    }


Case = tuple[str, dict[str, Any], list[bytes], dict[str, Any] | None, str, str, str]


def cases() -> list[Case]:
    """Every case: id, case file, ledger lines, statement, decision, reason and what it shows."""
    clean = ledger()
    revoked = ledger(with_row(4, "revoked", CREDENTIAL))
    edited = [*revoked[:4], revoked[4].replace(b'"revoked"', b'"rotated"'), *revoked[5:]]
    fed_b = {"ledger": "federation-b", "synchronisedWith": [], "verifier": "federation-a"}
    bridged = {
        "ledger": "federation-b",
        "synchronisedWith": ["federation-b"],
        "verifier": "federation-a",
    }
    around = ledger(
        tuple(
            ("revoked", CREDENTIAL) if i in (1, 6) else row for i, row in enumerate(BASE)
        )
    )
    abandoned = [*clean[:6], *ledger(with_row(6, "issued", "cred-5"))[6:]]
    deleted = [line for i, line in enumerate(revoked) if i != 4]
    return [
        (
            "interval-empty-not-recorded", case_file(), clean, statement(clean, []),
            "not_recorded", "no_revocation_in_covered_interval",
            "the chain is unbroken, a signed and timestamped checkpoint covers the interval "
            "and the ledger holds no revocation of the credential inside it",
        ),
        (
            "interval-holds-revocation", case_file(), revoked, statement(revoked, [4]),
            "recorded", "revocation_recorded",
            "the credential is revoked at position 4, inside the interval, and the statement "
            "lists it",
        ),
        (
            "statement-omits-recorded-event", case_file(), revoked, statement(revoked, []),
            "recorded", "statement_omits_recorded_event",
            "the negative control: a signed statement that lists nothing while the ledger holds "
            "a revocation inside the interval; the ledger decides, not the statement",
        ),
        (
            "other-credential-revoked-in-interval", case_file(),
            ledger(with_row(4, "revoked", "cred-9")),
            statement(ledger(with_row(4, "revoked", "cred-9")), []),
            "not_recorded", "no_revocation_in_covered_interval",
            "another credential is revoked inside the interval, which says nothing about this one",
        ),
        (
            "revocation-outside-interval", case_file(), around, statement(around, []),
            "not_recorded", "no_revocation_in_covered_interval",
            "the credential is revoked at position 1 and at position 6, one before the interval "
            "and one after it, and the interval is empty",
        ),
        (
            "query-failed", case_file(response={"detail": "timeout", "status": "error"},
                                      has_statement=False),
            clean, None, "query_failed", "ledger_query_failed",
            "the ledger returned no answer, which is never read as an empty interval",
        ),
        (
            "cross-federation-unsynchronised", case_file(federation=fed_b), clean,
            statement(clean, []), "cross_federation_unsynchronised",
            "federation_not_synchronised",
            "the ledger is in a federation the verifier has no synchronisation record with, so "
            "a missing event may only be one not yet exchanged",
        ),
        (
            "cross-federation-synchronised", case_file(federation=bridged), clean,
            statement(clean, []), "not_recorded", "no_revocation_in_covered_interval",
            "the control: the same ledger in another federation, with a synchronisation record "
            "bridging to it, is read as an interval of the verifier's own",
        ),
        (
            "forged-statement-signature", case_file(), clean,
            statement(clean, [], label="adversary"), "undetermined",
            "statement_signature_invalid",
            "the statement is signed by a key that is not the ledger's",
        ),
        (
            "statement-for-other-credential", case_file(), clean,
            statement(clean, [], credential="cred-9"), "undetermined",
            "statement_for_other_interval",
            "a genuine statement about another credential, replayed for this one",
        ),
        (
            "forged-checkpoint-signature", case_file(), clean,
            statement(clean, [], cp=checkpoint(clean, 6, label="adversary")), "undetermined",
            "checkpoint_signature_invalid",
            "the statement verifies and the checkpoint inside it is signed by another key",
        ),
        (
            "checkpoint-without-time", case_file(), clean,
            statement(clean, [], cp=checkpoint(clean, 6, signed_at=None)), "undetermined",
            "checkpoint_not_timestamped",
            "a correctly signed checkpoint that carries no signing time",
        ),
        (
            "checkpoint-stops-short", case_file(), clean,
            statement(clean, [], cp=checkpoint(clean, 4)), "undetermined",
            "checkpoint_does_not_cover_range",
            "the checkpoint is signed over position 4 and the interval ends at 5",
        ),
        (
            "event-edited-in-place", case_file(), edited, statement(edited, []),
            "undetermined", "ledger_event_invalid",
            "a revocation edited into a rotation after signing, which an empty list then "
            "appears to confirm",
        ),
        (
            "event-deleted-from-interval", case_file(), deleted, statement(revoked, []),
            "undetermined", "chain_link_broken",
            "the revocation is removed from the ledger and every remaining signature verifies; "
            "only the chain shows the hole",
        ),
        (
            "ledger-rolled-back-to-abandoned-branch", case_file(), abandoned,
            statement(clean, []), "undetermined", "checkpoint_head_mismatch",
            "every event verifies and links, and the checkpoint names a head the ledger no "
            "longer holds",
        ),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
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
    entries: list[dict[str, Any]] = []
    for name, case, lines, stmt, decision, reason, shows in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        files = {"case.json": _json(case), "ledger.jsonl": b"\n".join(lines) + b"\n"}
        if stmt is not None:
            files["statement.json"] = _json(stmt)
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "case.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append(
            {
                "edit": shows,
                "expected": expected,
                "files": {filename: _sha(data) for filename, data in sorted(files.items())},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(directory / "case.json"),
            }
        )
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "provenance": copy.deepcopy(SOURCE),
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier case.json --json; exit 0 recorded, 1 not_recorded, "
        "2 query_failed, 3 cross_federation_unsynchronised, 4 undetermined",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
