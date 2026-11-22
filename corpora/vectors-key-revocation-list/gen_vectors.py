"""Build the key-revocation-list cases byte-identically.

Every case is one signed list of revoked keys, the verifier's trust inputs (the
thumbprints of the list-signing keys it trusts, the issue time of the last list it
accepted and the revocations it has already seen), its clock and one question: is this
key revoked at this time? The cases cover the five decisions and the rules the reader
applies: a list accepted only from a key chosen by thumbprint, never older than the last
accepted, never past its next update, a revocation kept once seen, and silence about an
uncovered key read as no statement.

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
from agent_evidence_vectors import keyrevocation as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/key-revocation-list/v1/"
SOURCE = {
    "note": (
        "Synthetic lists and keys. The verifier rules restate an issuer-side policy for signed "
        "revocation lists; the decision and reason tokens are this corpus's own."
    ),
    "source": "W3C public-agent-identity list, 2026, discussion of revocation freshness",
}
ISSUED = "2026-11-20T08:00:00Z"
NEXT = "2026-11-20T20:00:00Z"
NOW = "2026-11-20T09:00:00Z"
AT = "2026-11-20T09:00:00Z"
REVOKED_KEY, OTHER_KEY, UNCOVERED_KEY = (
    hashlib.sha256(f"key/{name}".encode()).hexdigest() for name in ("revoked", "other", "uncovered")
)


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


def signer(label: str, claimed: str | None = None) -> dict[str, str]:
    """The key a list carries, with the thumbprint it claims."""
    key = _public(label)
    return {"key": key, "thumbprint": claimed or reader.thumbprint(key)}


def body(
    revoked: list[tuple[str, str]] | None = None,
    covered: list[str] | None = None,
    issued: str = ISSUED,
    next_update: str = NEXT,
) -> dict[str, Any]:
    """The payload of a list: entries as (thumbprint, effectiveFrom)."""
    return {
        "issuedAt": issued,
        "issuer": "https://issuer.example/keys",
        "keysCovered": sorted(covered if covered is not None else [REVOKED_KEY, OTHER_KEY]),
        "nextUpdate": next_update,
        "revoked": [{"effectiveFrom": at, "thumbprint": t} for t, at in (revoked or [])],
    }


def signed_list(
    payload: dict[str, Any], label: str = "issuer", claimed: str | None = None
) -> dict[str, Any]:
    """A list envelope signed by the labelled key, which it carries beside its thumbprint."""
    sig = rail.ed25519_sign(_seed(label), rail.jcs_dumps(payload))
    return {
        "list": payload,
        "sig": base64.b64encode(sig).decode(),
        "signer": signer(label, claimed),
    }


def case_file(
    key: str = REVOKED_KEY,
    seen: list[tuple[str, str]] | None = None,
    accepted: str | None = "2026-11-19T08:00:00Z",
    now: str = NOW,
    at: str = AT,
) -> dict[str, Any]:
    """The verifier's trust inputs, clock and question."""
    return {
        "list": "list.json",
        "now": now,
        "prior": {
            "acceptedIssuedAt": accepted,
            "seen": [{"effectiveFrom": t, "thumbprint": k} for k, t in (seen or [])],
        },
        "query": {"at": at, "key": key},
        "suite": SUITE,
        "trusted": [reader.thumbprint(_public("issuer"))],
    }


Case = tuple[str, dict[str, Any], dict[str, Any], str, str, str]
EARLY = "2026-11-20T07:00:00Z"


def cases() -> list[Case]:
    """Every case: id, case file, list envelope, decision, reason and what it shows."""
    listed = signed_list(body([(REVOKED_KEY, EARLY)]))
    clean = signed_list(body())
    tampered = copy.deepcopy(listed)
    tampered["list"]["revoked"] = []
    forged_claim = signed_list(
        body(), label="adversary", claimed=reader.thumbprint(_public("issuer"))
    )
    return [
        (
            "revoked-in-list", case_file(), listed, "revoked", "revoked_in_list",
            "the list carries the key with an effective time before the time asked",
        ),
        (
            "covered-no-entry", case_file(), clean, "not_revoked", "covered_no_entry",
            "the list covers the key and has no entry for it: not revoked in the record live "
            "when the list was served",
        ),
        (
            "key-not-covered", case_file(key=UNCOVERED_KEY), clean, "no_statement",
            "key_not_covered",
            "the list does not cover the key, so it says nothing about it; silence is not a "
            "statement",
        ),
        (
            "revocation-not-yet-effective", case_file(),
            signed_list(body([(REVOKED_KEY, "2026-11-20T12:00:00Z")])), "not_revoked",
            "revocation_not_yet_effective",
            "the entry takes effect after the time asked",
        ),
        (
            "revocation-kept-after-later-list-omits-it",
            case_file(seen=[(REVOKED_KEY, EARLY)]), clean, "revoked",
            "revoked_kept_from_earlier_list",
            "a revocation already seen is kept when a newer list covers the key and omits it",
        ),
        (
            "revocation-kept-for-key-the-later-list-no-longer-covers",
            case_file(seen=[(REVOKED_KEY, EARLY)]),
            signed_list(body(covered=[OTHER_KEY])), "revoked", "revoked_kept_from_earlier_list",
            "a revocation already seen is kept when a newer list no longer covers the key",
        ),
        (
            "signer-not-trusted", case_file(), signed_list(body([(REVOKED_KEY, EARLY)]),
                                                           label="adversary"),
            "rejected", "signer_not_trusted",
            "the list verifies under the key it carries and the verifier does not trust that key",
        ),
        (
            "signer-claims-a-trusted-thumbprint", case_file(), forged_claim, "rejected",
            "signer_not_trusted",
            "the list names a trusted thumbprint beside a key of its own; the verifier "
            "recomputes the thumbprint from the key",
        ),
        (
            "list-signature-invalid", case_file(), tampered, "rejected", "list_signature_invalid",
            "a revocation removed from a trusted signer's list after it was signed",
        ),
        (
            "list-older-than-accepted", case_file(accepted="2026-11-20T08:30:00Z"), clean,
            "rejected", "list_older_than_accepted",
            "an older genuine list replayed over a newer one, which omits a later revocation",
        ),
        (
            "list-issued-at-the-last-accepted-time",
            case_file(accepted=ISSUED), clean, "not_revoked", "covered_no_entry",
            "the control: a list issued at the same time as the last accepted one is not older",
        ),
        (
            "list-past-next-update", case_file(now="2026-11-20T20:00:01Z"), clean, "stale",
            "list_stale",
            "the verifier's clock is one second past the list's next update",
        ),
        (
            "list-at-next-update", case_file(now=NEXT), clean, "not_revoked", "covered_no_entry",
            "the control: at the next update instant the list is still current",
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
    for name, case, envelope, decision, reason, shows in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        files = {"case.json": _json(case), "list.json": _json(envelope)}
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
        "verifierContract": "verifier case.json --json; exit 0 revoked, 1 not_revoked, "
        "2 no_statement, 3 rejected, 4 stale",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
