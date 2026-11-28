"""Build the status-receipt-binding cases byte-identically.

Every case is an agent credential and an authority's status receipt for it, each a DSSE
envelope signed with Ed25519, and ``case.json`` naming the check time and the authority's
public key. The credential lists the capabilities it grants and every public key it may act
with, and is signed by one of those keys. The receipt says the credential is active from one
time until another and names the credential by identifier and by the SHA-256 of the
credential's payload bytes.

The cases that matter most keep the authority's genuine receipt and change the credential
beside it: more capabilities, another key, an added key, both. Their receipt files are byte
for byte the receipt of the accepted control (``sharedReceipt`` in the manifest), and the
credential's own signature verifies because the key that made it is in the credential's own
list. Two more carry a receipt that signs the status and the identifier and no digest.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild every
signature. They are test keys and protect nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import statusreceipt as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/status-receipt-binding/v1/"
ISSUED, MID, UNTIL = "2026-11-01T00:00:00Z", "2026-11-15T12:00:00Z", "2026-12-01T00:00:00Z"
BEFORE, AFTER = "2026-10-31T23:59:59Z", "2026-12-01T00:00:01Z"

AGENT = "urn:example:agent:refunds-7"
GRANTED = ["orders:read", "tickets:write"]
ESCALATED = sorted([*GRANTED, "payments:transfer", "refunds:issue"])


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> bytes:
    """The public key of a labelled seed."""
    h = hashlib.sha512(_seed(label)).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return bytes(rail._pt_compress(rail._pt_mul(a, rail._B)))


def _jwk(kid: str, label: str) -> dict[str, str]:
    x = base64.urlsafe_b64encode(_public(label)).rstrip(b"=").decode()
    return {"crv": "Ed25519", "kid": kid, "kty": "OKP", "x": x}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _envelope(payload_type: str, payload: bytes, signers: list[tuple[str, str]],
              served: bytes | None = None) -> bytes:
    """A DSSE envelope over ``payload``, one signature per ``(keyid, seed label)``.
    ``served`` replaces the payload after signing, as an edit made without the key must."""
    pae = rail.pae(payload_type, payload)
    sigs = [{"keyid": kid, "sig": base64.b64encode(rail.ed25519_sign(_seed(label), pae)).decode()}
            for kid, label in signers]
    body = served if served is not None else payload
    return _json({"payload": base64.b64encode(body).decode(), "payloadType": payload_type,
                  "signatures": sigs})


def credential_payload(agent: str = AGENT, capabilities: list[str] | None = None,
                       keys: list[tuple[str, str]] | None = None,
                       name: str = "refunds agent") -> bytes:
    """The RFC 8785 form of a credential: its id, name, capabilities and keys."""
    return bytes(rail.jcs_dumps({
        "capabilities": GRANTED if capabilities is None else capabilities,
        "id": agent,
        "keys": [_jwk(kid, label) for kid, label in (keys or [("key-1", "holder-1")])],
        "name": name,
    }))


def credential(payload: bytes, signers: list[tuple[str, str]],
               served: bytes | None = None) -> bytes:
    return _envelope(reader.CREDENTIAL_TYPE, payload, signers, served)


def receipt(binding: dict[str, Any], status: str = "active", issued: str = ISSUED,
            until: str = UNTIL, signer: str = "authority", served: dict[str, Any] | None = None,
            extra: dict[str, Any] | None = None) -> bytes:
    """The authority's status receipt. ``served`` replaces members after signing."""
    body = {"credential": binding, "issuedAt": issued, "status": status, "validUntil": until,
            **(extra or {})}
    payload = bytes(rail.jcs_dumps(body))
    shown = bytes(rail.jcs_dumps({**body, **served})) if served else None
    return _envelope(reader.RECEIPT_TYPE, payload, [("authority-1", signer)], shown)


def bound(payload: bytes, agent: str = AGENT) -> dict[str, Any]:
    """A receipt's binding to the credential with these payload bytes."""
    return {"digest": {"sha256": _sha(payload)}, "id": agent}


GENUINE = credential_payload()
EARLIER = credential_payload(capabilities=["orders:read"])
RAISED = credential_payload(capabilities=ESCALATED)
SWAPPED = credential_payload(keys=[("key-1", "substitute")])
ADDED = credential_payload(keys=[("key-1", "holder-1"), ("key-2", "substitute")])
FORGED = credential_payload(capabilities=ESCALATED, keys=[("key-1", "substitute")])
UNSORTED = credential_payload(capabilities=list(reversed(GRANTED)))
REPEATED_KID = credential_payload(keys=[("key-1", "holder-1"), ("key-1", "holder-2")])
TWO_KEYS = credential_payload("urn:example:agent:triage-2", ["tickets:read"],
                              [("key-1", "triage-1"), ("key-2", "triage-2")], "triage agent")
OTHER = credential_payload("urn:example:agent:billing-3", ["invoices:read"],
                           [("key-1", "billing-1")], "billing agent")

HOLDER = [("key-1", "holder-1")]
SUBSTITUTE = [("key-1", "substitute")]
GENUINE_RECEIPT = receipt(bound(GENUINE))
STATUS_ONLY = receipt({"id": AGENT})

Case = tuple[str, bytes, bytes, str, str, str, str]


def cases() -> list[Case]:
    """Every case: id, credential, receipt, check time, expected decision and reason, edit."""
    genuine = credential(GENUINE, HOLDER)
    return [
        ("accept-bound", genuine, GENUINE_RECEIPT, MID, "accept", "credential_bound",
         "control: the receipt binds the digest of the credential presented, inside its window"),
        ("accept-two-keys-second-signs", credential(TWO_KEYS, [("key-2", "triage-2")]),
         receipt(bound(TWO_KEYS, "urn:example:agent:triage-2")), MID, "accept",
         "credential_bound", "control: a credential with two keys, signed by the second"),
        ("accept-at-issued-at", genuine, GENUINE_RECEIPT, ISSUED, "accept", "credential_bound",
         "control: checked at the receipt's issuedAt, which is inside the window"),
        ("capabilities-escalated", credential(RAISED, HOLDER), GENUINE_RECEIPT, MID, "reject",
         "credential_digest_mismatch",
         "the holder adds two capabilities, re-signs with its own key and keeps the receipt"),
        ("key-swapped", credential(SWAPPED, SUBSTITUTE), GENUINE_RECEIPT, MID, "reject",
         "credential_digest_mismatch",
         "another key replaces the listed key and signs; the receipt is the genuine one"),
        ("key-added", credential(ADDED, [("key-2", "substitute")]), GENUINE_RECEIPT, MID,
         "reject", "credential_digest_mismatch",
         "the listed key stays, a second key is added and signs; the receipt is the genuine one"),
        ("capabilities-and-key-swapped", credential(FORGED, SUBSTITUTE), GENUINE_RECEIPT, MID,
         "reject", "credential_digest_mismatch",
         "more capabilities and another key, signed by that key, beside the genuine receipt"),
        ("receipt-status-only", genuine, STATUS_ONLY, MID, "reject", "receipt_unbound",
         "the receipt signs the identifier and the status and no digest of the credential"),
        ("receipt-status-only-forged-credential", credential(FORGED, SUBSTITUTE), STATUS_ONLY,
         MID, "reject", "receipt_unbound",
         "the same status-only receipt beside a credential with more capabilities and another "
         "key: nothing in the receipt tells the two credentials apart"),
        ("receipt-for-earlier-version", genuine, receipt(bound(EARLIER)), MID, "reject",
         "credential_digest_mismatch",
         "the receipt binds the digest of an earlier version of the credential, same id"),
        ("receipt-for-other-credential", genuine,
         receipt(bound(OTHER, "urn:example:agent:billing-3")), MID, "reject",
         "credential_id_mismatch", "the receipt binds another credential, by its id and digest"),
        ("receipt-signed-by-other-key", credential(FORGED, SUBSTITUTE),
         receipt(bound(FORGED), signer="substitute"), MID, "reject",
         "receipt_signature_invalid",
         "a receipt that binds the presented credential, signed by a key that is not the "
         "authority's"),
        ("receipt-altered-after-signing", genuine,
         receipt(bound(GENUINE), status="suspended", served={"status": "active"}), MID,
         "reject", "receipt_signature_invalid",
         "the authority signed suspended; the status was changed to active after signing"),
        ("receipt-window-inverted", genuine, receipt(bound(GENUINE), issued=UNTIL, until=ISSUED),
         MID, "reject", "receipt_malformed", "the receipt's validUntil is before its issuedAt"),
        ("receipt-member-unexpected", genuine,
         receipt(bound(GENUINE), extra={"capabilities": ESCALATED}), MID, "reject",
         "receipt_malformed",
         "the receipt carries a capabilities member of its own, which the format does not have"),
        ("credential-signed-by-unlisted-key", credential(GENUINE, [("key-9", "substitute")]),
         GENUINE_RECEIPT, MID, "reject", "credential_signature_invalid",
         "the credential's bytes are the genuine ones, signed by a key it does not list"),
        ("credential-altered-after-signing", credential(GENUINE, HOLDER, served=RAISED),
         GENUINE_RECEIPT, MID, "reject", "credential_signature_invalid",
         "the holder signed the genuine capabilities; two were added after signing"),
        ("credential-capabilities-unsorted", credential(UNSORTED, HOLDER),
         receipt(bound(UNSORTED)), MID, "reject", "credential_malformed",
         "the capability list is not sorted, so the credential has two spellings"),
        ("credential-kid-repeated", credential(REPEATED_KID, HOLDER),
         receipt(bound(REPEATED_KID)), MID, "reject", "credential_malformed",
         "two keys share one kid, so a keyid does not name one key"),
        ("receipt-not-yet-valid", genuine, GENUINE_RECEIPT, BEFORE, "reject",
         "receipt_not_yet_valid", "checked one second before the receipt's issuedAt"),
        ("receipt-expired", genuine, GENUINE_RECEIPT, AFTER, "reject", "receipt_expired",
         "checked one second after the receipt's validUntil"),
        ("receipt-expired-at-valid-until", genuine, GENUINE_RECEIPT, UNTIL, "reject",
         "receipt_expired", "checked at validUntil, which the window excludes"),
        ("credential-suspended", genuine, receipt(bound(GENUINE), status="suspended"), MID,
         "reject", "credential_not_active", "the receipt binds the credential and says suspended"),
        ("credential-revoked", genuine, receipt(bound(GENUINE), status="revoked"), MID,
         "reject", "credential_not_active", "the receipt binds the credential and says revoked"),
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


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    authority = base64.b64encode(_public("authority")).decode()
    built = cases()
    holders: dict[bytes, list[str]] = {}
    for name, _, receipt_bytes, *_ in built:
        holders.setdefault(receipt_bytes, []).append(name)
    entries = []
    for name, credential_bytes, receipt_bytes, now, decision, reason, edit in built:
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case = {"authorityKey": authority, "credential": "credential.json", "now": now,
                "receipt": "receipt.json", "schema_version": "status-receipt-binding-case/v1"}
        files = {"case.json": _json(case), "credential.json": credential_bytes,
                 "receipt.json": receipt_bytes}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        properties = reader.signature_properties(directory / "case.json")
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
            "sharedReceipt": sorted(other for other in holders[receipt_bytes] if other != name),
            **properties,
        })
    manifest = {
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 accept, 1 reject",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
