"""Build the agent DID identity-binding cases byte-identically.

Every case is one DSSE envelope over an agent record whose subject is a DID,
the resolution fixtures a resolver would return for the DIDs it names (each a
version history of DID documents), and ``case.json`` naming them. The did:wba
documents follow the did:wba method specification of the Agent Network
Protocol, ``03-did-wba-method-design-specification.md`` at commit
``c6a467b4e690137d237d8068f2c60b48955dbaf6``: an Ed25519 ``Multikey`` binding
key under ``authentication``, a path DID whose last segment is ``e1_`` and the
RFC 7638 thumbprint of that key (Section 2.2.2), and ``deactivated`` with
``successorDid`` on a document superseded by a key change (Section 2.5).

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
from agent_evidence_vectors import identitybinding as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/agent-did-identity-binding/v1/"
PAYLOAD_TYPE = "application/vnd.agent-evidence.agent-record+json"
WBA_SOURCE = {
    "repository": "https://github.com/agent-network-protocol/AgentNetworkProtocol",
    "file": "03-did-wba-method-design-specification.md",
    "commit": "c6a467b4e690137d237d8068f2c60b48955dbaf6",
}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WBA_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/data-integrity/v2",
               "https://w3id.org/security/multikey/v1"]
WEB_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"]
JAN, MAR, JUN, JUL = ("2026-01-05T09:00:00Z", "2026-03-10T12:00:00Z",
                      "2026-06-01T00:00:00Z", "2026-07-14T16:30:00Z")


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> bytes:
    """The public key of a labelled seed."""
    h = hashlib.sha512(_seed(label)).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return bytes(rail._pt_compress(rail._pt_mul(a, rail._B)))


def _b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = B58[rest] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def _multikey(label: str) -> str:
    return "z" + _b58encode(reader.MULTIKEY_ED25519 + _public(label))


def _jwk(label: str) -> dict[str, str]:
    x = base64.urlsafe_b64encode(_public(label)).rstrip(b"=").decode()
    return {"crv": "Ed25519", "kty": "OKP", "x": x}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def wba_did(path: str, label: str) -> str:
    return f"did:wba:agents.example.com:{path}:e1_{reader.jwk_thumbprint(_public(label))}"


WEB_ALICE = "did:web:agents.example.com:alice"
WEB_BOB = "did:web:agents.example.com:bob"
WBA_ALICE = wba_did("user:alice", "wba-alice")
WBA_ALICE_NEXT = wba_did("user:alice", "wba-alice-next")
WBA_CAROL = wba_did("user:carol", "wba-carol")
MALFORMED = "did:wba:agents.example.com/user/alice"


def web_document(did: str, keys: dict[str, str], authorised: tuple[str, ...],
                 invoke: tuple[str, ...] = ()) -> dict[str, Any]:
    """A did:web document whose keys are JsonWebKey methods."""
    doc: dict[str, Any] = {
        "@context": WEB_CONTEXT, "id": did,
        "verificationMethod": [{"controller": did, "id": f"{did}#{frag}",
                                "publicKeyJwk": _jwk(label), "type": "JsonWebKey"}
                               for frag, label in keys.items()],
        "authentication": [f"{did}#{frag}" for frag in authorised],
        "assertionMethod": [f"{did}#{frag}" for frag in authorised],
    }
    if invoke:
        doc["capabilityInvocation"] = [f"{did}#{frag}" for frag in invoke]
    return doc


def wba_document(did: str, label: str, **extra: Any) -> dict[str, Any]:
    """A did:wba document with one Ed25519 Multikey binding key."""
    key = f"{did}#key-1"
    return {"@context": WBA_CONTEXT, "id": did,
            "verificationMethod": [{"controller": did, "id": key,
                                    "publicKeyMultibase": _multikey(label),
                                    "type": "Multikey"}],
            "authentication": [key], "assertionMethod": [key], **extra}


def resolution(did: str, *versions: tuple[dict[str, Any], str]) -> dict[str, Any]:
    return {"did": did, "versions": [
        {"didDocument": doc, "didDocumentMetadata": {"updated": updated,
                                                     "versionId": str(i + 1)}}
        for i, (doc, updated) in enumerate(versions)]}


def envelope(subject: str, signed_at: str, keyid: str, label: str,
             statement: str = "Opened ticket 4411 in queue support.",
             served: str | None = None) -> bytes:
    """A DSSE envelope over the record. ``served`` replaces the payload after
    signing, as an edit made without the key must."""
    record = {"signedAt": signed_at, "statement": statement, "subject": {"id": subject}}
    payload = bytes(rail.jcs_dumps(record))
    sig = rail.ed25519_sign(_seed(label), rail.pae(PAYLOAD_TYPE, payload))
    if served is not None:
        payload = bytes(rail.jcs_dumps({**record, "statement": served}))
    return _json({"payload": base64.b64encode(payload).decode(), "payloadType": PAYLOAD_TYPE,
                  "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}]})


ALICE_WEB = resolution(WEB_ALICE, (web_document(WEB_ALICE, {"key-1": "web-alice",
                                                             "key-2": "web-alice-invoke"},
                                                ("key-1",), ("key-2",)), JAN))
ALICE_WEB_ROTATING = resolution(
    WEB_ALICE, (web_document(WEB_ALICE, {"key-1": "web-alice"}, ("key-1",)), JAN),
    (web_document(WEB_ALICE, {"key-3": "web-alice-rotated"}, ("key-3",)), JUN))
BOB_WEB = resolution(WEB_BOB, (web_document(WEB_BOB, {"key-1": "web-bob"}, ("key-1",)), JAN))
ALICE_WBA = resolution(WBA_ALICE, (wba_document(WBA_ALICE, "wba-alice"), JAN))
ALICE_WBA_SUPERSEDED = resolution(
    WBA_ALICE, (wba_document(WBA_ALICE, "wba-alice"), JAN),
    (wba_document(WBA_ALICE, "wba-alice", deactivated=True, successorDid=WBA_ALICE_NEXT), JUN))
# A document served under Alice's path DID that lists another key. The path's
# e1_ segment is the thumbprint of Alice's key, so the binding refuses it.
ALICE_WBA_SUBSTITUTED = resolution(WBA_ALICE, (wba_document(WBA_ALICE, "wba-mallory"), JAN))

Case = tuple[str, str, bytes, dict[str, dict[str, Any]], str, str, bool, str]


def cases() -> list[Case]:
    """Every case: id, DID method, envelope, resolutions, expected decision and
    reason, whether the signature verifies under the named key, and the edit."""
    alice1 = f"{WEB_ALICE}#key-1"
    wba1 = f"{WBA_ALICE}#key-1"
    return [
        ("web-verified", "web", envelope(WEB_ALICE, MAR, alice1, "web-alice"),
         {"alice": ALICE_WEB}, "verified", "subject_bound", True,
         "control: did:web subject, signed by a key its document authorises"),
        ("wba-verified", "wba", envelope(WBA_ALICE, JUL, wba1, "wba-alice"),
         {"alice": ALICE_WBA}, "verified", "subject_bound", True,
         "control: did:wba path DID, signed by the binding key its e1_ segment names"),
        ("web-signed-before-rotation", "web", envelope(WEB_ALICE, MAR, alice1, "web-alice"),
         {"alice": ALICE_WEB_ROTATING}, "verified", "subject_bound", True,
         "control: signed in March by a key rotated out in June; the March version decides"),
        ("key-not-in-authentication", "web",
         envelope(WEB_ALICE, MAR, f"{WEB_ALICE}#key-2", "web-alice-invoke"),
         {"alice": ALICE_WEB}, "rejected", "key_not_authorized", True,
         "signed by a key the document lists only under capabilityInvocation"),
        ("key-absent-from-document", "web",
         envelope(WEB_ALICE, MAR, f"{WEB_ALICE}#key-9", "web-mallory"),
         {"alice": ALICE_WEB}, "rejected", "key_not_authorized", False,
         "signed by a key the subject's document does not carry, under a keyid it invented"),
        ("did-unresolvable", "wba", envelope(WBA_CAROL, JUL, f"{WBA_CAROL}#key-1", "wba-carol"),
         {}, "rejected", "did_unresolvable", False,
         "no DID document is supplied for the subject"),
        ("web-key-rotated-out", "web", envelope(WEB_ALICE, JUL, alice1, "web-alice"),
         {"alice": ALICE_WEB_ROTATING}, "rejected", "key_rotated_out", True,
         "signed in July by a key the June version of the document no longer carries"),
        ("wba-deactivated-before-signing", "wba", envelope(WBA_ALICE, JUL, wba1, "wba-alice"),
         {"alice": ALICE_WBA_SUPERSEDED}, "rejected", "key_rotated_out", True,
         "signed in July by the binding key of a did:wba DID deactivated in June, with "
         "successorDid naming the DID of the new key"),
        ("subject-swap", "web", envelope(WEB_BOB, MAR, alice1, "web-alice"),
         {"alice": ALICE_WEB, "bob": BOB_WEB}, "rejected", "signer_not_subject", True,
         "Alice's key signs a record whose subject is Bob; both documents resolve"),
        ("did-malformed", "wba", envelope(MALFORMED, JUL, f"{MALFORMED}#key-1", "wba-alice"),
         {}, "rejected", "did_malformed", False,
         "the subject uses slashes where the did:wba syntax requires colons"),
        ("wba-fingerprint-mismatch", "wba", envelope(WBA_ALICE, JUL, wba1, "wba-mallory"),
         {"alice": ALICE_WBA_SUBSTITUTED}, "rejected", "binding_fingerprint_mismatch", True,
         "a document served under Alice's path DID lists another key, which signed"),
        ("payload-altered", "web",
         envelope(WEB_ALICE, MAR, alice1, "web-alice",
                  served="Closed ticket 4411 without a reply."),
         {"alice": ALICE_WEB}, "rejected", "signature_invalid", False,
         "the record's statement was changed after signing"),
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
    entries = []
    for name, method, env, resolutions, decision, reason, signed, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case = {"envelope": "envelope.json",
                "resolutions": {res["did"]: f"did-{label}.json"
                                for label, res in sorted(resolutions.items())},
                "schema_version": "agent-did-identity-binding-case/v1"}
        files = {"case.json": _json(case), "envelope.json": env}
        files.update({f"did-{label}.json": _json(res) for label, res in resolutions.items()})
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "didMethod": method, "edit": edit,
            "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}", "signatureVerifies": signed,
        })
    manifest = {
        "corpusDigest": _sha(_json(entries)), "didWbaSource": WBA_SOURCE, "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 verified, 1 rejected",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
