"""Build the badge credential cases byte-identically.

Every case is a directory with one ``case.json``: a Verifiable Credential in a
compact JWS signed with EdDSA, the verification time, the key material the
verifier resolved for each issuer DID, the issuers it trusts, and the issuer's
own revocation store. Each denied case departs from a conformant case in one
place. Keys come from fixed seeds and Ed25519 signatures are deterministic, so
the corpus regenerates byte for byte.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import badgevc as reader  # noqa: E402

SUITE = reader.SUITE
ISSUER = "did:web:issuer.example"
AGENT = "did:web:agent.example"
VERIFY_AT = "2026-10-28T12:00:00Z"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"badge-vc-verify/v1 seed {label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public(key: Ed25519PrivateKey) -> str:
    return b64(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))


KEYS = {name: _key(name) for name in ("issuer-1", "issuer-2", "agent", "stranger")}


def compact(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def credential_id(name: str) -> str:
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"badge-vc-verify/v1/{name}"))


def payload_for(name: str, **changes: Any) -> dict[str, Any]:
    """The conformant credential payload; ``None`` removes a member."""
    body: dict[str, Any] = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "credentialStatus": {"id": f"https://issuer.example/status/{name}",
                             "statusPurpose": "revocation", "type": "RevocationList"},
        "credentialSubject": {"badge": "code-reviewer", "id": AGENT, "level": "gold"},
        "id": credential_id(name),
        "issuanceDate": "2026-10-01T00:00:00Z",
        "issuer": ISSUER,
        "type": ["VerifiableCredential", "AgentBadge"],
    }
    for key, value in changes.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    return body


def header_for(kid: str = f"{ISSUER}#key-1", **changes: Any) -> dict[str, Any]:
    head: dict[str, Any] = {"alg": "EdDSA", "kid": kid, "typ": "vc+jwt"}
    head.update(changes)
    return head


def sign(header: Any, payload: Any, key: str = "issuer-1") -> str:
    """The compact JWS of ``header`` and ``payload`` under the named key."""
    head = b64(header if isinstance(header, bytes) else compact(header))
    body = b64(payload if isinstance(payload, bytes) else compact(payload))
    signature = KEYS[key].sign(f"{head}.{body}".encode("ascii"))
    return f"{head}.{body}.{b64(signature)}"


def issuers() -> dict[str, Any]:
    return {
        AGENT: {"keys": {"key-1": _public(KEYS["agent"])}},
        ISSUER: {"keys": {"key-1": _public(KEYS["issuer-1"]),
                          "key-2": _public(KEYS["issuer-2"])}},
    }


def case(token: str, *, revoked: list[str] | None = None, contract: str | None = reader.CONTRACT_ID,
         **changes: Any) -> dict[str, Any]:
    """One case; every argument is a departure from the conformant case."""
    body: dict[str, Any] = {
        "credential": token,
        "issuers": issuers(),
        "status": {"revoked": revoked or []},
        "trustedIssuers": [ISSUER],
        "verificationTime": VERIFY_AT,
    }
    if contract is not None:
        body["contractId"] = contract
    for key, value in changes.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    return body


def plain(name: str, **changes: Any) -> dict[str, Any]:
    """A conformant case whose credential payload carries ``changes``."""
    return case(sign(header_for(), payload_for(name, **changes)))


def altered_after_signing(name: str) -> str:
    head, _, signature = sign(header_for(), payload_for(name)).split(".")
    forged = payload_for(name, credentialSubject={"badge": "code-reviewer", "id": AGENT,
                                                  "level": "platinum"})
    return f"{head}.{b64(compact(forged))}.{signature}"


Case = tuple[str, dict[str, Any], str, str, str]
OK = "allow", reader.PASS_REASON


def _allow() -> list[Case]:
    second = case(sign(header_for(f"{ISSUER}#key-2"), payload_for("allow-second-key"),
                       "issuer-2"))
    other = payload_for("allow-other-revoked")
    return [
        ("allow-plain", plain("allow-plain"), *OK, "control: a conformant credential"),
        ("allow-expiration-in-future",
         plain("allow-expiration-in-future", expirationDate="2027-10-01T00:00:00Z"), *OK,
         "control: an expirationDate a year after the verification time"),
        ("allow-second-key-of-issuer", second, *OK,
         "control: the issuer's second key signs, named by its own fragment"),
        ("allow-revoked-list-names-another",
         case(sign(header_for(), other), revoked=[credential_id("some-other-badge")]), *OK,
         "control: the revocation store lists a different credential"),
        ("allow-expiration-one-second-after",
         plain("allow-expiration-one-second-after", expirationDate="2026-10-28T12:00:01Z"),
         *OK, "control: expiration one second after the verification time"),
        ("allow-issuance-equals-verification-time",
         plain("allow-issuance-equals-verification-time", issuanceDate=VERIFY_AT), *OK,
         "control: issuance at the verification time is not in the future"),
        ("allow-offset-timestamps",
         plain("allow-offset-timestamps", issuanceDate="2026-10-28T17:00:00+05:30",
               expirationDate="2026-10-28T08:00:00-05:00"), *OK,
         "control: offsets denote the same instants as 11:30Z and 13:00Z"),
    ]


def _validity_denials() -> list[Case]:
    name = "revoked-in-issuer-store"
    return [
        (name, case(sign(header_for(), payload_for(name)), revoked=[credential_id(name)]),
         "deny", "revoked",
         "the issuer's store lists the credential; the presented token carries no revocation"),
        ("expired-years-ago", plain("expired-years-ago", expirationDate="2020-01-01T00:00:00Z"),
         "deny", "expired", "expirationDate is in 2020"),
        ("expiration-equals-verification-time",
         plain("expiration-equals-verification-time", expirationDate=VERIFY_AT),
         "deny", "expired", "expirationDate is the verification time, which is not after it"),
        ("expired-by-offset",
         plain("expired-by-offset", expirationDate="2026-10-28T17:00:00+05:30"),
         "deny", "expired", "an offset date-time that is 11:30Z, before the verification time"),
        ("not-yet-valid", plain("not-yet-valid", issuanceDate="2027-01-01T00:00:00Z"),
         "deny", "not_yet_valid", "issuanceDate is in 2027"),
        ("not-yet-valid-by-one-second",
         plain("not-yet-valid-by-one-second", issuanceDate="2026-10-28T12:00:01Z"),
         "deny", "not_yet_valid", "issuanceDate is one second after the verification time"),
    ]


def _binding_denials() -> list[Case]:
    name = "issuer-claim-differs-from-kid"
    claimed = sign(header_for(f"{AGENT}#key-1"), payload_for(name), "agent")
    return [
        (name, case(claimed), "deny", "issuer_key_binding",
         "the credential names the issuer, the key id names the agent's own DID, and the "
         "agent's key signed it"),
        ("kid-fragment-not-an-issuer-key",
         case(sign(header_for(f"{ISSUER}#key-3"), payload_for("kid-fragment-not-an-issuer-key"))),
         "deny", "issuer_key_binding", "the issuer holds key-1 and key-2, and the key id says key-3"),
        ("kid-did-unknown-to-verifier",
         case(sign(header_for("did:web:unlisted.example#key-1"),
                   payload_for("kid-did-unknown-to-verifier"))),
         "deny", "issuer_key_binding", "the key id names a DID the verifier resolved no keys for"),
    ]


def _signature_denials() -> list[Case]:
    name = "signed-by-stranger-key"
    return [
        (name, case(sign(header_for(), payload_for(name), "stranger")),
         "deny", "signature_invalid", "the key id is right and a different key signed"),
        ("payload-altered-after-signing", case(altered_after_signing("payload-altered-after-signing")),
         "deny", "signature_invalid", "the badge level changed after the issuer signed"),
        ("signature-truncated",
         case(".".join([*sign(header_for(), payload_for("signature-truncated")).split(".")[:2],
                        b64(b"\x00" * 32)])),
         "deny", "signature_invalid", "the signature segment is 32 bytes, not 64"),
        ("kid-names-other-issuer-key",
         case(sign(header_for(f"{ISSUER}#key-2"), payload_for("kid-names-other-issuer-key"),
                   "issuer-1")),
         "deny", "signature_invalid", "the key id names key-2 and key-1 signed"),
    ]


def _trust_denials() -> list[Case]:
    return [
        ("issuer-untrusted",
         case(sign(header_for(), payload_for("issuer-untrusted")),
              trustedIssuers=["did:web:another-issuer.example"]),
         "deny", "issuer_not_trusted", "the verifier trusts a different issuer"),
        ("trusted-issuers-empty",
         case(sign(header_for(), payload_for("trusted-issuers-empty")), trustedIssuers=[]),
         "deny", "issuer_not_trusted", "the verifier trusts no issuer"),
    ]


def _jws_denials() -> list[Case]:
    good = sign(header_for(), payload_for("jws-base"))
    head, body, signature = good.split(".")
    return [
        ("jws-alg-none", case(f"{b64(compact(header_for(alg='none')))}.{body}."),
         "deny", "jws_malformed", "alg is none and the signature segment is empty"),
        ("jws-alg-hs256",
         case(sign(header_for(alg="HS256"), payload_for("jws-alg-hs256"))),
         "deny", "jws_malformed", "alg is HS256"),
        ("jws-two-parts", case(f"{head}.{body}"), "deny", "jws_malformed",
         "the token has two parts"),
        ("jws-four-parts", case(f"{good}.{signature}"), "deny", "jws_malformed",
         "the token has four parts"),
        ("jws-header-not-json", case(f"{b64(b'not json')}.{body}.{signature}"),
         "deny", "jws_malformed", "the header decodes to text that is not JSON"),
        ("jws-kid-without-fragment",
         case(sign(header_for(ISSUER), payload_for("jws-kid-without-fragment"))),
         "deny", "jws_malformed", "the key id has no #fragment"),
        ("jws-kid-missing",
         case(sign({"alg": "EdDSA", "typ": "vc+jwt"}, payload_for("jws-kid-missing"))),
         "deny", "jws_malformed", "the header has no kid"),
        ("jws-padded-base64",
         case(f"{head}=.{body}.{signature}"), "deny", "jws_malformed",
         "a segment carries base64 padding, which a compact JWS does not"),
    ]


def _credential_denials() -> list[Case]:
    return [
        ("credential-type-lacks-verifiable-credential",
         plain("credential-type-lacks-verifiable-credential", type=["AgentBadge"]),
         "deny", "credential_malformed", "type omits VerifiableCredential"),
        ("credential-subject-id-missing",
         plain("credential-subject-id-missing",
               credentialSubject={"badge": "code-reviewer", "level": "gold"}),
         "deny", "credential_malformed", "credentialSubject has no id"),
        ("credential-issuance-unparseable",
         plain("credential-issuance-unparseable", issuanceDate="1 October 2026"),
         "deny", "credential_malformed", "issuanceDate is not an RFC 3339 date-time"),
        ("credential-expiration-unparseable",
         plain("credential-expiration-unparseable", expirationDate="next year"),
         "deny", "credential_malformed", "expirationDate is not an RFC 3339 date-time"),
    ]


def _case_denials() -> list[Case]:
    token = sign(header_for(), payload_for("case-base"))
    return [
        ("case-status-missing", case(token, status=None), "deny", "malformed_case",
         "the case carries no status store"),
        ("case-revoked-not-a-list", case(token, status={"revoked": "none"}), "deny",
         "malformed_case", "revoked is text, not a list"),
        ("case-issuer-key-not-32-bytes",
         case(token, issuers={ISSUER: {"keys": {"key-1": b64(b"short")}}}), "deny",
         "malformed_case", "an issuer's key decodes to 5 bytes"),
        ("case-verification-time-unparseable", case(token, verificationTime="noon"), "deny",
         "malformed_case", "verificationTime is not an RFC 3339 date-time"),
        ("contract-id-missing", case(token, contract=None), "deny", "contract_id_missing",
         "the case names no contract"),
        ("contract-id-unknown", case(token, contract=reader.CONTRACT_ID.replace("/v1", "/v0")),
         "deny", "contract_id_unknown", "the case names a contract version that does not exist"),
    ]


def cases() -> list[Case]:
    """Every case: id, case.json body, decision, reason, departure."""
    return copy.deepcopy([
        *_allow(), *_validity_denials(), *_binding_denials(), *_signature_denials(),
        *_trust_denials(), *_jws_denials(), *_credential_denials(), *_case_denials(),
    ])


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
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "case.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"case.json": _sha(data)}, "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
