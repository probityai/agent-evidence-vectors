"""Build the holder-bound-credential cases byte-identically.

Every case is one credential that confirms a key (``cnf.jkt``, RFC 7800 section 3.1 and
RFC 9449 section 6.1) and the DPoP proofs (RFC 9449 section 4.2) presented with it. Each
refusal is an accepted record with one edit, re-signed where the edit sits before the
signature, so that every check before the one it names still passes. Keys are derived from
public seeds below: every member is synthetic and the keys sign nothing outside this
corpus.

The rules come from public standards text only: RFC 9449 (DPoP), RFC 7800 (proof-of-
possession key semantics for JWTs), RFC 7638 (JWK thumbprint) and RFC 8705 (the same idea
over mutual TLS, named here so a reader knows which sibling mechanism this contract leaves
out).
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import holderbound as reader  # noqa: E402

SUITE = reader.SUITE
SUBJECT = "agent:planner"
ISSUER = "idp.example"
AT = 1795359600  # 2026-11-21T15:00:00Z, the time the relying party saw the first request
IAT = AT - 600
EXP = AT + 3000
URI = "https://api.example/v1/tickets"
OTHER_URI = "https://api.example/v1/payments"
TOKEN = "synthetic-access-token-0001"
OTHER_TOKEN = "synthetic-access-token-0002"
SOURCES = {
    "rfc9449": {"title": "RFC 9449", "url": "https://www.rfc-editor.org/rfc/rfc9449"},
    "rfc7800": {"title": "RFC 7800", "url": "https://www.rfc-editor.org/rfc/rfc7800"},
    "rfc7638": {"title": "RFC 7638", "url": "https://www.rfc-editor.org/rfc/rfc7638"},
    "rfc8705": {"title": "RFC 8705", "url": "https://www.rfc-editor.org/rfc/rfc8705"},
}
#: One sentence per rule, quoted from the source text in _raw (whitespace normalised).
ANCHORS = {
    "dpop-type": (
        "rfc9449",
        "4.2",
        'typ: with value "dpop+jwt"',
    ),
    "dpop-alg": (
        "rfc9449",
        "4.2",
        "It MUST NOT be none or an identifier for a symmetric algorithm (MAC).",
    ),
    "dpop-jwk": ("rfc9449", "4.2", "It MUST NOT contain a private key."),
    "dpop-htu": (
        "rfc9449",
        "4.2",
        "The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is "
        "attached, without query and fragment parts.",
    ),
    "dpop-ath": (
        "rfc9449",
        "4.2",
        "ath: hash of the access token. The value MUST be the result of a base64url "
        "encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHA-256] hash of "
        "the ASCII encoding of the associated access token's value.",
    ),
    "dpop-jkt": ("rfc9449", "6.1", "jkt"),
}
CHECKS_BY_ANCHOR = {
    "proof_type_wrong": "dpop-type",
    "proof_alg_forbidden": "dpop-alg",
    "proof_key_invalid": "dpop-jwk",
    "proof_uri_mismatch": "dpop-htu",
    "proof_ath_mismatch": "dpop-ath",
    "proof_ath_missing": "dpop-ath",
    "proof_key_not_bound": "dpop-jkt",
}

Case = tuple[str, dict[str, Any], str, str, str, tuple[str, ...]]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def key(name: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"holder-bound-credential/v1 test key " + name.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def jwk(name: str) -> dict[str, str]:
    raw = key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"crv": "Ed25519", "kty": "OKP", "x": reader.b64url(raw)}


def _compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def proof(
    signer: str = "holder",
    *,
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
    at: int = AT,
    jti: str = "proof-1",
    method: str = "POST",
    uri: str = URI,
    token: str = TOKEN,
    sign_with: str | None = None,
) -> str:
    """A compact DPoP proof JWT, valid unless an argument changes it."""
    head = {"alg": "EdDSA", "jwk": jwk(signer), "typ": "dpop+jwt"}
    head.update(header or {})
    for member in [k for k, v in head.items() if v is None]:
        del head[member]
    body = {"ath": reader.ath(token), "htm": method, "htu": uri, "iat": at, "jti": jti}
    body.update(claims or {})
    for member in [k for k, v in body.items() if v is None]:
        del body[member]
    signing = f"{reader.b64url(_compact(head))}.{reader.b64url(_compact(body))}"
    signature = key(sign_with or signer).sign(signing.encode("ascii"))
    return f"{signing}.{reader.b64url(signature)}"


def flatten(text: str) -> dict[str, str]:
    """A compact JWS as the flattened JWS JSON the records carry (RFC 7515 section 7.2.2)."""
    parts = text.split(".")
    if len(parts) != 3:
        return {"payload": "", "protected": text, "signature": ""}
    return {"payload": parts[1], "protected": parts[0], "signature": parts[2]}


def presentation(
    proof_text: str | None = None, *, at: int = AT, method: str = "POST", uri: str = URI
) -> dict[str, Any]:
    return {
        "at": at,
        "proof": flatten(
            proof(method=method, uri=uri, at=at) if proof_text is None else proof_text
        ),
        "request": {"htm": method, "htu": uri},
    }


def record(
    presentations: list[dict[str, Any]] | None = None,
    *,
    cnf: bool = True,
    iat: int = IAT,
    exp: int = EXP,
) -> dict[str, Any]:
    credential: dict[str, Any] = {"exp": exp, "iat": iat, "issuer": ISSUER, "token": TOKEN}
    if cnf:
        credential["cnf"] = {"jkt": reader.thumbprint(jwk("holder"))}
    return {
        "contractId": reader.CONTRACT_ID,
        "credential": credential,
        "presentations": presentations if presentations is not None else [presentation()],
        "subject": SUBJECT,
    }


def _resign(text: str, edit: Callable[[dict[str, Any], dict[str, Any]], None], who: str) -> str:
    """Re-seal a proof after editing its decoded header and claims."""
    head_b, body_b, _ = text.split(".")
    head = json.loads(reader.unb64url(head_b) or b"{}")
    body = json.loads(reader.unb64url(body_b) or b"{}")
    edit(head, body)
    signing = f"{reader.b64url(_compact(head))}.{reader.b64url(_compact(body))}"
    return f"{signing}.{reader.b64url(key(who).sign(signing.encode('ascii')))}"


def _drop(member: str) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    return lambda head, body: body.pop(member)


def _set_claim(name: str, value: Any) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    return lambda head, body: body.__setitem__(name, value)


def _set_header(name: str, value: Any) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    return lambda head, body: head.__setitem__(name, value)


def _with_proof(text: str) -> dict[str, Any]:
    return record([presentation(text)])


def _edited_after_signing() -> str:
    head_b, body_b, sig_b = proof().split(".")
    body = json.loads(reader.unb64url(body_b) or b"{}")
    body["htu"] = OTHER_URI
    return f"{head_b}.{reader.b64url(_compact(body))}.{sig_b}"


def _flipped_signature() -> str:
    head_b, body_b, sig_b = proof().split(".")
    raw = bytearray(reader.unb64url(sig_b) or b"")
    raw[0] ^= 0x01
    return f"{head_b}.{body_b}.{reader.b64url(bytes(raw))}"


def _unsigned(alg: str) -> str:
    head = {"alg": alg, "jwk": jwk("holder"), "typ": "dpop+jwt"}
    body = {"ath": reader.ath(TOKEN), "htm": "POST", "htu": URI, "iat": AT, "jti": "proof-1"}
    return f"{reader.b64url(_compact(head))}.{reader.b64url(_compact(body))}."


def _private_jwk() -> str:
    dummy = hashlib.sha256(b"holder-bound-credential/v1 dummy private member").digest()
    leaky = dict(jwk("holder"), d=reader.b64url(dummy))
    return proof(header={"jwk": leaky})


def _weak_key_record(public: bytes, sign: Callable[[bytes], bytes], what: str) -> dict[str, Any]:
    """A record whose credential confirms a weak key, with a proof a naive verifier accepts.

    ``sign`` is tried over successive jti values until the reference rail's plain Ed25519
    check (no subgroup test) accepts the signature, so each case shows a forgery that holds
    unless the verifier refuses the key itself.
    """
    import run_vectors as rail  # the rail's pure-Python Ed25519, on the packaging path

    jwk_value = {"crv": "Ed25519", "kty": "OKP", "x": reader.b64url(public)}
    for attempt in range(512):
        head = {"alg": "EdDSA", "jwk": jwk_value, "typ": "dpop+jwt"}
        body = {
            "ath": reader.ath(TOKEN),
            "htm": "POST",
            "htu": URI,
            "iat": AT,
            "jti": f"weak-{attempt}",
        }
        signing = f"{reader.b64url(_compact(head))}.{reader.b64url(_compact(body))}"
        signature = sign(signing.encode("ascii"))
        if rail.ed25519_verify(public, signing.encode("ascii"), signature):
            result = record([presentation(f"{signing}.{reader.b64url(signature)}")])
            result["credential"]["cnf"] = {"jkt": reader.thumbprint(jwk_value)}
            return result
    raise SystemExit(f"no forged signature found for {what}")


def _weak_key_cases() -> list[tuple[str, dict[str, Any], str, str, tuple[str, ...]]]:
    import run_vectors as rail

    identity = (1).to_bytes(32, "little")
    order_two = (rail._P - 1).to_bytes(32, "little")
    forge_zero = identity + bytes(32)  # signature (R = identity, S = 0)
    seed = hashlib.sha256(b"holder-bound-credential/v1 test key holder").digest()
    h = rail._sha512(seed)
    scalar = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    honest = rail._pt_mul(scalar, rail._B)
    torsion = rail._pt_decompress(order_two)
    mixed = rail._pt_compress(rail._pt_add(honest, torsion))

    def sign_mixed(message: bytes) -> bytes:
        nonce = int.from_bytes(rail._sha512(h[32:], message), "little") % rail._L
        commitment = rail._pt_compress(rail._pt_mul(nonce, rail._B))
        k = int.from_bytes(rail._sha512(commitment, mixed, message), "little") % rail._L
        return commitment + ((nonce + k * scalar) % rail._L).to_bytes(32, "little")

    return [
        (
            "proof-key-identity-point",
            _weak_key_record(identity, lambda m: forge_zero, "identity"),
            "proof_key_invalid",
            "the confirmed key is the identity point, so (identity, 0) signs every message",
            (),
        ),
        (
            "proof-key-order-two",
            _weak_key_record(order_two, lambda m: forge_zero, "order two"),
            "proof_key_invalid",
            "the confirmed key has order two, so a forged signature verifies for half of all "
            "messages",
            (),
        ),
        (
            "proof-key-torsion-component",
            _weak_key_record(mixed, sign_mixed, "mixed order"),
            "proof_key_invalid",
            "the confirmed key is an honest key plus an order-two point: cofactored and "
            "cofactorless verifiers answer differently",
            (),
        ),
    ]


def cases() -> list[Case]:
    """(id, record, decision, reason, edit sentence, anchor names)."""
    rejected = reader.REJECT
    accepted = reader.ACCEPT
    held = reader.ACCEPT_REASON
    out: list[Case] = [
        (
            "accept-single-presentation",
            record(),
            accepted,
            held,
            "control: one request with a fresh proof signed by the confirmed key",
            (),
        ),
        (
            "accept-two-presentations",
            record([presentation(), presentation(proof(jti="proof-2", at=AT + 30), at=AT + 30)]),
            accepted,
            held,
            "control: two requests, each with its own proof",
            (),
        ),
        (
            "accept-proof-at-the-age-limit",
            record([presentation(proof(at=AT - reader.MAX_AGE))]),
            accepted,
            held,
            "control: a proof exactly 60 seconds old is still fresh",
            (),
        ),
        (
            "accept-proof-at-the-ahead-limit",
            record([presentation(proof(at=AT + reader.MAX_AHEAD))]),
            accepted,
            held,
            "control: a proof 5 seconds ahead of the clock is within skew",
            (),
        ),
        (
            "accept-request-at-credential-start",
            record([presentation(proof(at=IAT), at=IAT)]),
            accepted,
            held,
            "control: a request exactly at the credential's start is inside",
            (),
        ),
    ]
    refusals: list[tuple[str, dict[str, Any], str, str, tuple[str, ...]]] = []
    base = record()
    no_id = copy.deepcopy(base)
    del no_id["contractId"]
    wrong_id = copy.deepcopy(base)
    wrong_id["contractId"] += "-other"
    refusals += [
        ("contract-id-missing", no_id, "contract_id_missing", "no contract identifier", ()),
        ("contract-id-unknown", wrong_id, "contract_id_unknown", "another contract identifier", ()),
        (
            "no-presentations",
            record([]),
            "record_malformed",
            "a credential with no presentation at all",
            (),
        ),
        (
            "credential-is-bearer",
            record(cnf=False),
            "credential_not_holder_bound",
            "the credential confirms no key, so anyone who copies it can use it",
            ("dpop-jkt",),
        ),
        (
            "used-before-valid",
            record([presentation(proof(at=IAT - 1), at=IAT - 1)]),
            "credential_not_yet_valid",
            "a request one second before the credential starts",
            (),
        ),
        (
            "used-at-expiry",
            record([presentation(proof(at=EXP), at=EXP)]),
            "credential_expired",
            "a request exactly at exp; the window is half-open",
            (),
        ),
        (
            "used-after-expiry",
            record([presentation(proof(at=EXP + 600), at=EXP + 600)]),
            "credential_expired",
            "a request ten minutes after exp",
            (),
        ),
        (
            "proof-not-a-jws",
            _with_proof("not-a-jws"),
            "proof_malformed",
            "a proof that is not a compact JWS",
            (),
        ),
        (
            "proof-carries-crit",
            _with_proof(proof(header={"crit": ["exp"], "exp": 1})),
            "proof_malformed",
            "a proof header with a crit member the profile does not read",
            (),
        ),
        (
            "proof-type-jwt",
            _with_proof(proof(header={"typ": "JWT"})),
            "proof_type_wrong",
            "typ is JWT, so the proof can be confused with another token",
            ("dpop-type",),
        ),
        (
            "proof-alg-none",
            _with_proof(_unsigned("none")),
            "proof_alg_forbidden",
            "an unsecured proof: alg none and an empty signature",
            ("dpop-alg",),
        ),
        (
            "proof-alg-hs256",
            _with_proof(proof(header={"alg": "HS256"})),
            "proof_alg_forbidden",
            "a MAC algorithm that anyone holding the shared secret could forge",
            ("dpop-alg",),
        ),
        (
            "proof-alg-rs256",
            _with_proof(proof(header={"alg": "RS256"})),
            "proof_alg_unsupported",
            "an asymmetric algorithm this profile does not read",
            (),
        ),
        (
            "proof-jwk-has-private-member",
            _with_proof(_private_jwk()),
            "proof_key_invalid",
            "the header key carries the private member d",
            ("dpop-jwk",),
        ),
        (
            "proof-jwk-missing",
            _with_proof(proof(header={"jwk": None})),
            "proof_key_invalid",
            "the header carries no key",
            (),
        ),
        (
            "proof-signature-flipped",
            _with_proof(_flipped_signature()),
            "proof_signature_invalid",
            "one bit of the signature changed",
            (),
        ),
        (
            "proof-edited-after-signing",
            _with_proof(_edited_after_signing()),
            "proof_signature_invalid",
            "the request target was changed after the proof was signed",
            (),
        ),
        (
            "proof-jti-missing",
            _with_proof(_resign(proof(), _drop("jti"), "holder")),
            "proof_claims_malformed",
            "a re-signed proof with no jti",
            (),
        ),
        (
            "proof-method-mismatch",
            record([presentation(proof(method="GET"))]),
            "proof_method_mismatch",
            "the proof is for GET and the request is POST",
            (),
        ),
        (
            "proof-for-another-uri",
            record([presentation(proof(uri=OTHER_URI))]),
            "proof_uri_mismatch",
            "a proof for another endpoint replayed against this one",
            ("dpop-htu",),
        ),
        (
            "proof-stale",
            record([presentation(proof(at=AT - reader.MAX_AGE - 1))]),
            "proof_stale",
            "a proof 61 seconds old",
            (),
        ),
        (
            "proof-from-future",
            record([presentation(proof(at=AT + reader.MAX_AHEAD + 1))]),
            "proof_from_future",
            "a proof 6 seconds ahead of the clock",
            (),
        ),
        (
            "proof-ath-missing",
            _with_proof(proof(claims={"ath": None})),
            "proof_ath_missing",
            "a proof with no access token hash",
            ("dpop-ath",),
        ),
        (
            "proof-ath-for-another-token",
            _with_proof(proof(token=OTHER_TOKEN)),
            "proof_ath_mismatch",
            "a proof made for a different access token",
            ("dpop-ath",),
        ),
        (
            "proof-signed-by-other-key",
            _with_proof(proof("intruder")),
            "proof_key_not_bound",
            "a valid proof, signed by a key the credential does not confirm",
            ("dpop-jkt",),
        ),
        (
            "proof-replayed",
            record([presentation(), presentation(proof(at=AT + 10), at=AT + 10)]),
            "proof_replayed",
            "two requests carry proofs with the same jti",
            (),
        ),
        (
            "second-proof-bad",
            record(
                [
                    presentation(),
                    presentation(proof(jti="proof-2", at=AT + 30, uri=OTHER_URI), at=AT + 30),
                ]
            ),
            "proof_uri_mismatch",
            "the first request holds and the second does not",
            (),
        ),
    ]
    refusals += _weak_key_cases()
    for name, body, reason, edit, anchors in refusals:
        out.append((name, body, rejected, reason, edit, anchors))
    return out


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest; the reference reader must agree with each case."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, edit, anchors in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append(
            {
                "anchors": [
                    {"quote": ANCHORS[k][2], "section": ANCHORS[k][1], "source": ANCHORS[k][0]}
                    for k in anchors
                ],
                "edit": edit,
                "expected": expected,
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(body),
            }
        )
    words = [e["expected"]["decision"] for e in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {w: words.count(w) for w in sorted(set(words))},
        "sources": SOURCES,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 accept, 1 reject",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the corpus digest from the committed case files, not from their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {path.name for path in directory.iterdir() if path.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


if __name__ == "__main__":
    generate()
