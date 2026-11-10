"""Build the agent request-proof cases byte-identically.

Each case is a recorder's Ed25519 public key and an ordered list of DSSE
envelopes, each over an in-toto Statement v1 in RFC 8785 bytes whose predicate
is ``agent-request-proof/v1``: the HTTP request the recorder received, the
RS256 proof JWT the agent sent with it, the principal's RSA public JWK and its
registered RFC 7638 thumbprint, and the time the recorder observed the request.

The proof follows the per-request agent proof of the Okta AI Agent v2 contract
as ``openbox-ai/openbox-sdk-python`` signs it, ``openbox_core/identity_okta.py``
at commit ``e319c9311070931579a14a07e95251b4adf209b8``: header ``alg``, ``kid``
and ``typ: openbox-agent-proof+jwt``, claims ``iss``, ``sub``, ``aud``,
``iat``, ``exp`` sixty seconds later, a random ``jti``, ``htm``, ``htu`` and
``body_sha256`` over the exact transmitted bytes. The case ``upstream-golden``
records that repository's own golden fixture
``tests/signing/identity_v2/evaluate.json`` at the same commit, verbatim, under
its published fixture public key ``keypair.json``.

The RSA keys are derived from published labels, and the recorder key is an
Ed25519 seed derived the same way, so anyone can rebuild every signature. They
are test keys and protect nothing.
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
from agent_evidence_vectors import agentrequestproof as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/agent-request-proof/v1/"
TYP = "openbox-agent-proof+jwt"
UPSTREAM = {
    "repository": "https://github.com/openbox-ai/openbox-sdk-python",
    "commit": "e319c9311070931579a14a07e95251b4adf209b8",
    "signer": "openbox_core/identity_okta.py",
    "fixture": "tests/signing/identity_v2/evaluate.json",
    "fixtureKey": "tests/signing/identity_v2/keypair.json",
}
UPSTREAM_BODY = (
    "eyJzZXNzaW9uX2lkIjoiMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAw"
    "MDAwMDBhIiwiZXZlbnRfdHlwZSI6IkFjdGl2aXR5U3RhcnRlZCJ9"
)
UPSTREAM_ASSERTION = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUtb2t0YS1jcmVkZW50aWFsLWtpZC0wMDAxIiwidHlwIjoi"
    "b3BlbmJveC1hZ2VudC1wcm9vZitqd3QifQ.eyJhdWQiOiJ1cm46b3BlbmJveDpmaXh0dXJlLWRlcGxveW1lb"
    "nQ6Y29yZSIsImJvZHlfc2hhMjU2IjoiMTZkMDE3OTg1YjY2YWUwYTgyNDYyNWRhNGJiMjY1NTI4ZTk4OTQwO"
    "DY3Zjc3ZmVlZWZhOTQ4OTFlMmQxYWJkZSIsImV4cCI6MTc4NTMyMTA2MCwiaHRtIjoiUE9TVCIsImh0dSI6I"
    "i9hcGkvdjIvZ292ZXJuYW5jZS9ldmFsdWF0ZSIsImlhdCI6MTc4NTMyMTAwMCwiaXNzIjoiZml4dHVyZS1va"
    "3RhLWFpLWFnZW50LTAwMDEiLCJqdGkiOiJmaXh0dXJlLWp0aS0wMDAxIiwib2J4X2FnZW50X2lkIjoiMDAwM"
    "DAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAyIiwib2J4X2FwaV9rZXlfc2hhMjU2IjoiMTEwMzA5Y"
    "TBjZDcxNTcxNzFkMzk1OWQzYjQ5NDUwZjY0MjcwOWM4NTE3YmUzYTc3ZDJlNWQyZDUyYTRjZTk3NyIsIm9ie"
    "F9kZXBsb3ltZW50X2lkIjoiZml4dHVyZS1kZXBsb3ltZW50Iiwib2J4X29yZ2FuaXphdGlvbl9pZCI6IjAwM"
    "DAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMSIsInN1YiI6ImZpeHR1cmUtb2t0YS1haS1hZ2Vud"
    "C0wMDAxIn0.p777Be0h2PmTgye10Yem8X2XU7IbO7k2-rrtbALp2pjDnZzRoJ7BP6gY_j_z4DgtArB4rtWV1"
    "X8ziBUKGVOcgFE4vodITQmSyEcutQvyol8uWNv7_33mc_LwwCkxKaPN4QST754k-2frFiytlpvkx-oh2-nra"
    "TmF7LTiUZqysB30O5ublwYHlmjohSMKX7HVKwIqarH1dxJnbaK3gykciJncWG_1yN5o7-PAbNqs7RLLXllDp"
    "5TZmIXhtgWqBMBsqhEFSUlrbzTfmaf1dMRdaao3tjy5yfbeJSZEomFyEYDeBvnyXYZJqXCNZkocpqwByxKV9"
    "U1rojnKDj6efeGexQ"
)
UPSTREAM_N = (
    "wiat4phYVsAbLMMMHs4KU7gmEZolmD62CQx1mUdwLj1SG-973OwMUN3281LZ3XWDVLiWVGZBdoIon3Rs3h1X"
    "M8yOQ1yTW-OOVS637ne2Z5PWaMHZHgU1jRvsIBnGWco1DS-1_u9ScoH76XrNsviImF_P6ozLw_N9neuv1Lnr"
    "1VvvYqeTGTzA4bWMtVCOczKJNh3_QtcPHK6yRrvgkmSRqcZMWPaiOoOF5sX46p1lbRr47ostcWcgGNE8pSVd"
    "V7ksF51FKyC7CA2w8hvNlxiiZtxSpbxhXsyUoNq40XjGk38P0VSiW6pvgT25aEuK_5T49-1hRlYKEaO8SNNx"
    "v01sFw"
)
ISSUER = "agent-billing-0001"
AUDIENCE = "urn:example:governance:core"
T0 = 1785321000  # 2026-07-29T10:30:00Z


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _stream(label: str):  # type: ignore[no-untyped-def]
    counter = 0
    while True:
        yield hashlib.sha256(_seed(label) + counter.to_bytes(8, "big")).digest()
        counter += 1


_SMALL = [p for p in range(3, 2000) if all(p % q for q in range(2, int(p**0.5) + 1))]


def _probable_prime(n: int) -> bool:
    if any(n % p == 0 for p in _SMALL):
        return n in _SMALL
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for a in _SMALL[:40]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(label: str, bits: int) -> int:
    """The first probable prime of a labelled byte stream, top two bits set."""
    stream = _stream(label)
    while True:
        raw = b"".join(next(stream) for _ in range(bits // 256))
        candidate = int.from_bytes(raw, "big") | (3 << (bits - 2)) | 1
        if candidate % 65537 != 1 and _probable_prime(candidate):
            return candidate


class RsaKey:
    """A 2048-bit RSA key derived from a published label."""

    def __init__(self, label: str) -> None:
        self.p, self.q = _prime(label + "/p", 1024), _prime(label + "/q", 1024)
        self.n, self.e = self.p * self.q, 65537
        self.d = pow(self.e, -1, (self.p - 1) * (self.q - 1))

    def jwk(self) -> dict[str, str]:
        return {
            "e": reader.b64url(self.e.to_bytes(3, "big")),
            "kty": "RSA",
            "n": reader.b64url(self.n.to_bytes(256, "big")),
        }

    def sign(self, message: bytes) -> bytes:
        tail = (
            bytes.fromhex("3031300d060960864801650304020105000420")
            + hashlib.sha256(message).digest()
        )
        encoded = b"\x00\x01" + b"\xff" * (256 - len(tail) - 3) + b"\x00" + tail
        return pow(int.from_bytes(encoded, "big"), self.d, self.n).to_bytes(256, "big")


AGENT, MALLORY = RsaKey("agent"), RsaKey("mallory")


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _compact(value: dict[str, Any]) -> str:
    return reader.b64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def proof(
    method: str,
    path: str,
    body: bytes,
    *,
    jti: str = "jti-0001",
    iat: int = T0,
    lifetime: int = 60,
    key: RsaKey = AGENT,
    header: dict[str, Any] | None = None,
    iss: str = ISSUER,
    unsigned: bool = False,
    aud: str = AUDIENCE,
    extra: dict[str, Any] | None = None,
) -> str:
    """A compact proof JWT, as the agent signs it."""
    head = header or {"alg": "RS256", "kid": "agent-key-0001", "typ": TYP}
    claims = {
        **(extra or {}),
        "aud": aud,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "exp": iat + lifetime,
        "htm": method,
        "htu": path,
        "iat": iat,
        "iss": iss,
        "jti": jti,
        "sub": iss,
    }
    signing_input = f"{_compact(head)}.{_compact(claims)}"
    sig = "" if unsigned else reader.b64url(key.sign(signing_input.encode()))
    return f"{signing_input}.{sig}"


def _iso(seconds: int) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def statement(
    method: str,
    path: str,
    body: bytes,
    jws: str,
    *,
    observed: int = T0 + 5,
    jwk: dict[str, str] | None = None,
    thumbprint: str | None = None,
    predicate_type: str = reader.PREDICATE_TYPE,
    issuer: str = ISSUER,
) -> dict[str, Any]:
    """The in-toto statement the recorder writes for one received request."""
    key = jwk or AGENT.jwk()
    return {
        "_type": reader.STATEMENT_TYPE,
        "predicate": {
            "observedAt": _iso(observed),
            "principal": {
                "issuer": issuer,
                "jwk": key,
                "jwkThumbprint": thumbprint or reader.rsa_thumbprint(AGENT.jwk()),
                "subject": issuer,
                "verification": "proof-verified",
            },
            "proof": {"jws": jws, "typ": TYP},
            "request": {
                "bodyBase64": base64.b64encode(body).decode(),
                "method": method,
                "path": path,
            },
        },
        "predicateType": predicate_type,
        "subject": [
            {"digest": {"sha256": hashlib.sha256(body).hexdigest()}, "name": "request-body"}
        ],
    }


def envelope(stmt: dict[str, Any], served: dict[str, Any] | None = None) -> bytes:
    """A DSSE envelope the recorder signs. ``served`` replaces the statement
    after signing, as an edit made without the recorder key must."""
    payload = bytes(rail.jcs_dumps(stmt))
    sig = rail.ed25519_sign(_seed("recorder"), rail.pae(reader.PAYLOAD_TYPE, payload))
    if served is not None:
        payload = bytes(rail.jcs_dumps(served))
    return _json(
        {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": reader.PAYLOAD_TYPE,
            "signatures": [{"keyid": "recorder-0001", "sig": base64.b64encode(sig).decode()}],
        }
    )


KID = "agent-key-0001"
TENANT = {"obx_deployment_id": "deployment-0001", "obx_organization_id": "org-0001"}
# The relying party's pins for the audience, kid and tenant checks, by case id.
# They live in case.json, never in the record.
PINS: dict[str, dict[str, Any]] = {}

POST, PATH = "POST", "/api/v2/governance/evaluate"
BODY = b'{"event_type":"ActivityStarted","session_id":"session-0001"}'
OTHER_BODY = b'{"event_type":"ActivityStarted","session_id":"session-0002"}'


def _good(jti: str = "jti-0001", iat: int = T0, body: bytes = BODY) -> dict[str, Any]:
    return statement(POST, PATH, body, proof(POST, PATH, body, jti=jti, iat=iat), observed=iat + 5)


def _upstream() -> dict[str, Any]:
    body = base64.b64decode(UPSTREAM_BODY)
    jwk = {"e": "AQAB", "kty": "RSA", "n": UPSTREAM_N}
    claims = json.loads(reader.b64url_decode(UPSTREAM_ASSERTION.split(".")[1]))
    return statement(
        claims["htm"],
        claims["htu"],
        body,
        UPSTREAM_ASSERTION,
        observed=claims["iat"] + 5,
        jwk=jwk,
        thumbprint=reader.rsa_thumbprint(jwk),
        issuer=claims["iss"],
    )


Case = tuple[str, list[bytes], str, str, str]


def _pinned(name: str, **overrides: Any) -> dict[str, Any]:
    """Register the pins for one case: the audience, kid and tenant its good proof carries."""
    pins = {"audience": AUDIENCE, "claims": dict(TENANT), "kid": KID, **overrides}
    PINS[name] = pins
    return pins


def _pinned_good(**claims: Any) -> dict[str, Any]:
    body = BODY
    return statement(
        POST, PATH, body, proof(POST, PATH, body, extra={**TENANT, **claims}), observed=T0 + 5
    )


def cases() -> list[Case]:
    """Every case: id, envelopes in order, expected decision and reason, the edit."""
    wrong_typ = {"alg": "RS256", "kid": "agent-key-0001", "typ": "JWT"}
    embedded = {"alg": "RS256", "jwk": MALLORY.jwk(), "kid": "agent-key-0001", "typ": TYP}
    alg_none = {"alg": "none", "kid": "agent-key-0001", "typ": TYP}
    edited = _good()
    edited["predicate"]["request"]["path"] = "/api/v2/governance/approve"
    up_claims = json.loads(reader.b64url_decode(UPSTREAM_ASSERTION.split(".")[1]))
    up_header = json.loads(reader.b64url_decode(UPSTREAM_ASSERTION.split(".")[0]))
    PINS["upstream-golden-pinned"] = {
        "audience": up_claims["aud"],
        "claims": {k: v for k, v in up_claims.items() if k.startswith("obx_")},
        "kid": up_header["kid"],
    }
    _pinned("request-bound-pinned")
    _pinned("audience-mismatch")
    _pinned("kid-mismatch")
    _pinned("tenant-mismatch")
    _pinned("tenant-claim-absent")
    wrong_kid = {"alg": "RS256", "kid": "agent-key-0002", "typ": TYP}
    return [
        (
            "request-bound",
            [envelope(_good())],
            "verified",
            "request_bound",
            "control: one request, its proof and its body, recorded within the proof's lifetime",
        ),
        (
            "upstream-golden",
            [envelope(_upstream())],
            "verified",
            "request_bound",
            "control: the upstream SDK's own golden evaluate fixture, recorded verbatim",
        ),
        (
            "distinct-jti-sequence",
            [envelope(_good("jti-0001")), envelope(_good("jti-0002", T0 + 20, OTHER_BODY))],
            "verified",
            "request_bound",
            "control: two records from one agent, each proof with its own jti",
        ),
        (
            "statement-malformed",
            [
                envelope(
                    statement(
                        POST,
                        PATH,
                        BODY,
                        proof(POST, PATH, BODY),
                        predicate_type="https://in-toto.io/attestation/unknown/v1",
                    )
                )
            ],
            "rejected",
            "statement_malformed",
            "the statement names another predicate type",
        ),
        (
            "recorder-signature-invalid",
            [envelope(_good(), served=edited)],
            "rejected",
            "recorder_signature_invalid",
            "the recorded path was changed after the recorder signed",
        ),
        (
            "wrong-typ",
            [envelope(statement(POST, PATH, BODY, proof(POST, PATH, BODY, header=wrong_typ)))],
            "rejected",
            "typ_mismatch",
            "a generic JWT typ where the profile names its own",
        ),
        (
            "alg-none",
            [
                envelope(
                    statement(
                        POST, PATH, BODY, proof(POST, PATH, BODY, header=alg_none, unsigned=True)
                    )
                )
            ],
            "rejected",
            "alg_not_allowed",
            "an unsigned proof with alg none",
        ),
        (
            "embedded-jwk",
            [
                envelope(
                    statement(
                        POST,
                        PATH,
                        BODY,
                        proof(POST, PATH, BODY, header=embedded, key=MALLORY),
                        jwk=MALLORY.jwk(),
                    )
                )
            ],
            "rejected",
            "alg_not_allowed",
            "the proof carries its own verification key in the header",
        ),
        (
            "thumbprint-mismatch",
            [
                envelope(
                    statement(
                        POST, PATH, BODY, proof(POST, PATH, BODY, key=MALLORY), jwk=MALLORY.jwk()
                    )
                )
            ],
            "rejected",
            "thumbprint_mismatch",
            "another key signs the proof and the record carries that key, against the "
            "thumbprint the agent registered",
        ),
        (
            "proof-signature-invalid",
            [envelope(statement(POST, PATH, BODY, proof(POST, PATH, BODY, key=MALLORY)))],
            "rejected",
            "proof_signature_invalid",
            "another key signs the proof; the record carries the registered key",
        ),
        (
            "principal-mismatch",
            [
                envelope(
                    statement(POST, PATH, BODY, proof(POST, PATH, BODY, iss="agent-payments-0002"))
                )
            ],
            "rejected",
            "principal_mismatch",
            "the registered key signs a proof naming another agent as issuer",
        ),
        (
            "htm-htu-mismatch",
            [
                envelope(
                    statement(
                        "DELETE", "/api/v2/governance/policies/7", BODY, proof(POST, PATH, BODY)
                    )
                )
            ],
            "rejected",
            "htm_htu_mismatch",
            "a proof for POST evaluate presented with a DELETE of a policy",
        ),
        (
            "body-digest-mismatch",
            [envelope(statement(POST, PATH, OTHER_BODY, proof(POST, PATH, BODY)))],
            "rejected",
            "body_digest_mismatch",
            "the recorded body is not the body the proof hashed",
        ),
        (
            "expired",
            [envelope(statement(POST, PATH, BODY, proof(POST, PATH, BODY), observed=T0 + 61))],
            "rejected",
            "proof_expired",
            "the request arrived a second after the proof expired",
        ),
        (
            "excessive-lifetime",
            [envelope(statement(POST, PATH, BODY, proof(POST, PATH, BODY, lifetime=3600)))],
            "rejected",
            "proof_expired",
            "a proof valid for an hour where the profile allows 60 s",
        ),
        (
            "replayed-jti",
            [
                envelope(_good("jti-0001")),
                envelope(
                    statement(
                        POST,
                        PATH,
                        OTHER_BODY,
                        proof(POST, PATH, OTHER_BODY, jti="jti-0001", iat=T0 + 20),
                        observed=T0 + 25,
                    )
                ),
            ],
            "rejected",
            "replayed_jti",
            "a second proof reuses the jti of an earlier recorded proof from the same agent",
        ),
        (
            "request-bound-pinned",
            [envelope(_pinned_good())],
            "verified",
            "request_bound",
            "control: the proof carries the pinned audience, kid and tenant claims",
        ),
        (
            "upstream-golden-pinned",
            [envelope(_upstream())],
            "verified",
            "request_bound",
            "control: the upstream golden fixture under pins taken from its own aud, kid "
            "and obx_ claims",
        ),
        (
            "audience-mismatch",
            [
                envelope(
                    statement(
                        POST,
                        PATH,
                        BODY,
                        proof(POST, PATH, BODY, aud="urn:example:other:core", extra=TENANT),
                    )
                )
            ],
            "rejected",
            "audience_mismatch",
            "a valid proof minted for another audience, replayed at this service",
        ),
        (
            "kid-mismatch",
            [
                envelope(
                    statement(
                        POST,
                        PATH,
                        BODY,
                        proof(POST, PATH, BODY, header=wrong_kid, extra=TENANT),
                    )
                )
            ],
            "rejected",
            "kid_mismatch",
            "the registered key signs a proof whose kid names another credential",
        ),
        (
            "tenant-mismatch",
            [envelope(_pinned_good(obx_organization_id="org-0002"))],
            "rejected",
            "tenant_mismatch",
            "a valid proof carrying another organisation's tenant claim",
        ),
        (
            "tenant-claim-absent",
            [
                envelope(
                    statement(
                        POST,
                        PATH,
                        BODY,
                        proof(POST, PATH, BODY, extra={"obx_deployment_id": "deployment-0001"}),
                    )
                )
            ],
            "rejected",
            "tenant_mismatch",
            "a valid proof that omits the pinned organisation claim",
        ),
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
        files = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                 for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return hashlib.sha256(_json(entries)).hexdigest()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    recorder = rail._pt_compress(rail._pt_mul(_scalar(_seed("recorder")), rail._B))
    for name, envelopes, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        names = [f"envelope-{i + 1}.json" for i in range(len(envelopes))]
        case = {
            "envelopes": names,
            "recorderKey": base64.b64encode(bytes(recorder)).decode(),
            "schema_version": "agent-request-proof-case/v1",
        }
        if name in PINS:
            case["pins"] = PINS[name]
        files = {"case.json": _json(case), **dict(zip(names, envelopes, strict=True))}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append(
            {
                "edit": edit,
                "expected": {"decision": decision, "reason": reason},
                "files": {
                    key: hashlib.sha256(value).hexdigest() for key, value in sorted(files.items())
                },
                "id": name,
                "path": f"cases/{name}",
                "proofSignatureVerifies": reader.proof_signature_verifies(directory / "case.json"),
            }
        )
    manifest = {
        "corpusDigest": hashlib.sha256(_json(entries)).hexdigest(),
        "predicateType": reader.PREDICATE_TYPE,
        "suite": SUITE,
        "upstream": UPSTREAM,
        "verifierContract": "verifier case.json --json; exit 0 verified, 1 rejected",
        "vectors": entries,
    }
    words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: words.count(word) for word in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


def _scalar(seed: bytes) -> int:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    return a | 1 << 254


if __name__ == "__main__":
    generate()
