#!/usr/bin/env python3
"""Deterministic generator for the IETF agent-record drafts conformance corpus.

Emits every file under `cases/`, `MANIFEST.json` and `INDEX.md`. Run it and
the tree is byte-identical on any machine:

    uv run --extra generators python vectors-ietf-agent-record-drafts/gen_vectors.py

The corpus holds conformance cases for three individual Internet-Drafts of the
October 2026 SCITT wave, each case built from the draft's own structures:

  - draft-emirdag-scitt-ai-agent-execution-01, the AgentInteractionRecord (AIR)
    hash chain: a record whose prev_chain_hash is not the preceding record's
    chain_hash, two records at one chain position, and a record timestamped
    before its predecessor. The draft's Section 5.8 reads all three values and
    compares none of them.
  - draft-mih-scitt-checkpointed-local-log-02, the Checkpointed Local Log (CLL):
    a checkpoint registered two weeks after its issue time, a second history
    under one log identity at a second named service, and a checkpoint whose
    payload repeats a map key. The published checkpoints cp1 to cp4 are used
    as published, from the draft's vector repository, vendored verbatim at
    `upstream/cll-02-vectors.json`.
  - draft-gruszka-scitt-statement-identification-02: statement 01 of its
    Appendix A, re-signed by its own published issuer seed with the protected
    header keys written in another order.

README.md states every rule a case tests and what each verdict does not assert.

Determinism recipe, published so a stranger rebuilds rather than trusts:

  - Ed25519 is deterministic (RFC 8032). ES256 is signed with the deterministic
    nonce of RFC 6979, so the AIR records are byte-exact too.
  - The AIR operator key is derived from a published constant; the CLL key is
    the 0x07 fixture seed of the draft's own vectors; the statement
    identification keys are the issuer and auditor seeds printed in that draft's
    Appendix A.2. Every one of them is a PUBLISHED TEST KEY.
  - Every timestamp is a literal; every identifier and digest is derived.

Each case is built by an explicit call, never by merging overrides into a
baseline, for the reason the sibling generators record: a merge once kept a
baseline object a member was built to omit.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cbor_det import Tag, decode, encode, encode_pairs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from digest import corpus_digest

HERE = Path(__file__).resolve().parent
CASES = HERE / "cases"
ID_HEX = 16

SUITE = "ietf-agent-record-drafts-conformance"
DRAFT_AIR = "draft-emirdag-scitt-ai-agent-execution-01"
DRAFT_CLL = "draft-mih-scitt-checkpointed-local-log-02"
DRAFT_SID = "draft-gruszka-scitt-statement-identification-02"
SOURCES = {
    DRAFT_AIR: "https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/01/",
    DRAFT_CLL: "https://datatracker.ietf.org/doc/draft-mih-scitt-checkpointed-local-log/02/",
    DRAFT_SID: "https://datatracker.ietf.org/doc/draft-gruszka-scitt-statement-identification/02/",
    "cllVectors": (
        "https://github.com/action-state-group/checkpointed-local-log/tree/"
        "4e8f098bef262c718f7217bf62e2b10030b4bcb3/cll-02-vectors"
    ),
    "cllReferenceVerifier": (
        "https://github.com/action-state-group/checkpointed-local-log/blob/"
        "4e8f098bef262c718f7217bf62e2b10030b4bcb3/cll-02-vectors/cll02.py"
    ),
    "scittChairsRequest": "https://mailarchive.ietf.org/arch/browse/scitt/",
}
# The SHA-256 the draft's vector repository publishes for vectors.json in its
# SHA256SUMS, at the commit above. The vendored copy must still carry it.
CLL_VECTORS_SHA256 = "7eec8d865571223ea8cbc3ecdae5d6f2f9ac3582ab7c187d2feca588c4c4ed64"
CLL_REFERENCE_COMMIT = "4e8f098bef262c718f7217bf62e2b10030b4bcb3"

# Statement 01 of draft-gruszka-scitt-statement-identification-02, Appendix A
# (330 bytes, SHA-256 9c725361...54c6), and the reference digest its statement
# 02 carries (ToBeSigned SHA-256 c3f5f137...9dbc).
SID_S01 = bytes.fromhex(
    "d284587ba4013203706170706c69636174696f6e2f6a736f6e0458200e6e86cd"
    "20c07df4e95cb4a07a286192d29fc74567b41e726f1c7f7bd202eb5b0fa30176"
    "68747470733a2f2f6973737565722e6578616d706c65027820706b673a67656e"
    "657269632f6578616d706c652d77696467657440312e302e30061a68ce7b20a0"
    "58867b226172746966616374223a226578616d706c652d7769646765742d312e"
    "302e302e7461722e677a222c226c6963656e7365223a224d4954222c22736861"
    "323536223a223630376536633165366333356463633962373730646535646139"
    "3262393639373034613336366434363839373261386235356431613063333264"
    "623334613732227d58401fb31a6df345f1c1840d878bd4b4acedb6612956916e"
    "4b4550c5b6479289ed36f41cb604c8ab743dc2eb9fbda7fecfb896b3d444ba30"
    "e591e663093a4eeb8104"
)
SID_S01_SHA256 = "9c7253617b9fe51ba25eb0f957dadea493ca03e98c4a81806237757f13d054c6"
SID_REFERENCE = "c3f5f13764679b9f77918bb52782480bc222be5ae4bce37f51384a6b1faa9dbc"
SID_ISSUER_SEED = "51bdccce75df50a4bcee21a2f730ccdcd4917a0a4d20dd2ab3d2e5ffad3f6fd3"
SID_AUDITOR_SEED = "2a8b1161e212cc24681c06e6d7486daa0910253e54903d41ae964aaee2bfc681"

AIR_KEY_RECIPE = 'sha256("agent-evidence-ietf-agent-record-drafts-test-key/air-operator/v1")'
AIR_OTHER_RECIPE = 'sha256("agent-evidence-ietf-agent-record-drafts-test-key/air-other/v1")'
CLL_OTHER_RECIPE = 'sha256("agent-evidence-ietf-agent-record-drafts-test-key/cll-other/v1")'
AIR_ISS = "did:web:operator.example"
AIR_AGENT = "agent-pay-01"
AIR_KID = b"op-key-2026"
GENESIS = bytes(32)

# Codes a verdict of "malformed" carries; every other refusal is "invalid".
MALFORMED_CODES = frozenset(
    {"cose-malformed", "claims-malformed", "cbor-not-deterministic", "cbor-duplicate-key"}
)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- keys


def p256_from_recipe(label: bytes) -> ec.EllipticCurvePrivateKey:
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    scalar = int.from_bytes(sha256(label), "big") % (order - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def air_operator_key() -> ec.EllipticCurvePrivateKey:
    return p256_from_recipe(b"agent-evidence-ietf-agent-record-drafts-test-key/air-operator/v1")


def air_other_key() -> ec.EllipticCurvePrivateKey:
    return p256_from_recipe(b"agent-evidence-ietf-agent-record-drafts-test-key/air-other/v1")


def cll_producer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)


def cll_other_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        sha256(b"agent-evidence-ietf-agent-record-drafts-test-key/cll-other/v1")
    )


def sid_issuer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SID_ISSUER_SEED))


def sid_auditor_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SID_AUDITOR_SEED))


def es256_raw(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    der = key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    return encode(["Signature1", protected, b"", payload])


# ---------------------------------------------------------------- AIR (emirdag)


def air_chain_hash(content: bytes, prev: bytes, ts_ms: int, agent: str) -> bytes:
    """Section 5.7: SHA-256 over both digests, the u64 BE time, then agent_id behind its length."""
    raw = agent.encode("utf-8")
    pre = content + prev + ts_ms.to_bytes(8, "big") + len(raw).to_bytes(4, "big") + raw
    if len(pre) != 76 + len(raw):
        raise SystemExit("the Section 5.7 pre-image has the wrong length")
    return sha256(pre)


def air_payload(record_id: str, ts_ms: int, *, outcome: str = "completed", output: bytes) -> bytes:
    """The RFC 8785 serialisation of one AIR; every value is ASCII or a small integer.

    The draft names no JSON form for its bstr fields; this corpus writes them as
    lowercase hex, and no verdict below depends on that choice.
    """
    record = {
        "schema_version": "air-1.0",
        "record_id": record_id,
        "session_id": "4d0a8f6e-2b1c-4e3a-9f7d-1a2b3c4d5e6f",
        "agent_id": AIR_AGENT,
        "agent_version": "model-x/1.2;fw/0.9",
        "operator_id": AIR_ISS,
        "operator_pubkey_id": AIR_KID.decode(),
        "action_type": "payment_execution",
        "action_timestamp_ms": ts_ms,
        "captured_timestamp_ms": ts_ms + 250,
        "input_hash": sha256_hex(b"raw input " + record_id.encode()),
        "outcome_state": outcome,
        "outcome_hash": sha256_hex(output),
        "tool_calls": [],
        "jurisdiction": "DE",
        "retention_class": "regulatory_7yr",
        "policy_refs": [],
        "external_refs": [],
        "redaction_receipts": [],
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def air_record(
    payload: bytes,
    *,
    prev: bytes,
    seq: int,
    ts_ms: int,
    key: ec.EllipticCurvePrivateKey,
    content: bytes | None = None,
    chain: bytes | None = None,
    cwt: dict[int, str] | None = None,
) -> tuple[bytes, bytes]:
    """One COSE_Sign1 AIR record and its chain_hash.

    `content` and `chain` override the honest values, which is how the
    content-hash and chain-hash members are built: the Issuer signs a header
    whose integrity fields are wrong.
    """
    content_hash = sha256(payload) if content is None else content
    chain_hash = air_chain_hash(content_hash, prev, ts_ms, AIR_AGENT) if chain is None else chain
    protected = encode(
        {
            1: -7,
            4: AIR_KID,
            15: {1: AIR_ISS, 2: AIR_AGENT} if cwt is None else cwt,
            "content_hash": content_hash,
            "prev_chain_hash": prev,
            "chain_hash": chain_hash,
            "sequence_number": seq,
            "action_timestamp_ms": ts_ms,
            "agent_id": AIR_AGENT,
        }
    )
    signature = es256_raw(key, sig_structure(protected, payload))
    return encode(Tag(18, [protected, {}, payload, signature])), chain_hash


R_IDS = (
    "0192f5e0-7c3a-7b1e-9a40-3c1d2e4f5a6b",
    "0192f5e0-7c3a-7b1e-9a40-3c1d2e4f5a6c",
    "0192f5e0-7c3a-7b1e-9a40-3c1d2e4f5a6d",
)
T0, T1, T2 = 1791900000000, 1791900060000, 1791900120000
T_BACKDATED = 1791813600000  # one day before r0


def air_members() -> list[dict[str, Any]]:
    key, other = air_operator_key(), air_other_key()
    p0 = air_payload(R_IDS[0], T0, output=b"raw output 0")
    r0, c0 = air_record(p0, prev=GENESIS, seq=0, ts_ms=T0, key=key)
    p1 = air_payload(R_IDS[1], T1, output=b"raw output 1")
    r1, c1 = air_record(p1, prev=c0, seq=1, ts_ms=T1, key=key)
    p1b = air_payload(R_IDS[1], T1, outcome="failed", output=b"raw output 1, other branch")
    r1b, _ = air_record(p1b, prev=c0, seq=1, ts_ms=T1, key=key)
    spliced_prev = sha256(b"chain of agent-pay-02, record 41")
    r1_spliced, _ = air_record(p1, prev=spliced_prev, seq=1, ts_ms=T1, key=key)
    p2 = air_payload(R_IDS[2], T2, output=b"raw output 2")
    r2, _ = air_record(p2, prev=c1, seq=2, ts_ms=T2, key=key)
    p2_back = air_payload(R_IDS[2], T_BACKDATED, output=b"raw output 2")
    r2_back, _ = air_record(p2_back, prev=c1, seq=2, ts_ms=T_BACKDATED, key=key)
    p2_later = air_payload(R_IDS[2], T2 + 60000, output=b"raw output 2")
    r2_split, _ = air_record(p2_later, prev=c1, seq=2, ts_ms=T2, key=key)
    wrong_content = sha256(air_payload(R_IDS[1], T1, output=b"raw output never signed"))
    r1_content, _ = air_record(p1, prev=c0, seq=1, ts_ms=T1, key=key, content=wrong_content)
    little_endian = sha256(
        sha256(p1)
        + c0
        + T1.to_bytes(8, "little")
        + len(AIR_AGENT).to_bytes(4, "big")
        + AIR_AGENT.encode()
    )
    r1_chain, _ = air_record(p1, prev=c0, seq=1, ts_ms=T1, key=key, chain=little_endian)
    p2_gap = air_payload(R_IDS[2], T1, output=b"raw output 1")
    r_gap, _ = air_record(p2_gap, prev=c0, seq=2, ts_ms=T1, key=key)
    r1_other, _ = air_record(p1, prev=c0, seq=1, ts_ms=T1, key=other)
    r0_nosub, _ = air_record(p0, prev=GENESIS, seq=0, ts_ms=T0, key=key, cwt={1: AIR_ISS})

    def case(predecessors: list[bytes], candidates: list[bytes]) -> dict[str, Any]:
        return {
            "draft": DRAFT_AIR,
            "issuerKey": "air-operator",
            "predecessors": [r.hex() for r in predecessors],
            "candidates": [r.hex() for r in candidates],
        }

    not_content = "that the record's content is accurate, or that the Issuer recorded every action"
    return [
        air(
            "air-genesis",
            "the first record of agent-pay-01's chain: sequence 0, prev_chain_hash all zero",
            case([], [r0]),
            dna=[not_content],
        ),
        air(
            "air-follows",
            "record 1, whose prev_chain_hash is record 0's chain_hash",
            case([r0], [r1]),
            dna=[not_content, "that no other record claims sequence 1 at another custodian"],
        ),
        air(
            "air-third-follows",
            "record 2 after records 0 and 1, timestamped one minute after record 1",
            case([r0, r1], [r2]),
            dna=[not_content, "that the timestamps are the times the actions happened"],
        ),
        air(
            "air-prev-chain-hash-mismatch",
            "record 1 whose prev_chain_hash is the chain_hash of another agent's record, "
            "not record 0's; Section 5.8 takes the preceding chain_hash as input and "
            "never compares it",
            case([r0], [r1_spliced]),
            code="prev-chain-hash-mismatch",
            parent="air-follows",
            draft="valid",
            dna=[
                "which history the record does continue",
                "that the record's content is false",
                "that the Issuer meant to splice the chain",
            ],
        ),
        air(
            "air-two-records-one-position",
            "two records, completed and failed, both at sequence 1 over record 0 and both "
            "signed by the Issuer; each passes Section 5.8 on its own",
            case([r0], [r1, r1b]),
            code="chain-position-equivocation",
            parent="air-follows",
            draft="valid",
            dna=[
                "which of the two records is the true one",
                "that either record was registered at a Transparency Service",
            ],
        ),
        air(
            "air-timestamp-before-predecessor",
            "record 2 whose action_timestamp_ms, in the header and the payload alike, is "
            "one day before record 0's; Section 6.3 checks only captured time against "
            "action time",
            case([r0, r1], [r2_back]),
            code="timestamp-regression",
            parent="air-third-follows",
            draft="valid",
            dna=[
                "when the action actually happened",
                "that the Issuer backdated it deliberately rather than by a clock fault",
            ],
        ),
        air(
            "air-header-payload-time-differ",
            "record 2 whose header action_timestamp_ms, the value bound into chain_hash, "
            "is a minute before the payload's",
            case([r0, r1], [r2_split]),
            code="header-payload-disagree",
            parent="air-third-follows",
            draft="valid",
            dna=["which of the two times is the true one"],
        ),
        air(
            "air-content-hash-mismatch",
            "record 1 whose header content_hash is the hash of a payload it does not carry",
            case([r0], [r1_content]),
            code="content-hash-mismatch",
            parent="air-follows",
            draft="invalid",
            dna=["what the payload the hash names said"],
        ),
        air(
            "air-chain-hash-mismatch",
            "record 1 whose chain_hash takes action_timestamp_ms little-endian, against "
            "the big-endian encoding Section 5.7 pins",
            case([r0], [r1_chain]),
            code="chain-hash-mismatch",
            parent="air-follows",
            draft="invalid",
            dna=["that the record's other fields are wrong"],
        ),
        air(
            "air-sequence-gap",
            "a record at sequence 2 directly after record 0",
            case([r0], [r_gap]),
            code="sequence-gap",
            parent="air-follows",
            draft="invalid",
            dna=["that a record 1 existed, or what it said"],
        ),
        air(
            "air-signed-by-other-key",
            "record 1 signed by a P-256 key other than the operator's registered one",
            case([r0], [r1_other]),
            code="signature-invalid",
            parent="air-follows",
            draft="invalid",
            dna=["who did sign the record"],
        ),
        air(
            "air-cwt-sub-missing",
            "record 0 whose CWT Claims carry iss and no sub, which Section 5.5 requires",
            case([], [r0_nosub]),
            code="cose-malformed",
            parent="air-genesis",
            draft="malformed",
            dna=["which agent the record is about"],
        ),
    ]


def air(
    slug: str,
    row: str,
    case: dict[str, Any],
    *,
    dna: list[str],
    code: str | None = None,
    parent: str | None = None,
    draft: str = "valid",
) -> dict[str, Any]:
    return member(slug, row, DRAFT_AIR, case, dna=dna, code=code, parent=parent, draft=draft)


# ---------------------------------------------------------------- CLL (mih)


def cll_vectors() -> dict[str, Any]:
    raw = (HERE / "upstream" / "cll-02-vectors.json").read_bytes()
    if sha256_hex(raw) != CLL_VECTORS_SHA256:
        raise SystemExit("upstream/cll-02-vectors.json is not the published vectors.json")
    out: dict[str, Any] = json.loads(raw)
    return out


def mmr_size4_commitment(entries: list[bytes]) -> bytes:
    """The accumulator of a three-leaf MMR (size 4), tallest peak first.

    leaf = SHA-256(0x00 || entry); node 2 = SHA-256(be64(3) || leaf0 || leaf1),
    the interior-node rule of the MMR profile with pos = index + 1.
    """
    leaves = [sha256(b"\x00" + e) for e in entries]
    node2 = sha256((3).to_bytes(8, "big") + leaves[0] + leaves[1])
    return node2 + leaves[2]


def cll_sign(key: Ed25519PrivateKey, kid: bytes, payload: bytes, cwt: dict[int, str]) -> bytes:
    protected = encode({1: -19, 4: kid, 15: cwt})
    return encode(Tag(18, [protected, {}, payload, key.sign(sig_structure(protected, payload))]))


def check_published(
    vectors: dict[str, Any], published: dict[str, tuple[dict[str, Any], bytes]], cwt: dict[int, str]
) -> None:
    """The fixture key gives the published kid, and each checkpoint re-signs to its bytes."""
    key = cll_producer_key()
    kid = key.public_key().public_bytes_raw()
    if kid.hex() != vectors["kid"]:
        raise SystemExit("the 0x07 fixture seed does not give the published kid")
    for cp, (claims, body) in published.items():
        if cll_sign(key, kid, encode(claims), cwt) != body:
            raise SystemExit(f"{cp} does not re-sign to its published bytes")


def repeated_commitment(first_fork: dict[str, Any], c4: bytes, cwt: dict[int, str]) -> bytes:
    """A first checkpoint whose payload writes commitment twice: cp1's, then the fork's."""
    key = cll_producer_key()
    kid = key.public_key().public_bytes_raw()
    fork = first_fork["commitment"]
    pairs = [(k, v) for k, v in first_fork.items() if k != "commitment"]
    pairs += [("commitment", c4), ("commitment", fork)]
    # Python's sort is stable, so the two commitment pairs keep cp1's first.
    payload = encode_pairs(sorted(pairs, key=lambda kv: encode(kv[0])))
    if decode(payload, "last")["commitment"] != fork:
        raise SystemExit("a last-wins reader of the repeated key must read the forked commitment")
    if decode(payload, "first")["commitment"] != c4:
        raise SystemExit("a first-wins reader of the repeated key must read cp1's commitment")
    return cll_sign(key, kid, payload, cwt)


def cll_members() -> list[dict[str, Any]]:
    vectors = cll_vectors()
    cps = {cp["id"]: bytes.fromhex(cp["cose_hex"]) for cp in vectors["checkpoints"]}
    claims = {cp["id"]: cp["claims"] for cp in vectors["checkpoints"]}
    identity = vectors["conventions"]["log_identity"]
    cwt = {1: identity["iss"], 2: identity["sub"]}
    key = cll_producer_key()
    kid = key.public_key().public_bytes_raw()

    def payload_of(cp: str, **over: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in claims[cp].items():
            hexed = k in ("commitment", "prev_commitment", "consistency_proof")
            out[k] = bytes.fromhex(v) if hexed else v
        out.update(over)
        return out

    check_published(vectors, {cp: (payload_of(cp), body) for cp, body in cps.items()}, cwt)
    honest = [sha256(f"cll-02 vector entry {k}".encode()) for k in range(3)]
    c4 = mmr_size4_commitment(honest)
    if c4 != bytes.fromhex(claims["cp1"]["commitment"]):
        raise SystemExit("the size-4 accumulator does not reproduce cp1's commitment")
    fork = mmr_size4_commitment([sha256(f"fork entry {k}".encode()) for k in range(3)])

    def reg(cp: str) -> dict[str, Any]:
        c = claims[cp]
        return {
            "log_size": c["log_size"],
            "commitment": c["commitment"],
            "issued_at": c["issued_at"],
        }

    full = [reg("cp1"), reg("cp2"), reg("cp3"), reg("cp4")]

    def case(
        cose: bytes,
        clock: str,
        history: list[dict[str, Any]],
        *,
        second: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        services = [{"name": "ts1", "history": history}]
        if second is not None:
            services = [{"name": "ts2", "history": history}, {"name": "ts1", "history": second}]
        return {
            "draft": DRAFT_CLL,
            "producerKey": "cll-producer",
            "logIdentity": identity,
            "checkpoint": cose.hex(),
            "registerAt": services[0]["name"],
            "clock": clock,
            "services": services,
            "namedServices": [s["name"] for s in services],
        }

    reissued = cll_sign(key, kid, encode(payload_of("cp3", issued_at="2026-10-13T02:30:00Z")), cwt)
    regressed = cll_sign(key, kid, encode(payload_of("cp3", issued_at="2026-10-13T01:45:00Z")), cwt)
    first_fork = {
        "kind": "cll-checkpoint",
        "log_size": 4,
        "commitment": fork,
        "prev_size": 0,
        "prev_commitment": b"",
        "issued_at": "2026-10-13T00:00:00Z",
        "cadence": 3600,
    }
    forked = cll_sign(key, kid, encode(first_fork), cwt)
    repeated = repeated_commitment(first_fork, c4, cwt)
    other = cll_other_key()
    forged = encode(
        Tag(
            18,
            [
                encode({1: -19, 4: kid, 15: cwt}),
                {},
                encode(payload_of("cp1")),
                other.sign(
                    sig_structure(encode({1: -19, 4: kid, 15: cwt}), encode(payload_of("cp1")))
                ),
            ],
        )
    )
    wrong_kind = cll_sign(key, kid, encode(payload_of("cp1", kind="cll-checkpoint-v1")), cwt)
    no_sub = cll_sign(key, kid, encode(payload_of("cp1")), {1: identity["iss"]})

    not_content = "that any entry's content is true (Section 7)"
    not_only = "that this is the producer's only log, or that every record was appended"
    return [
        cll(
            "cll-cp1-first",
            "the published cp1, registered as the first checkpoint of the log",
            case(cps["cp1"], "2026-10-13T00:00:20Z", []),
            dna=[not_content, not_only],
        ),
        cll(
            "cll-cp2-continuous",
            "the published cp2 after cp1, with its consistency proof",
            case(cps["cp2"], "2026-10-13T01:00:20Z", full[:1]),
            dna=[not_content, not_only],
        ),
        cll(
            "cll-cp3-continuous",
            "the published cp3, no growth since cp2",
            case(cps["cp3"], "2026-10-13T02:00:20Z", full[:2]),
            dna=[not_content, not_only],
        ),
        cll(
            "cll-cp4-on-time",
            "the published cp4 after cp3, registered thirty seconds after its issued_at",
            case(cps["cp4"], "2026-10-13T03:00:30Z", full[:3]),
            dna=[not_content, not_only, "that entries 7 to 20 were appended at their own times"],
        ),
        cll(
            "cll-cp3-reissued",
            "cp3's claims issued again at 02:30, after cp3, with no growth",
            case(reissued, "2026-10-13T02:30:20Z", full[:3]),
            dna=[not_content, not_only],
        ),
        cll(
            "cll-cp1-at-second-service",
            "the published cp1 registered first-seen at ts2, while ts1, also named by the "
            "producer, holds cp1 to cp4",
            case(cps["cp1"], "2026-10-13T00:00:20Z", [], second=full),
            dna=[not_content, not_only],
        ),
        cll(
            "cll-cp4-registered-two-weeks-late",
            "the published cp4, unchanged, registered on 27 October, two weeks after its "
            "issued_at and its declared cadence of 3600 seconds; Sections 4.3 and 4.5 "
            "read neither time",
            case(cps["cp4"], "2026-10-27T03:00:00Z", full[:3]),
            code="registration-late",
            parent="cll-cp4-on-time",
            draft="valid",
            dna=[
                "that entries 7 to 20 were fabricated after 13 October",
                "when the producer actually signed the checkpoint",
            ],
        ),
        cll(
            "cll-issued-at-regression",
            "cp3's claims issued again at 01:45, before cp3's 02:00, registered after cp3",
            case(regressed, "2026-10-13T02:30:20Z", full[:3]),
            code="issued-at-regression",
            parent="cll-cp3-reissued",
            draft="valid",
            dna=["which of the two times the producer's clock really read"],
        ),
        cll(
            "cll-second-history-same-identity",
            "a first checkpoint for the same (iss, sub) over three other entries, "
            "registered first-seen at ts2 while ts1 holds cp1 to cp4; Section 4.5 lets "
            "ts2 start a history and nothing compares the two services",
            case(forked, "2026-10-13T00:00:20Z", [], second=full),
            code="history-fork",
            parent="cll-cp1-at-second-service",
            draft="valid",
            dna=[
                "which of the two histories is the true one",
                "that either service colluded with the producer",
            ],
        ),
        cll(
            "cll-commitment-key-repeated",
            "a first checkpoint whose payload map writes commitment twice, cp1's then a "
            "forked one; a last-wins decoder reads the fork, a first-wins decoder reads "
            "cp1, and each reading passes Section 4.3",
            case(repeated, "2026-10-13T00:00:20Z", []),
            code="cbor-not-deterministic",
            parent="cll-cp1-first",
            draft="valid",
            dna=["which of the two commitments the producer meant"],
        ),
        cll(
            "cll-signed-by-other-key",
            "cp1's claims and header, signed by another Ed25519 key",
            case(forged, "2026-10-13T00:00:20Z", []),
            code="signature-invalid",
            parent="cll-cp1-first",
            draft="invalid",
            dna=["who did sign the checkpoint"],
        ),
        cll(
            "cll-kind-wrong",
            "cp1 with kind cll-checkpoint-v1, which Table 1 does not allow",
            case(wrong_kind, "2026-10-13T00:00:20Z", []),
            code="claims-malformed",
            parent="cll-cp1-first",
            draft="malformed",
            dna=["that the log's history is wrong"],
        ),
        cll(
            "cll-not-continuous",
            "the published cp4 at a service whose last registration is cp1",
            case(cps["cp4"], "2026-10-13T03:00:30Z", full[:1]),
            code="not-continuous",
            parent="cll-cp4-on-time",
            draft="invalid",
            dna=["which checkpoints the service missed"],
        ),
        cll(
            "cll-sub-missing",
            "cp1 signed under CWT Claims with iss and no sub, the log name Section 4.5 needs",
            case(no_sub, "2026-10-13T00:00:20Z", []),
            code="cose-malformed",
            parent="cll-cp1-first",
            draft="malformed",
            dna=["which log the checkpoint belongs to"],
        ),
    ]


def cll(
    slug: str,
    row: str,
    case: dict[str, Any],
    *,
    dna: list[str],
    code: str | None = None,
    parent: str | None = None,
    draft: str = "valid",
) -> dict[str, Any]:
    out = member(slug, row, DRAFT_CLL, case, dna=dna, code=code, parent=parent, draft=draft)
    out["referenceVerifier"] = REFERENCE_VERIFIER[slug]
    return out


# What the draft's reference verifier, cll02.py at CLL_REFERENCE_COMMIT, returns
# for each case: parse_and_verify_signature then check_claims (Section 4.3) and
# registration_continuity (Section 4.5) against the service the case registers
# at. reference_run.py re-derives every row from a clone and fails on any
# difference, so this table is a record of a run, not a claim about one.
REFERENCE_VERIFIER: dict[str, dict[str, str]] = {
    "cll-cp1-first": {"checkClaims": "pass", "registration": "first-seen"},
    "cll-cp2-continuous": {"checkClaims": "pass", "registration": "continuous"},
    "cll-cp3-continuous": {"checkClaims": "pass", "registration": "continuous"},
    "cll-cp4-on-time": {"checkClaims": "pass", "registration": "continuous"},
    "cll-cp3-reissued": {"checkClaims": "pass", "registration": "continuous"},
    "cll-cp1-at-second-service": {"checkClaims": "pass", "registration": "first-seen"},
    "cll-cp4-registered-two-weeks-late": {"checkClaims": "pass", "registration": "continuous"},
    "cll-issued-at-regression": {"checkClaims": "pass", "registration": "continuous"},
    "cll-second-history-same-identity": {"checkClaims": "pass", "registration": "first-seen"},
    "cll-commitment-key-repeated": {"checkClaims": "cbor-not-deterministic", "registration": ""},
    "cll-signed-by-other-key": {"checkClaims": "signature-invalid", "registration": ""},
    "cll-kind-wrong": {"checkClaims": "kind", "registration": ""},
    "cll-not-continuous": {"checkClaims": "pass", "registration": "not-continuous"},
    "cll-sub-missing": {"checkClaims": "log-identity-missing", "registration": ""},
}


# ---------------------------------------------------------------- statement identification


def sid_members() -> list[dict[str, Any]]:
    if sha256_hex(SID_S01) != SID_S01_SHA256:
        raise SystemExit("statement 01 does not carry the SHA-256 Appendix A prints")
    issuer, auditor = sid_issuer_key(), sid_auditor_key()
    tag = decode(SID_S01, "strict")
    protected, _, payload, _ = tag.value
    if sha256_hex(sig_structure(protected, payload)) != SID_REFERENCE:
        raise SystemExit("statement 01's ToBeSigned is not the reference Appendix A prints")
    header = decode(protected, "strict")
    reordered = encode_pairs([(15, header[15]), (4, header[4]), (3, header[3]), (1, header[1])])
    if decode(reordered, "last") != header or reordered == protected:
        raise SystemExit("the reordered header must decode equal and differ in bytes")

    def signed(key: Ed25519PrivateKey, prot: bytes, body: bytes) -> bytes:
        return encode(Tag(18, [prot, {}, body, key.sign(sig_structure(prot, body))]))

    s01r = signed(issuer, reordered, payload)
    other_payload = payload.replace(b'"license":"MIT"', b'"license":"Apache-2.0"', 1)
    if other_payload == payload:
        raise SystemExit("the payload edit did not apply")
    s01_other = signed(issuer, protected, other_payload)
    s01_forged = encode(
        Tag(18, [protected, {}, payload, auditor.sign(sig_structure(protected, payload))])
    )
    repeated = encode_pairs(
        [(1, header[1]), (3, header[3]), (3, header[3]), (4, header[4]), (15, header[15])]
    )
    s01_repeated = signed(issuer, repeated, payload)

    def case(candidate: bytes) -> dict[str, Any]:
        return {
            "draft": DRAFT_SID,
            "issuerKey": "sid-issuer",
            "reference": {"triple": [-16, "ToBeSigned", SID_REFERENCE]},
            "candidate": candidate.hex(),
        }

    not_truth = "that the payload is true, that the issuer is trusted, or that it was registered"
    return [
        sid(
            "sid-statement-01",
            "statement 01 of Appendix A as printed, against the reference statement 02 carries",
            case(SID_S01),
            dna=[not_truth, "that no newer statement corrects it"],
        ),
        sid(
            "sid-header-keys-reordered",
            "statement 01 re-signed by its own issuer seed, the decoded protected header and "
            "payload unchanged, the header keys written 15, 4, 3, 1; the draft's ToBeSigned "
            "rule reports NO_MATCH with a valid signature",
            case(s01r),
            parent="sid-statement-01",
            draft="invalid",
            readings=[
                {
                    "verdict": "valid",
                    "rationale": "the identifier is computed over the deterministic encoding "
                    "of the protected header, so it stays stable across equivalent encodings "
                    "and this candidate is statement 01",
                },
                {
                    "verdict": "malformed",
                    "rationale": "the scheme defines a canonical encoding and requires it, so a "
                    "protected header not in RFC 8949 Section 4.2.1 form is refused",
                },
            ],
            dna=[not_truth, "that the issuer re-encoded the header to evade the reference"],
        ),
        sid(
            "sid-different-payload",
            "statement 01's protected header over a payload whose license is Apache-2.0, "
            "signed by the issuer: a different statement",
            case(s01_other),
            code="reference-mismatch",
            parent="sid-statement-01",
            draft="invalid",
            dna=["which of the two payloads the issuer stands behind"],
        ),
        sid(
            "sid-signature-other-key",
            "statement 01's ToBeSigned signed with the auditor seed in place of the issuer's",
            case(s01_forged),
            code="signature-invalid",
            parent="sid-statement-01",
            draft="invalid",
            dna=["that the candidate's content differs from statement 01"],
        ),
        sid(
            "sid-protected-header-key-repeated",
            "statement 01's protected header with label 3 written twice, signed by the issuer; "
            "Section 6 refuses a map with two equal keys",
            case(s01_repeated),
            code="cbor-duplicate-key",
            parent="sid-statement-01",
            draft="malformed",
            dna=["that either content type is wrong"],
        ),
    ]


def sid(
    slug: str,
    row: str,
    case: dict[str, Any],
    *,
    dna: list[str],
    code: str | None = None,
    parent: str | None = None,
    draft: str = "valid",
    readings: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    out = member(slug, row, DRAFT_SID, case, dna=dna, code=code, parent=parent, draft=draft)
    if readings is not None:
        out["readings"] = readings
    return out


# ---------------------------------------------------------------- the corpus


def member(
    slug: str,
    row: str,
    draft_name: str,
    case: dict[str, Any],
    *,
    dna: list[str],
    code: str | None,
    parent: str | None,
    draft: str,
) -> dict[str, Any]:
    return {
        "slug": slug,
        "row": row,
        "draft": draft_name,
        "case": case,
        "code": code,
        "parent": parent,
        "draftReading": draft,
        "does_not_assert": dna,
    }


def build_members() -> list[dict[str, Any]]:
    return air_members() + cll_members() + sid_members()


def case_bytes(case: dict[str, Any]) -> bytes:
    return json.dumps(case, indent=2, sort_keys=True).encode() + b"\n"


def verdict_for(code: str | None) -> str:
    if code is None:
        return "valid"
    return "malformed" if code in MALFORMED_CODES else "invalid"


def kind_of(m: dict[str, Any]) -> str:
    if "readings" in m:
        return "indeterminate"
    return "accept" if m["code"] is None else "reject"


def identify(members: list[dict[str, Any]]) -> dict[str, str]:
    slugs = [m["slug"] for m in members]
    if len(set(slugs)) != len(slugs):
        raise SystemExit("two members share a slug")
    for m in members:
        m["body"] = case_bytes(m["case"])
        m["id"] = "v" + sha256_hex(m["body"])[:ID_HEX]
    if len({m["id"] for m in members}) != len(members):
        raise SystemExit("two members share an identifier: refused rather than trusted to luck")
    return {m["slug"]: m["id"] for m in members}


def entry_for(m: dict[str, Any], by_slug: dict[str, str]) -> dict[str, Any]:
    (CASES / f"{m['id']}.json").write_bytes(m["body"])
    kind = kind_of(m)
    entry: dict[str, Any] = {
        "id": m["id"],
        "slug": m["slug"],
        "draft": m["draft"],
        "kind": kind,
        "file": f"cases/{m['id']}.json",
        "row": m["row"],
        "draftReading": {"verdict": m["draftReading"]},
        "does_not_assert": m["does_not_assert"],
    }
    if kind == "indeterminate":
        entry["expected"] = {"codes": []}
        entry["readings"] = m["readings"]
    else:
        entry["expected"] = {
            "verdict": verdict_for(m["code"]),
            "codes": [] if m["code"] is None else [m["code"]],
        }
    if m["parent"] is not None:
        entry["parent"] = by_slug[m["parent"]]
    if "referenceVerifier" in m:
        entry["referenceVerifier"] = {
            "source": SOURCES["cllReferenceVerifier"],
            **m["referenceVerifier"],
        }
    return entry


def keys_block() -> dict[str, Any]:
    air_pub = air_operator_key().public_key()
    numbers = air_pub.public_numbers()
    return {
        "air-operator": {
            "alg": "ES256",
            "x": numbers.x.to_bytes(32, "big").hex(),
            "y": numbers.y.to_bytes(32, "big").hex(),
            "recipe": AIR_KEY_RECIPE,
        },
        "cll-producer": {
            "alg": "Ed25519",
            "publicKey": cll_producer_key().public_key().public_bytes_raw().hex(),
            "recipe": "seed 0x07 repeated 32 times, the fixture of the draft's own vectors",
        },
        "sid-issuer": {
            "alg": "Ed25519",
            "publicKey": sid_issuer_key().public_key().public_bytes_raw().hex(),
            "recipe": f"seed {SID_ISSUER_SEED}, the issuer test key of the draft's Appendix A.2",
        },
    }


RULES = {
    DRAFT_AIR: {
        "cose-shape": (
            "COSE_Sign1 under tag 18, alg -7, a kid, and CWT Claims carrying iss and sub "
            "(Section 5.5)"
        ),
        "signature": "the ES256 signature verifies under the operator's registered key",
        "content-hash": "content_hash is SHA-256 over the payload bytes (Section 5.7)",
        "chain-hash": (
            "chain_hash is SHA-256 over the 76 + len(agent_id) byte pre-image of Section 5.7"
        ),
        "sequence": (
            "sequence_number is one more than the preceding record's, or zero first (Section "
            "5.8 step 4)"
        ),
        "header-payload": (
            "the header's action_timestamp_ms and agent_id equal the payload's [corpus]"
        ),
        "prev-chain-link": (
            "prev_chain_hash equals the preceding record's chain_hash, or all zero first [corpus]"
        ),
        "time-order": "action_timestamp_ms is not below the preceding record's [corpus]",
        "position-unique": "no two records claim one (agent_id, sequence_number) [corpus]",
    },
    DRAFT_CLL: {
        "deterministic-encoding": (
            "the checkpoint, its protected header and its payload are core deterministic "
            "CBOR, so no map repeats a key [corpus; Section 4.2 binds only the producer]"
        ),
        "cose-shape": (
            "COSE_Sign1 under tag 18, alg -19, and CWT Claims whose (iss, sub) is the case's "
            "log identity"
        ),
        "signature": "the Ed25519 signature verifies under the producer key",
        "claims": (
            "kind is cll-checkpoint and the required claims carry Table 1's types (Section "
            "4.3 step 2)"
        ),
        "continuity": (
            "prev_size and prev_commitment equal the service's last registration, or the "
            "service holds none and prev_size is 0 (Section 4.5)"
        ),
        "issued-at-order": (
            "issued_at is not earlier than the service's last registered issued_at [corpus]"
        ),
        "registration-time": (
            "the service's clock is within the declared cadence of issued_at [corpus]"
        ),
        "history-fork": (
            "no other named service holds a registration of the same log_size with another "
            "commitment [corpus]"
        ),
    },
    DRAFT_SID: {
        "duplicate-key": "no map in the protected header repeats a key (Section 6)",
        "signature": "the Ed25519 signature verifies under the issuer key",
        "identity": (
            "SHA-256 over ToBeSigned, with the protected header in its deterministic "
            "encoding, equals the reference digest [corpus; the draft hashes the header bytes "
            "as written]"
        ),
    },
}


def manifest_for(entries: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"accept": 0, "indeterminate": 0, "reject": 0}
    per_draft: dict[str, int] = {}
    for entry in entries:
        counts[entry["kind"]] += 1
        per_draft[entry["draft"]] = per_draft.get(entry["draft"], 0) + 1
    return {
        "suite": SUITE,
        "drafts": [DRAFT_AIR, DRAFT_CLL, DRAFT_SID],
        "sources": SOURCES,
        "upstream": {
            "cll-02-vectors.json": {
                "path": "upstream/cll-02-vectors.json",
                "sha256": CLL_VECTORS_SHA256,
                "commit": CLL_REFERENCE_COMMIT,
            }
        },
        "keys": keys_block(),
        "keyNote": (
            "PUBLISHED TEST KEYS. The AIR operator key is derived from the recipe above; the "
            "CLL and statement identification keys are the fixtures the drafts publish."
        ),
        "counts": counts,
        "perDraft": per_draft,
        "rules": RULES,
        "comparisonSurface": {
            "normative": ["verdict"],
            "measured": ["codes"],
            "note": (
                "A verifier conforms on a member when its verdict equals expected.verdict, or, "
                "for an indeterminate member, is one of the verdicts its readings list. The "
                "codes name the reference reader's first refusal; the drafts define none. A rule "
                "marked [corpus] is one the draft's text does not state, and draftReading is the "
                "verdict the draft's own procedure reaches without it: every member where the two "
                "differ is a case the draft's verification steps do not catch."
            ),
        },
        "note": (
            "Each member is one case file: the bytes a verifier reads, as hex, and the state it "
            "reads them against. What the verifier must decide lives here and never beside the "
            "input. does_not_assert lists what the expected verdict does not establish, so a "
            "verdict is never read as more than it is."
        ),
        "vectors": entries,
    }


def index_markdown(manifest: dict[str, Any], order: list[str]) -> str:
    lines = [
        "# IETF agent-record drafts conformance vectors",
        "",
        "Emitted by `gen_vectors.py`. Do not edit: the next build overwrites it.",
        "",
        f"Corpus digest: `{manifest['corpusDigest']}`",
        "",
    ]
    slug_of = {e["id"]: e["slug"] for e in manifest["vectors"]}
    by_slug = {e["slug"]: e for e in manifest["vectors"]}
    for draft in manifest["drafts"]:
        lines += [
            f"## {draft}",
            "",
            "| member | verdict | code | under the draft's own steps | what it carries | parent |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for slug in order:
            entry = by_slug[slug]
            if entry["draft"] != draft:
                continue
            if entry["kind"] == "indeterminate":
                verdict = " or ".join(r["verdict"] for r in entry["readings"])
            else:
                verdict = entry["expected"]["verdict"]
            codes = " ".join(f"`{c}`" for c in entry["expected"]["codes"])
            parent = f"`{slug_of[entry['parent']]}`" if "parent" in entry else ""
            row = entry["row"].replace("|", "\\|")
            lines.append(
                f"| [`{slug}`]({entry['file']}) | {verdict} | {codes} | "
                f"{entry['draftReading']['verdict']} | {row} | {parent} |"
            )
        lines += ["", "| rule | what it requires |", "| --- | --- |"]
        for name, text in manifest["rules"][draft].items():
            lines.append(f"| `{name}` | {text} |")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    members = build_members()
    by_slug = identify(members)
    CASES.mkdir(exist_ok=True)
    for stale in sorted(CASES.glob("*.json")):
        stale.unlink()
    entries = sorted((entry_for(m, by_slug) for m in members), key=lambda entry: entry["id"])
    manifest = manifest_for(entries)
    manifest["corpusDigest"] = corpus_digest(manifest, str(HERE))
    (HERE / "MANIFEST.json").write_bytes(
        json.dumps(manifest, indent=2, ensure_ascii=False).encode() + b"\n"
    )
    order = [m["slug"] for m in members]
    (HERE / "INDEX.md").write_text(index_markdown(manifest, order), encoding="utf-8")
    print(json.dumps(manifest["counts"]), "corpusDigest", manifest["corpusDigest"])


if __name__ == "__main__":
    main()
