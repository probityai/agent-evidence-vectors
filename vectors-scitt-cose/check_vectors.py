#!/usr/bin/env python3
"""Self-check the SCITT/COSE carriage suite.

    uv run --extra generators python vectors-scitt-cose/check_vectors.py
    uv run --extra generators python vectors-scitt-cose/check_vectors.py --json

This is the mutation check the corpus needs to be worth anything, and it asks a
different question from scripts/regenerability-gate.py. That gate asks whether
the committed bytes are the bytes the generator emits. This asks whether those
bytes BEHAVE as the manifest claims: that a member claiming a root divergence
actually diverges, that a member claiming a valid signature actually verifies,
that every reject member carries the specific fault it names and not some other
one, and that every reject condition is also carried by a member that must be
accepted.

The last of those is what makes the suite scoreable at all. A corpus of
refusals gives full marks to a verifier that refuses everything; the accept
twins turn that strategy into a zero.

Nothing here imports the generator. The Merkle verification below is RFC 9162
Section 2.1.3.2 stated a second time, on purpose: a checker that reused the
generator's tree code would produce a corpus and then agree with it, and two
independent statements of the same algorithm is the only arrangement in which
this file can fail.

Exit 0 when every member behaves as its manifest entry claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import cbor2
from pycose.algorithms import CoseAlgorithm, EdDSA
from pycose.keys.okp import OKPKey
from pycose.messages.sign1message import Sign1Message

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES: list[str] = []

LBL_ALG = 1
LBL_CRIT = 2
LBL_KID = 4
LBL_CWT_CLAIMS = 15
LBL_RECEIPTS = 394
LBL_VDS = 395
LBL_VDP = 396
PROOF_INCLUSION = -1
LBL_OBSERVER_POSITION = -70001
CWT_ISS = 1
CWT_SUB = 2
CWT_EXP = 4
CWT_NBF = 5
ALG_ED25519 = -19
ALG_EDDSA_DEPRECATED = -8
VDS_RFC9162_SHA256 = 1
NOW_EPOCH = 1789041600
COSE_SIGN1_TAG = 18


@CoseAlgorithm.register_attribute()
class Ed25519Alg(EdDSA):
    """RFC 9864 Section 4.2.1, value -19. Registered so pycose can read it."""

    identifier = ALG_ED25519
    fullname = "ED25519"


@CoseAlgorithm.register_attribute()
class EdDSADeprecated(EdDSA):
    """RFC 9864 Section 4.2.2, value -8, Recommended: Deprecated."""

    identifier = ALG_EDDSA_DEPRECATED
    fullname = "EDDSA_DEPRECATED"


def fail(vid: str, why: str) -> None:
    FAILURES.append(f"{vid}: {why}")


# ---------------------------------------------------------------------------
# RFC 9162 Section 2.1.
# ---------------------------------------------------------------------------
def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def apply_inclusion_proof(
    entry: bytes, tree_size: int, leaf_index: int, path: list[bytes]
) -> bytes | None:
    """RFC 9162 Section 2.1.3.2, step for step.

    Returns the recomputed root, or None where the proof cannot be applied.
    Step 1 is the bound RFC 9942 Section 5.2 quotes as a normative block: "If
    leaf_index is greater than or equal to tree_size, then fail the proof
    verification."

    Written out step by step rather than compressed. A shorter form that walked
    the path testing only the parity of the index was wrong for six of the
    forty-five (tree_size, leaf_index) pairs below ten, all on the right edge of
    a tree whose size is not a power of two, and every one of them failed
    CLOSED. A checker that only ever refuses looks correct against a corpus of
    rejections, and the accept half is this file's whole job.
    """
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return None
    fn, sn = leaf_index, tree_size - 1
    node = leaf_hash(entry)
    for sibling in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            node = hashlib.sha256(b"\x01" + sibling + node).digest()
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node = hashlib.sha256(b"\x01" + node + sibling).digest()
        fn >>= 1
        sn >>= 1
    return node if sn == 0 else None


# ---------------------------------------------------------------------------
# Reading a vector.
# ---------------------------------------------------------------------------
def decode_sign1(raw: bytes) -> tuple[dict[Any, Any], dict[Any, Any], Any, bytes]:
    """Protected map, unprotected map, payload and signature, from the bytes."""
    tagged = cbor2.loads(raw)
    if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != COSE_SIGN1_TAG:
        raise ValueError("not a tagged COSE_Sign1")
    body = list(tagged.value)
    protected = cbor2.loads(body[0]) if body[0] else {}
    return protected, dict(body[1]), body[2], body[3]


def deterministic_map_order(encoded_map: bytes) -> bool:
    """RFC 8949 Section 4.2.1: map keys sorted bytewise, each occurring once."""
    decoded = cbor2.loads(encoded_map)
    if not isinstance(decoded, dict):
        return False
    keys = [cbor2.dumps(key) for key in decoded]
    return keys == sorted(keys) and len(set(keys)) == len(keys)


def okp_key(spec: dict[str, str]) -> OKPKey:
    return OKPKey(crv="ED25519", x=bytes.fromhex(spec["x"]))


def verify_sign1(raw: bytes, key: OKPKey, detached_payload: bytes | None) -> bool:
    """True when the COSE_Sign1 signature verifies under `key`.

    A detached payload is reattached first, because RFC 9052 Section 4.4 field 5
    puts "the full payload ... independent of how it is transported" into the
    Sig_structure. A verifier that checked the encoded nil would verify nothing.
    """
    tagged = cbor2.loads(raw)
    body = list(tagged.value)
    if body[2] is None:
        if detached_payload is None:
            return False
        body[2] = detached_payload
    try:
        message = Sign1Message.decode(cbor2.dumps(cbor2.CBORTag(tagged.tag, body)))
        message.key = key
        # `decode` is annotated to return the TypeVar bound to CoseMessage, and
        # pycose additionally types Sign1Message itself as type[CoseMessage]
        # because `@CoseMessage.record_cbor_tag(18)` wraps it in an unannotated
        # decorator whose body narrows to the base. `verify_signature` is
        # defined on SignCommon and is what the runtime object carries; the
        # isinstance check inside `decode` already refuses anything else.
        return bool(message.verify_signature())  # pyright: ignore[reportAttributeAccessIssue]
    except Exception:  # noqa: BLE001 -- see below
        # Every way this can raise is a way the signature did not verify, and a
        # verifier that crashed accepted nothing. The one that actually fires is
        # the algorithm-confusion member: the header declares ECDSA, pycose
        # selects the ECDSA verifier, and that verifier reaches for a coordinate
        # an Ed25519 key does not have. A rail that let the exception escape
        # would report a corpus fault where the corpus measures the exact fault
        # it named.
        return False


def signature_is_ed25519(raw: bytes, key: OKPKey, detached: bytes | None) -> bool:
    """The signature verifies as Ed25519 whatever the header declares.

    The measurement that makes the algorithm-confusion member real: the bytes
    ARE a good Ed25519 signature and the protected header names a different
    algorithm, so a verifier dispatching on the key type accepts and one
    dispatching on the declared identifier refuses.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    body = list(cbor2.loads(raw).value)
    payload = body[2] if body[2] is not None else detached
    if payload is None:
        return False
    tbs = cbor2.dumps(["Signature1", body[0], b"", payload])
    try:
        Ed25519PublicKey.from_public_bytes(key.x).verify(body[3], tbs)
    except InvalidSignature:
        return False
    return True


def signed_statement_bytes(transparent: bytes) -> bytes:
    """The registered entry: this object with label 394 removed.

    RFC 9943 Section 7 builds a Transparent Statement by ADDING the receipt to
    the unprotected header of a Signed Statement, so the entry a receipt proves
    inclusion of is what is left when the receipt is taken back out. Receipts
    live in the unprotected bucket, so removing them changes no signed byte.
    """
    tagged = cbor2.loads(transparent)
    body = list(tagged.value)
    body[1] = {k: v for k, v in dict(body[1]).items() if k != LBL_RECEIPTS}
    return cbor2.dumps(cbor2.CBORTag(tagged.tag, body))


def receipt_root(receipt_raw: bytes, entry: bytes) -> tuple[bytes | None, str]:
    """The root a verifier recomputes from this receipt over this entry."""
    _protected, uhdr, _payload, _sig = decode_sign1(receipt_raw)
    if LBL_VDP not in uhdr:
        return None, "no-vdp"
    proofs = uhdr[LBL_VDP]
    if PROOF_INCLUSION not in proofs:
        return None, "no-inclusion-proof-type"
    tree_size, leaf_index, path = cbor2.loads(proofs[PROOF_INCLUSION][0])
    root = apply_inclusion_proof(entry, tree_size, leaf_index, list(path))
    return (None, "proof-unapplicable") if root is None else (root, "applied")


# ---------------------------------------------------------------------------
# One vector, read once, handed to whichever checks apply to its kind.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Read:
    """Everything the checks below need, derived once from the bytes on disk."""

    vid: str
    protected: dict[Any, Any]
    uhdr: dict[Any, Any]
    receipts: list[bytes]
    entry_bytes: bytes
    payload: bytes | None
    detached: bytes | None
    raw: bytes
    trust: dict[str, Any]
    issuer: dict[str, Any]
    issuer_key: OKPKey
    signature_ok: bool

    @property
    def cwt(self) -> dict[Any, Any] | None:
        claims = self.protected.get(LBL_CWT_CLAIMS)
        return claims if isinstance(claims, dict) else None

    @property
    def declared_alg(self) -> Any:
        return self.protected.get(LBL_ALG)

    @property
    def crit(self) -> list[Any]:
        listed = self.protected.get(LBL_CRIT)
        return list(listed) if isinstance(listed, list) else []

    def subject_from_payload(self) -> str | None:
        if self.payload is None:
            return None
        statement = json.loads(self.payload)
        return "sha256:" + statement["subject"][0]["digest"]["sha256"]

    def trust_key_for(self, receipt_raw: bytes) -> OKPKey | None:
        protected, _u, _p, _s = decode_sign1(receipt_raw)
        kid = protected.get(LBL_KID)
        for candidate in self.trust["transparencyServices"]:
            if bytes.fromhex(candidate["kid"]) == kid:
                return okp_key(candidate["key"])
        return None

    def receipt_headers(self) -> list[dict[Any, Any]]:
        return [decode_sign1(receipt)[0] for receipt in self.receipts]

    def receipt_unprotected(self) -> list[dict[Any, Any]]:
        return [decode_sign1(receipt)[1] for receipt in self.receipts]


def read_vector(entry: dict[str, Any], vector: dict[str, Any]) -> Read | None:
    raw = bytes.fromhex(vector["transparentStatement"])
    detached = (
        bytes.fromhex(vector["detachedPayload"])
        if vector["detachedPayload"] is not None
        else None
    )
    try:
        protected, uhdr, payload, _sig = decode_sign1(raw)
    except (ValueError, cbor2.CBORDecodeError) as exc:
        fail(entry["id"], f"the statement bytes do not decode as a COSE_Sign1: {exc}")
        return None
    if LBL_RECEIPTS not in uhdr:
        fail(
            entry["id"],
            "no receipts in the unprotected header, so it is not a Transparent "
            "Statement at all",
        )
        return None
    issuer = vector["trust"]["issuers"][0]
    issuer_key = okp_key(issuer["key"])
    return Read(
        vid=entry["id"],
        protected=protected,
        uhdr=uhdr,
        receipts=list(uhdr[LBL_RECEIPTS]),
        entry_bytes=signed_statement_bytes(raw),
        payload=detached if payload is None else payload,
        detached=detached,
        raw=raw,
        trust=vector["trust"],
        issuer=issuer,
        issuer_key=issuer_key,
        signature_ok=verify_sign1(raw, issuer_key, detached),
    )


# ---------------------------------------------------------------------------
# The three kinds.
# ---------------------------------------------------------------------------
def check_encoding(read: Read) -> None:
    encoded_protected = list(cbor2.loads(read.raw).value)[0]
    if not deterministic_map_order(encoded_protected):
        fail(
            read.vid,
            "the protected header is not in RFC 8949 Section 4.2.1 map order, so "
            "two conforming encoders would disagree about the signed bytes",
        )


def check_accept(read: Read) -> None:
    if not read.signature_ok:
        fail(read.vid, "an accept member's issuer signature does not verify")
    if read.declared_alg != ALG_ED25519:
        fail(
            read.vid,
            f"an accept member declares alg {read.declared_alg}, and this profile "
            f"pins {ALG_ED25519}, the fully-specified Ed25519 of RFC 9864 "
            "Section 4.2.1",
        )
    check_accept_claims(read)
    check_accept_observer(read)
    check_accept_receipts(read)


def check_accept_claims(read: Read) -> None:
    cwt = read.cwt
    if cwt is None or CWT_ISS not in cwt or CWT_SUB not in cwt:
        fail(
            read.vid,
            "an accept member's protected CWT Claims lack iss or sub, which "
            "RFC 9943 Section 6 makes a MUST",
        )
        return
    if cwt[CWT_ISS] != read.issuer["iss"]:
        fail(
            read.vid,
            "an accept member's iss is not the identity the trust inputs bind to "
            "the verification key",
        )
    want = read.subject_from_payload()
    if want is not None and cwt[CWT_SUB] != want:
        fail(
            read.vid,
            "an accept member's sub is not the digest its in-toto subject carries",
        )


def check_accept_observer(read: Read) -> None:
    if read.crit != [LBL_OBSERVER_POSITION]:
        fail(
            read.vid,
            f"an accept member's crit is {read.crit!r}; this profile requires "
            f"exactly [{LBL_OBSERVER_POSITION}], the observer position, so a "
            "verifier that does not implement the profile refuses instead of "
            "ignoring it",
        )
    if LBL_OBSERVER_POSITION not in read.protected:
        fail(
            read.vid,
            "an accept member carries no observer position in the protected bucket",
        )


def check_accept_receipts(read: Read) -> None:
    verified_one = False
    for receipt_raw in read.receipts:
        root, status = receipt_root(receipt_raw, read.entry_bytes)
        if root is None:
            fail(read.vid, f"an accept member's receipt yields no root ({status})")
            continue
        ts_key = read.trust_key_for(receipt_raw)
        if ts_key is None:
            fail(
                read.vid,
                "an accept member's receipt names a kid no trust input carries",
            )
            continue
        if verify_sign1(receipt_raw, ts_key, root):
            verified_one = True
        else:
            fail(
                read.vid,
                "an accept member's receipt does not verify over the root "
                "recomputed from its own inclusion proof",
            )
    if not verified_one:
        fail(read.vid, "no receipt on an accept member verified")


def check_reject(read: Read, expected: dict[str, Any]) -> None:
    codes = list(expected.get("codes", []))
    if not codes:
        fail(read.vid, "a reject member declares no code, so nothing says which "
                       "fault it carries")
        return
    unknown = [code for code in codes if code not in WITNESSES]
    if unknown:
        fail(
            read.vid,
            f"{unknown} name faults this checker cannot measure. A declared code "
            "with no witness is a claim nothing tests, which is the shape of "
            "every silent pass this file exists to prevent.",
        )
        return
    if not all(WITNESSES[code](read) for code in codes):
        fail(
            read.vid,
            f"the fault {sorted(codes)} this member declares is not present in "
            "its bytes. A reject vector that is not actually faulty measures "
            "nothing and passes any verifier that refuses on some other ground.",
        )


def check_indeterminate(read: Read, expected: dict[str, Any]) -> None:
    readings = expected.get("readings", {})
    if "verdict" in expected:
        fail(
            read.vid,
            "an indeterminate member pins expected.verdict beside readings, so a "
            "scorer reading that field marks a listed reading wrong. Its readings "
            "are what a verifier is scored on, and any one of them conforms.",
        )
    if len(readings) < 2:
        fail(
            read.vid,
            "an indeterminate member declares fewer than two readings. One "
            "reading is a rule, and a member carrying a rule belongs in accept or "
            "reject rather than here.",
        )
    if "valid" not in readings.values():
        fail(
            read.vid,
            "no declared reading accepts this member, so a verifier that refuses "
            "every input is right about it under every reading and the member "
            "measures nothing.",
        )
    if not read.signature_ok:
        fail(
            read.vid,
            "an indeterminate member's issuer signature does not verify, so the "
            "disagreement it records is about a broken object rather than about "
            "an open question",
        )


# ---------------------------------------------------------------------------
# One witness per declared code. Each MEASURES the fault in the bytes.
#
# A table and not a chain of branches, for a reason this repository has paid
# for elsewhere: a branch that stops matching falls through silently and the
# member it was meant to test is then checked by nothing, while the run still
# reports OK. A missing key here is a named failure instead, raised by
# check_reject above before any measurement runs.
# ---------------------------------------------------------------------------
def _subject_digest_mismatch(read: Read) -> bool:
    cwt = read.cwt
    want = read.subject_from_payload()
    return (
        cwt is not None
        and want is not None
        and cwt.get(CWT_SUB) != want
        and read.signature_ok
    )


def _inclusion_proof_absent(read: Read) -> bool:
    return all(LBL_VDP not in uhdr for uhdr in read.receipt_unprotected())


def _receipt_subject_mismatch(read: Read) -> bool:
    if not read.signature_ok:
        return False
    for receipt_raw in read.receipts:
        root, _status = receipt_root(receipt_raw, read.entry_bytes)
        ts_key = read.trust_key_for(receipt_raw)
        if root is not None and ts_key is not None and verify_sign1(
            receipt_raw, ts_key, root
        ):
            return False
    return True


def _critical_parameter_unprotected(read: Read) -> bool:
    return any(label not in read.protected for label in read.crit)


def _critical_parameter_unprocessable(read: Read) -> bool:
    return any(
        label in read.protected and label != LBL_OBSERVER_POSITION
        for label in read.crit
    )


def _observer_position_not_critical(read: Read) -> bool:
    return (
        LBL_OBSERVER_POSITION in read.protected
        and LBL_OBSERVER_POSITION not in read.crit
    )


def _algorithm_mismatch(read: Read) -> bool:
    declared = read.declared_alg
    return declared not in (
        ALG_ED25519,
        ALG_EDDSA_DEPRECATED,
    ) and signature_is_ed25519(read.raw, read.issuer_key, read.detached)


def _algorithm_deprecated(read: Read) -> bool:
    return read.declared_alg == ALG_EDDSA_DEPRECATED and read.signature_ok


def _receipt_algorithm_mismatch(read: Read) -> bool:
    return any(
        header.get(LBL_ALG) not in (ALG_ED25519, ALG_EDDSA_DEPRECATED)
        for header in read.receipt_headers()
    )


def _statement_expired(read: Read) -> bool:
    cwt = read.cwt
    return cwt is not None and CWT_EXP in cwt and cwt[CWT_EXP] < NOW_EPOCH


def _statement_not_yet_valid(read: Read) -> bool:
    cwt = read.cwt
    return cwt is not None and CWT_NBF in cwt and cwt[CWT_NBF] > NOW_EPOCH


def _issuer_identity_mismatch(read: Read) -> bool:
    cwt = read.cwt
    return (
        cwt is not None
        and cwt.get(CWT_ISS) != read.issuer["iss"]
        and read.signature_ok
    )


def _cwt_claims_absent(read: Read) -> bool:
    return LBL_CWT_CLAIMS not in read.protected


def _cwt_claims_duplicated(read: Read) -> bool:
    return LBL_CWT_CLAIMS in read.protected and LBL_CWT_CLAIMS in read.uhdr


def _receipt_vds_absent(read: Read) -> bool:
    return all(LBL_VDS not in header for header in read.receipt_headers())


def _receipt_vds_unregistered(read: Read) -> bool:
    return all(
        header.get(LBL_VDS) != VDS_RFC9162_SHA256 for header in read.receipt_headers()
    )


def _inclusion_proof_unapplicable(read: Read) -> bool:
    return all(
        receipt_root(receipt, read.entry_bytes)[0] is None for receipt in read.receipts
    )


WITNESSES: dict[str, Callable[[Read], bool]] = {
    "subject-digest-mismatch": _subject_digest_mismatch,
    "inclusion-proof-absent": _inclusion_proof_absent,
    "receipt-subject-mismatch": _receipt_subject_mismatch,
    "critical-parameter-unprotected": _critical_parameter_unprotected,
    "critical-parameter-unprocessable": _critical_parameter_unprocessable,
    "observer-position-not-critical": _observer_position_not_critical,
    "algorithm-mismatch": _algorithm_mismatch,
    "algorithm-deprecated": _algorithm_deprecated,
    "receipt-algorithm-mismatch": _receipt_algorithm_mismatch,
    "statement-expired": _statement_expired,
    "statement-not-yet-valid": _statement_not_yet_valid,
    "issuer-identity-mismatch": _issuer_identity_mismatch,
    "cwt-claims-absent": _cwt_claims_absent,
    "cwt-claims-duplicated": _cwt_claims_duplicated,
    "receipt-vds-absent": _receipt_vds_absent,
    "receipt-vds-unregistered": _receipt_vds_unregistered,
    "inclusion-proof-unapplicable": _inclusion_proof_unapplicable,
}


# ---------------------------------------------------------------------------
# Corpus-level checks.
# ---------------------------------------------------------------------------
def check_files(manifest: dict[str, Any]) -> None:
    on_disk = [
        name
        for name in os.listdir(os.path.join(HERE, "statements"))
        if name.endswith(".json")
    ]
    if len(on_disk) != len(manifest["vectors"]):
        FAILURES.append(
            f"the manifest carries {len(manifest['vectors'])} entr(ies) and "
            f"statements/ holds {len(on_disk)} file(s). A file with no entry is a "
            "vector no replay reaches, and an entry with no file is a claim about "
            "bytes that are not here."
        )


def check_twins(manifest: dict[str, Any]) -> None:
    """Every reject condition is carried by an accept member too.

    Scoped to reject deliberately. An indeterminate condition names a question
    the cited documents do not answer, so there is no conforming member that
    exercises it correctly and an accept twin would be this corpus inventing the
    rule it exists to report missing. Those members are protected instead by the
    accepting-reading rule in check_indeterminate.
    """
    buckets: dict[str, set[str]] = {"accept": set(), "reject": set(), "indeterminate": set()}
    for entry in manifest["vectors"]:
        buckets[entry["kind"]].update(entry["conditions"])
    unanchored = sorted(buckets["reject"] - buckets["accept"])
    if unanchored:
        FAILURES.append(
            f"{unanchored} are cited only by members that must be refused. A "
            "verifier that refuses every input scores full marks on those "
            "conditions, which is the failure mode the accept twins exist to "
            "remove."
        )
    settled = buckets["accept"] | buckets["reject"]
    overlap = sorted(buckets["indeterminate"] & settled)
    if overlap:
        FAILURES.append(
            f"{overlap} are cited by an indeterminate member and by a member that "
            "carries a verdict. A condition is either settled by the documents or "
            "it is not, and one that is both says the corpus disagrees with "
            "itself about which."
        )
    check_condition_table(manifest, settled | buckets["indeterminate"])


def check_condition_table(manifest: dict[str, Any], cited: set[str]) -> None:
    declared = set(manifest["conditions"])
    if cited - declared:
        FAILURES.append(
            f"{sorted(cited - declared)} are cited by a vector and have no row in "
            "the manifest's condition table, so nothing says what they mean."
        )
    if declared - cited:
        FAILURES.append(
            f"{sorted(declared - cited)} have a row and no vector cites them, so "
            "the table promises coverage the corpus does not carry."
        )


def check_parents(manifest: dict[str, Any]) -> None:
    by_id = {entry["id"]: entry for entry in manifest["vectors"]}
    for entry in manifest["vectors"]:
        if entry["kind"] != "reject":
            continue
        parent = entry.get("parent")
        if parent is None:
            FAILURES.append(
                f"{entry['id']}: no parent, so nothing says which conforming "
                "member this is one mutation from."
            )
        elif parent not in by_id or by_id[parent]["kind"] != "accept":
            FAILURES.append(
                f"{entry['id']}: parent {parent} is not an accept member of this "
                "corpus."
            )


def corpus_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"".join(
            open(os.path.join(HERE, entry["file"]), "rb").read()
            for entry in sorted(manifest["vectors"], key=lambda e: e["id"])
        )
    ).hexdigest()


def check_totals(manifest: dict[str, Any]) -> dict[str, int]:
    counts = {
        kind: sum(1 for entry in manifest["vectors"] if entry["kind"] == kind)
        for kind in ("accept", "reject", "indeterminate")
    }
    if counts != manifest["counts"]:
        FAILURES.append(
            f"counts disagree: manifest {manifest['counts']}, measured {counts}"
        )
    digest = corpus_digest(manifest)
    if digest != manifest["corpusDigest"]:
        FAILURES.append(
            f"the corpus digests to {digest[:12]} and the manifest pins "
            f"{manifest['corpusDigest'][:12]}."
        )
    return counts


def check_member(entry: dict[str, Any]) -> None:
    path = os.path.join(HERE, entry["file"])
    if not os.path.exists(path):
        FAILURES.append(f"{entry['id']}: {entry['file']} is missing")
        return
    with open(path, "rb") as fh:
        body = fh.read()
    want = "v" + hashlib.sha256(body).hexdigest()[:16]
    if want != entry["id"]:
        FAILURES.append(
            f"{entry['id']}: the file digests to {want}. An identifier that is "
            "not a function of the bytes stops being an identifier the moment the "
            "bytes move."
        )
    read = read_vector(entry, json.loads(body))
    if read is None:
        return
    check_encoding(read)
    if entry["kind"] == "accept":
        check_accept(read)
    elif entry["kind"] == "reject":
        check_reject(read, entry["expected"])
    else:
        check_indeterminate(read, entry["expected"])


def member_result(entry: dict[str, Any], start: int) -> dict[str, Any]:
    """One member as the corpus readers report it: id, kind, and its findings.

    A finding is attributed to the member whose check raised it, and the
    "<id>: " prefix this script prints is taken off, so the object has the
    shape ``aee-verify -json <corpus>`` prints for every other corpus.
    """
    prefix = f"{entry['id']}: "
    findings = [f[len(prefix):] if f.startswith(prefix) else f for f in FAILURES[start:]]
    member: dict[str, Any] = {"id": entry["id"], "kind": entry["kind"]}
    if findings:
        member["findings"] = findings
    return member


def main() -> None:
    as_json = sys.argv[1:] == ["--json"]
    if sys.argv[1:] and not as_json:
        print("usage: check_vectors.py [--json]", file=sys.stderr)
        sys.exit(2)
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)

    check_files(manifest)
    corpus_findings = list(FAILURES)
    members = []
    for entry in manifest["vectors"]:
        start = len(FAILURES)
        check_member(entry)
        members.append(member_result(entry, start))
    tail = len(FAILURES)
    check_twins(manifest)
    check_parents(manifest)
    counts = check_totals(manifest)
    corpus_findings += FAILURES[tail:]

    if as_json:
        # One line, the shape aee-verify -json prints for a corpus, so a
        # conformance record can carry it as the native per-case output.
        result: dict[str, Any] = {
            "suite": manifest["suite"], "dir": "vectors-scitt-cose", "members": members,
        }
        if corpus_findings:
            result["findings"] = corpus_findings
        print(json.dumps(result, separators=(",", ":")))
        sys.exit(1 if FAILURES else 0)
    if FAILURES:
        for failure in FAILURES:
            print("FAIL", failure)
        sys.exit(1)
    print(
        f"OK {counts['accept']} accept, {counts['reject']} reject, "
        f"{counts['indeterminate']} indeterminate, "
        f"{len(manifest['conditions'])} conditions, "
        f"corpus {corpus_digest(manifest)[:12]}"
    )


if __name__ == "__main__":
    main()
