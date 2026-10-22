#!/usr/bin/env python3
"""Does the committed corpus behave as MANIFEST.json claims, and is every rule
of the reference reader load-bearing?

    uv run --extra generators python vectors-ietf-agent-record-drafts/check_vectors.py

The checks below can each fail on their own:

- Every member reaches its declared verdict and first refusal code (an
  indeterminate member reaches one of the verdicts its readings list), every
  reject and indeterminate member names an accept parent, the counts hold,
  and the corpus digest holds.
- The draft reading: with every rule this corpus adds switched off, and the
  draft's own procedure in its place (lenient CBOR for the checkpointed local
  log, header bytes as written for statement identification), the reader
  reaches each member's recorded draftReading. That is what makes "the draft's
  steps do not catch this" a measured claim.
- A second CBOR path: every CBOR item in every case is decoded again with
  cbor2, a library this directory did not write, and must agree with
  `cbor_det`; the repeated-key checkpoint must read as the forked commitment
  under cbor2, the last-wins behaviour the member is built against.
- The rule sweep: disabling any one rule must turn at least one reject member
  into a non-refusal, and must never refuse an accept member.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cbor_det import (  # noqa: E402
    Malformed,
    NotDeterministic,
    Tag,
    decode,
    encode,
    has_repeated_key,
)
from digest import corpus_digest  # noqa: E402

DRAFT_AIR = "draft-emirdag-scitt-ai-agent-execution-01"
DRAFT_CLL = "draft-mih-scitt-checkpointed-local-log-02"
DRAFT_SID = "draft-gruszka-scitt-statement-identification-02"
CORPUS_RULES = {
    DRAFT_AIR: ("header-payload", "prev-chain-link", "time-order", "position-unique"),
    DRAFT_CLL: ("deterministic-encoding", "issued-at-order", "registration-time", "history-fork"),
    DRAFT_SID: ("identity-canonical",),
}
RULES = {
    DRAFT_AIR: (
        "cose-shape",
        "signature",
        "content-hash",
        "chain-hash",
        "sequence",
        "header-payload",
        "prev-chain-link",
        "time-order",
        "position-unique",
    ),
    DRAFT_CLL: (
        "deterministic-encoding",
        "cose-shape",
        "signature",
        "claims",
        "continuity",
        "issued-at-order",
        "registration-time",
        "history-fork",
    ),
    DRAFT_SID: ("duplicate-key", "signature", "identity"),
}
MALFORMED_CODES = frozenset(
    {"cose-malformed", "claims-malformed", "cbor-not-deterministic", "cbor-duplicate-key"}
)


@dataclass
class Report:
    verdict: str = "valid"
    codes: list[str] = field(default_factory=list)


class Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
        self.verdict = "malformed" if code in MALFORMED_CODES else "invalid"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    return encode(["Signature1", protected, b"", payload])


def cose_parts(raw: bytes, policy: str, *, tag_required: bool = True) -> list[Any]:
    try:
        item = decode(raw, policy)
    except NotDeterministic as exc:
        raise Refused("cbor-not-deterministic") from exc
    except Malformed as exc:
        raise Refused("cose-malformed") from exc
    if isinstance(item, Tag):
        if item.number != 18:
            raise Refused("cose-malformed")
        item = item.value
    elif tag_required:
        raise Refused("cose-malformed")
    if not (isinstance(item, list) and len(item) == 4):
        raise Refused("cose-malformed")
    if not (
        isinstance(item[0], bytes) and isinstance(item[2], bytes) and isinstance(item[3], bytes)
    ):
        raise Refused("cose-malformed")
    return item


def header_of(protected: bytes, policy: str) -> dict[Any, Any]:
    try:
        header = decode(protected, policy)
    except NotDeterministic as exc:
        raise Refused("cbor-not-deterministic") from exc
    except Malformed as exc:
        raise Refused("cose-malformed") from exc
    if not isinstance(header, dict):
        raise Refused("cose-malformed")
    return header


# ---------------------------------------------------------------- AIR


def air_key(manifest: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    k = manifest["keys"]["air-operator"]
    numbers = ec.EllipticCurvePublicNumbers(int(k["x"], 16), int(k["y"], 16), ec.SECP256R1())
    return numbers.public_key()


def air_chain_hash(content: bytes, prev: bytes, ts_ms: int, agent: str) -> bytes:
    raw = agent.encode("utf-8")
    return sha256(content + prev + ts_ms.to_bytes(8, "big") + len(raw).to_bytes(4, "big") + raw)


def air_shape(h: dict[Any, Any], off: frozenset[str]) -> None:
    """Section 5.5's header: alg, kid and CWT Claims, then the integrity fields' types."""
    cwt = h.get(15)
    shaped = (
        h.get(1) == -7
        and isinstance(h.get(4), bytes)
        and isinstance(cwt, dict)
        and isinstance(cwt.get(1), str)
        and isinstance(cwt.get(2), str)
    )
    if "cose-shape" not in off and not shaped:
        raise Refused("cose-malformed")
    digests = ("content_hash", "prev_chain_hash", "chain_hash")
    integers = ("sequence_number", "action_timestamp_ms")
    typed = (
        all(isinstance(h.get(f), bytes) and len(h[f]) == 32 for f in digests)
        and all(isinstance(h.get(f), int) for f in integers)
        and isinstance(h.get("agent_id"), str)
    )
    if not typed:
        raise Refused("cose-malformed")


def air_signature(
    key: ec.EllipticCurvePublicKey, protected: bytes, payload: bytes, signature: bytes
) -> None:
    if len(signature) != 64:
        raise Refused("signature-invalid")
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    try:
        key.verify(der, sig_structure(protected, payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise Refused("signature-invalid") from exc


def air_header_payload(h: dict[Any, Any], payload: bytes) -> None:
    try:
        body = json.loads(payload)
    except ValueError as exc:
        raise Refused("header-payload-disagree") from exc
    pair = (h["action_timestamp_ms"], h["agent_id"])
    if (
        not isinstance(body, dict)
        or (body.get("action_timestamp_ms"), body.get("agent_id")) != pair
    ):
        raise Refused("header-payload-disagree")


def air_record(raw: bytes, key: ec.EllipticCurvePublicKey, off: frozenset[str]) -> dict[Any, Any]:
    """Every check one record carries on its own; returns its header."""
    protected, _, payload, signature = cose_parts(raw, "last")
    h = header_of(protected, "last")
    air_shape(h, off)
    if "signature" not in off:
        air_signature(key, protected, payload, signature)
    if "content-hash" not in off and sha256(payload) != h["content_hash"]:
        raise Refused("content-hash-mismatch")
    recomputed = air_chain_hash(
        h["content_hash"], h["prev_chain_hash"], h["action_timestamp_ms"], h["agent_id"]
    )
    if "chain-hash" not in off and recomputed != h["chain_hash"]:
        raise Refused("chain-hash-mismatch")
    if "header-payload" not in off:
        air_header_payload(h, payload)
    return h


def air_follow(prior: dict[str, Any] | None, h: dict[str, Any], off: frozenset[str]) -> None:
    """The checks a record carries against the record before it."""
    expected_seq = 0 if prior is None else prior["sequence_number"] + 1
    if "sequence" not in off and h["sequence_number"] != expected_seq:
        raise Refused("sequence-gap")
    expected_prev = bytes(32) if prior is None else prior["chain_hash"]
    if "prev-chain-link" not in off and h["prev_chain_hash"] != expected_prev:
        raise Refused("prev-chain-hash-mismatch")
    if (
        "time-order" not in off
        and prior is not None
        and h["action_timestamp_ms"] < prior["action_timestamp_ms"]
    ):
        raise Refused("timestamp-regression")


def verify_air(case: dict[str, Any], manifest: dict[str, Any], off: frozenset[str]) -> None:
    key = air_key(manifest)
    prior: dict[str, Any] | None = None
    for raw in case["predecessors"]:
        h = air_record(bytes.fromhex(raw), key, off)
        air_follow(prior, h, off)
        prior = h
    seen: dict[tuple[str, int], bytes] = {}
    for raw in case["candidates"]:
        h = air_record(bytes.fromhex(raw), key, off)
        air_follow(prior, h, off)
        position = (h["agent_id"], h["sequence_number"])
        if "position-unique" not in off and seen.get(position, h["chain_hash"]) != h["chain_hash"]:
            raise Refused("chain-position-equivocation")
        seen[position] = h["chain_hash"]


# ---------------------------------------------------------------- CLL


def instant(text: Any) -> datetime:
    if not isinstance(text, str):
        raise Refused("claims-malformed")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refused("claims-malformed") from exc


def cll_envelope(
    case: dict[str, Any], manifest: dict[str, Any], off: frozenset[str]
) -> dict[Any, Any]:
    """Decode, check the header and the signature; returns the payload's claims."""
    policy = "last" if "deterministic-encoding" in off else "strict"
    protected, _, payload, signature = cose_parts(bytes.fromhex(case["checkpoint"]), policy)
    h = header_of(protected, policy)
    try:
        m = decode(payload, policy)
    except NotDeterministic as exc:
        raise Refused("cbor-not-deterministic") from exc
    except Malformed as exc:
        raise Refused("claims-malformed") from exc
    cwt = h.get(15)
    identity = case["logIdentity"]
    shaped = (
        h.get(1) == -19
        and isinstance(cwt, dict)
        and cwt.get(1) == identity["iss"]
        and cwt.get(2) == identity["sub"]
    )
    if "cose-shape" not in off and not shaped:
        raise Refused("cose-malformed")
    if "signature" not in off:
        public = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(manifest["keys"]["cll-producer"]["publicKey"])
        )
        try:
            public.verify(signature, sig_structure(protected, payload))
        except InvalidSignature as exc:
            raise Refused("signature-invalid") from exc
    if not isinstance(m, dict):
        raise Refused("claims-malformed")
    return m


def cll_claims(m: dict[Any, Any], off: frozenset[str]) -> None:
    """Section 4.3 step 2: the required claims with Table 1's types, and the kind."""
    typed = (
        isinstance(m.get("log_size"), int)
        and isinstance(m.get("prev_size"), int)
        and isinstance(m.get("commitment"), bytes)
        and isinstance(m.get("prev_commitment"), bytes)
        and isinstance(m.get("issued_at"), str)
    )
    if not typed:
        raise Refused("claims-malformed")
    if "claims" not in off and m.get("kind") != "cll-checkpoint":
        raise Refused("claims-malformed")


def cll_registration(
    case: dict[str, Any], m: dict[Any, Any], history: list[dict[str, Any]], off: frozenset[str]
) -> None:
    """Section 4.5 continuity, then the two clock rules this corpus adds."""
    last = history[-1] if history else None
    if "continuity" not in off:
        expected = (0, "") if last is None else (last["log_size"], last["commitment"])
        got = (m["prev_size"], m["prev_commitment"].hex())
        if got != expected and not (last is None and m["prev_size"] == 0):
            raise Refused("not-continuous")
    issued = instant(m["issued_at"])
    if "issued-at-order" not in off and last is not None and issued < instant(last["issued_at"]):
        raise Refused("issued-at-regression")
    cadence = m.get("cadence")
    late = isinstance(cadence, int) and (
        abs((instant(case["clock"]) - issued).total_seconds()) > cadence
    )
    if "registration-time" not in off and late:
        raise Refused("registration-late")


def cll_fork(case: dict[str, Any], m: dict[Any, Any], services: dict[str, Any]) -> None:
    """No other named service holds this log_size under another commitment."""
    for name in case["namedServices"]:
        if name == case["registerAt"]:
            continue
        for row in services[name]:
            if row["log_size"] == m["log_size"] and row["commitment"] != m["commitment"].hex():
                raise Refused("history-fork")


def verify_cll(case: dict[str, Any], manifest: dict[str, Any], off: frozenset[str]) -> None:
    m = cll_envelope(case, manifest, off)
    cll_claims(m, off)
    services = {s["name"]: s["history"] for s in case["services"]}
    cll_registration(case, m, services[case["registerAt"]], off)
    if "history-fork" not in off:
        cll_fork(case, m, services)


# ---------------------------------------------------------------- statement identification


def verify_sid(case: dict[str, Any], manifest: dict[str, Any], off: frozenset[str]) -> None:
    raw = bytes.fromhex(case["candidate"])
    protected, _, payload, signature = cose_parts(raw, "last", tag_required=False)
    header = header_of(protected, "last")
    if "duplicate-key" not in off and has_repeated_key(protected):
        raise Refused("cbor-duplicate-key")
    if "signature" not in off:
        public = bytes.fromhex(manifest["keys"]["sid-issuer"]["publicKey"])
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, sig_structure(protected, payload)
            )
        except InvalidSignature as exc:
            raise Refused("signature-invalid") from exc
    if "identity" in off:
        return
    signing_header = protected if "identity-canonical" in off else encode(header)
    digest = hashlib.sha256(sig_structure(signing_header, payload)).hexdigest()
    if digest != case["reference"]["triple"][2]:
        raise Refused("reference-mismatch")


VERIFIERS = {DRAFT_AIR: verify_air, DRAFT_CLL: verify_cll, DRAFT_SID: verify_sid}


def verify(
    case: dict[str, Any], manifest: dict[str, Any], off: frozenset[str] = frozenset()
) -> Report:
    try:
        VERIFIERS[case["draft"]](case, manifest, off)
    except Refused as refused:
        return Report(refused.verdict, [refused.code])
    return Report()


def draft_off(draft: str) -> frozenset[str]:
    return frozenset(CORPUS_RULES[draft])


# ---------------------------------------------------------------- the checks


def _case(entry: dict[str, Any]) -> dict[str, Any]:
    with open(os.path.join(HERE, entry["file"]), encoding="utf-8") as fh:
        out: dict[str, Any] = json.load(fh)
    return out


def judge(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    entries = manifest["vectors"]
    accepts = {e["id"] for e in entries if e["kind"] == "accept"}
    counts = {"accept": 0, "indeterminate": 0, "reject": 0}
    for entry in entries:
        counts[entry["kind"]] += 1
        case = _case(entry)
        if case["draft"] != entry["draft"]:
            findings.append(f"{entry['slug']}: the case names {case['draft']}")
        report = verify(case, manifest)
        if entry["kind"] == "indeterminate":
            allowed = {r["verdict"] for r in entry["readings"]}
            if report.verdict not in allowed or "verdict" in entry["expected"]:
                findings.append(
                    f"{entry['slug']}: reached {report.verdict}, readings allow {sorted(allowed)}"
                )
        else:
            expected = entry["expected"]
            if report.verdict != expected["verdict"] or report.codes != expected["codes"]:
                findings.append(
                    f"{entry['slug']}: expected {expected['verdict']} {expected['codes']}, "
                    f"reached {report.verdict} {report.codes}"
                )
        if entry["kind"] != "accept" and entry.get("parent") not in accepts:
            findings.append(f"{entry['slug']}: parent is not an accept member")
        if not entry.get("does_not_assert"):
            findings.append(f"{entry['slug']}: does_not_assert is empty")
    if counts != manifest["counts"]:
        findings.append(f"counts {manifest['counts']} disagree with the members {counts}")
    if corpus_digest(manifest, HERE) != manifest["corpusDigest"]:
        findings.append("corpusDigest does not match the committed bytes")
    return findings


def draft_reading(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    missed = 0
    for entry in manifest["vectors"]:
        report = verify(_case(entry), manifest, draft_off(entry["draft"]))
        if report.verdict != entry["draftReading"]["verdict"]:
            findings.append(
                f"{entry['slug']}: the draft's own steps reach {report.verdict}, "
                f"the manifest records {entry['draftReading']['verdict']}"
            )
        expected = entry["expected"].get("verdict")
        if entry["kind"] == "reject" and expected != report.verdict:
            missed += 1
        if entry["kind"] == "indeterminate":
            allowed = {r["verdict"] for r in entry["readings"]}
            missed += report.verdict not in allowed
    if missed == 0:
        findings.append("no member separates this corpus from the drafts' own steps")
    else:
        print(
            f"draft reading: {missed} members get a verdict under the drafts' own steps "
            "that conformance refuses"
        )
    return findings


def cbor_items(case: dict[str, Any]) -> list[bytes]:
    if case["draft"] == DRAFT_AIR:
        return [bytes.fromhex(r) for r in case["predecessors"] + case["candidates"]]
    if case["draft"] == DRAFT_CLL:
        return [bytes.fromhex(case["checkpoint"])]
    return [bytes.fromhex(case["candidate"])]


def plain(value: Any) -> Any:
    if isinstance(value, Tag):
        return ("tag", value.number, plain(value.value))
    if isinstance(value, cbor2.CBORTag):
        return ("tag", value.tag, plain(value.value))
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    return value


def second_path(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    read = 0
    for entry in manifest["vectors"]:
        for raw in cbor_items(_case(entry)):
            ours = decode(raw, "last")
            theirs = cbor2.loads(raw)
            if plain(ours) != plain(theirs):
                findings.append(f"{entry['slug']}: cbor2 and cbor_det disagree on the outer item")
                continue
            assert isinstance(ours, Tag) or isinstance(ours, list)
            parts = ours.value if isinstance(ours, Tag) else ours
            for inner in (parts[0], parts[2]):
                read += 1
                try:
                    theirs_inner = cbor2.loads(inner)
                except Exception:
                    continue  # an AIR or statement payload is JSON, not CBOR
                if plain(decode(inner, "last")) != plain(theirs_inner):
                    findings.append(
                        f"{entry['slug']}: cbor2 and cbor_det disagree on an inner item"
                    )
        if entry["slug"] == "cll-commitment-key-repeated":
            payload = cbor2.loads(bytes.fromhex(_case(entry)["checkpoint"])).value[2]
            first = decode(payload, "first")["commitment"]
            if cbor2.loads(payload)["commitment"] == first:
                findings.append(
                    "cbor2 reads the repeated commitment first-wins; the member assumes last-wins"
                )
    if read == 0:
        findings.append("the second CBOR path read nothing")
    return findings


def sweep(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    cases = [(e, _case(e)) for e in manifest["vectors"]]
    for draft, rules in RULES.items():
        for rule in rules:
            flipped = []
            for entry, case in cases:
                if entry["draft"] != draft or entry["kind"] == "indeterminate":
                    continue
                report = verify(case, manifest, frozenset({rule}))
                if entry["kind"] == "accept" and report.verdict != "valid":
                    findings.append(
                        f"disabling {draft} {rule} refuses accept member {entry['slug']}"
                    )
                if entry["kind"] == "reject" and report.verdict == "valid":
                    flipped.append(entry["slug"])
            if not flipped:
                findings.append(
                    f"rule {draft} {rule} is inert: disabling it admits no reject member"
                )
            else:
                print(f"rule {rule} ({draft}): disabling it admits {', '.join(flipped)}")
    return findings


def main() -> int:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    findings = judge(manifest) + draft_reading(manifest) + second_path(manifest) + sweep(manifest)
    for finding in findings:
        print(f"FAIL check: {finding}")
    if findings:
        return 1
    print(
        f"check: {manifest['counts']} members behave as declared, the drafts' own steps reach "
        "every recorded draftReading, cbor2 agrees, and every rule is load-bearing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
