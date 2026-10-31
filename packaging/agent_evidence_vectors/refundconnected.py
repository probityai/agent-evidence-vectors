"""Judge a retained connected refund run offline, step by step, from its bytes.

A run directory holds the inputs and trust files of each case, the admission
state, the signed handoffs and resolutions, the executor's four streams and the
provider's own record. The reader never opens ``results.json`` or
``verdicts.json``. For each case it re-derives six verdicts, one per step:

1. ``input_pic``: the PIC proposal's attestation signature, its three digests
   and the refund profile, then the runner's result file against the retained
   proposal and keyring bytes.
2. ``input_aps``: the APS intent and approval receipts (ids and signatures), the
   decision components, the action and payload references, the single use of the
   approval and the PIC claim's binding to it.
3. ``admission``: the committed admission record against the hash of every
   input file, the approval, the arguments and the native time bounds, or the
   signed ``resolved_existing`` record for a reissue.
4. ``signature_trust``: the handoff's Ed25519 signature over
   ``ASCII(type) || 0x00 || JCS(payload)`` against the issuance trust snapshot,
   the evaluation trust, and each recorded dispatch against the window and
   revocation state at the exact dispatch instant.
5. ``execution``: one idempotency key per operation, the stored arguments and
   digest, and the provider's apply count.
6. ``observed_effect``: exactly one effect per key, bound to its operation, its
   arguments and its original dispatch attempt, read back from the provider's
   own snapshot, at the report cutoff.

A step is ``ESTABLISHED``, ``REFUSED:<code>`` (a layer refused the case and
nothing downstream exists), ``CONTRADICTED:<code>`` (the bytes disagree),
``NOT_ESTABLISHED:<code>`` (the bytes needed to establish it are absent) or
``NOT_REACHED`` (an earlier layer legitimately ended the case). Run-level
checks cover the effect count per key, the apply count and replays.

Exit 0 when every case ended as it should and every run-level check holds,
1 otherwise. Usage: ``python -m agent_evidence_vectors.refundconnected RUN_DIR``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SUITE = "refund-connected/v1"
CONTRACT_REVISION = "review-2026-10-23"
STEPS = ("input_pic", "input_aps", "admission", "signature_trust", "execution", "observed_effect")
ESTABLISHED = "ESTABLISHED"
NOT_REACHED = "NOT_REACHED"

_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-refund-connected"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "vectors-refund-connected"
)
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")

WORKER = "did:example:refund-worker"
BOUNDARY = "did:example:refund-approval-boundary"
TARGET_PREFIX = "https://payments.operator.example/v1/payments/"
TARGET_SUFFIX = "/refunds"
IDEMPOTENCY = "refund-sandbox-idempotency/0.1"
HANDOFF, RESOLUTION = "refund-sandbox-handoff/0.1", "refund-sandbox-resolution/0.1"
ADMISSION, TRUST = "refund-sandbox-admission/0.1", "refund-sandbox-trust/0.1"
SIGNER_ROLE = "admission-signer"
HANDOFF_CEILING_S = 600
SCOPE = ("workflow_id", "admission_issuer", "provider_namespace")
REFUND_ARGS = frozenset({"payment_id", "amount_minor", "currency"})
SAFE_INT = 2**53 - 1

ADMISSION_FIELDS = frozenset(
    {
        "schema",
        "contract_revision",
        "workflow_id",
        "admission_issuer",
        "provider_namespace",
        "decision_id",
        "operation_id",
        "approval_ref",
        "pic_evidence_ref",
        "pic_verification_ref",
        "pic_trust_file_ref",
        "aps_evidence_ref",
        "aps_intent_file_ref",
        "aps_action_file_ref",
        "aps_payload_file_ref",
        "decision_evidence_ref",
        "aps_consumption_trust_ref",
        "tool",
        "arguments",
        "state",
        "committed_at",
        "valid_until",
    }
)
# Record field -> the retained file whose raw bytes it names.
INPUT_FILES = {
    "pic_evidence_ref": "inputs/pic-proposal.json",
    "pic_verification_ref": "inputs/pic-verification.json",
    "pic_trust_file_ref": "trust/pic-keys.json",
    "aps_evidence_ref": "inputs/aps-approval.json",
    "aps_intent_file_ref": "inputs/aps-intent.json",
    "aps_action_file_ref": "inputs/aps-action.json",
    "aps_payload_file_ref": "inputs/aps-payload.json",
    "decision_evidence_ref": "inputs/decision-evidence.json",
    "aps_consumption_trust_ref": "trust/aps-consumption.json",
}
CASE_FILES = (*INPUT_FILES.values(), "trust/handoff-issuance.json", "trust/handoff-evaluation.json")
HANDOFF_FIELDS = frozenset(
    {
        "schema",
        "contract_revision",
        "workflow_id",
        "admission_issuer",
        "provider_namespace",
        "operation_id",
        "admission_ref",
        "key_id",
        "trust_snapshot_ref",
        "issued_at",
        "not_before",
        "valid_until",
    }
)
RESOLUTION_FIELDS = frozenset(
    {
        "schema",
        "contract_revision",
        "workflow_id",
        "admission_issuer",
        "provider_namespace",
        "decision_id",
        "operation_id",
        "original_admission_ref",
        "original_approval_ref",
        "presented_approval_ref",
        "presented_inputs",
        "disposition",
        "dispatch_authorized",
        "key_id",
        "trust_snapshot_ref",
        "issued_at",
    }
)
TRUST_FIELDS = frozenset({"schema", "workflow_id", "version", "provider_namespaces", "keys"})
KEY_FIELDS = frozenset(
    {"key_id", "issuer", "role", "public_key_hex", "not_before", "not_after", "revoked_at"}
)
EVALUATION_FIELDS = frozenset(
    {
        "schema",
        "contract_revision",
        "evaluation_id",
        "workflow_id",
        "selected_at",
        "accepted_issuance_snapshots",
        "keys",
    }
)
ATTESTATION_FIELDS = frozenset(
    {
        "attestation_version",
        "tool",
        "impact",
        "provenance_ids",
        "args_digest",
        "claims_digest",
        "intent_digest",
        "expires_at",
    }
)
PIC_RESULT_FIELDS = frozenset(
    {
        "schema",
        "contract_revision",
        "run_id",
        "pic_sdk_commit",
        "proposal_file_ref",
        "pic_trust_file_ref",
        "evaluated_at",
        "result",
        "tool",
        "impact",
        "args_digest",
        "claims_digest",
        "intent_digest",
        "error_code",
    }
)
PIC_SDK_COMMIT = "330fdd817ef81d43461ea1787939e0d1cc87d589"
COMMON = frozenset(
    {
        "schema",
        "contract_revision",
        "run_id",
        "workflow_id",
        "admission_issuer",
        "provider_namespace",
        "operation_id",
        "recorded_at",
        "admission_ref",
        "idempotency_key",
    }
)
STREAMS = {
    "attempts": (
        "refund-sandbox-attempt/0.1",
        COMMON
        | {
            "attempt_id",
            "kind",
            "handoff_file_ref",
            "trust_evaluation_file_ref",
            "tool",
            "arguments",
            "arguments_digest",
            "started_at",
        },
    ),
    "outcomes": (
        "refund-sandbox-outcome/0.1",
        COMMON | {"attempt_id", "attempt_ref", "status", "effect_ref", "observation_ref"},
    ),
    "effects": (
        "refund-sandbox-effect/0.1",
        COMMON
        | {
            "effect_id",
            "attempt_id",
            "attempt_ref",
            "arguments",
            "arguments_digest",
            "committed_at",
        },
    ),
    "observations": (
        "refund-sandbox-observation/0.1",
        COMMON
        | {
            "observation_id",
            "observation_kind",
            "attempt_id",
            "attempt_ref",
            "source_file_ref",
            "effect_refs",
            "observed_at",
        },
    ),
}
REPORT_FIELDS = frozenset(
    {
        "schema",
        "contract_revision",
        "run_id",
        "scenario_id",
        "workflow_id",
        "admission_issuer",
        "provider_namespace",
        "report_cutoff",
    }
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_REF = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_MS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
_PAYMENT_ID = re.compile(r"[A-Za-z0-9_-]+\Z")


class Finding(Exception):
    """A step's outcome other than ESTABLISHED, with its kind and code."""

    def __init__(self, kind: str, code: str) -> None:
        super().__init__(f"{kind}:{code}")
        self.kind, self.code = kind, code

    @property
    def verdict(self) -> str:
        return f"{self.kind}:{self.code}"


def _refuse(code: str) -> Finding:
    return Finding("REFUSED", code)


def _contra(code: str) -> Finding:
    return Finding("CONTRADICTED", code)


def _absent(code: str) -> Finding:
    return Finding("NOT_ESTABLISHED", code)


def _need(cond: bool, make: Any, code: str) -> None:
    if not cond:
        raise make(code)


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to dispatch
    suites, so a module-level import would be a cycle."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    raise ImportError("the reference rail's Ed25519 and RFC 8785 primitives are unavailable")


def jcs(value: Any) -> bytes:
    return bytes(_rail().jcs_dumps(value))


def ed_verify(pub: bytes, message: bytes, sig: bytes) -> bool:
    return bool(_rail().ed25519_verify(pub, message, sig))


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_ref(data: bytes) -> str:
    return "sha256:" + sha_hex(data)


def ref_of(value: Any) -> str:
    return file_ref(jcs(value))


# ----------------------------------------------------------------------------
# Strict parsing and small helpers.
# ----------------------------------------------------------------------------


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate member")
    return dict(pairs)


def _no_float(text: str) -> Any:
    raise ValueError("float")


def _no_const(text: str) -> Any:
    raise ValueError("constant")


def parse(data: bytes) -> Any:
    """Parse one JSON document strictly: UTF-8, no duplicate members, floats or constants."""
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_float=_no_float,
        parse_constant=_no_const,
    )


def typed_equal(a: Any, b: Any) -> bool:
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(typed_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(typed_equal(x, y) for x, y in zip(a, b, strict=True))
    return bool(a == b)


def ts_s(value: Any) -> datetime:
    if not (isinstance(value, str) and _TS.match(value)):
        raise ValueError("timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def ts_ms(value: Any) -> datetime:
    if not (isinstance(value, str) and _MS.match(value)):
        raise ValueError("timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def ts_exact(value: Any) -> datetime:
    return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def ceil_s(value: datetime) -> datetime:
    whole = value.replace(microsecond=0)
    return whole + timedelta(seconds=1) if value.microsecond else whole


def floor_s(value: datetime) -> datetime:
    return value.replace(microsecond=0)


def is_obj(value: Any) -> bool:
    return isinstance(value, dict)


def ascii_id(value: Any) -> bool:
    return isinstance(value, str) and value != "" and value.isascii() and value.isprintable()


def refund_args_ok(args: Any) -> bool:
    return (
        is_obj(args)
        and set(args) == REFUND_ARGS
        and isinstance(args["payment_id"], str)
        and bool(_PAYMENT_ID.match(args["payment_id"]))
        and type(args["amount_minor"]) is int
        and 0 < args["amount_minor"] <= SAFE_INT
        and args["currency"] == "EUR"
    )


class RunDir:
    """Read-only view of one run directory; every read is of raw bytes."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def read(self, rel: str) -> bytes | None:
        path = self.root / rel
        return path.read_bytes() if path.is_file() else None

    def json(self, rel: str) -> Any:
        data = self.read(rel)
        if data is None:
            return None
        return parse(data)

    def lines(self, rel: str) -> list[bytes]:
        data = self.read(rel)
        return data.splitlines() if data else []

    def cases(self) -> list[str]:
        base = self.root / "cases"
        return sorted(p.name for p in base.iterdir() if p.is_dir()) if base.is_dir() else []

    def files_in(self, rel: str, suffix: str) -> dict[str, bytes]:
        base = self.root / rel
        if not base.is_dir():
            return {}
        return {p.name: p.read_bytes() for p in sorted(base.iterdir()) if p.name.endswith(suffix)}


# ----------------------------------------------------------------------------
# Step 1: PIC.
# ----------------------------------------------------------------------------


class Case:
    """The retained files of one case plus values derived while judging it."""

    def __init__(self, run: RunDir, name: str) -> None:
        self.run, self.name = run, name
        self.files: dict[str, bytes] = {}
        self.missing: list[str] = []
        for rel in CASE_FILES:
            data = run.read(f"cases/{name}/{rel}")
            if data is None:
                self.missing.append(rel)
            else:
                self.files[rel] = data
        self.parsed: dict[str, Any] = {}
        self.bad: list[str] = []
        for rel, data in self.files.items():
            try:
                self.parsed[rel] = parse(data)
            except (ValueError, UnicodeDecodeError):
                self.bad.append(rel)
        self.consumed_at = ""
        self.decision_id = ""
        self.approval_id = ""
        self.pic_args: Any = None
        self.pic_args_digest = ""
        self.attestation: dict[str, Any] = {}
        self.run_id = ""

    def p(self, rel: str) -> Any:
        return self.parsed[rel]

    def raw_ref(self, rel: str) -> str:
        return file_ref(self.files[rel])

    def input_refs(self) -> dict[str, str]:
        return {field: self.raw_ref(rel) for field, rel in INPUT_FILES.items()}


def _inputs_ready(case: Case) -> None:
    _need(not case.missing, _absent, "input-files-missing")
    _need(not case.bad, _refuse, "STRICT_PARSE")


def check_pic(case: Case) -> None:
    """Native-equivalent PIC verification of the retained proposal, then the runner's result."""
    _inputs_ready(case)
    prop, keys = case.p("inputs/pic-proposal.json"), case.p("trust/pic-keys.json")
    result = case.p("inputs/pic-verification.json")
    evidence: Any = prop.get("evidence") if is_obj(prop) else None
    _need(
        isinstance(evidence, list)
        and len(evidence) == 1
        and is_obj(evidence[0])
        and evidence[0].get("type") == "sig",
        _refuse,
        "PIC_EVIDENCE",
    )
    entry = evidence[0]
    try:
        att = parse(entry["payload"].encode("utf-8"))
    except (KeyError, AttributeError, ValueError, UnicodeEncodeError):
        raise _refuse("PIC_ATTESTATION") from None
    _need(
        is_obj(att)
        and att.get("attestation_version") == "PIC-ATT/1.0"
        and set(att) == ATTESTATION_FIELDS,
        _refuse,
        "PIC_ATTESTATION",
    )
    _need(
        is_obj(keys)
        and set(keys) == {"trusted_keys", "revoked_keys"}
        and is_obj(keys["trusted_keys"])
        and isinstance(keys["revoked_keys"], list),
        _refuse,
        "PIC_KEYRING",
    )
    key_id = entry.get("key_id")
    _need(key_id == entry.get("signer") and key_id not in keys["revoked_keys"], _refuse, "PIC_KEY")
    pub_hex = keys["trusted_keys"].get(key_id)
    if is_obj(pub_hex):
        pub_hex = pub_hex.get("public_key")
    _need(isinstance(pub_hex, str) and bool(_HEX64.match(pub_hex)), _refuse, "PIC_KEY")
    try:
        sig = base64.b64decode(str(entry.get("signature", "")), validate=True)
    except (binascii.Error, ValueError):
        raise _refuse("PIC_SIGNATURE") from None
    _need(
        entry.get("alg") == "ed25519" and ed_verify(bytes.fromhex(pub_hex), jcs(att), sig),
        _refuse,
        "PIC_SIGNATURE",
    )
    action = prop.get("action")
    args = action.get("args") if is_obj(action) else None
    claims, intent = prop.get("claims"), prop.get("intent")
    _need(
        is_obj(action)
        and action.get("tool") == "refund"
        and prop.get("impact") == "money"
        and att["tool"] == "refund"
        and att["impact"] == "money"
        and att["provenance_ids"] == [entry.get("id")],
        _refuse,
        "PIC_PROFILE",
    )
    _need(refund_args_ok(args), _refuse, "PIC_PROFILE")
    _need(sha_hex(jcs(args)) == att["args_digest"], _refuse, "PIC_ARGS_DIGEST")
    _need(sha_hex(jcs(claims)) == att["claims_digest"], _refuse, "PIC_CLAIMS_DIGEST")
    _need(
        isinstance(intent, str) and sha_hex(intent.encode("utf-8")) == att["intent_digest"],
        _refuse,
        "PIC_INTENT_DIGEST",
    )
    _need(
        isinstance(claims, list)
        and len(claims) == 1
        and is_obj(claims[0])
        and set(claims[0]) == {"text", "evidence"}
        and claims[0]["evidence"] == [entry.get("id")]
        and isinstance(claims[0]["text"], str),
        _refuse,
        "PIC_CLAIM",
    )
    try:
        inner = parse(claims[0]["text"].encode("utf-8"))
    except ValueError:
        raise _refuse("PIC_CLAIM") from None
    _need(
        is_obj(inner)
        and set(inner) == {"approval_ref", "decision_id"}
        and jcs(inner).decode("utf-8") == claims[0]["text"]
        and bool(_HEX64.match(str(inner["approval_ref"])))
        and ascii_id(inner["decision_id"]),
        _refuse,
        "PIC_CLAIM",
    )
    case.pic_args, case.pic_args_digest = args, att["args_digest"]
    case.attestation = att
    case.claim = inner  # type: ignore[attr-defined]
    case.proposal = prop  # type: ignore[attr-defined]
    _need(is_obj(result) and set(result) == PIC_RESULT_FIELDS, _contra, "PIC_RESULT_SHAPE")
    _need(
        result["result"] == "allow" and result["error_code"] is None, _contra, "PIC_RESULT_BLOCKS"
    )
    _need(
        result["schema"] == "refund-sandbox-pic-result/0.1"
        and result["contract_revision"] == CONTRACT_REVISION
        and result["pic_sdk_commit"] == PIC_SDK_COMMIT,
        _contra,
        "PIC_RESULT_SCHEMA",
    )
    _need(
        result["proposal_file_ref"] == case.raw_ref("inputs/pic-proposal.json"),
        _contra,
        "PIC_RESULT_PROPOSAL_REF",
    )
    _need(
        result["pic_trust_file_ref"] == case.raw_ref("trust/pic-keys.json"),
        _contra,
        "PIC_RESULT_TRUST_REF",
    )
    _need(
        (result["args_digest"], result["claims_digest"], result["intent_digest"])
        == (att["args_digest"], att["claims_digest"], att["intent_digest"]),
        _contra,
        "PIC_RESULT_DIGESTS",
    )
    _need(result["tool"] == "refund" and result["impact"] == "money", _contra, "PIC_RESULT_TOOL")
    case.run_id = str(result["run_id"])
    case.pic_evaluated_at = str(result["evaluated_at"])  # type: ignore[attr-defined]


def runner_allowed_refused(case: Case) -> bool:
    """Whether the runner's own result says allow for a proposal the reader refused."""
    result: Any = case.parsed.get("inputs/pic-verification.json")
    return bool(is_obj(result) and result.get("result") == "allow")


# ----------------------------------------------------------------------------
# Step 2: APS.
# ----------------------------------------------------------------------------


def _aps_key(
    trust: dict[str, Any], signer: str, key_id: str, issued_at: str, revocation_at_issuance: bool
) -> bytes | None:
    for key in trust["keys"]:
        if key["signer"] != signer or key["key_id"] != key_id:
            continue
        if issued_at < key["not_before"]:
            return None
        if key["not_after"] is not None and issued_at >= key["not_after"]:
            return None
        if (
            revocation_at_issuance
            and key["revoked_at"] is not None
            and key["revoked_at"] <= issued_at
        ):
            return None
        return bytes.fromhex(key["public_key"])
    return None


def _aps_receipt_ok(
    receipt: Any,
    receipt_type: str,
    trust: dict[str, Any],
    issuer: str,
    revocation_at_issuance: bool,
) -> bool:
    if not (
        is_obj(receipt)
        and receipt.get("profile") == "aps-receipt-v1"
        and receipt.get("receipt_type") == receipt_type
        and receipt.get("issuer") == issuer
        and isinstance(receipt.get("signatures"), list)
        and receipt["signatures"]
    ):
        return False
    body = {k: v for k, v in receipt.items() if k not in ("receipt_id", "signatures")}
    if receipt.get("receipt_id") != sha_hex(b"APS-RECEIPT-ID-V1\0" + jcs(body)):
        return False
    unsigned = {k: v for k, v in receipt.items() if k != "signatures"}
    for sig in receipt["signatures"]:
        if not (is_obj(sig) and sig.get("alg") == "Ed25519" and isinstance(sig.get("value"), str)):
            return False
        pub = _aps_key(
            trust,
            str(sig.get("signer")),
            str(sig.get("key_id")),
            str(receipt.get("issued_at")),
            revocation_at_issuance,
        )
        descriptor = {k: v for k, v in sig.items() if k != "value"}
        message = b"APS-RECEIPT-SIG-V1\0" + jcs({"receipt": unsigned, "signer": descriptor})
        try:
            value = bytes.fromhex(sig["value"])
        except ValueError:
            return False
        if pub is None or not ed_verify(pub, message, value):
            return False
    return True


def _tag_ref(tag: str, value: Any) -> str:
    return sha_hex(tag.encode("ascii") + b"\0" + jcs(value))


def check_aps(case: Case, consumed_at: str) -> None:
    """The adapter's steps 1 to 8 over the eleven retained files."""
    _inputs_ready(case)
    trust = case.p("trust/aps-consumption.json")
    ok = bool(
        is_obj(trust)
        and set(trust) == {"schema", "profile", "scope", "keys"}
        and trust["schema"] == "hs-aps-consumption-trust/0.1"
        and trust["profile"] == "aps-receipt-v1"
        and trust["scope"] == ["payments:refund"]
        and isinstance(trust["keys"], list)
        and trust["keys"]
    )
    _need(ok, _refuse, "TRUST_SELECTION")
    for key in trust["keys"]:
        _need(
            is_obj(key)
            and set(key)
            == {"signer", "key_id", "role", "public_key", "not_before", "not_after", "revoked_at"}
            and bool(_HEX64.match(str(key["public_key"]))),
            _refuse,
            "TRUST_SELECTION",
        )
    intent, approval = case.p("inputs/aps-intent.json"), case.p("inputs/aps-approval.json")
    decision, action = case.p("inputs/decision-evidence.json"), case.p("inputs/aps-action.json")
    payload = case.p("inputs/aps-payload.json")
    _need(
        is_obj(intent) and intent.get("issuer") == WORKER and intent.get("subject_agent") == WORKER,
        _refuse,
        "INTENT_IDENTITY",
    )
    _need(
        _aps_receipt_ok(intent, "aps:action-intent:v1", trust, WORKER, True),
        _refuse,
        "INTENT_NOT_VALID",
    )
    _need(
        is_obj(decision)
        and set(decision)
        == {"authority_state", "policy_input", "decision_context", "decision_output"},
        _refuse,
        "DECISION_COMPONENTS",
    )
    _need(is_obj(approval) and approval.get("issuer") == BOUNDARY, _refuse, "APPROVAL_ISSUER")
    _need(
        _aps_receipt_ok(approval, "aps:policy-decision:v1", trust, BOUNDARY, False),
        _refuse,
        "APPROVAL_NOT_VALID",
    )
    components = {
        "profile": "aps-decision-ref-v1",
        "action_ref": approval["action_ref"],
        "authority_state_ref": _tag_ref("APS-DECISION-AUTHORITY-V1", decision["authority_state"]),
        "policy_ref": _tag_ref("APS-DECISION-POLICY-V1", decision["policy_input"]),
        "context_ref": _tag_ref("APS-DECISION-CONTEXT-V1", decision["decision_context"]),
        "decision_output_ref": _tag_ref("APS-DECISION-OUTPUT-V1", decision["decision_output"]),
    }
    _need(
        _tag_ref("APS-DECISION-REF-V1", components) == approval.get("decision_ref")
        and jcs(decision["decision_output"]) == jcs(approval.get("result")),
        _refuse,
        "DECISION_NOT_BOUND",
    )
    _need(approval.get("prev") == intent["receipt_id"], _refuse, "APPROVAL_PREV")
    _need(
        approval["action_ref"] == intent.get("action_ref")
        and approval.get("subject_agent") == intent.get("subject_agent"),
        _refuse,
        "APPROVAL_INTENT_ACTION",
    )
    _need(str(intent["issued_at"]) <= str(approval["issued_at"]), _refuse, "APPROVAL_BEFORE_INTENT")
    result = approval["result"]
    _need(is_obj(result) and result.get("verdict") == "permit", _refuse, "VERDICT_NOT_PERMIT")
    _need(result.get("constraints") == [], _refuse, "DECISION_CONSTRAINTS")
    _need(approval["issued_at"] <= consumed_at, _refuse, "APPROVAL_AFTER_CONSUMPTION")
    _need(consumed_at < str(result.get("valid_until")), _refuse, "DECISION_EXPIRED_AT_CONSUMPTION")
    for sig in approval["signatures"]:
        for key in trust["keys"]:
            if (key["signer"], key["key_id"]) == (sig["signer"], sig["key_id"]):
                _need(
                    key["revoked_at"] is None or key["revoked_at"] > consumed_at,
                    _refuse,
                    "APPROVAL_SIGNER_REVOKED_AT_CONSUMPTION",
                )
    _need(
        is_obj(action)
        and action.get("profile") == "aps-action-ref-v2"
        and action.get("action_type") == "refund"
        and action.get("scope_required") == ["payments:refund"]
        and action.get("agent_id") == WORKER,
        _refuse,
        "ACTION_INPUT",
    )
    target = action.get("target")
    _need(
        isinstance(target, str)
        and target.startswith(TARGET_PREFIX)
        and target.endswith(TARGET_SUFFIX),
        _refuse,
        "TARGET",
    )
    target_id = target[len(TARGET_PREFIX) : len(target) - len(TARGET_SUFFIX)]
    _need(
        sha_hex(b"APS-ACTION-REF-V2\0" + jcs(action)) == approval["action_ref"],
        _refuse,
        "ACTION_REF",
    )
    _need(refund_args_ok(payload), _refuse, "PAYLOAD_SCHEMA")
    _need(
        sha_hex(b"APS-ACTION-PAYLOAD-V1\0" + jcs(payload)) == action.get("payload_ref"),
        _refuse,
        "PAYLOAD_REF",
    )
    _need(payload["payment_id"] == target_id, _refuse, "TARGET_PAYMENT_ID")
    merchant: Any = (
        (decision["policy_input"] or {}).get("merchant_decision")
        if is_obj(decision["policy_input"])
        else None
    )
    _need(is_obj(merchant) and ascii_id(merchant.get("decision_id")), _refuse, "DECISION_ID")
    claim = case.claim  # type: ignore[attr-defined]
    _need(claim["decision_id"] == merchant["decision_id"], _refuse, "PIC_DECISION_ID")
    _need(claim["approval_ref"] == approval["receipt_id"], _refuse, "PIC_APPROVAL_REF")
    _need(
        consumed_at < case.attestation["expires_at"].replace("Z", ".000Z"),
        _refuse,
        "PIC_EXPIRED_AT_CONSUMPTION",
    )
    _need(jcs(case.pic_args) == jcs(payload), _refuse, "PIC_ARGS_NOT_PAYLOAD")
    case.decision_id, case.approval_id = merchant["decision_id"], approval["receipt_id"]


def native_bounds(case: Case) -> list[tuple[str, str]]:
    approval = case.p("inputs/aps-approval.json")
    expires = case.attestation["expires_at"].replace("Z", ".000Z")
    return [
        (approval["issued_at"], approval["result"]["valid_until"]),
        (approval["issued_at"], expires),
    ]


# ----------------------------------------------------------------------------
# Step 3: admission and the signed records.
# ----------------------------------------------------------------------------


def admission_record_ref(record: Any) -> str:
    """Closed shape of a committed admission record; returns its admission_ref."""
    _need(is_obj(record) and set(record) == ADMISSION_FIELDS, _contra, "admission-fields")
    _need(
        record["schema"] == ADMISSION
        and record["contract_revision"] == CONTRACT_REVISION
        and record["state"] == "committed"
        and record["tool"] == "refund",
        _contra,
        "admission-schema",
    )
    for name in (*SCOPE, "decision_id", "operation_id", "approval_ref"):
        _need(ascii_id(record[name]), _contra, f"admission-{name}")
    for name in INPUT_FILES:
        _need(
            isinstance(record[name], str)
            and bool(_REF.match(record[name]))
            or (name == "aps_evidence_ref" and False),
            _contra,
            f"admission-{name}",
        )
    _need(refund_args_ok(record["arguments"]), _contra, "admission-arguments")
    try:
        _need(
            ts_s(record["committed_at"]) < ts_s(record["valid_until"]), _contra, "admission-window"
        )
    except ValueError:
        raise _contra("admission-window") from None
    return ref_of(record)


def check_trust_snapshot(snapshot: Any) -> str:
    _need(
        bool(is_obj(snapshot)
        and set(snapshot) == TRUST_FIELDS
        and snapshot["schema"] == TRUST
        and isinstance(snapshot["keys"], list)
        and snapshot["keys"]),
        _contra,
        "trust-fields",
    )
    ids: set[str] = set()
    for key in snapshot["keys"]:
        _need(
            is_obj(key)
            and set(key) == KEY_FIELDS
            and bool(_HEX64.match(str(key["public_key_hex"])))
            and key["key_id"] not in ids,
            _contra,
            "trust-key-fields",
        )
        ids.add(key["key_id"])
        try:
            ts_s(key["not_before"])
            ts_s(key["not_after"])
            if key["revoked_at"] is not None:
                ts_s(key["revoked_at"])
        except ValueError:
            raise _contra("trust-key-time") from None
    return ref_of(snapshot)


def _signer_key(
    snapshot: dict[str, Any], key_id: str, scope: dict[str, Any], at: datetime
) -> dict[str, Any]:
    matches = [k for k in snapshot["keys"] if k["key_id"] == key_id]
    _need(len(matches) == 1, _contra, "key-unknown")
    key: dict[str, Any] = matches[0]
    _need(key["role"] == SIGNER_ROLE, _contra, "key-role")
    _need(key["issuer"] == scope["admission_issuer"], _contra, "key-issuer")
    _need(snapshot["workflow_id"] == scope["workflow_id"], _contra, "key-workflow")
    _need(scope["provider_namespace"] in snapshot["provider_namespaces"], _contra, "key-provider")
    _need(ts_s(key["not_before"]) <= at < ts_s(key["not_after"]), _contra, "key-validity")
    _need(key["revoked_at"] is None or at < ts_s(key["revoked_at"]), _contra, "key-revoked")
    return key


def verify_envelope(
    kind: str, data: bytes, record: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    """Verify a handoff or resolution against the expected type, never the claimed one."""
    fields = {HANDOFF: HANDOFF_FIELDS, RESOLUTION: RESOLUTION_FIELDS}[kind]
    try:
        env = parse(data)
    except (ValueError, UnicodeDecodeError):
        raise _contra("envelope-parse") from None
    _need(is_obj(env) and set(env) == {"payload", "alg", "signature"}, _contra, "envelope-fields")
    _need(env["alg"] == "ed25519", _contra, "envelope-alg")
    payload = env["payload"]
    _need(is_obj(payload) and set(payload) == fields, _contra, "payload-fields")
    _need(
        payload["schema"] == kind and payload["contract_revision"] == CONTRACT_REVISION,
        _contra,
        "payload-schema",
    )
    record_ref = admission_record_ref(record)
    _need(
        payload["trust_snapshot_ref"] == check_trust_snapshot(snapshot),
        _contra,
        "trust-snapshot-ref",
    )
    for name in (*SCOPE, "operation_id"):
        _need(payload[name] == record[name], _contra, f"scope-{name}")
    try:
        if kind == HANDOFF:
            _need(payload["admission_ref"] == record_ref, _contra, "admission-ref")
            _need(payload["not_before"] == payload["issued_at"], _contra, "handoff-not-before")
            _need(
                ts_s(payload["valid_until"]) <= ts_s(record["valid_until"]),
                _contra,
                "handoff-extends-record",
            )
            issued, until = ts_s(payload["issued_at"]), ts_s(payload["valid_until"])
            _need(issued < until, _contra, "handoff-window-empty")
            _need(
                until - issued <= timedelta(seconds=HANDOFF_CEILING_S), _contra, "handoff-lifetime"
            )
        else:
            _need(
                payload["original_admission_ref"] == record_ref, _contra, "original-admission-ref"
            )
            _need(
                payload["original_approval_ref"] == record["approval_ref"],
                _contra,
                "original-approval-ref",
            )
            _need(payload["decision_id"] == record["decision_id"], _contra, "decision-id")
            _need(payload["disposition"] == "resolved_existing", _contra, "disposition")
            _need(payload["dispatch_authorized"] is False, _contra, "dispatch-authorized")
        key = _signer_key(snapshot, payload["key_id"], record, ts_s(payload["issued_at"]))
    except ValueError:
        raise _contra("timestamp-format") from None
    try:
        sig = base64.b64decode(str(env["signature"]), validate=True)
    except (binascii.Error, ValueError):
        raise _contra("signature-encoding") from None
    _need(
        len(sig) == 64 and base64.b64encode(sig).decode("ascii") == env["signature"],
        _contra,
        "signature-encoding",
    )
    message = kind.encode("ascii") + b"\x00" + jcs(payload)
    _need(
        ed_verify(bytes.fromhex(key["public_key_hex"]), message, sig), _contra, "signature-invalid"
    )
    return payload  # type: ignore[no-any-return]


def idempotency_key(scope: dict[str, Any]) -> str:
    body = {k: scope[k] for k in (*SCOPE, "operation_id")}
    return "sha256:" + sha_hex(IDEMPOTENCY.encode("ascii") + b"\x00" + jcs(body))


class Admission:
    """The admission state for the run, loaded once."""

    def __init__(self, run: RunDir) -> None:
        raw = run.json("admission/state.json")
        self.consumed: dict[str, str] = raw.get("consumed", {}) if is_obj(raw) else {}
        self.decisions: dict[str, Any] = raw.get("decisions", {}) if is_obj(raw) else {}

    def for_decision(self, decision_id: str) -> list[dict[str, Any]]:
        out = []
        for key, value in self.decisions.items():
            if key.split("\n")[-1] == decision_id and is_obj(value) and is_obj(value.get("record")):
                out.append(value["record"])
        return out


def _dispatch_bounds(
    payload: dict[str, Any],
    record: dict[str, Any],
    keys: tuple[dict[str, Any], ...],
    native: list[tuple[str, str]],
) -> tuple[datetime, datetime]:
    lowers = [ts_s(payload["not_before"]), ts_s(record["committed_at"])]
    uppers = [ts_s(payload["valid_until"]), ts_s(record["valid_until"])]
    for key in keys:
        lowers.append(ts_s(key["not_before"]))
        uppers.append(ts_s(key["not_after"]))
    for low, high in native:
        lowers.append(ceil_s(ts_ms(low)))
        uppers.append(floor_s(ts_ms(high)))
    return max(lowers), min(uppers)


def check_admission(case: Case, adm: Admission, ctx: dict[str, Any]) -> None:
    """The committed record against every retained input, or the resolution of a reissue."""
    records = adm.for_decision(case.decision_id)
    _need(bool(records), _absent, "no-admission-record")
    same = [r for r in records if is_obj(r) and r.get("approval_ref") == case.approval_id]
    if not same:
        ctx["reissue_of"] = records[0]
        return
    record = same[0]
    admission_record_ref(record)
    for name, rel in INPUT_FILES.items():
        _need(record[name] == case.raw_ref(rel), _contra, f"admission-{name}-mismatch")
    _need(typed_equal(record["arguments"], case.pic_args), _contra, "admission-arguments")
    _need(
        typed_equal(
            record["arguments"], {k: case.p("inputs/aps-payload.json")[k] for k in REFUND_ARGS}
        ),
        _contra,
        "admission-arguments",
    )
    _need(
        adm.consumed.get(case.approval_id) == record["operation_id"],
        _contra,
        "approval-not-consumed",
    )
    _need(
        sum(1 for v in adm.consumed.values() if v == record["operation_id"]) == 1,
        _contra,
        "operation-consumed-twice",
    )
    native = native_bounds(case)
    _need(
        ts_s(record["committed_at"]) >= max(ceil_s(ts_ms(low)) for low, _ in native),
        _contra,
        "admission-before-native-window",
    )
    _need(
        ts_s(record["valid_until"]) <= min(floor_s(ts_ms(high)) for _, high in native),
        _contra,
        "admission-extends-native-window",
    )
    ctx["record"] = record


def check_snapshot_files(case: Case) -> tuple[dict[str, Any], dict[str, Any]]:
    issuance = case.p("trust/handoff-issuance.json")
    evaluation = case.p("trust/handoff-evaluation.json")
    check_trust_snapshot(issuance)
    _need(is_obj(evaluation) and set(evaluation) == EVALUATION_FIELDS, _contra, "evaluation-fields")
    _need(evaluation["workflow_id"] == issuance["workflow_id"], _contra, "evaluation-workflow")
    issued = {k["key_id"]: k for k in issuance["keys"]}
    for key in evaluation["keys"]:
        _need(is_obj(key) and set(key) == KEY_FIELDS, _contra, "evaluation-key-fields")
        old = issued.get(key["key_id"])
        if old is not None:
            _need(
                all(old[f] == key[f] for f in ("public_key_hex", "issuer", "role")),
                _contra,
                "key-rebound",
            )
    return issuance, evaluation


def check_signature_trust(case: Case, run: RunDir, ctx: dict[str, Any]) -> None:
    """Handoff or resolution signature, evaluation trust and each recorded dispatch's authority."""
    issuance, evaluation = check_snapshot_files(case)
    if "reissue_of" in ctx:
        _verify_resolution(case, run, ctx, issuance)
        return
    record = ctx["record"]
    op = record["operation_id"]
    handoffs = run.files_in("signer", ".handoff.json")
    good: dict[str, dict[str, Any]] = {}
    first: Finding | None = None
    for data in handoffs.values():
        try:
            env = parse(data)
            if (
                is_obj(env)
                and is_obj(env.get("payload"))
                and env["payload"].get("operation_id") != op
            ):
                continue
        except (ValueError, UnicodeDecodeError):
            pass
        try:
            good[file_ref(data)] = verify_envelope(HANDOFF, data, record, issuance)
        except Finding as found:
            first = first or found
    if not good:
        raise first or _absent("no-handoff")
    ctx["handoffs"], ctx["evaluation"], ctx["issuance"] = good, evaluation, issuance
    run_trust = run.read("trust/handoff-evaluation.json")
    ctx["evaluation_ref"] = (
        file_ref(run_trust)
        if run_trust is not None
        else case.raw_ref("trust/handoff-evaluation.json")
    )
    for attempt in ctx.get("dispatches", []):
        _authorize_attempt(case, ctx, attempt)


def _authorize_attempt(case: Case, ctx: dict[str, Any], attempt: dict[str, Any]) -> None:
    payload = ctx["handoffs"].get(attempt["handoff_file_ref"])
    _need(payload is not None, _contra, "attempt-handoff-unknown")
    _need(
        attempt["trust_evaluation_file_ref"] == ctx["evaluation_ref"],
        _contra,
        "attempt-evaluation-ref",
    )
    evaluation, issuance, record = ctx["evaluation"], ctx["issuance"], ctx["record"]
    _need(
        payload["trust_snapshot_ref"] in evaluation["accepted_issuance_snapshots"],
        _contra,
        "issuance-snapshot-not-accepted",
    )
    issued = [k for k in issuance["keys"] if k["key_id"] == payload["key_id"]]
    current = [k for k in evaluation["keys"] if k["key_id"] == payload["key_id"]]
    _need(len(issued) == 1 and len(current) == 1, _contra, "evaluation-key-unknown")
    _need(current[0]["role"] == SIGNER_ROLE, _contra, "key-role")
    at = ctx["dispatch_times"].get(attempt["attempt_id"])
    _need(at is not None, _absent, "dispatch-time-missing")
    keys = (issued[0], current[0])
    for key in keys:
        if key["revoked_at"] is not None:
            _need(at < floor_s(ts_s(key["revoked_at"])), _contra, "key-revoked-at-dispatch")
    lower, upper = _dispatch_bounds(payload, record, keys, native_bounds(case))
    _need(lower < upper, _contra, "dispatch-window-empty")
    _need(lower <= at, _contra, "dispatch-before-window")
    _need(at < upper, _contra, "dispatch-after-window")


def _verify_resolution(
    case: Case, run: RunDir, ctx: dict[str, Any], issuance: dict[str, Any]
) -> None:
    original = ctx["reissue_of"]
    admission_record_ref(original)
    found: Finding | None = None
    for data in run.files_in("signer", ".resolution.json").values():
        try:
            payload = verify_envelope(RESOLUTION, data, original, issuance)
        except Finding as exc:
            found = found or exc
            continue
        if payload["presented_approval_ref"] != case.approval_id:
            continue
        _need(payload["presented_inputs"] == case.input_refs(), _contra, "presented-inputs")
        _need(
            payload["presented_approval_ref"] != original["approval_ref"],
            _contra,
            "resolution-same-receipt",
        )
        ctx["resolution_ref"] = file_ref(data)
        return
    raise found or _absent("no-resolution")


# ----------------------------------------------------------------------------
# Steps 5 and 6: the executor's streams and the provider's record.
# ----------------------------------------------------------------------------


class Streams:
    """The four execution streams, the operations file and the provider's record."""

    def __init__(self, run: RunDir) -> None:
        self.run = run
        self.records: dict[str, list[dict[str, Any]]] = {}
        self.problem: Finding | None = None
        for name, (schema, fields) in STREAMS.items():
            rows: list[dict[str, Any]] = []
            for line in run.lines(f"executor/{name}.jsonl"):
                try:
                    row = parse(line)
                except (ValueError, UnicodeDecodeError):
                    self.problem = self.problem or _contra(f"{name}-parse")
                    continue
                if not (
                    is_obj(row)
                    and set(row) == fields
                    and row["schema"] == schema
                    and row["contract_revision"] == CONTRACT_REVISION
                ):
                    self.problem = self.problem or _contra(f"{name}-fields")
                    continue
                rows.append(row)
            self.records[name] = rows
        self.dispatch_times: dict[str, datetime] = {}
        for line in run.lines("executor/raw/dispatch-times.jsonl"):
            try:
                entry = parse(line)
                self.dispatch_times[entry["attempt_id"]] = ts_exact(entry["at"])
            except (ValueError, KeyError, TypeError):
                self.problem = self.problem or _contra("dispatch-times-parse")
        sim = run.json("sim/sim.json")
        self.sim = sim if is_obj(sim) else None

    def of(self, name: str, **match: str) -> list[dict[str, Any]]:
        return [r for r in self.records[name] if all(r.get(k) == v for k, v in match.items())]


def check_execution(case: Case, st: Streams, ctx: dict[str, Any]) -> None:
    record = ctx["record"]
    op, key = record["operation_id"], idempotency_key(record)
    ctx["key"] = key
    attempts = st.of("attempts", operation_id=op)
    _need(bool(attempts), _absent, "no-dispatch-attempt")
    dispatches = [a for a in attempts if a["kind"] == "dispatch"]
    _need(bool(dispatches), _absent, "no-dispatch-attempt")
    handoffs = ctx.get("handoffs", {})
    for number, attempt in enumerate(attempts, start=1):
        _need(attempt["attempt_id"] == f"{op}-a{number}", _contra, "attempt-id-sequence")
        _need(attempt["run_id"] == case.run_id, _contra, "attempt-run-id")
        _need(all(attempt[k] == record[k] for k in SCOPE), _contra, "attempt-scope")
        _need(attempt["idempotency_key"] == key, _contra, "idempotency-key")
        _need(attempt["admission_ref"] == ref_of(record), _contra, "attempt-admission-ref")
        _need(attempt["handoff_file_ref"] in handoffs, _contra, "attempt-handoff-unknown")
        _need(
            attempt["tool"] == "refund" and attempt["kind"] in ("dispatch", "reconcile_lookup"),
            _contra,
            "attempt-kind",
        )
        _need(typed_equal(attempt["arguments"], record["arguments"]), _contra, "attempt-arguments")
        digest = file_ref(jcs(attempt["arguments"]))
        _need(
            attempt["arguments_digest"] == digest == "sha256:" + case.pic_args_digest,
            _contra,
            "arguments-digest",
        )
    ctx["attempts"], ctx["dispatches"] = attempts, dispatches
    ctx["dispatch_times"] = st.dispatch_times
    if st.sim is None:
        raise _absent("provider-record-missing")
    applies = [
        r
        for r in st.sim.get("requests", [])
        if r.get("kind") == "apply" and r.get("idempotency_key") == key
    ]
    _need(len(applies) == len(dispatches), _contra, "apply-count")
    ops_file = ctx.get("operations")
    if ops_file is not None:
        stored = ops_file.get(key)
        _need(
            is_obj(stored)
            and stored.get("operation_id") == op
            and stored.get("pic_args_digest") == case.pic_args_digest
            and typed_equal(stored.get("arguments"), record["arguments"]),
            _contra,
            "operation-record",
        )


def check_effect(case: Case, run: RunDir, st: Streams, ctx: dict[str, Any]) -> None:
    record, key = ctx["record"], ctx["key"]
    op = record["operation_id"]
    dispatches, attempts = ctx["dispatches"], {a["attempt_id"]: a for a in ctx["attempts"]}
    keyed = st.of("effects", idempotency_key=key)
    _need(all(e["operation_id"] == op for e in keyed), _contra, "effect-operation-id-binding")
    _need(len(keyed) <= 1, _contra, "effect-count-per-key")
    _need(len(keyed) == 1, _absent, "effect-missing")
    effect = keyed[0]
    _need(
        all(effect[k] == record[k] for k in SCOPE) and effect["admission_ref"] == ref_of(record),
        _contra,
        "effect-scope",
    )
    _need(typed_equal(effect["arguments"], record["arguments"]), _contra, "effect-arguments")
    digest = file_ref(jcs(effect["arguments"]))
    _need(
        effect["arguments_digest"] == digest == "sha256:" + case.pic_args_digest,
        _contra,
        "effect-arguments-digest",
    )
    origin = attempts.get(effect["attempt_id"])
    _need(
        origin is not None
        and origin["kind"] == "dispatch"
        and ref_of(origin) == effect["attempt_ref"]
        and origin in dispatches,
        _contra,
        "effect-attempt",
    )
    effect_ref = ref_of(effect)
    observed = [
        o
        for o in st.of("observations", idempotency_key=key)
        if o["observation_kind"] == "effect_present" and effect_ref in o["effect_refs"]
    ]
    _need(bool(observed), _absent, "observation-missing")
    good = None
    for obs in observed:
        raw = run.read(f"executor/raw/{obs['observation_id']}.json")
        if raw is None or file_ref(raw) != obs["source_file_ref"]:
            continue
        try:
            snapshot = parse(raw)
        except ValueError:
            continue
        rows = [r for r in snapshot.get("ledger", []) if r.get("effect_id") == effect["effect_id"]]
        if (
            len(rows) == 1
            and rows[0].get("operation_id") == op
            and rows[0].get("idempotency_key") == key
            and typed_equal(rows[0].get("arguments"), record["arguments"])
            and rows[0].get("attempt_id") == effect["attempt_id"]
            and sum(1 for r in snapshot["ledger"] if r.get("idempotency_key") == key) == 1
        ):
            good = obs
            break
    if good is None:
        raise _contra("readback-disagrees")
    _need(
        good["attempt_ref"] == ref_of(attempts[good["attempt_id"]]), _contra, "observation-attempt"
    )
    outcomes = [
        o
        for o in st.of("outcomes", idempotency_key=key)
        if o["status"] == "observed_success"
        and o["effect_ref"] == effect_ref
        and o["observation_ref"] == ref_of(good)
    ]
    _need(len(outcomes) == 1, _absent, "outcome-missing")
    _need(
        outcomes[0]["attempt_ref"] == ref_of(attempts[outcomes[0]["attempt_id"]]),
        _contra,
        "outcome-attempt",
    )
    _check_cutoff(case, run, record, effect, good, outcomes[0])


def _check_cutoff(
    case: Case,
    run: RunDir,
    record: dict[str, Any],
    effect: dict[str, Any],
    obs: dict[str, Any],
    outcome: dict[str, Any],
) -> None:
    scenario = case.name.split("-")[0].lower()
    raw = run.read(f"executor/report-context-{scenario}.json")
    if raw is None:
        raise _absent("report-context-missing")
    try:
        context = parse(raw)
    except ValueError:
        raise _contra("report-context-fields") from None
    _need(is_obj(context) and set(context) == REPORT_FIELDS, _contra, "report-context-fields")
    _need(
        context["run_id"] == case.run_id and all(context[k] == record[k] for k in SCOPE),
        _contra,
        "report-context-scope",
    )
    try:
        cutoff = ts_ms(context["report_cutoff"])
        within = all(
            ts_s(x) <= cutoff
            for x in (obs["observed_at"], obs["recorded_at"], outcome["recorded_at"])
        )
    except ValueError:
        raise _contra("report-context-time") from None
    _need(within, _absent, "success-after-cutoff")


# ----------------------------------------------------------------------------
# Case and run judgement.
# ----------------------------------------------------------------------------


def judge_case(  # noqa: C901
    run: RunDir, name: str, adm: Admission, st: Streams, operations: dict[str, Any] | None
) -> dict[str, str]:
    case = Case(run, name)
    out = {step: NOT_REACHED for step in STEPS}
    ctx: dict[str, Any] = {"operations": operations}

    def attempt(step: str, fn: Any) -> bool:
        try:
            fn()
        except Finding as found:
            out[step] = found.verdict
            return False
        out[step] = ESTABLISHED
        return True

    pic_finding: Finding | None = None
    try:
        check_pic(case)
    except Finding as found:
        pic_finding = found
    if pic_finding is not None:
        out["input_pic"] = pic_finding.verdict
        if pic_finding.kind == "REFUSED" and runner_allowed_refused(case) and case.name:
            out["input_pic"] = _contra(f"runner-allowed-{pic_finding.code}").verdict
        return _downstream_check(out, case, adm, st)
    case.consumed_at = ""
    consumed = str(case.pic_evaluated_at)  # type: ignore[attr-defined]
    records = adm.for_decision(str(case.claim["decision_id"]))  # type: ignore[attr-defined]
    mine = [r for r in records if r.get("approval_ref") == case.claim["approval_ref"]]  # type: ignore[attr-defined]
    if mine and is_obj(mine[0]) and isinstance(mine[0].get("committed_at"), str):
        consumed = mine[0]["committed_at"].replace("Z", ".000Z")
    out["input_pic"] = ESTABLISHED
    try:
        check_aps(case, consumed)
    except Finding as found:
        out["input_aps"] = found.verdict
        return _downstream_check(out, case, adm, st, found.code)
    out["input_aps"] = ESTABLISHED
    if not attempt("admission", lambda: check_admission(case, adm, ctx)):
        return out
    if "reissue_of" in ctx:
        _reissue(out, case, run, st, ctx, attempt)
        return out
    key = idempotency_key(ctx["record"])
    ctx["key"] = key
    ctx["dispatches"] = [
        a
        for a in st.of("attempts", operation_id=ctx["record"]["operation_id"])
        if a["kind"] == "dispatch"
    ]
    ctx["dispatch_times"] = st.dispatch_times
    if not attempt("signature_trust", lambda: check_signature_trust(case, run, ctx)):
        return out
    if not attempt("execution", lambda: check_execution(case, st, ctx)):
        return out
    attempt("observed_effect", lambda: check_effect(case, run, st, ctx))
    case_ctx_store[name] = ctx
    return out


case_ctx_store: dict[str, dict[str, Any]] = {}


def _reissue(
    out: dict[str, str], case: Case, run: RunDir, st: Streams, ctx: dict[str, Any], attempt: Any
) -> None:
    if not attempt("signature_trust", lambda: check_signature_trust(case, run, ctx)):
        return
    out["signature_trust"] = "ESTABLISHED"
    original = ctx["reissue_of"]
    resolution = ctx["resolution_ref"]
    # A resolution authorizes nothing: no attempt may name it as its handoff.
    if any(a["handoff_file_ref"] == resolution for a in st.records["attempts"]):
        out["execution"] = _contra("resolution-used-as-handoff").verdict
        return
    del original
    out["execution"] = NOT_REACHED
    out["observed_effect"] = NOT_REACHED
    out["admission"] = "ESTABLISHED"
    ctx["terminal"] = "resolved_existing"


def _downstream_check(
    out: dict[str, str], case: Case, adm: Admission, st: Streams, code: str = ""
) -> dict[str, str]:
    """After a refusal at an input layer nothing downstream may exist for the case."""
    claim: Any = getattr(case, "claim", None)
    decision = claim["decision_id"] if is_obj(claim) else _claim_decision(case)
    approval = claim["approval_ref"] if is_obj(claim) else _claim_approval(case)
    refs = case.input_refs() if not case.missing and not case.bad else {}
    leaked = [
        r
        for r in adm.for_decision(str(decision))
        if r.get("approval_ref") == approval
        and (not refs or all(r.get(field) == ref for field, ref in refs.items()))
    ]
    if leaked:
        out["admission"] = _contra("admitted-after-refusal").verdict
        return out
    if approval in adm.consumed and code != "APPROVAL_AFTER_CONSUMPTION":
        out["admission"] = _contra("consumed-after-refusal").verdict
    return out


def _claim_text(case: Case) -> dict[str, Any]:
    prop: Any = case.parsed.get("inputs/pic-proposal.json")
    try:
        return parse(prop["claims"][0]["text"].encode("utf-8"))  # type: ignore[no-any-return]
    except (TypeError, KeyError, IndexError, ValueError, AttributeError):
        return {}


def _claim_decision(case: Case) -> Any:
    return _claim_text(case).get("decision_id")


def _claim_approval(case: Case) -> Any:
    return _claim_text(case).get("approval_ref")


def case_ok(steps: dict[str, str]) -> bool:
    for position, step in enumerate(STEPS):
        verdict = steps[step]
        if verdict == ESTABLISHED:
            continue
        if verdict.startswith("REFUSED:") or verdict == NOT_REACHED:
            return all(steps[s] == NOT_REACHED for s in STEPS[position + 1 :]) and (
                verdict != NOT_REACHED or position > 0
            )
        return False
    return True


def run_checks(  # noqa: C901
    run: RunDir, st: Streams, adm: Admission, judged: dict[str, dict[str, str]]
) -> dict[str, str]:
    """Checks over the whole run: counts per key, replays, orphans and alternate arguments."""
    out: dict[str, str] = {}
    admitted: dict[str, dict[str, Any]] = {}
    for name in judged:
        ctx = case_ctx_store.get(f"{run.root}|{name}") or case_ctx_store.get(name)
        if ctx and "record" in ctx:
            admitted[idempotency_key(ctx["record"])] = ctx["record"]
    for count in _counts(st.records["effects"], "idempotency_key").values():
        if count > 1:
            out["effect_count_per_key"] = _contra(f"{count}-effects-for-one-key").verdict
    out.setdefault("effect_count_per_key", ESTABLISHED)
    orphans = [
        r for stream in st.records.values() for r in stream if r["idempotency_key"] not in admitted
    ]
    out["no_orphan_records"] = (
        _contra("record-without-verified-admission").verdict if orphans else ESTABLISHED
    )
    alternates = False
    for key, record in admitted.items():
        for stream in ("attempts", "effects"):
            for row in st.of(stream, idempotency_key=key):
                alternates = alternates or not typed_equal(row["arguments"], record["arguments"])
        if st.sim is not None:
            for row in st.sim.get("ledger", []):
                if row.get("idempotency_key") == key and not typed_equal(
                    row.get("arguments"), record["arguments"]
                ):
                    alternates = True
    out["no_alternate_arguments"] = (
        _contra("arguments-differ-from-admission").verdict if alternates else ESTABLISHED
    )
    replay = ESTABLISHED
    for key, record in admitted.items():
        handoffs = [
            n
            for n, data in run.files_in("signer", ".handoff.json").items()
            if _handoff_op(data) == record["operation_id"]
        ]
        applies = 0
        if st.sim is not None:
            applies = sum(
                1
                for r in st.sim.get("requests", [])
                if r.get("kind") == "apply" and r.get("idempotency_key") == key
            )
        if len(handoffs) > 1 and (len(st.of("effects", idempotency_key=key)) != 1 or applies != 1):
            replay = _contra("replayed-handoff-redispatched").verdict
    out["replay_single_effect"] = replay
    total = len(st.records["effects"])
    ledger = len(st.sim.get("ledger", [])) if st.sim is not None else total
    out["effect_count"] = (
        ESTABLISHED
        if total == ledger == len(admitted_effects(st, admitted))
        else _contra(f"effects-{total}-ledger-{ledger}").verdict
    )
    return out


def admitted_effects(st: Streams, admitted: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in st.records["effects"] if e["idempotency_key"] in admitted]


def _counts(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[row[field]] = out.get(row[field], 0) + 1
    return out


def _handoff_op(data: bytes) -> Any:
    try:
        env = parse(data)
        return env["payload"]["operation_id"]
    except (ValueError, KeyError, TypeError):
        return None


def judge_run(root: Path) -> dict[str, Any]:
    """Judge every case directory and the run as a whole; the structure the CLI prints."""
    run = RunDir(root)
    adm = Admission(run)
    st = Streams(run)
    operations = (
        run.json("executor/operations.json") if run.read("executor/operations.json") else None
    )
    case_ctx_store.clear()
    judged = {
        name: judge_case(run, name, adm, st, operations if is_obj(operations) else None)
        for name in run.cases()
    }
    if st.problem is not None:
        for steps in judged.values():
            if steps["execution"] == ESTABLISHED:
                steps["execution"] = st.problem.verdict
    checks = run_checks(run, st, adm, judged)
    ok = all(case_ok(s) for s in judged.values()) and all(v == ESTABLISHED for v in checks.values())
    ok = ok and bool(judged)
    return {"suite": SUITE, "run": str(root), "ok": ok, "cases": judged, "run_checks": checks}


def render(result: dict[str, Any]) -> str:
    lines = []
    for name, steps in result["cases"].items():
        mark = "ok  " if case_ok(steps) else "FAIL"
        lines.append(f"{mark} {name}")
        for step in STEPS:
            lines.append(f"       {step:16} {steps[step]}")
    for name, verdict in result["run_checks"].items():
        lines.append(f"{'ok  ' if verdict == ESTABLISHED else 'FAIL'} run:{name:26} {verdict}")
    return "\n".join(lines)


def check(root: Path | None = None) -> tuple[int, list[str]]:
    """Judge each shipped case against the verdicts the manifest records for it."""
    base = root or ROOT
    manifest = json.loads((base / "MANIFEST.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    answered = 0
    for vector in manifest["vectors"]:
        result = judge_run(base / vector["path"])
        expected = vector["expected"]
        got = {
            "steps": {s: result["cases"][vector["case"]][s] for s in STEPS},
            "run_checks": result["run_checks"],
        }
        want = {"steps": expected["steps"], "run_checks": expected["run_checks"]}
        answered += 1
        if got != want:
            errors.append(f"{vector['id']}: expected {want} but the reader derived {got}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus with the reference reader and write the package's report."""
    directory = Path(root)
    if verifier is not None:
        print(
            f"the verifier {' '.join(verifier)!r} did NOT run: {SUITE} is judged only by "
            "this package's own reader and has no external-verifier contract"
        )
        return 2
    answered, errors = check(directory)
    manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
    total = len(manifest["vectors"])
    for error in errors:
        print(error)
    print(
        f"{SUITE}: reference reader answered {answered} of {total} cases, "
        f"{len(errors)} disagreements"
    )
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE,
        "rail": "own-reader",
        "verifier": {"command": None, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {
            "vectors": total,
            "conform": total - len(errors),
            "fail": len(errors),
            "suiteRefusals": 0,
        },
        "failures": errors,
    }
    Path(report_path).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("run_dir", nargs="?", help="a retained run directory to judge")
    parser.add_argument("--json", action="store_true", help="print the verdicts as JSON")
    args = parser.parse_args(argv)
    if args.run_dir:
        result = judge_run(Path(args.run_dir))
        print(json.dumps(result, sort_keys=True, indent=2) if args.json else render(result))
        return 0 if result["ok"] else 1
    answered, errors = check()
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
