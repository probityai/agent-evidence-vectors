"""Write the lifecycle-binding corpus from our own bytes.

Keys come from seeds under the neutral label ``aev-lifecycle-binding-vectors/``; every record is
written here. Four families: eleven lifecycle shapes, the binding-scope vectors V1 to V11 and
C0, the tag-confusion family (domain separation, including a signature over a DSSE
pre-authentication encoding replayed as a record signature), and JSON admissibility. Every case
carries ``expected`` (positive, negative or absent) and a ``does_not_establish`` sentence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import a2ajcs  # noqa: E402
from agent_evidence_vectors import lifecyclebinding as reader  # noqa: E402
from agent_evidence_vectors.monitorcoverage import _json, _sha  # noqa: E402

SUITE = reader.SUITE
SEED = "aev-lifecycle-binding-vectors/"
X = "sha256:" + hashlib.sha256(b"action X").hexdigest()
Y = "sha256:" + hashlib.sha256(b"action Y").hexdigest()
DOES_NOT_ESTABLISH = (
    "that the executed bytes themselves were observed: the claim is about records, and an "
    "execution record is the executor's own report"
)
PRODUCERS = ("governor", "executor")


def _seed(name: str) -> bytes:
    return hashlib.sha256((SEED + name).encode()).digest()


BINDINGS = {
    p: {"public_key_hex": bytes(rail.ed25519_public_key(_seed(p))).hex(), "suite": "ed25519"}
    for p in PRODUCERS
}
ACTIVE = {p: {"state": "active"} for p in PRODUCERS}
REVOKED_EXECUTOR = {**ACTIVE, "executor": {"state": "revoked"}}
#: Cases whose consumer binds one key under two producer names.
CASE_BINDINGS = {
    "scope-v11-executor-key-under-second-name": {**BINDINGS, "governor-2": BINDINGS["executor"]}
}
REVOKED_GOVERNOR = {**ACTIVE, "governor": {"state": "revoked"}}


def tag(kind: str, purpose: str, version: str = "v1") -> bytes:
    return f"agent-evidence/lifecycle-binding/{version}/{kind}/{purpose}".encode("ascii")


def hash_body(record: dict) -> bytes:
    body = {k: v for k, v in record.items() if k != "integrity"}
    rest = {
        k: v for k, v in record.get("integrity", {}).items() if k not in ("current", "signature")
    }
    if rest:
        body["integrity"] = rest
    return a2ajcs.canonicalize(body)


def seal(
    record: dict,
    signer: str | None = None,
    suite: str = "ed25519",
    hash_tag: bytes | None = None,
    sig_tag: bytes | None = None,
    separator: bytes = b"\n",
) -> dict:
    record = copy.deepcopy(record)
    record["integrity"] = {
        k: v for k, v in record.get("integrity", {}).items() if k not in ("current", "signature")
    }
    current = (
        "sha256:"
        + hashlib.sha256(
            (hash_tag or tag(record["artifact_type"], "hash")) + separator + hash_body(record)
        ).hexdigest()
    )
    record["integrity"]["current"] = current
    message = (
        (sig_tag or tag(record["artifact_type"], "signature"))
        + b"\n"
        + a2ajcs.canonicalize({"current": current, "suite": suite})
    )
    sig = bytes(rail.ed25519_sign(_seed(signer or record["producer"]), message))
    record["integrity"]["signature"] = {"alg": "ed25519", "value": sig.hex()}
    return record


def decision(rid: str = "d-1") -> dict:
    return seal(
        {
            "lifecycle_version": "v1",
            "artifact_type": "decision",
            "record_id": rid,
            "producer": "governor",
            "integrity": {},
            "verb": "release",
        }
    )


def control(
    rid: str,
    digest: str = X,
    side: str = "issuer",
    instruction: str = "pause-1",
    decision_id: str = "d-1",
    producer: str | None = None,
    signer: str | None = None,
) -> dict:
    return seal(
        {
            "lifecycle_version": "v1",
            "artifact_type": "control",
            "record_id": rid,
            "producer": producer or ("governor" if side == "issuer" else "executor"),
            "integrity": {},
            "decision_ref": {"record_id": decision_id},
            "instruction_id": instruction,
            "boundary_side": side,
            "authorized_action_digest": digest,
        },
        signer,
    )


def execution(
    rid: str,
    digest: str = X,
    instruction: str = "pause-1",
    decision_id: str = "d-1",
    signer: str | None = None,
) -> dict:
    return seal(
        {
            "lifecycle_version": "v1",
            "artifact_type": "execution",
            "record_id": rid,
            "producer": "executor",
            "integrity": {},
            "decision_ref": {"record_id": decision_id},
            "instruction_id": instruction,
            "executed_action_digest": digest,
        },
        signer,
    )


def _flip(record: dict, member: str, value: Any) -> dict:
    out = copy.deepcopy(record)
    out[member] = value
    return out


def complete() -> list[dict]:
    return [
        decision(),
        control("c-issuer"),
        control("c-receiver", side="receiver"),
        execution("e-1"),
    ]


Case = tuple[str, str, str, list[Any] | str, dict, str, str, str]
# (id, family, expected class, records or raw text, revocation, decision, reason, edit)


def shapes() -> list[Case]:
    d, ci, cr, e = complete()
    return [
        (
            "shape-complete",
            "lifecycle-shape",
            "positive",
            [d, ci, cr, e],
            ACTIVE,
            "satisfied",
            "satisfied",
            "decision, issuer and receiver controls, execution: all agree",
        ),
        (
            "shape-issuer-only-authorization",
            "lifecycle-shape",
            "positive",
            [d, ci, e],
            ACTIVE,
            "satisfied",
            "satisfied",
            "no receiving-side record: the profile does not require one",
        ),
        (
            "shape-no-execution",
            "lifecycle-shape",
            "absent",
            [d, ci, cr],
            ACTIVE,
            "missing",
            "missing",
            "authorized, never reported executed",
        ),
        (
            "shape-no-control",
            "lifecycle-shape",
            "absent",
            [d, e],
            ACTIVE,
            "not_evaluated",
            "not_evaluated",
            "an execution no authorization covers",
        ),
        (
            "shape-no-decision",
            "lifecycle-shape",
            "absent",
            [ci, cr, e],
            ACTIVE,
            "missing",
            "missing",
            "the cited decision record is absent",
        ),
        (
            "shape-authorized-differs-from-executed",
            "lifecycle-shape",
            "negative",
            [d, ci, cr, execution("e-1", Y)],
            ACTIVE,
            "failure",
            "failure",
            "the executor reports another action",
        ),
        (
            "shape-two-instructions-both-complete",
            "lifecycle-shape",
            "positive",
            [
                d,
                ci,
                cr,
                e,
                control("c-2", instruction="pause-2"),
                execution("e-2", instruction="pause-2"),
            ],
            ACTIVE,
            "satisfied",
            "satisfied",
            "two groups under one decision, each complete",
        ),
        (
            "shape-broken-decision",
            "lifecycle-shape",
            "negative",
            [_flip(d, "verb", "hold"), ci, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "the decision edited after sealing",
        ),
        (
            "shape-broken-control",
            "lifecycle-shape",
            "negative",
            [d, _flip(ci, "authorized_action_digest", Y), cr, e],
            ACTIVE,
            "failure",
            "failure",
            "a control edited after sealing",
        ),
        (
            "shape-broken-execution",
            "lifecycle-shape",
            "negative",
            [d, ci, cr, _flip(e, "executed_action_digest", Y)],
            ACTIVE,
            "failure",
            "failure",
            "an execution edited after sealing",
        ),
        (
            "shape-revoked-governor",
            "lifecycle-shape",
            "absent",
            [d, ci, cr, e],
            REVOKED_GOVERNOR,
            "not_evaluated",
            "not_evaluated",
            "the governor's binding is revoked in the snapshot",
        ),
    ]


def scope() -> list[Case]:
    d, ci, cr, honest = complete()
    unsigned = copy.deepcopy(honest)
    unsigned["integrity"]["signature"]["value"] = "00" * 64
    return [
        (
            "scope-v1-cross-instruction",
            "binding-scope",
            "negative",
            [d, ci, cr, execution("e-1", instruction="pause-2")],
            ACTIVE,
            "not_evaluated",
            "not_evaluated",
            "V1: the execution reports pause-2; only pause-1 was authorized",
        ),
        (
            "scope-v2-receiver-disagrees",
            "binding-scope",
            "negative",
            [d, ci, control("c-receiver", Y, side="receiver"), honest],
            ACTIVE,
            "failure",
            "failure",
            "V2: the issuer authorized X, the receiver recorded Y, the executor reports X",
        ),
        (
            "scope-v3-duplicate-execution-identity",
            "binding-scope",
            "negative",
            [d, ci, cr, execution("e-1"), execution("e-1", Y)],
            ACTIVE,
            "indeterminate",
            "indeterminate",
            "V3: two executions share one id, one X and one Y",
        ),
        (
            "scope-v3b-duplicate-identity-reordered",
            "binding-scope",
            "negative",
            [d, ci, cr, execution("e-1", Y), execution("e-1")],
            ACTIVE,
            "indeterminate",
            "indeterminate",
            "V3b: the same set in the other order",
        ),
        (
            "scope-v4-revoked-executor",
            "binding-scope",
            "negative",
            [d, ci, cr, honest],
            REVOKED_EXECUTOR,
            "not_evaluated",
            "not_evaluated",
            "V4: a valid signature under a revoked executor binding",
        ),
        (
            "scope-v5-unbound-key",
            "binding-scope",
            "negative",
            [d, ci, cr, execution("e-1", signer="unbound")],
            ACTIVE,
            "failure",
            "failure",
            "V5: an execution sealed by a key nobody bound",
        ),
        (
            "scope-v6-unsigned-valid-self-hash",
            "binding-scope",
            "negative",
            [d, ci, cr, unsigned],
            ACTIVE,
            "failure",
            "failure",
            "V6: the self-hash recomputes; the signature is zeroed",
        ),
        (
            "scope-v7-honest-revoked-executor",
            "binding-scope",
            "negative",
            [d, ci, cr, honest],
            REVOKED_EXECUTOR,
            "not_evaluated",
            "not_evaluated",
            "V7: an honest execution under a revoked binding",
        ),
        (
            "scope-v8-duplicate-identity-other-action",
            "binding-scope",
            "negative",
            [d, ci, cr, honest, execution("e-2", Y), execution("e-2", Y)],
            ACTIVE,
            "indeterminate",
            "indeterminate",
            "V8: two byte-identical executions share one id and report another action",
        ),
        (
            "scope-v9-receiver-only-control",
            "binding-scope",
            "negative",
            [d, cr, honest],
            ACTIVE,
            "missing",
            "missing",
            "V9: only the executor's receiver-side control; no issuer-side control authorized",
        ),
        (
            "scope-v10-issuer-control-signed-by-executor",
            "binding-scope",
            "negative",
            [d, control("c-issuer", producer="executor"), honest],
            ACTIVE,
            "failure",
            "failure",
            "V10: the executor writes and signs the issuer-side control for its own execution",
        ),
        (
            "scope-v11-executor-key-under-second-name",
            "binding-scope",
            "negative",
            [d, control("c-issuer", producer="governor-2", signer="executor"), honest],
            {**ACTIVE, "governor-2": {"state": "active"}},
            "failure",
            "failure",
            "V11: the executor's key, bound again as governor-2, signs the issuer-side control",
        ),
        (
            "scope-c0-honest",
            "binding-scope",
            "positive",
            [d, ci, cr, honest],
            ACTIVE,
            "satisfied",
            "satisfied",
            "C0: control",
        ),
    ]


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode(), len(payload), payload)


def tags() -> list[Case]:
    d, ci, cr, e = complete()
    as_decision_tag = seal(ci, hash_tag=tag("decision", "hash"))
    sig_from_decision = seal(ci, sig_tag=tag("decision", "signature"))
    untagged = copy.deepcopy(ci)
    untagged["integrity"]["current"] = "sha256:" + hashlib.sha256(hash_body(ci)).hexdigest()
    untagged = seal(untagged, hash_tag=b"", separator=b"")
    crlf = seal(ci, separator=b"\r\n")
    double_lf = seal(ci, separator=b"\n\n")
    alg_relabelled = copy.deepcopy(ci)
    alg_relabelled["integrity"]["signature"]["alg"] = "ml-dsa-65"
    other_suite = seal(ci, suite="ed448")
    dsse = copy.deepcopy(ci)
    pae = _dsse_pae(
        "application/vnd.agent-evidence.lifecycle-binding+json",
        a2ajcs.canonicalize({"current": ci["integrity"]["current"], "suite": "ed25519"}),
    )
    dsse["integrity"]["signature"]["value"] = bytes(rail.ed25519_sign(_seed("governor"), pae)).hex()
    rewritten = _flip(seal(_flip(ci, "note", "sealed body")), "note", "rewritten body")
    out: list[Case] = [
        (
            "tag-a1-hashed-under-another-type-tag",
            "tag-confusion",
            "negative",
            [d, as_decision_tag, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "A1: a control's body hashed under the decision hash tag",
        ),
        (
            "tag-a2-decision-retyped-as-execution",
            "tag-confusion",
            "negative",
            [
                d,
                ci,
                cr,
                _flip(
                    _flip(
                        _flip(
                            _flip(_flip(d, "artifact_type", "execution"), "record_id", "e-x"),
                            "decision_ref",
                            {"record_id": "d-1"},
                        ),
                        "instruction_id",
                        "pause-1",
                    ),
                    "executed_action_digest",
                    X,
                ),
            ],
            ACTIVE,
            "failure",
            "failure",
            "A2: a decision's integrity carried onto a record typed execution",
        ),
        (
            "tag-a3-decision-signature-on-control",
            "tag-confusion",
            "negative",
            [d, sig_from_decision, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "A3: a signature over the decision signature tag on a control",
        ),
        (
            "tag-a5-untagged-pre-image",
            "tag-confusion",
            "negative",
            [d, untagged, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "A5: hash and signature over untagged bytes",
        ),
        (
            "tag-a6-unregistered-type",
            "tag-confusion",
            "negative",
            [d, _flip(ci, "artifact_type", "approval"), cr, e],
            ACTIVE,
            "refused",
            "unregistered_tag",
            "A6: a type no tag is registered for, refused with no nearest match",
        ),
        (
            "tag-a7-case-folded-type",
            "tag-confusion",
            "negative",
            [d, _flip(ci, "artifact_type", "Control"), cr, e],
            ACTIVE,
            "refused",
            "unregistered_tag",
            "A7: a type differing only in case",
        ),
        (
            "tag-a8-crlf-separator",
            "tag-confusion",
            "negative",
            [d, crlf, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "A8: CRLF between the tag and the bytes",
        ),
        (
            "tag-a8-double-lf-separator",
            "tag-confusion",
            "negative",
            [d, double_lf, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "A8: two LF between the tag and the bytes",
        ),
        (
            "tag-a9-other-version",
            "tag-confusion",
            "negative",
            [d, _flip(ci, "lifecycle_version", "v2"), cr, e],
            ACTIVE,
            "refused",
            "unregistered_tag",
            "A9: a version no tag is registered for",
        ),
        (
            "tag-a9-body-rewritten-after-signing",
            "tag-confusion",
            "negative",
            [d, rewritten, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "A9: a member rewritten after the hash and signature",
        ),
        (
            "tag-a11a-wire-alg-relabelled",
            "tag-confusion",
            "positive",
            [d, alg_relabelled, cr, e],
            ACTIVE,
            "satisfied",
            "satisfied",
            "A11a: the wire alg is informative only",
        ),
        (
            "tag-a11b-other-suite-in-pre-image",
            "tag-confusion",
            "negative",
            [d, other_suite, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "A11b: the signature input names a suite the binding does not",
        ),
        (
            "tag-cross-format-dsse-pae-replayed",
            "tag-confusion",
            "negative",
            [d, dsse, cr, e],
            ACTIVE,
            "failure",
            "failure",
            "a signature over a DSSE pre-authentication encoding presented as a record signature",
        ),
    ]
    return out


def admissibility() -> list[Case]:
    text = json.dumps(complete())
    negzero = complete()
    negzero[0] = seal(_flip(negzero[0], "weight", 0))
    return [
        (
            "json-duplicate-after-escape",
            "admissibility",
            "negative",
            text.replace('"verb": "release"', '"verb": "release", "v\\u0065rb": "hold"', 1),
            ACTIVE,
            "refused",
            "no_duplicate_member",
            "a member repeated under an escaped spelling",
        ),
        (
            "json-lone-surrogate",
            "admissibility",
            "negative",
            text.replace('"verb": "release"', '"verb": "rel\\ud800ease"', 1),
            ACTIVE,
            "refused",
            "record_shape",
            "a lone surrogate in a string",
        ),
        (
            "json-number-overflow",
            "admissibility",
            "negative",
            text.replace('"verb": "release"', '"verb": "release", "weight": 1E400', 1),
            ACTIVE,
            "refused",
            "record_shape",
            "1E400 has no finite value",
        ),
        (
            "json-unsafe-integer",
            "admissibility",
            "negative",
            text.replace('"verb": "release"', '"verb": "release", "weight": 9007199254740993', 1),
            ACTIVE,
            "refused",
            "record_shape",
            "9007199254740993 is outside the I-JSON integer range",
        ),
        (
            "json-negative-zero-admitted",
            "admissibility",
            "positive",
            json.dumps(negzero).replace('"weight": 0', '"weight": -0', 1),
            ACTIVE,
            "satisfied",
            "satisfied",
            "-0 is the number 0 and its RFC 8785 form is 0, so the sealed hash still recomputes",
        ),
    ]


def cases() -> list[Case]:
    return shapes() + scope() + tags() + admissibility()


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
    entries = []
    for name, family, expected, records, revocation, decision_value, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        record = {
            "bindings": CASE_BINDINGS.get(name, BINDINGS),
            "does_not_establish": DOES_NOT_ESTABLISH,
            "records_text": records if isinstance(records, str) else json.dumps(records),
            "revocation": revocation,
        }
        data = _json(record)
        (directory / "record.json").write_bytes(data)
        entries.append(
            {
                "edit": edit,
                "expected": {"decision": decision_value, "reason": reason},
                "expectedClass": expected,
                "family": family,
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
            }
        )
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "keySeedLabel": SEED,
        "revision": 1,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": (
            "verifier record.json --json; exit 0 satisfied, 1 failure or "
            "refused, 2 missing, not_evaluated or indeterminate"
        ),
        "vectors": entries,
    }
    words = [e["expected"]["decision"] for e in entries]
    manifest["counts"] = {w: words.count(w) for w in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    print(json.dumps(generate()["counts"], sort_keys=True))
