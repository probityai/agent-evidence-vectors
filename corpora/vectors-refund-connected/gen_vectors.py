"""Build the refund-connected manifest from the retained run trees, byte for byte.

The corpus is two retained runs of the connected refund pilot (J01), copied from
``examples/checkout-runner/connected/runs`` at commit
``dcc07c3cdde0ca4beab6f7b5afe6a7e15801eb58`` of the pilot's repository. Run r2 is
the run in which every layer held; run r1 is the run before the dispatch-window
fix, which stopped at an execution step. The manifest records, for every case of
every run, the verdict the reference reader derives at each of the six steps from
the retained bytes alone, and the digest of every file.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import refundconnected as reader  # noqa: E402

SUITE = reader.SUITE
SOURCE_COMMIT = "dcc07c3cdde0ca4beab6f7b5afe6a7e15801eb58"
SOURCE_PATH = "examples/checkout-runner/connected/runs"
RUNS = {
    "r1": "source/j01-connected-20261028-r1",
    "r2": "source/j01-connected-20261028-r2",
}
NOTE = {
    "r1": "run before the dispatch-window fix: the executor stopped before it dispatched",
    "r2": "run after the fix: every layer held and each effect is bound to its operation",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def run_files(root: Path, rel: str) -> dict[str, str]:
    """Every file of one run tree with its SHA-256, keyed by path inside the tree."""
    base = root / rel
    return {
        p.relative_to(base).as_posix(): _sha(p.read_bytes())
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }


def corpus_digest(manifest: dict[str, Any], root: str | Path = ROOT) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    runs = {}
    for key, entry in manifest["runs"].items():
        files = run_files(base, entry["path"])
        if files != entry["files"]:
            raise ValueError(f"{key}: the run tree differs from the manifest")
        runs[key] = {**entry, "files": files}
    return _sha(_json({"runs": runs, "vectors": manifest["vectors"]}))


def _outcome(steps: dict[str, str]) -> str:
    """One word per vector, from the statuses its steps carry.

    The corpus has no accept/reject split because its expectation is a table of step
    statuses. A vector counts as `refused` when any step is refused, `established`
    when every step is established, and `not_established` otherwise.
    """
    statuses = list(steps.values())
    if any(status.startswith("REFUSED") for status in statuses):
        return "refused"
    if all(status == "ESTABLISHED" for status in statuses):
        return "established"
    return "not_established"


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write the manifest from the run trees and return it."""
    runs = {
        key: {"files": run_files(root, rel), "note": NOTE[key], "path": rel}
        for key, rel in RUNS.items()
    }
    vectors = []
    for key, rel in RUNS.items():
        result = reader.judge_run(root / rel)
        for case, steps in result["cases"].items():
            vectors.append(
                {
                    "case": case,
                    "expected": {"run_checks": result["run_checks"], "steps": steps},
                    "id": f"{key}-{case}",
                    "path": rel,
                    "run": key,
                }
            )
    manifest = {
        "contractId": "https://probityai.github.io/agent-evidence-vectors/contract/refund-connected/v1",
        "runs": runs,
        "source": {"commit": SOURCE_COMMIT, "path": SOURCE_PATH},
        "suite": SUITE,
        "vectors": vectors,
        # The reader below carries all six layers. The external contract is stated for
        # one of them, input_aps, in INPUT-CONTRACT.md beside this file, with its
        # fixtures under input-aps/; a verifier built from it answers for that layer
        # and not for the run.
        "verifierContract": (
            "verifier <suite> <case-dir> --json, input_aps layer only; "
            "exit 0 established, 1 refused"
        ),
    }
    outcomes = [_outcome(entry["expected"]["steps"]) for entry in vectors]
    manifest["counts"] = {word: outcomes.count(word) for word in sorted(set(outcomes))}
    manifest["corpusDigest"] = corpus_digest(manifest, root)
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    write_input_aps(root, manifest)
    return manifest


# ----------------------------------------------------------------------------
# The input_aps layer as an external contract: INPUT-CONTRACT.md and input-aps/.
#
# input-aps/check-order.json is the order of checks of the contract, and
# input-aps/retained.json the ten retained cases the layer decides, with the
# consumption instant the corpus derives for each. input-aps/cases/<id>/ holds one
# fixture: case/ (the eleven case files) and expected.json. Nine fixtures are byte
# edits of r2 j01, or of the instant supplied beside it, each meant to reach one
# check. One fixture breaks only a stage rule of APS SDK 8.0.1, so it is built
# with keys of its own and signed for real. The packaged reader's input_aps
# verdict is recorded beside the expected one: it equals it for the nine edits and
# is ESTABLISHED for the stage fixture, the case on which the two readers split.
# ----------------------------------------------------------------------------

INPUT_APS = "input-aps"
BASE = "source/j01-connected-20261028-r2/cases/j01"
INTENT, APPROVAL = "inputs/aps-intent.json", "inputs/aps-approval.json"
ACTION, PAYLOAD = "inputs/aps-action.json", "inputs/aps-payload.json"
DECISION, APS_TRUST = "inputs/decision-evidence.json", "trust/aps-consumption.json"
PROPOSAL, RESULT = "inputs/pic-proposal.json", "inputs/pic-verification.json"
PIC_KEYS = "trust/pic-keys.json"

#: The order of checks of INPUT-CONTRACT.md and the verdict each one gives.
CHECK_ORDER = (
    ("0a", "NOT_ESTABLISHED:input-files-missing"),
    ("0b", "REFUSED:STRICT_PARSE"),
    ("1", "REFUSED:TRUST_SELECTION"),
    ("2a", "REFUSED:INTENT_IDENTITY"),
    ("2b", "REFUSED:INTENT_NOT_VALID"),
    ("3a", "REFUSED:DECISION_COMPONENTS"),
    ("3b", "REFUSED:APPROVAL_ISSUER"),
    ("3c", "REFUSED:APPROVAL_NOT_VALID"),
    ("3d", "REFUSED:DECISION_NOT_BOUND"),
    ("3e", "REFUSED:APPROVAL_PREV"),
    ("3f", "REFUSED:APPROVAL_INTENT_ACTION"),
    ("3g", "REFUSED:APPROVAL_BEFORE_INTENT"),
    ("3h", "REFUSED:VERDICT_NOT_PERMIT"),
    ("3i", "REFUSED:DECISION_CONSTRAINTS"),
    ("3j", "REFUSED:APPROVAL_AFTER_CONSUMPTION"),
    ("3k", "REFUSED:DECISION_EXPIRED_AT_CONSUMPTION"),
    ("3l", "REFUSED:APPROVAL_SIGNER_REVOKED_AT_CONSUMPTION"),
    ("4a", "REFUSED:ACTION_INPUT"),
    ("4b", "REFUSED:TARGET"),
    ("4c", "REFUSED:ACTION_REF"),
    ("5a", "REFUSED:PAYLOAD_SCHEMA"),
    ("5b", "REFUSED:PAYLOAD_REF"),
    ("5c", "REFUSED:TARGET_PAYMENT_ID"),
    ("6", "REFUSED:DECISION_ID"),
    ("7a", "REFUSED:PIC_DECISION_ID"),
    ("7b", "REFUSED:PIC_APPROVAL_REF"),
    ("7c", "REFUSED:PIC_EXPIRED_AT_CONSUMPTION"),
    ("7d", "REFUSED:PIC_ARGS_NOT_PAYLOAD"),
)
VERDICT_OF = dict(CHECK_ORDER)

#: The stage fixture's keys are Ed25519 seeds derived from these labels, so that
#: anyone can rebuild its signatures; they are test keys and nothing else.
STAGE_LABEL = "agent-evidence-vectors/refund-connected/input-aps/stage/"
STAGE_MERCHANT = "refund-sandbox-merchant-stage-v1"


def _pretty(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def _pretty_sorted(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _compact(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


#: How each case file of the retained run is written, so a rewritten file keeps
#: the layout of the one it replaces.
WRITERS = {PROPOSAL: _pretty_sorted, RESULT: _compact}


#: The case files a fixture rewrites from their parsed form.
REWRITTEN = (APS_TRUST, INTENT, APPROVAL, PROPOSAL, RESULT, PIC_KEYS)


def _write(files: dict[str, bytes], rel: str, value: Any) -> None:
    files[rel] = WRITERS.get(rel, _pretty)(value)


def _once(data: bytes, old: bytes, new: bytes) -> bytes:
    if data.count(old) != 1:
        raise ValueError(f"{old!r} does not occur exactly once")
    return data.replace(old, new)


def _shift(instant: str, seconds: int) -> str:
    moved = reader.ts_ms(instant) + timedelta(seconds=seconds)
    return moved.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moved.microsecond // 1000:03d}Z"


def consumption_instant(run_root: Path, name: str) -> tuple[str, str] | None:
    """The instant the corpus derives for one case, as judge_case derives it."""
    run = reader.RunDir(run_root)
    case = reader.Case(run, name)
    try:
        reader.check_pic(case)
    except reader.Finding:
        return None
    claim = case.claim  # type: ignore[attr-defined]
    records = reader.Admission(run).for_decision(str(claim["decision_id"]))
    mine = [r for r in records if r.get("approval_ref") == claim["approval_ref"]]
    if mine and isinstance(mine[0].get("committed_at"), str):
        return mine[0]["committed_at"].replace("Z", ".000Z"), "admission record"
    return str(case.pic_evaluated_at), "pic evaluated_at"  # type: ignore[attr-defined]


def packaged_input_aps(fixture: Path, consumed_at: str) -> str:
    """The packaged reader's input_aps verdict on input-aps/cases/<id>/case."""
    case = reader.Case(reader.RunDir(fixture.parent.parent), f"{fixture.name}/case")
    try:
        reader.check_pic(case)
    except reader.Finding as found:
        if found.code in ("input-files-missing", "STRICT_PARSE"):
            return found.verdict
        return reader.NOT_REACHED
    try:
        reader.check_aps(case, consumed_at)
    except reader.Finding as found:
        return found.verdict
    return reader.ESTABLISHED


def retained(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """The retained cases the layer decides, with the frozen consumption instant."""
    rows = []
    for entry in manifest["vectors"]:
        found = consumption_instant(root / entry["path"], entry["case"])
        if found is None:
            continue
        rows.append(
            {
                "case": f"{entry['path']}/cases/{entry['case']}",
                "consumed_at": found[0],
                "id": entry["id"],
                "input_aps": entry["expected"]["steps"]["input_aps"],
                "instant_from": found[1],
            }
        )
    return rows


def _edited(base: dict[str, bytes], rel: str, old: bytes, new: bytes) -> dict[str, bytes]:
    files = dict(base)
    files[rel] = _once(files[rel], old, new)
    return files


def _boundary_revoked(base: dict[str, bytes], revoked_at: str) -> dict[str, bytes]:
    files = dict(base)
    trust = reader.parse(files[APS_TRUST])
    for key in trust["keys"]:
        if key["signer"] == reader.BOUNDARY:
            key["revoked_at"] = revoked_at
    _write(files, APS_TRUST, trust)
    return files


def byte_edits(base: dict[str, bytes], consumed: str) -> list[dict[str, Any]]:
    """The nine fixtures that edit r2 j01 or its supplied instant, without new signatures."""
    approval = reader.parse(base[APPROVAL])
    missing = dict(base)
    del missing[ACTION]
    rows = [
        (
            "x-trust-scope",
            "1",
            "trust/aps-consumption.json scope set to payments:charge",
            _edited(base, APS_TRUST, b'"payments:refund"', b'"payments:charge"'),
            consumed,
        ),
        (
            "x-intent-edit",
            "2b",
            "inputs/aps-intent.json issued_at one millisecond earlier",
            _edited(
                base,
                INTENT,
                b'"2026-10-28T21:45:45.527Z",\n  "evidence_refs"',
                b'"2026-10-28T21:45:45.526Z",\n  "evidence_refs"',
            ),
            consumed,
        ),
        (
            "x-decision-edit",
            "3d",
            "inputs/decision-evidence.json decision_context.channel changed",
            _edited(base, DECISION, b'"channel": "sandbox"', b'"channel": "operator"'),
            consumed,
        ),
        (
            "x-consumed-early",
            "3j",
            "consumed_at one second before the approval's issued_at",
            dict(base),
            _shift(approval["issued_at"], -1),
        ),
        (
            "x-consumed-late",
            "3k",
            "consumed_at equal to the approval's valid_until",
            dict(base),
            approval["result"]["valid_until"],
        ),
        (
            "x-boundary-revoked",
            "3l",
            "trust/aps-consumption.json boundary key revoked_at one second before consumed_at",
            _boundary_revoked(base, _shift(consumed, -1)),
            consumed,
        ),
        (
            "x-action-edit",
            "4c",
            "inputs/aps-action.json nonce changed",
            _edited(
                base,
                ACTION,
                b'"00000000000000000000000000000001"',
                b'"00000000000000000000000000000002"',
            ),
            consumed,
        ),
        (
            "x-payload-dup",
            "0b",
            "inputs/aps-payload.json carries currency twice",
            _edited(
                base, PAYLOAD, b'"currency": "EUR"\n', b'"currency": "EUR",\n  "currency": "EUR"\n'
            ),
            consumed,
        ),
        ("x-file-missing", "0a", "inputs/aps-action.json removed", missing, consumed),
    ]
    return [
        {"id": i, "check": c, "edit": e, "files": f, "consumed_at": t, "split": False}
        for i, c, e, f, t in rows
    ]


def _seed(role: str) -> bytes:
    return hashlib.sha256((STAGE_LABEL + role).encode()).digest()


def _sign_receipt(receipt: dict[str, Any], seed: bytes) -> None:
    """Receipt id and Ed25519 signatures, in the forms the contract states."""
    body = {k: v for k, v in receipt.items() if k not in ("receipt_id", "signatures")}
    receipt["receipt_id"] = reader.sha_hex(b"APS-RECEIPT-ID-V1\0" + reader.jcs(body))
    unsigned = {k: v for k, v in receipt.items() if k != "signatures"}
    for sig in receipt["signatures"]:
        descriptor = {k: v for k, v in sig.items() if k != "value"}
        message = b"APS-RECEIPT-SIG-V1\0" + reader.jcs({"receipt": unsigned, "signer": descriptor})
        sig["value"] = reader._rail().ed25519_sign(seed, message).hex()


def _stage_receipts(files: dict[str, bytes]) -> str:
    """The intent with a result its stage does not allow, and the approval over it."""
    keys = {reader.WORKER: ("wrk-stage-1", "worker"), reader.BOUNDARY: ("bnd-stage-1", "boundary")}
    trust = reader.parse(files[APS_TRUST])
    for key in trust["keys"]:
        key["key_id"], role = keys[key["signer"]]
        key["public_key"] = reader._rail().ed25519_public_key(_seed(role)).hex()
    _write(files, APS_TRUST, trust)
    intent, approval = reader.parse(files[INTENT]), reader.parse(files[APPROVAL])
    intent["result"]["status"] = "submitted"
    intent["signatures"][0]["key_id"] = keys[reader.WORKER][0]
    _sign_receipt(intent, _seed("worker"))
    approval["prev"] = intent["receipt_id"]
    approval["signatures"][0]["key_id"] = keys[reader.BOUNDARY][0]
    _sign_receipt(approval, _seed("boundary"))
    _write(files, INTENT, intent)
    _write(files, APPROVAL, approval)
    return str(approval["receipt_id"])


def _stage_pic(files: dict[str, bytes], approval_ref: str) -> None:
    """The PIC claim names the new approval; attestation and runner result follow it."""
    prop = reader.parse(files[PROPOSAL])
    claim = reader.parse(prop["claims"][0]["text"].encode())
    claim["approval_ref"] = approval_ref
    prop["claims"][0]["text"] = reader.jcs(claim).decode()
    entry = prop["evidence"][0]
    att = reader.parse(entry["payload"].encode())
    att["claims_digest"] = reader.sha_hex(reader.jcs(prop["claims"]))
    payload = reader.jcs(att)
    signature = reader._rail().ed25519_sign(_seed("merchant"), payload)
    entry.update(
        payload=payload.decode(),
        key_id=STAGE_MERCHANT,
        signer=STAGE_MERCHANT,
        signature=base64.b64encode(signature).decode(),
    )
    for row in prop["provenance"]:
        row["source"] = "merchant-signer:" + STAGE_MERCHANT
    _write(files, PROPOSAL, prop)
    merchant = reader._rail().ed25519_public_key(_seed("merchant")).hex()
    _write(files, PIC_KEYS, {"trusted_keys": {STAGE_MERCHANT: merchant}, "revoked_keys": []})
    result = reader.parse(files[RESULT])
    result["claims_digest"] = att["claims_digest"]
    result["proposal_file_ref"] = reader.file_ref(files[PROPOSAL])
    result["pic_trust_file_ref"] = reader.file_ref(files[PIC_KEYS])
    _write(files, RESULT, result)


def stage_fixture(base: dict[str, bytes], consumed: str) -> dict[str, Any]:
    """r2 j01 with an intent whose result breaks only the action-intent stage rule."""
    files = dict(base)
    _stage_pic(files, _stage_receipts(files))
    return {
        "id": "s-intent-result-status",
        "check": "2b",
        "edit": (
            "inputs/aps-intent.json result.status set to submitted, which the "
            "aps:action-intent:v1 stage rule of APS SDK 8.0.1 refuses; intent, approval "
            "and PIC attestation re-signed with keys from the seeds sha256(label + role), "
            "the trust files and the runner result carrying those keys and digests"
        ),
        "files": files,
        "consumed_at": consumed,
        "split": True,
        "keys": {"label": STAGE_LABEL, "roles": ["worker", "boundary", "merchant"]},
    }


def _write_fixture(out: Path, fixture: dict[str, Any]) -> None:
    where = out / "cases" / fixture["id"]
    for rel, data in fixture["files"].items():
        (where / "case" / rel).parent.mkdir(parents=True, exist_ok=True)
        (where / "case" / rel).write_bytes(data)
    expected = VERDICT_OF[fixture["check"]]
    packaged = packaged_input_aps(where, fixture["consumed_at"])
    if packaged != (reader.ESTABLISHED if fixture["split"] else expected):
        raise ValueError(f"{fixture['id']}: the packaged reader gives {packaged}")
    document = {
        "base": BASE,
        "check": fixture["check"],
        "consumed_at": fixture["consumed_at"],
        "edit": fixture["edit"],
        "expected": {"input_aps": expected},
        "id": fixture["id"],
        "packaged_reader": {"input_aps": packaged},
    }
    if "keys" in fixture:
        document["keys"] = fixture["keys"]
    (where / "expected.json").write_bytes(_json(document))


def write_input_aps(root: Path, manifest: dict[str, Any]) -> None:
    """Write input-aps/ from r2 j01 and the manifest; refuse if any file drifts."""
    out = root / INPUT_APS
    if out.exists():
        shutil.rmtree(out)
    base = {rel: (root / BASE / rel).read_bytes() for rel in reader.CASE_FILES}
    for rel in REWRITTEN:
        if WRITERS.get(rel, _pretty)(reader.parse(base[rel])) != base[rel]:
            raise ValueError(f"{rel}: its layout is not one this generator writes")
    found = consumption_instant(root / RUNS["r2"], "j01")
    if found is None:
        raise ValueError("r2 j01 does not reach input_aps")
    out.mkdir(parents=True)
    order = [{"check": check, "verdict": verdict} for check, verdict in CHECK_ORDER]
    (out / "check-order.json").write_bytes(
        _json({"contract": "INPUT-CONTRACT.md", "layer": "input_aps", "order": order})
    )
    (out / "retained.json").write_bytes(_json(retained(root, manifest)))
    for fixture in [*byte_edits(base, found[0]), stage_fixture(base, found[0])]:
        _write_fixture(out, fixture)


if __name__ == "__main__":
    out = generate()
    print(f"wrote {len(out['vectors'])} vectors, corpusDigest {out['corpusDigest']}")
