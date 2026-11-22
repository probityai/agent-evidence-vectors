"""Build the responsibility-escalation cases byte-identically.

Every case is one synthetic record of a hiring agent's decision and the escalation of
that decision to a designated human role: the versions of the authority record the
agent acted under, what the reference to that record resolved to, the evidence slots
of the escalation and the instant the receiver evaluates at. The nine cases follow the
nine-case matrix on the W3C public-agent-identity list (October 2026, messages 0035
and 0043): the first eight are the authority and escalation failures and the ninth is
the clean path closed on time. Each case is the clean record of the ninth with the
change that names the case, except that the first eight end at acceptance, because
the list's first matrix stops there and closure is a further slot.

The outcome tokens are this corpus's proposal. The list gives expected outcomes for
the failure states and leaves success in prose.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import responsibilityescalation as reader  # noqa: E402

SUITE = reader.SUITE
SOURCE = {
    "note": (
        "The cases restate the nine-case matrix of the list thread in this corpus's own "
        "words, over synthetic records. The expected outcome tokens are this corpus's "
        "proposal and are not an agreed text."
    ),
    "source": "W3C public-agent-identity list, October 2026, messages 2026Oct 0035 and 0043",
}
DECIDED = "2026-03-02T10:00:00Z"
NARROWED = "2026-03-05T00:00:00Z"
EVALUATED = "2026-03-10T09:00:00Z"
#: The decision classes of the list's closing-role discussion, each with the role that closes it.
CLASSES = {
    "screen_out_candidate": "hiring-manager",
    "adverse_background_determination": "compliance-officer",
    "request_sensitive_documents": "hr-business-partner",
}


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def present(at: str, by: str | None = None) -> dict[str, Any]:
    """A slot the record evidences."""
    slot: dict[str, Any] = {"at": at, "evidenced": True}
    if by is not None:
        slot["by"] = by
    return slot


def absent() -> dict[str, Any]:
    """A slot the record does not evidence, observed over complete coverage."""
    return {"coverage": "complete", "evidenced": False}


def base(name: str, decision_class: str = "screen_out_candidate") -> dict[str, Any]:
    """The clean record of the ninth case: authority held, every slot evidenced, closed on time."""
    role = CLASSES[decision_class]
    return {
        "authority": {
            "readAt": "decision",
            "reference": "https://authority.example/records/agent-hr-7",
            "resolution": {"returned": "v1", "status": "resolved"},
            "versions": [{"effectiveFrom": "2026-01-01T00:00:00Z", "holds": True, "id": "v1"}],
        },
        "contractId": reader.CONTRACT_ID,
        "decision": {"agent": "agent-hr-7", "at": DECIDED, "class": decision_class, "id": "d-0001"},
        "escalation": {
            "closure": {"dueBy": "2026-03-03T17:00:00Z", "required": True},
            "designatedRole": role,
            "slots": {
                "acceptance": present("2026-03-02T11:30:00Z", role),
                "acknowledgement": present("2026-03-02T11:00:00Z", role),
                "closure": present("2026-03-03T09:00:00Z", role),
                "receipt": present("2026-03-02T10:06:00Z"),
                "referral": present("2026-03-02T10:05:00Z"),
            },
        },
        "evaluatedAt": EVALUATED,
        "recordId": f"record-{name}",
    }


def v0_1(record: dict[str, Any]) -> dict[str, Any]:
    """Make the record one the first matrix could hold: it ends at acceptance."""
    record["escalation"]["closure"] = {"required": False}
    record["escalation"]["slots"].pop("closure")
    return record


def narrowed(record: dict[str, Any], at: str) -> dict[str, Any]:
    """Add a later version of the authority record that no longer holds."""
    record["authority"]["versions"].append({"effectiveFrom": at, "holds": False, "id": "v2"})
    return record


def truncate(record: dict[str, Any], *dropped: str) -> dict[str, Any]:
    """Leave the named slots, and every slot after the first of them, unevidenced."""
    order: list[str] = list(reader.SLOTS)
    slots = record["escalation"]["slots"]
    for name in order[order.index(dropped[0]) :]:
        if name == "closure" and "closure" not in slots:
            continue
        slots[name] = absent()
    return record


Case = tuple[str, dict[str, Any], str, str, str, dict[str, Any]]


def meta(number: int, line: str, statement: str, **extra: Any) -> dict[str, Any]:
    """The list's case number, the rule it exercises and the evaluation instant."""
    row: dict[str, Any] = {"case": number, "line": line, "statement": statement}
    row.update(extra)
    return row


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, what it shows and its provenance."""
    h01 = narrowed(v0_1(base("h01", "screen_out_candidate")), NARROWED)
    h02 = truncate(v0_1(base("h02", "adverse_background_determination")), "receipt")
    h03 = truncate(v0_1(base("h03", "request_sensitive_documents")), "acceptance")
    h04 = truncate(v0_1(base("h04", "screen_out_candidate")), "acknowledgement")
    h05 = v0_1(base("h05", "adverse_background_determination"))
    h05["authority"]["resolution"] = {"status": "unavailable"}
    h06 = narrowed(v0_1(base("h06", "request_sensitive_documents")), "2026-03-02T10:30:00Z")
    h06["authority"]["readAt"] = "referral"
    h07 = narrowed(v0_1(base("h07", "screen_out_candidate")), NARROWED)
    h07["authority"]["resolution"] = {"returned": "v2", "status": "resolved"}
    h08 = truncate(v0_1(base("h08", "adverse_background_determination")), "acceptance")
    h08["escalation"]["slots"]["acknowledgement"] = present("2026-03-02T11:00:00Z", "recruiter")
    h09 = base("h09", "screen_out_candidate")
    rows: list[tuple[str, dict[str, Any], str, str, str, dict[str, Any]]] = [
        (
            "h01-authority-narrowed-after-decision",
            h01,
            "established",
            "authority_held_at_decision_time",
            "the agent's authority narrowed three days after the decision and after the whole "
            "escalation; read at the decision instant it held",
            meta(1, "authority-valid-then-narrowed", "valid at decision time, narrowed later"),
        ),
        (
            "h02-referral-without-receipt",
            h02,
            "partial",
            "receipt_not_evidenced",
            "the referral is evidenced and no receipt is: the receiver does not infer delivery",
            meta(2, "referral-without-receipt", "referral issued, receipt not evidenced"),
        ),
        (
            "h03-acknowledged-without-acceptance",
            h03,
            "partial",
            "acceptance_not_evidenced",
            "the designated role acknowledged and nothing evidences that it accepted",
            meta(3, "acknowledged-without-acceptance", "acknowledged, acceptance not evidenced"),
        ),
        (
            "h04-unanswered-escalation",
            h04,
            "unresolved",
            "escalation_unanswered",
            "the referral was received and, at the stated evaluation instant, nothing answers it",
            meta(4, "unanswered-escalation", "unanswered, remains unresolved"),
        ),
        (
            "h05-reference-unavailable",
            h05,
            "not_established",
            "reference_unavailable",
            "the reference to the authority record did not resolve, so what the agent held "
            "cannot be reconstructed even though the escalation is fully evidenced",
            meta(5, "reference-unavailable", "reference unavailable or inconsistent"),
        ),
        (
            "h06-authority-narrowed-before-acknowledgement",
            h06,
            "partial",
            "authority_narrowed_before_acknowledgement",
            "authority is read at the referral instant, where it held, and had narrowed by the "
            "time the designated role acknowledged",
            meta(
                6,
                "narrowed-between-referral-and-acknowledgement",
                "narrowed between escalation and acknowledgement",
                evaluationInstants={"authorityRead": "referral"},
            ),
        ),
        (
            "h07-current-record-resolved",
            h07,
            "not_established",
            "current_record_resolved_not_decision_time",
            "the reference returned the current record, which no longer holds, in place of the "
            "version in force at the decision instant",
            meta(7, "current-record-resolved", "resolution returns the current record"),
        ),
        (
            "h08-acknowledged-outside-role",
            h08,
            "partial",
            "acknowledged_outside_designated_role",
            "the acknowledgement is evidenced and its author is not the designated role",
            meta(8, "acknowledged-outside-role", "acknowledged outside the designated role"),
        ),
        (
            "h09-clean-path-closed-on-time",
            h09,
            "established",
            "closed_as_accepted",
            "authority held, every slot through closure is evidenced and the designated role "
            "closed inside the window",
            meta(9, "clean-path-closed-on-time", "closed as accepted on time"),
        ),
    ]
    return rows


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
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, edit, provenance in cases():
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
                **provenance,
                "decisionClass": body["decision"]["class"],
                "edit": edit,
                "expected": expected,
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(copy.deepcopy(body)),
            }
        )
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "provenance": SOURCE,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 established, 1 not_established, "
        "2 partial, 3 unresolved",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
