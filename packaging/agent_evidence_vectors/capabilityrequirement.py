"""Judge a signed capability requirement, a hosted-endpoint report and a drift comparison.

A customer who buys a product built on a hosted model cannot hash the weights, so
a swap of the model behind the endpoint leaves no bytes to compare. What the
customer can hold is a record made before any swap: the capability stated apart
from any model, the pass thresholds, and the evaluation set, with a held-out part
that an assessor keeps and signs per run. A verifier then reports two separate
things about a hosted endpoint: ``modelIdentity`` (``unproven``, because no weights
are held) and ``behaviour`` on the pinned set (``supported``, ``contradicted`` or
``not_established``). Drift is two signed runs of one requirement against one
endpoint, compared.

Every record is one of three kinds, named by ``kind``:

``requirement``
    The requirement record: ``requirement`` (the capability, the pinned thresholds
    and the evaluation set), ``requirerSignature`` over its canonical bytes, and
    ``assessorAttestation``, the assessor's signature over the held-out commitment.
``endpoint-report``
    A ``requirementRecord``, the ``endpoint``, one signed ``run``, and the two
    findings ``modelIdentity`` and ``behaviour``.
``drift``
    A ``requirementRecord``, a ``baseline`` run, a ``current`` run and the
    ``comparison`` of the two.

A run is ``body`` (run id, requirement digest, endpoint, time, public metric
values and the held-out results), ``verifierSignature`` over the body, and
``assessorSignature`` over the held-out results with the run id and requirement
digest. Metric values are integers in the metric's own unit. Canonical bytes are
compact JSON with sorted keys, which is RFC 8785 output for the integers and ASCII
strings used here.

The reader checks in a fixed order and names the first check that fails. A check
that does not apply to the record's kind passes.

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is this contract (``contract_id_unknown``);
3. ``kind`` is one of the three (``kind_unknown``);
4. the requirer's signature verifies over the requirement
   (``requirement_signature_invalid``);
5. the capability holds an id and a statement and nothing else, so it names no
   model, endpoint or provider (``capability_names_a_model``);
6. the thresholds are a non-empty list, one per metric, each with a known set,
   comparator, an integer value and an integer drift tolerance
   (``thresholds_invalid``);
7. the evaluation-set digest is the digest of its item digests
   (``evaluation_set_digest_mismatch``);
8. the held-out commitment is attested by the assessor key the requirement names
   (``held_out_commitment_not_attested``);
9. a report or drift record carries a requirement that passes checks 4 to 8
   (``requirement_invalid``);
10. every run names the digest of that requirement
    (``run_against_other_requirement``);
11. the two runs of a drift record name one endpoint (``runs_on_different_endpoints``);
12. every run's verifier signature verifies over its body (``run_signature_invalid``);
13. a run that carries held-out results carries them with the named assessor's
    signature (``held_out_not_assessor_signed``);
14. a report states ``modelIdentity`` and ``behaviour`` as two members and no
    combined verdict (``findings_merged``);
15. ``modelIdentity`` is ``unproven`` unless the endpoint holds weights and the
    report proves the digest it claims (``model_identity_overclaimed``);
16. ``behaviour`` is the one the thresholds and the run's usable values give
    (``behaviour_mismatch``);
17. a drift record's two runs are two runs (``runs_not_distinct``);
18. the current run is later than the baseline (``runs_out_of_order``);
19. the comparison is the one recomputed from the two runs (``comparison_wrong``).

A held-out value is usable only with a valid assessor signature. Behaviour is
``contradicted`` when any usable value misses its threshold, else
``not_established`` when any threshold has no usable value, else ``supported``. A
comparison is ``drifted`` when a metric worsened by more than its tolerance or fell
from meeting its threshold to missing it, else ``not_established`` when a metric
has no usable value in both runs, else ``stable``.

The checks verify signatures against the keys a record names. Which keys a
deployment trusts is a separate decision and is not tested here.

A record that passes every check is ``allow`` with reason ``record_consistent``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictjson
from agent_evidence_vectors.cardreceipt import _rail
from agent_evidence_vectors.identifiers import identifier, same_identifier
from agent_evidence_vectors.monitorcoverage import (
    ALLOW,
    DENY,
    EXIT_FOR,
    check_corpus,
    cli,
    run_corpus,
)

SUITE = "capability-requirement/v1"
CONTRACT_ID = identifier("agent-evidence-vectors/predicate/v1/"
               "capability-requirement")
ALLOWED_REASON = "record_consistent"
KINDS = ("requirement", "endpoint-report", "drift")
BEHAVIOURS = ("supported", "contradicted", "not_established")
UNPROVEN = "unproven"
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "kind_unknown",
    "requirement_signature_invalid",
    "capability_names_a_model",
    "thresholds_invalid",
    "evaluation_set_digest_mismatch",
    "held_out_commitment_not_attested",
    "requirement_invalid",
    "run_against_other_requirement",
    "runs_on_different_endpoints",
    "run_signature_invalid",
    "held_out_not_assessor_signed",
    "findings_merged",
    "model_identity_overclaimed",
    "behaviour_mismatch",
    "runs_not_distinct",
    "runs_out_of_order",
    "comparison_wrong",
)
REQUIREMENT_CHECKS = CHECKS[3:8]
THRESHOLD_KEYS = {"metric", "set", "comparator", "value", "maxDrift"}
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-capability-requirement" if
        (_HERE / "corpora").exists() else
        _HERE.parents[1] / "corpora" / "vectors-capability-requirement")

Record = dict[str, Any]
_SHAPE_ERRORS = (KeyError, TypeError, ValueError, AttributeError, IndexError, binascii.Error)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    """The bytes every signature in this contract covers."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def requirement_digest(requirement: dict[str, Any]) -> str:
    """The digest a run names to say which requirement it ran."""
    return _sha(canonical(requirement))


def items_digest(items: list[str]) -> str:
    """The evaluation-set digest: the digest of the sorted item digests."""
    return _sha(canonical(sorted(items)))


def attestation_bytes(requirement: dict[str, Any]) -> bytes:
    """What the assessor signs to attest the held-out commitment."""
    return canonical({"capabilityId": requirement["capability"]["id"],
                      "commitment": requirement["evaluationSet"]["heldOut"]["commitment"]})


def assessor_run_bytes(run: dict[str, Any]) -> bytes:
    """What the assessor signs for one run's held-out results."""
    body = run["body"]
    return canonical({"requirementDigest": body["requirementDigest"],
                      "results": body["heldOut"]["results"], "runId": body["runId"]})


def _verified(signature: object, data: bytes) -> bool:
    """Whether ``signature`` is a key and a signature that verify over ``data``."""
    if not isinstance(signature, dict):
        return False
    try:
        key = base64.b64decode(signature["publicKey"], validate=True)
        sig = base64.b64decode(signature["signature"], validate=True)
        return bool(_rail().ed25519_verify(key, data, sig))
    except _SHAPE_ERRORS:
        return False


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


def _requirement(rr: Record) -> dict[str, Any]:
    body: dict[str, Any] = rr["requirement"]
    return body


def _thresholds_invalid(rr: Record) -> bool:
    thresholds = _requirement(rr)["thresholds"]
    if not isinstance(thresholds, list) or not thresholds:
        return True
    metrics = []
    for item in thresholds:
        if not isinstance(item, dict) or set(item) != THRESHOLD_KEYS:
            return True
        if not isinstance(item["metric"], str) or not item["metric"]:
            return True
        if item["set"] not in ("public", "heldOut") or item["comparator"] not in ("gte", "lte"):
            return True
        if not _is_int(item["value"]) or not _is_int(item["maxDrift"]) or item["maxDrift"] < 0:
            return True
        metrics.append(item["metric"])
    return len(metrics) != len(set(metrics))


def _digest_mismatch(rr: Record) -> bool:
    evaluation = _requirement(rr)["evaluationSet"]
    items = evaluation["items"]
    if not isinstance(items, list) or not items or not all(_is_digest(i) for i in items):
        return True
    return bool(evaluation["digest"] != items_digest(items))


def _not_attested(rr: Record) -> bool:
    requirement = _requirement(rr)
    held = requirement["evaluationSet"].get("heldOut")
    if not isinstance(held, dict) or not _is_digest(held.get("commitment")):
        return True
    attestation = rr.get("assessorAttestation")
    if not isinstance(attestation, dict) or attestation.get("publicKey") != held.get("assessorKey"):
        return True
    return not _verified(attestation, attestation_bytes(requirement))


def _requirement_checks() -> dict[str, Callable[[Record], bool]]:
    return {
        "requirement_signature_invalid": lambda rr: not _verified(
            rr.get("requirerSignature"), canonical(_requirement(rr))),
        "capability_names_a_model": lambda rr: (
            set(_requirement(rr)["capability"]) != {"id", "statement"}
            or not all(isinstance(v, str) for v in _requirement(rr)["capability"].values())),
        "thresholds_invalid": _thresholds_invalid,
        "evaluation_set_digest_mismatch": _digest_mismatch,
        "held_out_commitment_not_attested": _not_attested,
    }


def requirement_failure(rr: Record) -> str | None:
    """The first requirement check the record's requirement fails, or None."""
    for name, failing in _requirement_checks().items():
        try:
            if failing(rr):
                return name
        except _SHAPE_ERRORS:
            return name
    return None


def _held_out_valid(rr: Record, run: Record) -> bool:
    """Whether a run's held-out part is absent, or carries the named assessor's signature."""
    if run["body"].get("heldOut") is None:
        return True
    signature = run.get("assessorSignature")
    named = _requirement(rr)["evaluationSet"]["heldOut"]["assessorKey"]
    return (isinstance(signature, dict) and signature.get("publicKey") == named
            and _verified(signature, assessor_run_bytes(run)))


def _value(rr: Record, run: Record, threshold: dict[str, Any]) -> int | None:
    """The run's usable value for a threshold's metric, or None."""
    metric = threshold["metric"]
    if threshold["set"] == "public":
        values = run["body"]["public"]
    else:
        held = run["body"].get("heldOut")
        if held is None or not _held_out_valid(rr, run):
            return None
        values = held["results"]
    found = values.get(metric)
    return found if _is_int(found) else None


def _meets(threshold: dict[str, Any], value: int) -> bool:
    if threshold["comparator"] == "gte":
        return bool(value >= threshold["value"])
    return bool(value <= threshold["value"])


def behaviour(rr: Record, run: Record) -> str:
    """Behaviour on the pinned set: contradicted, else not established, else supported."""
    values = [(t, _value(rr, run, t)) for t in _requirement(rr)["thresholds"]]
    if any(v is not None and not _meets(t, v) for t, v in values):
        return "contradicted"
    if any(v is None for _, v in values):
        return "not_established"
    return "supported"


def compare(rr: Record, baseline: Record, current: Record) -> dict[str, Any]:
    """The comparison two runs of one requirement give."""
    changes: list[dict[str, Any]] = []
    unmatched: list[str] = []
    drifted = False
    for threshold in _requirement(rr)["thresholds"]:
        before, after = _value(rr, baseline, threshold), _value(rr, current, threshold)
        if before is None or after is None:
            unmatched.append(threshold["metric"])
            continue
        worse = before - after if threshold["comparator"] == "gte" else after - before
        meets_before, meets_after = _meets(threshold, before), _meets(threshold, after)
        changes.append({"baseline": before, "baselineMeets": meets_before, "current": after,
                        "currentMeets": meets_after, "metric": threshold["metric"],
                        "worsenedBy": worse})
        drifted = drifted or worse > threshold["maxDrift"] or (meets_before and not meets_after)
    outcome = "drifted" if drifted else ("not_established" if unmatched else "stable")
    return {"baselineRunId": baseline["body"]["runId"], "changes": changes,
            "currentRunId": current["body"]["runId"], "outcome": outcome,
            "unmatched": sorted(unmatched)}


def _at(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _runs(record: Record) -> list[Record]:
    if record["kind"] == "endpoint-report":
        return [record["run"]]
    return [record["baseline"], record["current"]]


def _rr(record: Record) -> Record:
    return record if record["kind"] == "requirement" else record["requirementRecord"]


def _identity_overclaimed(record: Record) -> bool:
    claim = record["modelIdentity"]
    if claim == UNPROVEN:
        return False
    endpoint = record["endpoint"]
    proof = record.get("identityProof")
    return not (claim == "proven" and endpoint["access"] == "weights-held"
                and isinstance(proof, dict) and _is_digest(proof.get("weightsDigest"))
                and proof["weightsDigest"] == endpoint["claimedWeightsDigest"])


def _check_table(record: Record) -> dict[str, Callable[[], bool]]:
    kind = record.get("kind")
    on_rr = kind in KINDS
    table_rr: dict[str, Callable[[], bool]] = {}
    for name, failing in _requirement_checks().items():
        table_rr[name] = (lambda failing=failing: kind == "requirement"  # type: ignore[misc]
                          and bool(failing(record)))
    runs_kind = kind in ("endpoint-report", "drift")

    def digest() -> str:
        return requirement_digest(_requirement(_rr(record)))

    return {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: not same_identifier(
            record.get("contractId", CONTRACT_ID), CONTRACT_ID),
        "kind_unknown": lambda: not on_rr,
        **table_rr,
        "requirement_invalid": lambda: runs_kind and requirement_failure(_rr(record)) is not None,
        "run_against_other_requirement": lambda: runs_kind and any(
            run["body"]["requirementDigest"] != digest() for run in _runs(record)),
        "runs_on_different_endpoints": lambda: kind == "drift" and (
            record["baseline"]["body"]["endpoint"] != record["current"]["body"]["endpoint"]),
        "run_signature_invalid": lambda: runs_kind and any(
            not _verified(run.get("verifierSignature"), canonical(run["body"]))
            for run in _runs(record)),
        "held_out_not_assessor_signed": lambda: runs_kind and any(
            not _held_out_valid(_rr(record), run) for run in _runs(record)),
        "findings_merged": lambda: kind == "endpoint-report" and (
            "verdict" in record or "modelIdentity" not in record or "behaviour" not in record),
        "model_identity_overclaimed": lambda: (
            kind == "endpoint-report" and _identity_overclaimed(record)),
        "behaviour_mismatch": lambda: kind == "endpoint-report" and (
            record["behaviour"] != behaviour(_rr(record), record["run"])),
        "runs_not_distinct": lambda: kind == "drift" and (
            record["baseline"]["body"]["runId"] == record["current"]["body"]["runId"]
            or canonical(record["baseline"]["body"]) == canonical(record["current"]["body"])),
        "runs_out_of_order": lambda: kind == "drift" and (
            _at(record["current"]["body"]["observedAt"])
            <= _at(record["baseline"]["body"]["observedAt"])),
        "comparison_wrong": lambda: kind == "drift" and (
            record["comparison"] != compare(_rr(record), record["baseline"], record["current"])),
    }


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. A record whose shape
    a check cannot read fails that check.
    """
    failures = _check_table(record)
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except _SHAPE_ERRORS:
            return name
    return None


def _load(record_path: Path) -> Record:
    loaded: Record = strictjson.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def _safe(read: Callable[[], Any]) -> Any:
    try:
        return read()
    except _SHAPE_ERRORS:
        return None


def retained(record: Record) -> dict[str, Any]:
    """The facts a verifier keeps from a record: its kind and what it found."""
    kind = record.get("kind")
    kept: dict[str, Any] = {"kind": kind}
    if kind == "requirement":
        kept["requirementDigest"] = _safe(lambda: requirement_digest(_requirement(record)))
        kept["thresholds"] = _safe(lambda: len(_requirement(record)["thresholds"]))
    elif kind == "endpoint-report":
        kept["behaviour"] = record.get("behaviour")
        kept["modelIdentity"] = record.get("modelIdentity")
        kept["runId"] = _safe(lambda: record["run"]["body"]["runId"])
    elif kind == "drift":
        kept["outcome"] = _safe(lambda: record["comparison"]["outcome"])
        kept["runIds"] = _safe(lambda: [record["baseline"]["body"]["runId"],
                                        record["current"]["body"]["runId"]])
    return kept


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    return check_corpus(root, SUITE, verify, retained, verifier, skip)


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    return cli(argv, __doc__, verify, check, ROOT)


__all__ = ["ALLOW", "ALLOWED_REASON", "BEHAVIOURS", "CHECKS", "CONTRACT_ID", "DENY", "EXIT_FOR",
           "KINDS", "ROOT", "SUITE", "UNPROVEN", "behaviour", "canonical", "check", "compare",
           "items_digest", "main", "requirement_digest", "requirement_failure", "retained", "run",
           "verify"]

if __name__ == "__main__":
    raise SystemExit(main())
