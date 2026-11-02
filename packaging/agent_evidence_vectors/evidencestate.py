"""Check a declared evidence state against the observations that ground it.

The vocabulary term ``evidence_state`` orders what responders can observe about
one system at one time into nine codes, from silence (``ES0``) to a requested
restart (``ES8``). Each code has an observable entry condition, and a record's
state is the highest code whose condition its observations meet:

====  ==================================================================
ES8   containment is recorded and a restart is requested
ES7   effects outside the organisation are confirmed
ES6   the scope is bounded and containment is verified
ES5   the propagation pathway is identified
ES4   propagation is observed
ES3   the recorded anomalies have crossed a declared change-detection threshold
ES2   at least one anomaly is recorded
ES1   no anomaly is recorded and monitor coverage was measured
ES0   no anomaly is recorded and monitor coverage was not measured
====  ==================================================================

A record carries the code it declares, ``evidenceState``, beside the
observations. The reader derives the code from the observations and checks, in
a fixed order, naming the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the evidence-state contract (``contract_id_unknown``);
3. the record has exactly its members, each of its type, with non-negative
   counts and a threshold of at least one where one is declared
   (``record_malformed``);
4. ``evidenceState`` is one of ``ES0`` to ``ES8`` (``evidence_state_unregistered``);
5. the observations do not contradict each other: a pathway is identified only
   for an observed propagation, a propagation is observed only beside a recorded
   anomaly, and containment is verified only where it is recorded
   (``observations_inconsistent``);
6. a declared ``ES1`` rests on measured coverage, so a silence nobody measured
   is not read as a clean one (``clean_without_coverage``);
7. the declared code is no higher than the observations support
   (``evidence_state_unsupported``);
8. the declared code is no lower than the observations support
   (``evidence_state_understated``).

A record that passes all eight is ``allow`` with reason ``state_supported``.
The code says what was observed. It does not say which response is right, and
it does not decide whether a restart is admitted.

Run it on your own records::

    python -m agent_evidence_vectors.evidencestate record.json [more.json ...] --json

prints one JSON object per record carrying ``record``, ``decision``, ``reason``
and, for a well-formed record, ``derivedState``; it exits 0 when every record is
``allow``, 1 when any is ``deny`` and 2 when any cannot be read.
With no record it replays this package's corpus; ``--verifier`` replays it
through another verifier instead, under the contract every decision corpus
shares: ``<verifier> <case-dir>/record.json --json`` prints ``decision`` and
``reason`` and exits 0 for ``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors import monitorcoverage as _shared

SUITE = "evidence-state/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/evidence-state"
TERM_URI = "https://w3id.org/agent-evidence/vocab/v1/evidence_state"
ALLOW, DENY = "allow", "deny"
ALLOWED_REASON = "state_supported"
EXIT_FOR = {ALLOW: 0, DENY: 1}
STATES = ("ES0", "ES1", "ES2", "ES3", "ES4", "ES5", "ES6", "ES7", "ES8")
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "record_malformed",
    "evidence_state_unregistered",
    "observations_inconsistent",
    "clean_without_coverage",
    "evidence_state_unsupported",
    "evidence_state_understated",
)
TOP = ("assessedAt", "contractId", "evidenceState", "observations", "recordId", "system")
FLAGS = ("containmentRecorded", "containmentVerified", "coverageMeasured",
         "externalEffectsConfirmed", "pathwayIdentified", "propagationObserved",
         "restartRequested", "scopeBounded")
OBSERVATIONS = ("anomaliesRecorded", "changeThreshold", *FLAGS)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-evidence-state" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-evidence-state")

Record = dict[str, Any]


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _malformed(record: Record) -> bool:
    if set(record) != set(TOP):
        return True
    if not all(isinstance(record[key], str) and record[key]
               for key in ("assessedAt", "evidenceState", "recordId", "system")):
        return True
    seen = record["observations"]
    if not isinstance(seen, dict) or set(seen) != set(OBSERVATIONS):
        return True
    threshold = seen["changeThreshold"]
    return (not _count(seen["anomaliesRecorded"])
            or not (threshold is None or (_count(threshold) and threshold >= 1))
            or not all(isinstance(seen[flag], bool) for flag in FLAGS))


def _inconsistent(seen: dict[str, Any]) -> bool:
    return bool((seen["pathwayIdentified"] and not seen["propagationObserved"])
                or (seen["propagationObserved"] and seen["anomaliesRecorded"] == 0)
                or (seen["containmentVerified"] and not seen["containmentRecorded"]))


def derive(seen: dict[str, Any]) -> str:
    """The highest code whose entry condition the observations meet."""
    threshold = seen["changeThreshold"]
    conditions = (
        ("ES8", seen["containmentRecorded"] and seen["restartRequested"]),
        ("ES7", seen["externalEffectsConfirmed"]),
        ("ES6", seen["scopeBounded"] and seen["containmentVerified"]),
        ("ES5", seen["pathwayIdentified"]),
        ("ES4", seen["propagationObserved"]),
        ("ES3", threshold is not None and seen["anomaliesRecorded"] >= threshold),
        ("ES2", seen["anomaliesRecorded"] >= 1),
        ("ES1", seen["coverageMeasured"]),
    )
    return next((code for code, holds in conditions if holds), "ES0")


def _rank(code: str) -> int:
    return STATES.index(code)


def retained(record: Record) -> dict[str, Any]:
    """The declared and derived codes a verifier keeps."""
    return {"declared": record["evidenceState"], "derived": derive(record["observations"]),
            "system": record["system"]}


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    def declared() -> str:
        return str(record["evidenceState"])

    def derived() -> str:
        return derive(record["observations"])

    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "record_malformed": lambda: _malformed(record),
        "evidence_state_unregistered": lambda: declared() not in STATES,
        "observations_inconsistent": lambda: _inconsistent(record["observations"]),
        "clean_without_coverage": lambda: declared() == "ES1" and derived() == "ES0",
        "evidence_state_unsupported": lambda: _rank(declared()) > _rank(derived()),
        "evidence_state_understated": lambda: _rank(declared()) < _rank(derived()),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def _load(record_path: Path) -> Record:
    loaded = json.loads(record_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("a record is a JSON object")
    return loaded


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    record = _load(record_path)
    if not isinstance(record.get("contractId", ""), str):
        return {"decision": DENY, "reason": "record_malformed"}
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def judge(record_path: Path) -> dict[str, str]:
    """Decision, reason and, where the record is well formed, the derived code."""
    answer = verify(record_path)
    record = _load(record_path)
    if answer["reason"] not in CHECKS[:3]:
        answer = {**answer, "derivedState": derive(record["observations"])}
    return answer


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    return _shared.check_corpus(root, SUITE, verify, retained, verifier, skip)


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return _shared.run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def _judge_records(paths: list[str], as_json: bool) -> int:
    worst = 0
    for name in paths:
        try:
            answer = judge(Path(name))
        except (OSError, ValueError) as exc:
            print(json.dumps({"record": name, "error": str(exc)}) if as_json
                  else f"{name}: unreadable: {exc}")
            worst = 2
            continue
        if as_json:
            print(json.dumps({"record": name, **answer}, sort_keys=True))
        else:
            print(f"{name}: {answer['decision']} {answer['reason']} "
                  f"{answer.get('derivedState', '')}".rstrip())
        worst = max(worst, EXIT_FOR[answer["decision"]])
    return worst


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("records", nargs="*", help="judge these record.json files")
    parser.add_argument("--json", action="store_true", help="print each decision as JSON")
    parser.add_argument("--verifier", help="replay the corpus through this verifier instead")
    args = parser.parse_args(argv)
    if args.records:
        return _judge_records(args.records, args.json)
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    sys.exit(main())
