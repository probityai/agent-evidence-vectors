"""Derive an evidence grade on the E0-E4 ladder and enforce the claim floor.

The corpus this module reads pins one rule for the E0-E4 ladder put to the AAIF
Observability WG in https://github.com/aaif/wg-observability-and-traceability/issues/37:
the grade is DERIVED by the consumer from what the record shows, and nothing
the producer declares about its own record can raise it. A producer-declared
grade and producer-declared integrity booleans are read only to be compared
against the derived grade.

The ladder, as this reader derives it, each rung requiring the one below:

* E0 Declared: the agent's own report, and nothing else.
* E1 Observed: at least one observation from a framework or gateway whose
  ``witness_scope`` is not ``SELF`` (``e1_no_external_observer``).
* E2 Enforced: policy enforced at a boundary, with at least one denial recorded
  by an observation at ``observation_vantage`` ``substrate`` and
  ``observation_directness`` ``intercepted`` (``e2_no_recorded_denial``).
* E3 Corroborated: at least two distinct basis engines whose relationship to
  the observed party is ``independent``, neither a self report nor ``SELF``
  scoped (``e3_insufficient_independent_engines``).
* E4 Anchored: an external timestamp, a chain link to the previous record, and
  an independent verification, each present as a marker object with its own
  fields (``e4_missing_external_timestamp``, ``e4_missing_chain_link``,
  ``e4_missing_independent_verification``).

The claim floor: an ``operationally-conformant`` claim requires a derived grade
of at least E3 (``claim_floor_below_e3``) and a reconciliation state other than
``contradiction`` (``claim_floor_contradiction``).

A record is accepted when the derived grade is at least the declared grade and
the claim floor holds. A rejected record names the rule that stopped it: the
contradiction floor first, then the rung the derivation could not reach, then
the E3 floor when the declared grade itself was met.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints
one JSON object carrying ``decision``, ``derivedGrade`` and ``reason``, and
exits 0 for ``accepted`` and 1 for ``rejected``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

SUITE = "evidence-grade-floor/v1"
ACCEPTED, REJECTED = "accepted", "rejected"
EXIT_FOR = {ACCEPTED: 0, REJECTED: 1}
GRADES = ("E0", "E1", "E2", "E3", "E4")
CONFORMANT = "operationally-conformant"
OBSERVER_SOURCES = ("framework", "gateway")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Every rule the reader applies. The first two are not refusal codes: they are
# the property under test, that declared values never raise the grade, and the
# mutation check switches them off to prove a member depends on each.
RULES = (
    "declared_grade_ignored",
    "declared_integrity_ignored",
    "e1_no_external_observer",
    "e2_no_recorded_denial",
    "e3_insufficient_independent_engines",
    "e4_missing_external_timestamp",
    "e4_missing_chain_link",
    "e4_missing_independent_verification",
    "claim_floor_below_e3",
    "claim_floor_contradiction",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-grade-floor" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-grade-floor")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _external_observer(obs: dict[str, Any]) -> bool:
    return obs.get("source") in OBSERVER_SOURCES and obs.get("witness_scope") != "SELF"


def _rung_e1(record: dict[str, Any]) -> bool:
    return any(_external_observer(o) for o in record.get("observations", []))


def _rung_e2(record: dict[str, Any]) -> bool:
    enforcement = record.get("enforcement") or {}
    if enforcement.get("policy_enforced_at_boundary") is not True:
        return False
    engines = {o.get("engine") for o in record.get("observations", [])
               if o.get("observation_vantage") == "substrate"
               and o.get("observation_directness") == "intercepted"
               and o.get("witness_scope") != "SELF"}
    return any(d.get("recorded_by") in engines for d in enforcement.get("denials", [])
               if isinstance(d, dict))


def _rung_e3(record: dict[str, Any]) -> bool:
    engines = {o.get("engine") for o in record.get("observations", [])
               if o.get("relationship") == "independent"
               and o.get("source") != "self_report"
               and o.get("witness_scope") != "SELF"}
    return len(engines) >= 2


def _marker(record: dict[str, Any], name: str, skip: frozenset[str]) -> bool:
    """Whether an integrity marker is present as an object with its own fields.

    A producer's ``integrity_claims`` booleans are ignored unless the rule that
    ignores them is switched off, which only the mutation check does.
    """
    if ("declared_integrity_ignored" in skip
            and (record.get("integrity_claims") or {}).get(name) is True):
        return True
    marker = (record.get("integrity_markers") or {}).get(name)
    if not isinstance(marker, dict):
        return False
    if name == "external_timestamp":
        return (marker.get("witness_scope") == "EXTERNAL"
                and bool(HEX64.match(str(marker.get("token_sha256", "")))))
    if name == "chain_link":
        return bool(HEX64.match(str(marker.get("prev_sha256", ""))))
    return marker.get("witness_scope") == "EXTERNAL" and marker.get("result") == "verified"


def _ladder(skip: frozenset[str]) -> list[tuple[str, Callable[[dict[str, Any]], bool]]]:
    """The rung checks in order: (rule, predicate) for each step above E0."""
    return [
        ("e1_no_external_observer", _rung_e1),
        ("e2_no_recorded_denial", _rung_e2),
        ("e3_insufficient_independent_engines", _rung_e3),
        ("e4_missing_external_timestamp", lambda r: _marker(r, "external_timestamp", skip)),
        ("e4_missing_chain_link", lambda r: _marker(r, "chain_link", skip)),
        ("e4_missing_independent_verification",
         lambda r: _marker(r, "independent_verification", skip)),
    ]


_RUNG_OF = {"e1_no_external_observer": 1, "e2_no_recorded_denial": 2,
            "e3_insufficient_independent_engines": 3, "e4_missing_external_timestamp": 4,
            "e4_missing_chain_link": 4, "e4_missing_independent_verification": 4}


def derive(record: dict[str, Any], skip: frozenset[str] = frozenset()) -> tuple[int, str | None]:
    """The derived grade index and the rule that blocked the next rung, if any."""
    for rule, holds in _ladder(skip):
        if rule not in skip and not holds(record):
            return _RUNG_OF[rule] - 1, rule
    return len(GRADES) - 1, None


def decide(record: dict[str, Any], skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision for one record."""
    grade, blocked_by = derive(record, skip)
    declared = GRADES.index(record.get("declared_grade", "E0"))
    if "declared_grade_ignored" in skip:
        grade = max(grade, declared)
    claim = record.get("claim")
    out = {"derivedGrade": GRADES[grade]}
    if (claim == CONFORMANT and record.get("reconciliation") == "contradiction"
            and "claim_floor_contradiction" not in skip):
        return {**out, "decision": REJECTED, "reason": "claim_floor_contradiction"}
    if grade < declared:
        return {**out, "decision": REJECTED, "reason": blocked_by or "e1_no_external_observer"}
    if claim == CONFORMANT and grade < 3 and "claim_floor_below_e3" not in skip:
        return {**out, "decision": REJECTED, "reason": "claim_floor_below_e3"}
    return {**out, "decision": ACCEPTED, "reason": "grade_derived"}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    return decide(json.loads(case_path.read_text(encoding="utf-8")), skip)


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    ids = {entry["id"] for entry in entries}
    if not entries or len(ids) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != ids:
        return [], "case directories do not match manifest"
    by_id = {entry["id"]: entry for entry in entries}
    for entry in entries:
        if entry["expected"]["decision"] != REJECTED:
            continue
        twin = by_id.get(entry.get("twin", ""))
        if twin is None or twin["expected"]["decision"] != ACCEPTED:
            return [], f"{entry['id']}: a rejected member must name an accepted twin"
        if entry["expected"]["reason"] not in RULES:
            return [], f"{entry['id']}: refusal code is not a rule this reader applies"
    return entries, None


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "derivedGrade", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement.
    """
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(directory / "case.json", skip)
        else:
            ran, observed = _external_answer(command, directory / "case.json")
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['derivedGrade']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
