"""Judge the accounting decisions taken against one budget shared by a principal.

A control that limits each agent can hold while the budget the agents share
does not. Every record is the accounting authority's decision log for one
budget: the requests that raced for it, what each was granted, the outcome of
each reservation, and the counts the producer retained. The reader checks in a
fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the aggregate-accounting contract (``contract_id_unknown``);
3. every decision names its principal, subtree, budget and action
   (``accounting_identity_missing``);
4. no request is admitted after the accounting authority took longer than its
   latency bound to answer (``latency_bound_admitted``);
5. a reservation whose outcome is unknown is still charged at ``asOf``, also
   after it expired (``unknown_outcome_not_charged``);
6. the units charged across the principal and every subtree do not exceed the
   budget (``aggregate_overspend``);
7. no request was refused for budget that fitted beside everything admitted
   (``fitting_request_refused``);
8. the retained counts equal the counts the decisions give
   (``effect_counts_disagree``).

A request is charged when it was admitted and its outcome is ``committed`` or
``unknown``; a ``released`` reservation returns its units. A record that passes
all eight is ``allow`` with reason ``aggregate_held``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

SUITE = "aggregate-accounting/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-observer/contract/"
               "aggregate-accounting/v1")
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
IDENTITY = ("principal", "subtree", "budget", "action")
CHARGED_OUTCOMES = ("committed", "unknown")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "accounting_identity_missing",
    "latency_bound_admitted",
    "unknown_outcome_not_charged",
    "aggregate_overspend",
    "fitting_request_refused",
    "effect_counts_disagree",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-aggregate-accounting" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-aggregate-accounting")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def is_charged(decision: dict[str, Any]) -> bool:
    """Whether the decision's units count against the budget."""
    return bool(decision["decision"] == "admitted"
                and decision["outcome"] in CHARGED_OUTCOMES)


def charged_units(record: dict[str, Any]) -> int:
    """The units charged across every request in the record."""
    return sum(item["units"] for item in record["decisions"] if is_charged(item))


def effect_counts(record: dict[str, Any]) -> dict[str, int]:
    """The counts the decisions give: what a producer must retain."""
    tally = {kind: sum(1 for item in record["decisions"] if item["decision"] == kind)
             for kind in ("admitted", "refused", "held")}
    charged = charged_units(record)
    return {**tally, "chargedUnits": charged,
            "remainingUnits": record["budget"]["remainingBefore"] - charged}


def retained(record: dict[str, Any]) -> dict[str, Any]:
    """The principal, subtrees, budget, actions and counts a verifier must keep."""
    decisions = record["decisions"]
    return {
        "actions": sorted({str(item.get("action") or "") for item in decisions}),
        "budget": record["budget"]["id"],
        "counts": effect_counts(record),
        "principal": record["principal"],
        "subtrees": sorted({str(item.get("subtree") or "") for item in decisions}),
    }


def _identity_missing(record: dict[str, Any]) -> bool:
    return any(not item.get(key) for item in record["decisions"] for key in IDENTITY)


def _latency_admitted(record: dict[str, Any]) -> bool:
    bound = record["latencyBoundMs"]
    return any(item["decision"] == "admitted" and item["latencyMs"] > bound
               for item in record["decisions"])


def _unknown_released(record: dict[str, Any]) -> bool:
    return any(item["decision"] == "admitted" and item["outcome"] == "unknown"
               and not item["charged"] for item in record["decisions"])


def _overspend(record: dict[str, Any]) -> bool:
    return bool(charged_units(record) > record["budget"]["remainingBefore"])


def _fitting_refused(record: dict[str, Any]) -> bool:
    room = record["budget"]["remainingBefore"] - charged_units(record)
    return any(item["decision"] == "refused" and item.get("reason") == "budget"
               and item["units"] <= room for item in record["decisions"])


def _load(record_path: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "accounting_identity_missing": lambda: _identity_missing(record),
        "latency_bound_admitted": lambda: _latency_admitted(record),
        "unknown_outcome_not_charged": lambda: _unknown_released(record),
        "aggregate_overspend": lambda: _overspend(record),
        "fitting_request_refused": lambda: _fitting_refused(record),
        "effect_counts_disagree": lambda: record["effectCounts"] != effect_counts(record),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": "aggregate_held"}


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
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader.

    Returns the number of records answered and every disagreement. A record
    whose retained principal, subtrees, budget, actions or counts differ from
    what its decisions give is a corpus error, whichever verifier is under test.
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
        record_path = directory / "record.json"
        if retained(_load(record_path)) != entry["retained"]:
            errors.append(f"{name}: declared retained fields do not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(record_path, skip)
        else:
            ran, observed = _external_answer(command, record_path)
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
    parser.add_argument("record", nargs="?",
                        help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
