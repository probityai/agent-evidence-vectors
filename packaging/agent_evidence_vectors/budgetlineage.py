"""Judge whether every charge a delegation tree made stays in the budget its principal granted.

A runtime that keeps per-flow counters can be reset by a sub-agent that opens a
new root: the counters for the new flow start at zero, the spend is booked
against a budget nobody delegated, and the parent's record shows a clean
picture. Every record here holds the delegation edges of one principal's tree
(each as granted by the delegator and accepted by the delegate), the budgets the
tree may spend from, the depth limit, and every charge the accounting authority
booked for the agents the edges name, whatever budget each charge names. The
reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the budget-lineage contract (``contract_id_unknown``);
3. every field has the type the contract gives it (``malformed_record``);
4. every grant has the delegate's acceptance of the same grant, and every
   acceptance names a grant (``delegation_unilateral``);
5. every delegator is the principal or a member of the tree when it grants
   (``delegation_detached``);
6. no member deeper than ``maxDepth`` was admitted a charge
   (``depth_limit_exceeded``);
7. no carved budget is larger than the budget its delegator holds
   (``carve_exceeds_parent``);
8. no member is charged against a budget outside the lineage while it is a
   member (``charge_outside_lineage``);
9. the units charged against the lineage stay inside the principal's limit and
   inside every carve's limit (``lineage_overspend``).

An agent is a member at an instant when its grant was issued at or before it,
is not revoked at it, and its delegator is the principal or a member at that
instant, so revoking a delegate removes its whole subtree. A charge counts when
it was admitted and its outcome is ``committed`` or ``unknown``. A record that
passes all nine is ``allow`` with reason ``lineage_held``.

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
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "budget-lineage/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-observer/contract/"
               "budget-lineage/v1")
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
DECISIONS = ("admitted", "refused")
OUTCOMES = ("committed", "released", "unknown", "none")
CHARGED_OUTCOMES = ("committed", "unknown")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "delegation_unilateral",
    "delegation_detached",
    "depth_limit_exceeded",
    "carve_exceeds_parent",
    "charge_outside_lineage",
    "lineage_overspend",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-budget-lineage" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-budget-lineage")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: object) -> datetime | None:
    """An RFC 3339 instant in UTC written with a trailing Z, or None."""
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def _is_name(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _grant_ok(grant: object) -> bool:
    if not isinstance(grant, dict):
        return False
    names = all(_is_name(grant.get(key)) for key in ("grantId", "delegator", "delegate"))
    revoked = grant.get("revokedAt")
    carve = grant.get("carve")
    carve_ok = carve is None or (isinstance(carve, dict) and _is_name(carve.get("id"))
                                 and _is_count(carve.get("limit")))
    return bool(names and _when(grant.get("issuedAt")) and carve_ok
                and (revoked is None or _when(revoked) is not None))


def _acceptance_ok(item: object) -> bool:
    return (isinstance(item, dict) and _is_name(item.get("grantId"))
            and _is_name(item.get("delegate")) and _when(item.get("acceptedAt")) is not None)


def _charge_ok(item: object) -> bool:
    return (isinstance(item, dict)
            and all(_is_name(item.get(key)) for key in ("requestId", "agent", "budget"))
            and _is_count(item.get("units")) and _when(item.get("at")) is not None
            and item.get("decision") in DECISIONS and item.get("outcome") in OUTCOMES)


def malformed(record: dict[str, Any]) -> bool:
    """Whether any field lacks the type the contract gives it."""
    budget = record.get("budget")
    depth = record.get("maxDepth")
    delegations = record.get("delegations")
    acceptances = record.get("acceptances")
    ledger = record.get("ledger")
    if not (_is_name(record.get("principal")) and isinstance(budget, dict)
            and _is_name(budget.get("id")) and _is_count(budget.get("limit"))
            and isinstance(depth, int) and _is_count(depth) and depth >= 1
            and isinstance(delegations, list) and isinstance(acceptances, list)
            and isinstance(ledger, list)):
        return True
    return not (all(_grant_ok(g) for g in delegations)
                and all(_acceptance_ok(a) for a in acceptances)
                and all(_charge_ok(c) for c in ledger))


def is_charged(item: dict[str, Any]) -> bool:
    """Whether a ledger entry's units count against the budget it names."""
    return bool(item["decision"] == "admitted" and item["outcome"] in CHARGED_OUTCOMES)


def _active(grant: dict[str, Any], at: datetime) -> bool:
    issued = _when(grant["issuedAt"])
    revoked = _when(grant.get("revokedAt"))
    return bool(issued is not None and issued <= at and (revoked is None or at < revoked))


def depth_at(record: dict[str, Any], agent: str, at: datetime,
             seen: frozenset[str] = frozenset()) -> int | None:
    """The agent's depth below the principal at ``at``, or None when it is not a member."""
    if agent == record["principal"]:
        return 0
    if agent in seen:
        return None
    depths = []
    for grant in record["delegations"]:
        if grant["delegate"] != agent or not _active(grant, at):
            continue
        parent = depth_at(record, grant["delegator"], at, seen | {agent})
        if parent is not None:
            depths.append(parent + 1)
    return min(depths) if depths else None


def lineage_budgets(record: dict[str, Any]) -> set[str]:
    """The principal's budget and every budget carved from it in the tree."""
    budgets = {record["budget"]["id"]}
    budgets.update(g["carve"]["id"] for g in record["delegations"] if g.get("carve"))
    return budgets


def charged_units(record: dict[str, Any]) -> int:
    """The units charged against the lineage, by anyone."""
    lineage = lineage_budgets(record)
    return sum(item["units"] for item in record["ledger"]
               if is_charged(item) and item["budget"] in lineage)


def retained(record: dict[str, Any]) -> dict[str, Any]:
    """The principal, budget, agents and charged units a verifier must keep."""
    try:
        units: int | None = charged_units(record)
    except (KeyError, TypeError, AttributeError):
        units = None
    raw_ledger = record.get("ledger")
    raw_budget = record.get("budget")
    ledger: list[Any] = raw_ledger if isinstance(raw_ledger, list) else []
    budget: dict[str, Any] = raw_budget if isinstance(raw_budget, dict) else {}
    return {
        "agents": sorted({str(item.get("agent")) for item in ledger if isinstance(item, dict)}),
        "budget": budget.get("id"),
        "chargedUnits": units,
        "principal": record.get("principal"),
    }


def _unilateral(record: dict[str, Any]) -> bool:
    grants = {(g["grantId"], g["delegate"]): _when(g["issuedAt"]) for g in record["delegations"]}
    accepted = {(a["grantId"], a["delegate"]): _when(a["acceptedAt"])
                for a in record["acceptances"]}
    if set(grants) != set(accepted):
        return True
    return any(accepted[key] < grants[key] for key in grants)  # type: ignore[operator]


def _detached(record: dict[str, Any]) -> bool:
    for grant in record["delegations"]:
        issued = _when(grant["issuedAt"])
        assert issued is not None
        if depth_at(record, grant["delegator"], issued) is None:
            return True
    return False


def _too_deep(record: dict[str, Any]) -> bool:
    for item in record["ledger"]:
        if item["decision"] != "admitted":
            continue
        depth = depth_at(record, item["agent"], _when(item["at"]))  # type: ignore[arg-type]
        if depth is not None and depth > record["maxDepth"]:
            return True
    return False


def _holding(record: dict[str, Any], agent: str, seen: frozenset[str] = frozenset()) -> int:
    """The limit an agent may carve from: its own carve, else its delegator's."""
    if agent == record["principal"] or agent in seen:
        return int(record["budget"]["limit"])
    for grant in record["delegations"]:
        if grant["delegate"] == agent:
            if grant.get("carve"):
                return int(grant["carve"]["limit"])
            return _holding(record, grant["delegator"], seen | {agent})
    return int(record["budget"]["limit"])


def _carve_wider(record: dict[str, Any]) -> bool:
    return any(g.get("carve") and g["carve"]["limit"] > _holding(record, g["delegator"])
               for g in record["delegations"])


def _outside(record: dict[str, Any]) -> bool:
    lineage = lineage_budgets(record)
    for item in record["ledger"]:
        if not is_charged(item) or item["budget"] in lineage:
            continue
        if item["agent"] == record["principal"]:
            continue
        if depth_at(record, item["agent"], _when(item["at"])) is not None:  # type: ignore[arg-type]
            return True
    return False


def _overspend(record: dict[str, Any]) -> bool:
    if charged_units(record) > record["budget"]["limit"]:
        return True
    for grant in record["delegations"]:
        carve = grant.get("carve")
        if not carve:
            continue
        spent = sum(item["units"] for item in record["ledger"]
                    if is_charged(item) and item["budget"] == carve["id"])
        if spent > carve["limit"]:
            return True
    return False


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
        "malformed_record": lambda: malformed(record),
        "delegation_unilateral": lambda: _unilateral(record),
        "delegation_detached": lambda: _detached(record),
        "depth_limit_exceeded": lambda: _too_deep(record),
        "carve_exceeds_parent": lambda: _carve_wider(record),
        "charge_outside_lineage": lambda: _outside(record),
        "lineage_overspend": lambda: _overspend(record),
    }
    for name in CHECKS:
        if name in skip:
            continue
        if name != "malformed_record" and "malformed_record" in skip and malformed(record):
            continue
        if failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": "lineage_held"}


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
    whose retained principal, budget, agents or charged units differ from what
    its fields give is a corpus error, whichever verifier is under test.
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
