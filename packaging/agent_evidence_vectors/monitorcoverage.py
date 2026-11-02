"""Judge one monitor verdict against what the monitor could see.

A monitor (a detector, a defence, a log reader) reports over a window that it
saw nothing wrong. A consumer reads "clean". Two gaps hide inside that word:
the collector behind the monitor may have dropped or never received part of
the window, and the monitor's vantage may not include the channel an effect
actually used. A missing observation then reads as a clean one. A third gap
sits in evaluations of defences: a defence that never acted is credited with
the harm it is said to have prevented.

Every record is one monitor's verdict over one window: the monitor, its
vantage and the channels it reads, the window, the collector-side coverage
count (events expected, collected, dropped, and who counted them), the effect
under question when another source observed one, the verdict with its decision
and effective-action counts, and an optional claim drawn from it. The reader
checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the monitor-coverage contract (``contract_id_unknown``);
3. the window ends after it starts (``window_invalid``);
4. the counts are non-negative, collected plus dropped is at most expected, and
   effective actions are at most decisions (``coverage_counts_invalid``);
5. a clean verdict rests on a count the collector made, not on one the
   watched producer reported about itself (``coverage_self_reported``);
6. a clean verdict has every expected event collected and none dropped
   (``clean_with_incomplete_coverage``);
7. a clean verdict covers the channel the observed effect used
   (``clean_outside_vantage``);
8. a clean verdict does not stand beside an effect observed inside the window
   on a channel the monitor reads with complete coverage
   (``clean_contradicts_observed_effect``);
9. a claim that the defence reduced harm rests on at least one effective
   action (``defence_effect_without_effective_actions``).

A record that passes all nine is ``allow`` with reason ``verdict_supported``.
``not_established`` is always available to a monitor whose coverage is
incomplete, and a ``flagged`` verdict needs no completeness to stand.

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

SUITE = "monitor-coverage/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/monitor-coverage"
ALLOW, DENY = "allow", "deny"
ALLOWED_REASON = "verdict_supported"
EXIT_FOR = {ALLOW: 0, DENY: 1}
RESULTS = ("clean", "flagged", "not_established")
BASES = ("collector_count", "producer_count")
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "window_invalid",
    "coverage_counts_invalid",
    "coverage_self_reported",
    "clean_with_incomplete_coverage",
    "clean_outside_vantage",
    "clean_contradicts_observed_effect",
    "defence_effect_without_effective_actions",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-monitor-coverage" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-monitor-coverage")

Record = dict[str, Any]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _at(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _complete(record: Record) -> bool:
    coverage = record["coverage"]
    return coverage["collected"] == coverage["expected"] and coverage["dropped"] == 0


def _clean(record: Record) -> bool:
    return bool(record["verdict"]["result"] == "clean")


def _counts_invalid(record: Record) -> bool:
    coverage, verdict = record["coverage"], record["verdict"]
    counts = [coverage["expected"], coverage["collected"], coverage["dropped"],
              verdict["decisions"], verdict["effectiveActions"]]
    return (any(n < 0 for n in counts)
            or coverage["collected"] + coverage["dropped"] > coverage["expected"]
            or verdict["effectiveActions"] > verdict["decisions"])


def _outside_vantage(record: Record) -> bool:
    effect = record.get("effect")
    return (_clean(record) and effect is not None
            and effect["channel"] not in record["monitor"]["channels"])


def _contradicted(record: Record) -> bool:
    effect, window = record.get("effect"), record["window"]
    return (_clean(record) and effect is not None and _complete(record)
            and effect["channel"] in record["monitor"]["channels"]
            and _at(window["start"]) <= _at(effect["at"]) < _at(window["end"]))


def _defence_effect_unearned(record: Record) -> bool:
    claim = record.get("claim")
    return (claim is not None and claim["kind"] == "defence_reduced_harm"
            and record["verdict"]["effectiveActions"] == 0)


def retained(record: Record) -> dict[str, Any]:
    """The monitor, result, coverage completeness and action counts a verifier keeps."""
    return {
        "complete": _complete(record),
        "decisions": record["verdict"]["decisions"],
        "effectiveActions": record["verdict"]["effectiveActions"],
        "monitor": record["monitor"]["id"],
        "result": record["verdict"]["result"],
    }


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    window = record["window"]
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "window_invalid": lambda: _at(window["end"]) <= _at(window["start"]),
        "coverage_counts_invalid": lambda: _counts_invalid(record),
        "coverage_self_reported": lambda: (_clean(record)
                                           and record["coverage"]["basis"] != "collector_count"),
        "clean_with_incomplete_coverage": lambda: _clean(record) and not _complete(record),
        "clean_outside_vantage": lambda: _outside_vantage(record),
        "clean_contradicts_observed_effect": lambda: _contradicted(record),
        "defence_effect_without_effective_actions": lambda: _defence_effect_unearned(record),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def _load(record_path: Path) -> Record:
    loaded: Record = json.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path, suite: str) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != suite:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    """Run one external verifier on one record and read its decision."""
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


def check_corpus(
    root: Path, suite: str, verify_one: Callable[[Path, frozenset[str]], dict[str, str]],
    keep: Callable[[Record], dict[str, Any]], verifier: str | list[str] | None = None,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record of a decision corpus through a verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, suite)
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
        if keep(_load(record_path)) != entry["retained"]:
            errors.append(f"{name}: declared retained fields do not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify_one(record_path, skip)
        else:
            ran, observed = external_answer(command, record_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    return check_corpus(root, SUITE, verify, retained, verifier, skip)


def run_corpus(suite: str, checker: Callable[..., tuple[int, list[str]]], root: str,
               verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge a decision corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = checker(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{suite}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": suite, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def cli(argv: list[str] | None, doc: str | None, verify_one: Callable[[Path], dict[str, str]],
        checker: Callable[..., tuple[int, list[str]]], root: Path) -> int:
    """The command line every decision corpus shares."""
    parser = argparse.ArgumentParser(description=(doc or "").splitlines()[0])
    parser.add_argument("record", nargs="?",
                        help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify_one(Path(args.record))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = checker(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    return cli(argv, __doc__, verify, check, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
