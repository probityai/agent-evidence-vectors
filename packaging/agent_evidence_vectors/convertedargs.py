"""Judge one approved tool call: what the approver was shown against what ran.

A tool call is approved on one representation of its arguments and run on
another. Between them sit conversion (a string made a boolean, a float cut to
an integer, an object turned into its repr), constructors that fill defaults,
and an approval chain that may edit the call in place. The rule this corpus
tests is the one UKGovernmentBEIS/inspect_ai adopted in pull request 5652: the
approver sees the converted arguments, and what runs is rebuilt from the
approved JSON and must serialize back to exactly it. Comparison is under
RFC 8785, so two files with the same members in a different order are equal.

A case holds ``raw.json`` (the arguments the model gave), ``shown.json`` (the
converted arguments shown to the approver), ``rebuilt.json`` (the call rebuilt
from the approved JSON), ``executed.json`` (the arguments the tool ran with), an
optional ``modified.json`` (the approver's full replacement) and ``record.json``
(the contract, the parameter declarations, the approval and the digests of the
call before and after the approval chain). The reader checks in a fixed order
and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the converted-argument-binding contract
   (``contract_id_unknown``);
3. the approval's ``shownSha256`` is the SHA-256 of the bytes of ``shown.json``
   (``approval_not_bound_to_shown``);
4. ``shown.json`` is I-JSON: no duplicate member, no NaN or Infinity, no
   unpaired surrogate, no integer beyond 2^53 (``shown_not_storable``);
5. ``raw.json`` satisfies the declared parameter types and enums, so the call
   should have been shown at all (``invalid_call_approved``);
6. under a ``modify`` decision, ``modified.json`` carries every declared
   parameter that has a default and no parameter that is not declared
   (``modify_not_full_call``);
7. the RFC 8785 form of ``rebuilt.json`` equals that of the approved arguments,
   which are ``shown.json``, or ``modified.json`` under ``modify``
   (``rebuild_not_identical``);
8. under ``approve``, the call's digest after the approval chain equals its
   digest before (``call_mutated_after_approval``);
9. the RFC 8785 form of ``executed.json`` equals that of the approved
   arguments (``shown_not_executed``).

A record that passes all nine is ``allow`` with reason ``bound``.

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

from . import a2ajcs

SUITE = "converted-argument-binding/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-observer/contract/"
               "converted-argument-binding/v1")
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "approval_not_bound_to_shown",
    "shown_not_storable",
    "invalid_call_approved",
    "modify_not_full_call",
    "rebuild_not_identical",
    "call_mutated_after_approval",
    "shown_not_executed",
)
_SAFE_INTEGER = 1 << 53  # exclusive: an I-JSON integer has magnitude below 2^53
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-converted-argument-binding" if
        (_HERE / "corpora").exists()
        else _HERE.parents[1] / "vectors-converted-argument-binding")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _safe(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return abs(value) < _SAFE_INTEGER
    if isinstance(value, list):
        return all(_safe(item) for item in value)
    if isinstance(value, dict):
        return all(_safe(item) for item in value.values())
    return True


def parse_ijson(data: bytes) -> Any:
    """The value of I-JSON bytes, or ValueError when the bytes are not I-JSON."""
    try:
        value = a2ajcs.parse(data.decode("utf-8"))
        a2ajcs.canonicalize(value)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(str(exc)) from exc
    if not _safe(value):
        raise ValueError("integer outside the I-JSON range")
    return value


def canonical(data: bytes | None) -> bytes | None:
    """The RFC 8785 form of I-JSON bytes, or None when absent or not I-JSON."""
    if data is None:
        return None
    try:
        return a2ajcs.canonicalize(parse_ijson(data))
    except ValueError:
        return None


class Case:
    """One case directory: its record and the bytes of each argument file."""

    def __init__(self, record_path: Path) -> None:
        self.record: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
        directory = record_path.parent
        self.files: dict[str, bytes | None] = {
            name: (directory / name).read_bytes() if (directory / name).is_file() else None
            for name in ("raw.json", "shown.json", "rebuilt.json", "executed.json",
                         "modified.json")}

    @property
    def modifying(self) -> bool:
        return bool(self.record["approval"]["decision"] == "modify")

    def approved(self) -> bytes | None:
        """The RFC 8785 form of the arguments the approver approved."""
        return canonical(self.files["modified.json" if self.modifying else "shown.json"])


def shown_equals_executed(case: Case) -> bool:
    """Whether the shown and executed arguments are the same under RFC 8785."""
    shown = canonical(case.files["shown.json"])
    return shown is not None and shown == canonical(case.files["executed.json"])


def _type_holds(kind: Any, value: Any) -> bool:
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if kind == "string":
        return isinstance(value, str)
    return bool(kind == "object" and isinstance(value, dict))


def _enum_holds(declared: dict[str, Any], value: Any) -> bool:
    if "enum" not in declared:
        return True
    return a2ajcs.canonicalize(value) in {a2ajcs.canonicalize(item) for item in declared["enum"]}


def _invalid_call(case: Case) -> bool:
    raw = case.files["raw.json"]
    parameters: dict[str, Any] = case.record["parameters"]
    try:
        arguments = parse_ijson(raw) if raw is not None else None
    except ValueError:
        return True
    if not isinstance(arguments, dict):
        return True
    return any(name not in parameters or not _type_holds(parameters[name]["type"], value)
               or not _enum_holds(parameters[name], value)
               for name, value in arguments.items())


def _not_full_call(case: Case) -> bool:
    if not case.modifying:
        return False
    parameters: dict[str, Any] = case.record["parameters"]
    try:
        modified = parse_ijson(case.files["modified.json"] or b"")
    except ValueError:
        return True
    if not isinstance(modified, dict):
        return True
    defaulted = {name for name, declared in parameters.items() if "default" in declared}
    return not defaulted <= set(modified) or not set(modified) <= set(parameters)


def _shown_unstorable(case: Case) -> bool:
    try:
        parse_ijson(case.files["shown.json"] or b"")
    except ValueError:
        return True
    return False


def _first_failure(case: Case, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the case fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    record = case.record
    approved = case.approved()
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "approval_not_bound_to_shown": lambda: record["approval"]["shownSha256"] != _sha(
            case.files["shown.json"] or b""),
        "shown_not_storable": lambda: _shown_unstorable(case),
        "invalid_call_approved": lambda: _invalid_call(case),
        "modify_not_full_call": lambda: _not_full_call(case),
        "rebuild_not_identical": lambda: (
            approved is None or canonical(case.files["rebuilt.json"]) != approved),
        "call_mutated_after_approval": lambda: (
            not case.modifying
            and record["callCopyBeforeSha256"] != record["callCopyAfterSha256"]),
        "shown_not_executed": lambda: (
            approved is None or canonical(case.files["executed.json"]) != approved),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(Case(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": "bound"}


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
    whose declared shown-and-executed property does not hold is a corpus error, whichever
    verifier is under test.
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
        if shown_equals_executed(Case(record_path)) != entry["shownEqualsExecuted"]:
            errors.append(f"{name}: declared shown-and-executed property does not hold")
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
