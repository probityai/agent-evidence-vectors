"""Connector scope record: the reference reader for the `connector-scope-record/v1` corpus.

A connector that reaches a health-system record states three things: what it can read, what it
can change, and what it refused. The reader judges one action against the scope the connector
was granted: a change under a read-only grant, an unlisted action that ran, a permitted action
refused as out of scope, and a refusal with no recorded reason are all refused. The scope must
match the digest granted, and a fixture that carries a protected-health-information pattern is
refused so a shared corpus stays clean.

Every rule below is a refusal code. A record is accepted only when none of the
rules fires; a rejected record names the first rule that fired, in the order
listed in ``RULES``. The fixtures are synthetic: no real merchant, patient,
account or server appears in any of them.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one
JSON object carrying ``decision`` and ``reason``, and exits 0 for ``accepted``
and 1 for ``rejected``.
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

SUITE = "connector-scope-record/v1"
ACCEPTED, REJECTED = "accepted", "rejected"
EXIT_FOR = {ACCEPTED: 0, REJECTED: 1}
ACCEPT_REASON = "scope_respected"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-connector-scope"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "vectors-connector-scope"
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def canon(value: object) -> bytes:
    """The bytes a digest in a record is taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_of(value: object) -> str:
    return _sha(canon(value))


PHI_PATTERNS = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"(?i)\bmrn[:=]?\s*\d{5,}"),
    re.compile(r"(?i)\bdob[:=]"),
    re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b.*(?i:born)"),
)


def _get(record: dict[str, Any], path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _in(record: dict[str, Any], kind: str) -> bool:
    scope = _get(record, "connector.declared_scope") or {}
    return _get(record, "action.resource") in (scope.get(kind) or [])


def _permitted(record: dict[str, Any]) -> bool:
    kind = _get(record, "action.kind")
    return kind in ("read", "change") and _in(record, str(kind))


def _scope_missing(r: dict[str, Any]) -> bool:
    scope = _get(r, "connector.declared_scope")
    return not (isinstance(scope, dict) and "read" in scope and "change" in scope)


def _scope_digest(r: dict[str, Any]) -> bool:
    return bool(_get(r, "connector.grant_digest") != digest_of(_get(r, "connector.declared_scope")))


def _phi(r: dict[str, Any]) -> bool:
    text = canon(r).decode()
    return any(p.search(text) for p in PHI_PATTERNS) or _get(r, "fixture.phi_free") is not True


def _performed(r: dict[str, Any]) -> bool:
    return bool(_get(r, "outcome.result") == "performed")


def _change_on_read_grant(r: dict[str, Any]) -> bool:
    return (
        _get(r, "action.kind") == "change"
        and _performed(r)
        and not _in(r, "change")
        and _in(r, "read")
    )


def _out_of_scope_performed(r: dict[str, Any]) -> bool:
    return _performed(r) and not _permitted(r)


def _in_scope_refused(r: dict[str, Any]) -> bool:
    return (
        _get(r, "outcome.result") == "refused"
        and _permitted(r)
        and _get(r, "outcome.reason") == "out_of_scope"
    )


def _refusal_unrecorded(r: dict[str, Any]) -> bool:
    return (
        _get(r, "outcome.result") == "refused"
        and not _permitted(r)
        and not (_get(r, "outcome.reason") and _get(r, "outcome.refusal_recorded_by"))
    )


def _action_digest(r: dict[str, Any]) -> bool:
    return bool(_get(r, "record.action_digest") != digest_of(_get(r, "action")))


CHECKS: tuple[tuple[str, Callable[[dict[str, Any]], bool]], ...] = (
    ("scope_declaration_missing", _scope_missing),
    ("grant_digest_mismatch", _scope_digest),
    ("fixture_not_phi_free", _phi),
    ("change_performed_under_read_grant", _change_on_read_grant),
    ("out_of_scope_action_performed", _out_of_scope_performed),
    ("in_scope_action_refused_as_out_of_scope", _in_scope_refused),
    ("refusal_not_recorded", _refusal_unrecorded),
    ("action_digest_mismatch", _action_digest),
)

RULES = tuple(code for code, _ in CHECKS)


def decide(record: dict[str, Any], skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision: the first rule that fires, else accepted."""
    for code, fires in CHECKS:
        if code not in skip and fires(record):
            return {"decision": REJECTED, "reason": code}
    return {"decision": ACCEPTED, "reason": ACCEPT_REASON}


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
        result = subprocess.run(
            [*command, str(case_path), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
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
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
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
        "suite": SUITE,
        "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {
            "vectors": total,
            "conform": total - len(errors),
            "fail": len(errors),
            "suiteRefusals": 0,
        },
        "failures": errors,
    }
    Path(report_path).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
