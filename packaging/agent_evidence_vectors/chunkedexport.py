"""Judge an export gate's decision on one chunk of a chunked export.

An agent exports a flagged dataset in chunks. Each export is reversible on its
own, through a documented delete-from-destination capability, so every chunk's
per-step class is honestly ``reversible``. The chain as a whole is not: once
enough of the dataset has left, the recipient can reconstruct it, and deleting
the chunks no longer undoes the disclosure. A seal that takes the maximum of the
per-step labels says ``reversible`` while the chain is irreversible.

Every record is the gate's view at the moment one chunk is presented: the chunks
already exported in order, the chunk now presented last, the reconstruction
rule the issuer committed to and when, and the class the seal declares. The
reader derives the composed class from the exported chunks and the committed
rule, then checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the chunked-export contract (``contract_id_unknown``);
3. the reconstruction rule was committed no later than the first chunk left
   (``threshold_not_precommitted``);
4. the seal's ``maxClass`` is the composed class (``seal_understates_composition``);
5. the composed class is ``reversible`` (``export_irreversible``).

A record that passes all five is ``allow`` with reason ``reversible_so_far``.

The composed class is ``irreversible`` when any exported chunk's per-step class
is ``irreversible``, or when the reconstruction rule holds over the exported
chunks. A ``count`` rule holds once at least ``k`` chunks have left. A ``sets``
rule holds once the exported chunks include every chunk of one of its minimal
reconstructing sets, so which chunks have left decides, not how many.

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

SUITE = "chunked-export/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-vectors/contract/"
               "chunked-export/v1")
ALLOW, DENY = "allow", "deny"
REVERSIBLE, IRREVERSIBLE = "reversible", "irreversible"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "threshold_not_precommitted",
    "seal_understates_composition",
    "export_irreversible",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-chunked-export" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-chunked-export")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _exported(record: dict[str, Any]) -> list[dict[str, Any]]:
    chunks = {chunk["index"]: chunk for chunk in record["chunks"]}
    return [chunks[index] for index in record["exported"]]


def rule_holds(rule: dict[str, Any], indices: set[int]) -> bool:
    """Whether the committed reconstruction rule holds over the exported indices."""
    if rule["kind"] == "count":
        return len(indices) >= int(rule["k"])
    if rule["kind"] == "sets":
        return any(set(subset) <= indices for subset in rule["minimalSets"])
    raise ValueError(f"unknown reconstruction rule kind {rule['kind']!r}")


def composed_class(record: dict[str, Any]) -> str:
    """The class of the export chain so far, from its chunks and the committed rule."""
    exported = _exported(record)
    if any(chunk["stepClass"] == IRREVERSIBLE for chunk in exported):
        return IRREVERSIBLE
    indices = {chunk["index"] for chunk in exported}
    return IRREVERSIBLE if rule_holds(record["reconstruction"], indices) else REVERSIBLE


def payloads_match(record: dict[str, Any], directory: Path) -> bool:
    """Whether every chunk's payload file has the digest the record states."""
    return all(_sha((directory / chunk["payloadFile"]).read_bytes()) == chunk["payloadSha256"]
               for chunk in record["chunks"])


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    first_left = min(_when(chunk["leftAt"]) for chunk in _exported(record))
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "threshold_not_precommitted": lambda: _when(
            record["reconstruction"]["committedAt"]) > first_left,
        "seal_understates_composition": lambda: record["seal"]["maxClass"] != composed_class(
            record),
        "export_irreversible": lambda: composed_class(record) == IRREVERSIBLE,
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    record = json.loads(record_path.read_text(encoding="utf-8"))
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": "reversible_so_far"}


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


def _corpus_errors(record_path: Path, entry: dict[str, Any]) -> list[str]:
    """Corpus errors in one member, whichever verifier is under test."""
    record = json.loads(record_path.read_text(encoding="utf-8"))
    errors = []
    if not payloads_match(record, record_path.parent):
        errors.append("a chunk payload does not match its stated digest")
    if composed_class(record) != entry["composedClass"]:
        errors.append("declared composed class does not hold")
    return errors


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader.

    Returns the number of records answered and every disagreement. A record
    whose declared composed class does not hold, or whose chunk payloads do not
    match their digests, is a corpus error, whichever verifier is under test.
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
        errors.extend(f"{name}: {error}" for error in _corpus_errors(record_path, entry))
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
