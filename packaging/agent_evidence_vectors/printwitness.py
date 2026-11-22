"""Judge signed machine-job logs written by a print witness.

A print witness sits between the agent that controls a machine and the machine.
It signs the job file it received before forwarding it, signs log records while
the job runs, and signs a closing record when the job ends. The corpus this
module reads asks what a verifier of such a log does in the cases a signature
check alone does not settle: the log stops early, the job file changed after the
witness signed it, or the log is signed by a different witness than the one
that took the job in. Several rejected logs carry only records that verify
under a key the consumer trusts.

The reader checks in a fixed order and names the first check that fails:

1. every log record verifies under the trusted witness key its ``kid`` names,
   and the record names that witness (``signature_invalid``);
2. the first record is the intake record that names the job file
   (``intake_missing``);
3. every record is signed by the witness that signed the intake
   (``witness_changed``);
4. every record names the job of the intake (``job_mismatch``);
5. record ``i`` carries ``seq`` ``i`` and names the digest of the stored line
   before it (``chain_link_broken``);
6. the job file beside the log is the one the intake names
   (``gcode_altered``);
7. the intake names the job file the consumer ordered (``gcode_not_ordered``);
8. the log ends with a closing record (``log_truncated``);
9. the closing record says the job finished every layer the intake declared
   (``print_not_finished``).

A log that passes all nine is ``verified`` with ``print_witnessed``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``verified`` and 1 for ``rejected``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictjson

SUITE = "print-witness/v1"
VERIFIED, REJECTED = "verified", "rejected"
EXIT_FOR = {VERIFIED: 0, REJECTED: 1}
GENESIS = "0" * 64
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "signature_invalid",
    "intake_missing",
    "witness_changed",
    "job_mismatch",
    "chain_link_broken",
    "gcode_altered",
    "gcode_not_ordered",
    "log_truncated",
    "print_not_finished",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-print-witness" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-print-witness")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to
    dispatch the suite, so a module-level import would be a cycle."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    raise ImportError("the reference rail's Ed25519 and RFC 8785 primitives are unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _signed(envelope: Any, keys: dict[str, str]) -> bool:
    """Whether a log line verifies under the trusted key its kid names, and its
    record names the same witness."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("record"), dict):
        return False
    kid = envelope.get("kid")
    key = keys.get(kid) if isinstance(kid, str) else None
    if key is None or envelope["record"].get("witness") != kid:
        return False
    try:
        sig = base64.b64decode(str(envelope.get("sig", "")), validate=True)
        public = bytes.fromhex(key)
    except ValueError:
        return False
    rail = _rail()
    return bool(rail.ed25519_verify(public, rail.jcs_dumps(envelope["record"]), sig))


def _load(case_path: Path) -> tuple[dict[str, Any], bytes, list[bytes]]:
    """The consumer's trust inputs, the job file, and the stored log lines."""
    case = strictjson.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    job = (base / case["job"]).read_bytes()
    lines = [line for line in (base / case["log"]).read_bytes().split(b"\n") if line]
    return case, job, lines


def _first_failure(
    case: dict[str, Any], job: bytes, lines: list[bytes],
    skip: frozenset[str] = frozenset(),
) -> str | None:
    """Name the first check in ``CHECKS`` the log fails, or None.

    ``skip`` switches named checks off. It exists so the corpus's own tests can
    prove that every check is forced by some member; a verifier never sets it.
    Every check is total on its own, so switching one off never crashes the next.
    """
    keys = case["witnesses"]
    envelopes = [strictjson.loads(line) for line in lines]
    records = [env.get("record", {}) if isinstance(env, dict) else {} for env in envelopes]
    intake = records[0] if records else {}
    last = records[-1] if records else {}
    failures: dict[str, Callable[[], bool]] = {
        "signature_invalid": lambda: not records or not all(
            _signed(env, keys) for env in envelopes),
        "intake_missing": lambda: intake.get("type") != "intake",
        "witness_changed": lambda: any(
            r.get("witness") != intake.get("witness") for r in records),
        "job_mismatch": lambda: any(r.get("job") != intake.get("job") for r in records),
        "chain_link_broken": lambda: any(
            type(r.get("seq")) is not int or r.get("seq") != i
            or r.get("prev") != (GENESIS if i == 0 else _sha(lines[i - 1]))
            for i, r in enumerate(records)),
        "gcode_altered": lambda: _sha(job) != intake.get("gcode_sha256"),
        "gcode_not_ordered": lambda: (
            intake.get("gcode_sha256") != case["order"]["gcode_sha256"]),
        "log_truncated": lambda: last.get("type") != "close",
        "print_not_finished": lambda: (
            last.get("type") != "close" or last.get("status") != "finished"
            or type(last.get("layers_printed")) is not int
            or last.get("layers_printed") != intake.get("layers")),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case, job, lines = _load(case_path)
    failure = _first_failure(case, job, lines, skip)
    if failure is not None:
        return {"decision": REJECTED, "reason": failure}
    return {"decision": VERIFIED, "reason": "print_witnessed"}


def log_signatures_verify(case_path: Path) -> bool:
    """Whether every log record verifies under the trusted key its kid names."""
    case, _, lines = _load(case_path)
    return all(_signed(strictjson.loads(line), case["witnesses"]) for line in lines)


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = strictjson.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
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
    if any(entry.get("pairsWith", entry["id"]) not in ids for entry in entries):
        return [], "a case pairs with a case the manifest does not hold"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != ids:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
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
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement. A case whose
    declared signature property does not hold is a corpus error, whichever
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
        case_path = directory / "case.json"
        if log_signatures_verify(case_path) != entry["logSignaturesVerify"]:
            errors.append(f"{name}: declared signature property does not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(case_path, skip)
        else:
            ran, observed = _external_answer(command, case_path)
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
        manifest = strictjson.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
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
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
