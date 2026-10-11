"""Judge signed record chains whose head is anchored outside the store.

The corpus this module reads separates two questions a verifier can be asked
about a stored history of signed records. The first is whether each record is
genuine: every signature verifies under the producer's key. The second is
whether the history is the one that was written: every record sits where it was
written, and nothing written before the last anchor is missing. Eight of the
corpus's rejected stores pass the first question completely, because an
adversary who can edit the store needs no key to delete, reorder, replay or
roll back records the system signed itself. Only the chain links and the anchor
answer the second question.

The reader checks in a fixed order and names the first check that fails:

1. every stored record verifies under the producer key (``signature_invalid``);
2. the anchor verifies under the anchor key, which the store does not hold
   (``anchor_signature_invalid``);
3. every record names the chain under test (``record_from_other_chain``);
4. every record names the digest of the stored line before it
   (``chain_link_broken``);
5. the store still holds the record the anchor names (``anchored_head_missing``);
6. that record's digest is the one the anchor commits to
   (``anchored_head_mismatch``). A store restored from a branch the producer
   signed and later abandoned passes every check above this one.

A store that passes all six is ``verified``. The reason is ``chain_anchored``
when the anchor names the last stored record and ``records_after_last_anchor``
when records follow it, because those records are protected only by the chain
links until the next anchor: removing them leaves a store no verifier can tell
from an honest one, and the corpus carries that case as a verified member so a
verifier that claims to catch it is refused.

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

SUITE = "anchored-record-chain/v1"
VERIFIED, REJECTED = "verified", "rejected"
EXIT_FOR = {VERIFIED: 0, REJECTED: 1}
GENESIS = "0" * 64
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "signature_invalid",
    "anchor_signature_invalid",
    "record_from_other_chain",
    "chain_link_broken",
    "anchored_head_missing",
    "anchored_head_mismatch",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-anchored-chain" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-anchored-chain")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")


def _rail() -> Any:
    """The rail module, resolved at call time, as ``receiptsignature`` does: the
    rail imports this module to dispatch the suite, so a module-level import
    would be a cycle."""
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


def _signed(envelope: Any, body_key: str, key: bytes) -> bool:
    """Whether an envelope's signature verifies over the RFC 8785 form of its body."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get(body_key), dict):
        return False
    try:
        sig = base64.b64decode(str(envelope.get("sig", "")), validate=True)
    except ValueError:
        return False
    rail = _rail()
    return bool(rail.ed25519_verify(key, rail.jcs_dumps(envelope[body_key]), sig))


def _load(case_path: Path) -> tuple[dict[str, Any], list[bytes], dict[str, Any]]:
    """The consumer's trust inputs, the stored lines, and the anchor envelope."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    lines = [line for line in (base / case["store"]).read_bytes().split(b"\n") if line]
    anchor = json.loads((base / case["anchor"]).read_text(encoding="utf-8"))
    return case, lines, anchor


def _first_failure(
    case: dict[str, Any], lines: list[bytes], anchor: dict[str, Any],
    skip: frozenset[str] = frozenset(),
) -> str | None:
    """Name the first check in ``CHECKS`` the store fails, or None.

    ``skip`` switches named checks off. It exists so the corpus's own tests can
    prove that every check is forced by some member; a verifier never sets it.
    """
    producer = bytes.fromhex(case["keys"]["producer"])
    envelopes = [json.loads(line) for line in lines]
    failures: dict[str, Callable[[], bool]] = {
        "signature_invalid": lambda: not all(
            _signed(env, "record", producer) for env in envelopes),
        "anchor_signature_invalid": lambda: not _signed(
            anchor, "anchor", bytes.fromhex(case["keys"]["anchor"])),
        "record_from_other_chain": lambda: any(
            env["record"].get("chain") != case["chain"] for env in envelopes),
        "chain_link_broken": lambda: any(
            env["record"].get("prev") != (GENESIS if i == 0 else _sha(lines[i - 1]))
            for i, env in enumerate(envelopes)),
        "anchored_head_missing": lambda: anchor["anchor"]["index"] >= len(lines),
        # Total on its own, so switching the check above off cannot crash it.
        "anchored_head_mismatch": lambda: (
            anchor["anchor"]["index"] >= len(lines)
            or _sha(lines[anchor["anchor"]["index"]]) != anchor["anchor"]["head"]),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case, lines, anchor = _load(case_path)
    failure = _first_failure(case, lines, anchor, skip)
    if failure is not None:
        return {"decision": REJECTED, "reason": failure}
    after = len(lines) - 1 - int(anchor["anchor"]["index"])
    reason = "records_after_last_anchor" if after > 0 else "chain_anchored"
    return {"decision": VERIFIED, "reason": reason}


def store_signatures_verify(case_path: Path) -> bool:
    """Whether every stored record verifies under the producer key."""
    case, lines, _ = _load(case_path)
    producer = bytes.fromhex(case["keys"]["producer"])
    return all(_signed(json.loads(line), "record", producer) for line in lines)


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


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
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
        if store_signatures_verify(case_path) != entry["storeSignaturesVerify"]:
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
