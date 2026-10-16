"""Judge TRACE registry anchors the way a verifier that trusts nobody must.

The corpus this module reads is for TRACE Registry Anchor Format v1
(``spec/registry-anchor-v1.md`` in agentrust-io/trace-spec), as amended by
trace-spec#533: a Level 2 verdict rests on the registry entry itself, and a
merkle_root or leaf_count the receipt brings with it is a claim to check
against that entry, never the thing the proof is replayed against.

Each case gives a verifier three inputs, the same three section 5.1 names: the
claim (the complete signed object that was anchored), the receipt (the proof's
``leaf_index`` and ``audit_path``, and optionally the ``merkle_root`` and
``leaf_count`` the producer copied into it), and the registry entry of section
4. Either of the last two may be missing, because a verifier is handed
whatever the record's holder chooses to hand it.

The reader checks in a fixed order and names the first check that fails:

1. a receipt was supplied (``receipt_absent``);
2. the receipt is well formed: an integer ``leaf_index``, an ``audit_path``
   array of ``sha256:<64 lowercase hex>`` strings, and, where present, a
   ``merkle_root`` of that form and an integer ``leaf_count``
   (``receipt_malformed``);
3. a registry entry was supplied (``entry_absent``). Without one, section 6
   says a verifier MUST NOT report Level 2, however consistent the receipt is
   with itself;
4. the entry carries the five section 4 fields with their section 4 types
   (``entry_malformed``);
5. a ``merkle_root`` the receipt carries equals the entry's
   (``receipt_root_mismatch``);
6. a ``leaf_count`` the receipt carries equals the entry's
   (``receipt_count_mismatch``);
7. the leaf index is inside the entry's batch, section 5.1 step 1
   (``index_out_of_range``);
8. the claim is a JSON object inside the section 1 profile: no non-integer
   number and no integer outside the safe-integer range
   (``claim_outside_profile``);
9. the section 5.1 replay, over the section 1 bytes of the claim with the
   section 2 leaf prefix, reaches the entry's root with the entry's count
   (``proof_does_not_replay``).

A case that passes all nine is ``anchored``. Its reason is always
``included_link_unchecked``: trace-spec#533 says a verifier MUST state that the
link from the record's ``transparency`` value to the entry it was given was not
checked, because nothing yet defines that link (trace-spec#448 finding 21).

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``anchored`` and 1 for ``refused``.
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

SUITE = "trace-registry-anchor/v1"
ANCHORED, REFUSED = "anchored", "refused"
EXIT_FOR = {ANCHORED: 0, REFUSED: 1}
LINK_UNCHECKED = "included_link_unchecked"
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "receipt_absent",
    "receipt_malformed",
    "entry_absent",
    "entry_malformed",
    "receipt_root_mismatch",
    "receipt_count_mismatch",
    "index_out_of_range",
    "claim_outside_profile",
    "proof_does_not_replay",
)
ENTRY_FIELDS = ("ts", "merkle_root", "leaf_count", "producer", "batch_id")
SAFE_INTEGER = 2**53 - 1
LEAF_PREFIX, NODE_PREFIX = b"\x00", b"\x01"
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-trace-anchor" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-trace-anchor")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _is_int(value: object) -> bool:
    """A JSON integer: Python's bool is an int subclass, and JSON's true is not 1."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _hash_bytes(value: object) -> bytes | None:
    return bytes.fromhex(value[7:]) if _is_hash(value) else None  # type: ignore[index]


def canonical_claim_bytes(claim: object) -> bytes | None:
    """Section 1 bytes of the claim, or None when the claim is outside the profile.

    Sorted keys by code point, ``,`` and ``:`` separators, ASCII escapes. A
    non-integer number or an integer outside the safe-integer range puts the
    claim outside the profile, because two implementations of the four rules
    write different bytes for it.
    """
    if not isinstance(claim, dict):
        return None
    stack: list[object] = [claim]
    while stack:
        value = stack.pop()
        if isinstance(value, float):
            return None
        if _is_int(value) and not -SAFE_INTEGER <= value <= SAFE_INTEGER:  # type: ignore[operator]
            return None
        if isinstance(value, dict):
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return json.dumps(claim, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def replays(claim: object, leaf_index: object, audit_path: object,
            leaf_count: object, root: object) -> bool:
    """Section 5.1, total over any input: a malformed input simply does not replay."""
    leaf = canonical_claim_bytes(claim)
    target = _hash_bytes(root)
    if (leaf is None or target is None or not _is_int(leaf_index) or not _is_int(leaf_count)
            or not isinstance(audit_path, list)):
        return False
    path = [_hash_bytes(node) for node in audit_path]
    if any(node is None for node in path):
        return False
    fn, sn = int(leaf_index), int(leaf_count) - 1  # type: ignore[call-overload]
    if fn < 0 or sn < 0 or fn > sn:
        return False
    r = hashlib.sha256(LEAF_PREFIX + leaf).digest()
    for p in path:
        assert p is not None
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = hashlib.sha256(NODE_PREFIX + p + r).digest()
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(NODE_PREFIX + r + p).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == target


def _receipt_malformed(receipt: Any) -> bool:
    if not isinstance(receipt, dict):
        return True
    path = receipt.get("audit_path")
    if not _is_int(receipt.get("leaf_index")) or not isinstance(path, list):
        return True
    if not all(_is_hash(node) for node in path):
        return True
    if "merkle_root" in receipt and not _is_hash(receipt["merkle_root"]):
        return True
    return "leaf_count" in receipt and not _is_int(receipt["leaf_count"])


def _entry_malformed(entry: Any) -> bool:
    if not isinstance(entry, dict) or any(key not in entry for key in ENTRY_FIELDS):
        return True
    if any(not isinstance(entry[key], str) or not entry[key]
           for key in ("ts", "producer", "batch_id")):
        return True
    return not _is_hash(entry["merkle_root"]) or not (
        _is_int(entry["leaf_count"]) and entry["leaf_count"] >= 1)


def _field(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else None


def _first_failure(case: dict[str, Any], skip: frozenset[str] = frozenset()) -> str | None:
    """Name the first check in ``CHECKS`` the case fails, or None.

    ``skip`` switches named checks off. It exists so the corpus's own tests can
    prove that every check is forced by some member; a verifier never sets it.
    Every check below is total on its own, so switching any earlier one off
    cannot crash a later one.
    """
    receipt, entry, claim = case.get("receipt"), case.get("entry"), case.get("claim")
    index = _field(receipt, "leaf_index")
    count = _field(entry, "leaf_count")
    failures: dict[str, Callable[[], bool]] = {
        "receipt_absent": lambda: receipt is None,
        "receipt_malformed": lambda: _receipt_malformed(receipt),
        "entry_absent": lambda: entry is None,
        "entry_malformed": lambda: _entry_malformed(entry),
        "receipt_root_mismatch": lambda: isinstance(receipt, dict) and "merkle_root" in receipt
        and receipt["merkle_root"] != _field(entry, "merkle_root"),
        "receipt_count_mismatch": lambda: isinstance(receipt, dict) and "leaf_count" in receipt
        and receipt["leaf_count"] != count,
        "index_out_of_range": lambda: _is_int(index) and _is_int(count)
        and not 0 <= index < count,
        "claim_outside_profile": lambda: canonical_claim_bytes(claim) is None,
        "proof_does_not_replay": lambda: not replays(
            claim, index, _field(receipt, "audit_path"), count, _field(entry, "merkle_root")),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    failure = _first_failure(case, skip)
    if failure is not None:
        return {"decision": REFUSED, "reason": failure}
    return {"decision": ANCHORED, "reason": LINK_UNCHECKED}


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
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    try:
        answer = json.loads(lines[-1])
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError, IndexError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(), decision_only: bool = False,
) -> tuple[int, list[str]]:
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement. With
    ``decision_only`` a named verifier is held to the decision alone, for a
    verifier whose refusals carry its own vocabulary rather than this corpus's.
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
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(case_path, skip)
        else:
            ran, observed = _external_answer(command, case_path)
        answered += int(ran)
        expected = entry["expected"]
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif decision_only and observed["decision"] != expected["decision"]:
            errors.append(f"{name}: expected {expected['decision']}, got {observed['decision']}")
        elif not decision_only and observed != expected:
            errors.append(f"{name}: expected {expected}, got {observed}")
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
    parser.add_argument("--decision-only", action="store_true",
                        help="hold a named verifier to the decision, not the reason")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier, decision_only=args.decision_only)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
