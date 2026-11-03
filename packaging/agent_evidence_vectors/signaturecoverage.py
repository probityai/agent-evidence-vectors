"""Judge whether a signature covers what a reader of the record reads.

A signature binds bytes. It says nothing about the structure those bytes were
derived from, and that structure is often what a consumer goes on to read. A
list of key-value entries can hold one key twice; one reader takes the first
entry, another the last, and a signer that flattens the list into a map keeps
one and signs that. The signature then verifies while a reader sees a value the
signature never covered, and changing the entry the flatten threw away leaves
the signed bytes as they were. The same gap opens when a flatten folds two keys
into one, drops a member, or changes a value's type, and when the signed bytes
themselves repeat a member or carry an integer two parsers read differently.

The rule is one sentence: the signature input must determine everything a
reader can read. If two records read differently, they may not share a
signature input.

Every record is one signed structure: ``source``, the structure as readers see
it (a map is ``{"entries": [[key, value], ...]}``, in order, repeats kept; a
list is a JSON array; anything else is a JSON scalar), ``envelope``, the signed
payload with its Ed25519 signature, public key and the top-level keys the signer
declares outside the signature, and ``consumerReads``, the paths a consumer goes
on to rely on. The reader checks in a fixed order and names the first check that
fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the signature-coverage contract (``contract_id_unknown``);
3. the signature verifies over the payload bytes (``signature_invalid``);
4. the payload repeats no object member at any depth, comparing decoded names
   (``payload_repeated_member``);
5. no integer in the payload or the source is outside the range every JSON
   parser reads exactly (``number_not_interoperable``);
6. the source repeats no key at any depth, whatever the values and whether or
   not the key is declared outside the signature (``source_repeated_key``);
7. outside the declared keys, the source and the signed payload hold the same
   members with the same values (``reading_differs_from_signed``);
8. no path a consumer reads starts at a key declared outside the signature
   (``consumer_reads_unsigned``).

A record that passes all eight is ``allow`` with reason ``signature_covers_reading``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.

``signer-pairs.json`` turns the rule on a signer. Each row holds two sources a
reader can tell apart; a signer passes a row when it refuses at least one of them
or gives the two different signature inputs. The external-signer contract:
``<signer> <source.json> --json`` prints ``{"refused": true}`` or
``{"signatureInput": "<base64>"}``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors.cardreceipt import _rail
from agent_evidence_vectors.monitorcoverage import (
    ALLOW,
    DENY,
    EXIT_FOR,
    check_corpus,
    cli,
    run_corpus,
)

SUITE = "signature-coverage/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/signature-coverage"
ALLOWED_REASON = "signature_covers_reading"
MAX_EXACT_INTEGER = 2**53 - 1
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "signature_invalid",
    "payload_repeated_member",
    "number_not_interoperable",
    "source_repeated_key",
    "reading_differs_from_signed",
    "consumer_reads_unsigned",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-signature-coverage" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-signature-coverage")

Record = dict[str, Any]


class _RepeatedMember(ValueError):
    """The payload repeats an object member."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _RepeatedMember(key)
        result[key] = value
    return result


def _is_map(value: object) -> bool:
    return isinstance(value, dict) and set(value) == {"entries"}


def _children(value: object) -> list[Any]:
    if _is_map(value):
        return [item for _, item in value["entries"]]  # type: ignore[index]
    return list(value) if isinstance(value, list) else []


def repeats(value: object) -> bool:
    """Whether a source repeats a key in any map at any depth."""
    if _is_map(value):
        keys = [key for key, _ in value["entries"]]  # type: ignore[index]
        if len(keys) != len(set(keys)):
            return True
    return any(repeats(child) for child in _children(value))


def flatten(value: object, *, keep_first: bool = False) -> object:
    """A source as a reader sees it: plain JSON, one entry kept for each key."""
    if _is_map(value):
        out: dict[str, Any] = {}
        for key, item in value["entries"]:  # type: ignore[index]
            if not (keep_first and key in out):
                out[key] = flatten(item, keep_first=keep_first)
        return out
    if isinstance(value, list):
        return [flatten(item, keep_first=keep_first) for item in value]
    return value


def signature_input(source: object) -> bytes | None:
    """The reference signer: refuse a repeated key, else sign sorted compact JSON."""
    if repeats(source):
        return None
    return _canonical(flatten(source))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _entry_count(value: object) -> int:
    own = len(value["entries"]) if _is_map(value) else 0  # type: ignore[index]
    return own + sum(_entry_count(child) for child in _children(value))


def _has_inexact_integer(value: object) -> bool:
    if isinstance(value, dict):
        return any(_has_inexact_integer(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_inexact_integer(item) for item in value)
    return isinstance(value, int) and not isinstance(value, bool) and (
        abs(value) > MAX_EXACT_INTEGER)


def _same(left: object, right: object) -> bool:
    """Equal as JSON values: numbers by value, and a boolean is never a number."""
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(  # type: ignore[attr-defined]
            _same(item, right[key]) for key, item in left.items())  # type: ignore[index]
    if isinstance(left, list):
        return len(left) == len(right) and all(  # type: ignore[arg-type]
            _same(a, b) for a, b in zip(left, right))  # type: ignore[arg-type]
    return left == right


def _payload(record: Record) -> bytes:
    return base64.b64decode(record["envelope"]["payload"], validate=True)


def _signature_valid(record: Record) -> bool:
    envelope = record["envelope"]
    key = base64.b64decode(envelope["publicKey"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    return bool(_rail().ed25519_verify(key, _payload(record), signature))


def _payload_value(record: Record) -> object:
    return json.loads(_payload(record))


def _repeated_member(record: Record) -> bool:
    try:
        json.loads(_payload(record), object_pairs_hook=_unique)
    except _RepeatedMember:
        return True
    return False


def _reading_differs(record: Record) -> bool:
    reading = flatten(record["source"])
    if not isinstance(reading, dict):
        return True
    excluded = set(record["envelope"]["excluded"])
    covered = {key: item for key, item in reading.items() if key not in excluded}
    return not _same(covered, _payload_value(record))


def _reads_unsigned(record: Record) -> bool:
    excluded = set(record["envelope"]["excluded"])
    return any(path[0] in excluded for path in record["consumerReads"])


def retained(record: Record) -> dict[str, Any]:
    """The signed bytes' digest and the counts a verifier keeps."""
    return {
        "consumerReads": len(record["consumerReads"]),
        "excluded": len(record["envelope"]["excluded"]),
        "payloadSha256": hashlib.sha256(_payload(record)).hexdigest(),
        "sourceEntries": _entry_count(record["source"]),
    }


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "signature_invalid": lambda: not _signature_valid(record),
        "payload_repeated_member": lambda: _repeated_member(record),
        "number_not_interoperable": lambda: (
            _has_inexact_integer(_payload_value(record))
            or _has_inexact_integer(record["source"])),
        "source_repeated_key": lambda: repeats(record["source"]),
        "reading_differs_from_signed": lambda: _reading_differs(record),
        "consumer_reads_unsigned": lambda: _reads_unsigned(record),
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


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    return check_corpus(root, SUITE, verify, retained, verifier, skip)


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def signer_pairs(root: Path = ROOT) -> list[dict[str, Any]]:
    """The signer pairs, after their digest is checked against the manifest."""
    raw = (root / "signer-pairs.json").read_bytes()
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    if hashlib.sha256(raw).hexdigest() != manifest["signerPairsSha256"]:
        raise ValueError("signer-pairs.json does not match its manifest digest")
    pairs: list[dict[str, Any]] = json.loads(raw)
    return pairs


def judge_signer(sign: Callable[[object], bytes | None],
                 root: Path = ROOT) -> tuple[int, list[str]]:
    """Run a signer over every pair; a pair fails when both sides share one input."""
    pairs = signer_pairs(root)
    errors = []
    for pair in pairs:
        first, second = sign(pair["first"]), sign(pair["second"])
        if first is not None and first == second:
            errors.append(f"{pair['id']}: two records a reader tells apart share one "
                          "signature input")
    return len(pairs), errors


def _external_signer(command: list[str]) -> Callable[[object], bytes | None]:
    def sign(source: object) -> bytes | None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                    text=True, timeout=90, check=False)
        answer = json.loads(result.stdout)
        if answer.get("refused") is True:
            return None
        return base64.b64decode(answer["signatureInput"], validate=True)
    return sign


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--signer")
    known, rest = parser.parse_known_args(argv)
    if known.signer is None:
        return cli(rest, __doc__, verify, check, ROOT)
    total, errors = judge_signer(_external_signer(shlex.split(known.signer)))
    for error in errors:
        print(error)
    print(f"signer passed {total - len(errors)} of {total} pairs")
    return 1 if errors else 0


__all__ = ["ALLOW", "ALLOWED_REASON", "CHECKS", "CONTRACT_ID", "DENY", "EXIT_FOR", "ROOT",
           "SUITE", "check", "flatten", "judge_signer", "main", "repeats", "retained", "run",
           "signature_input", "signer_pairs", "verify"]

if __name__ == "__main__":
    raise SystemExit(main())
