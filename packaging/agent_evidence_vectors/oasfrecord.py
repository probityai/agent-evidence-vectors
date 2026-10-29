"""Judge an OASF record's identity digest and the signer bound to it.

An OASF record is named by a digest, and a consumer accepts a signature over
that digest only from the signer its own policy names. The rules are:

1. The digest is SHA-256 over the RFC 8785 canonical bytes of the record.
2. Every integer in the record is inside the exact range of an IEEE 754
   double (RFC 7493 section 2.2); this reader refuses the rest.
3. The signer's certificate subject and issuer equal the policy's exactly,
   never as a pattern or a substring.

Each case holds ``record.json``, the record's bytes as the producer wrote them,
and ``case.json``, which carries the digest the producer claims for the record
(``recordDigest``, ``sha256:`` followed by lowercase hexadecimal), the subject
and issuer of the certificate whose signature over that digest verified
(``signer``), and the subject and issuer the consumer's policy names
(``policy``). The cryptography of the signature is outside this corpus;
``vectors-receipt-signature`` and ``vectors-identity-binding`` cover it.

The reader checks in a fixed order and names the first check that fails:

1. ``case.json`` carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the OASF record contract (``contract_id_unknown``);
3. ``case.json`` has the fields and types the contract names
   (``malformed_case``);
4. ``record.json`` is UTF-8 JSON with no duplicate member and no NaN or
   Infinity (``record_not_json``);
5. every integer in the record is inside the exact double range
   (``number_not_exact``);
6. the record carries the fields OASF marks required, with their types
   (``oasf_required_field``);
7. ``recordDigest`` is SHA-256 over the RFC 8785 bytes of the record
   (``digest_mismatch``);
8. the signer's subject and issuer equal the policy's exactly
   (``signer_not_policy``).

A case that passes all eight is ``allow`` with reason ``conformant``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``. The record is ``record.json`` beside it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence_vectors.a2ajcs import Refusal, canonicalize

SUITE = "oasf-record/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/oasf-record/v1"
ALLOW, DENY = "allow", "deny"
PASS_REASON = "conformant"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_case",
    "record_not_json",
    "number_not_exact",
    "oasf_required_field",
    "digest_mismatch",
    "signer_not_policy",
)
# RFC 7493 section 2.2: integers in [-(2**53)+1, (2**53)-1] are exact as doubles.
EXACT_LIMIT = 2**53 - 1
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-oasf-record" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-oasf-record")


class NotJSON(ValueError):
    """The record bytes are not strict JSON."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise NotJSON(f"duplicate member {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise NotJSON(f"{name} is not JSON")


def parse_record(data: bytes) -> Any:
    """Parse record bytes strictly: UTF-8, no duplicate member, no NaN or Infinity."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NotJSON("not UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except json.JSONDecodeError as exc:
        raise NotJSON(str(exc)) from exc


def record_digest(record: Any) -> str:
    """``sha256:`` and the hexadecimal SHA-256 of the record's RFC 8785 bytes."""
    return "sha256:" + _sha(canonicalize(record))


def _integers(value: Any) -> list[int]:
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        return [n for item in value for n in _integers(item)]
    if isinstance(value, dict):
        return [n for item in value.values() for n in _integers(item)]
    return []


def _not_exact(record: Any) -> bool:
    if any(abs(n) > EXACT_LIMIT for n in _integers(record)):
        return True
    try:
        canonicalize(record)
    except Refusal:
        return True
    return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _skill(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    named = _text(value.get("name"))
    numbered = isinstance(value.get("id"), int) and not isinstance(value.get("id"), bool)
    return named or numbered


def _oasf_missing(record: Any) -> bool:
    """Whether a field OASF's record object marks required is absent or mistyped."""
    if not isinstance(record, dict):
        return True
    if not all(_text(record.get(name)) for name in
               ("name", "version", "schema_version", "description")):
        return True
    authors = record.get("authors")
    if not (isinstance(authors, list) and authors and all(_text(a) for a in authors)):
        return True
    created = record.get("created_at")
    if not (isinstance(created, str) and _RFC3339.fullmatch(created)):
        return True
    try:
        datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return True
    skills = record.get("skills")
    return not (isinstance(skills, list) and skills and all(_skill(s) for s in skills))


def _identity(value: Any) -> bool:
    return isinstance(value, dict) and _text(value.get("subject")) and _text(value.get("issuer"))


def _case_malformed(case: dict[str, Any]) -> bool:
    digest = case.get("recordDigest")
    if not (isinstance(digest, str) and _DIGEST.fullmatch(digest)):
        return True
    return not (_identity(case.get("signer")) and _identity(case.get("policy")))


def _signer_differs(case: dict[str, Any]) -> bool:
    signer, policy = case["signer"], case["policy"]
    return bool(signer["subject"] != policy["subject"] or signer["issuer"] != policy["issuer"])


def _first_failure(case: dict[str, Any], record_bytes: bytes,
                   skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the case fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    parsed: dict[str, Any] = {}

    def record() -> Any:
        if "value" not in parsed:
            parsed["value"] = parse_record(record_bytes)
        return parsed["value"]

    def not_json() -> bool:
        try:
            record()
        except NotJSON:
            return True
        return False

    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in case,
        "contract_id_unknown": lambda: case.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_case": lambda: _case_malformed(case),
        "record_not_json": not_json,
        "number_not_exact": lambda: _not_exact(record()),
        "oasf_required_field": lambda: _oasf_missing(record()),
        "digest_mismatch": lambda: record_digest(record()) != case["recordDigest"],
        "signer_not_policy": lambda: _signer_differs(case),
    }
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except (NotJSON, Refusal, KeyError, TypeError, ValueError, AttributeError):
            # A case an earlier check would have refused, reached only because
            # that check was switched off; the tests see it as a different reason.
            return "unreadable_case"
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case: dict[str, Any] = json.loads(case_path.read_text(encoding="utf-8"))
    record_bytes = (case_path.parent / "record.json").read_bytes()
    failure = _first_failure(case, record_bytes, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": PASS_REASON}


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
    """Check every case, through the named verifier or the reference reader.

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
        case_path = directory / "case.json"
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
