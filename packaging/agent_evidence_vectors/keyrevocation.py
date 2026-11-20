"""Judge what a signed key-revocation list says about one key at one time.

An issuer publishes a signed list of the keys it has revoked, each with the time the
revocation takes effect, the keys the list covers, the time it was issued and the time
its next update is due. A verifier holds the thumbprints of the list-signing keys it
trusts, the issue time of the last list it accepted and the revocations it has already
seen. It is asked whether one key is revoked at one time, and answers from the list.

The reader checks in a fixed order and names the first check that fails:

1. the list's signing key is one the verifier trusts, chosen by the SHA-256 thumbprint
   of the key itself, never by the thumbprint the list claims (``signer_not_trusted``);
2. the list verifies under that key (``list_signature_invalid``);
3. the list was not issued before the last list accepted (``list_older_than_accepted``);
   a replayed older list can omit a revocation a newer one carries;
4. the verifier's time is not past the list's ``nextUpdate`` (``list_stale``).

A list that passes is read together with the revocations already seen: a revocation once
seen is kept even when a later list omits it (``keep_seen_revocations``). A key whose
revocation has taken effect at the time asked is ``revoked``; a key revoked from a later
time is ``not_revoked`` until then; a key the list covers with no entry is
``not_revoked``; a key the list does not cover and no earlier list revoked is
``no_statement``, because silence about a key is not a statement about it
(``coverage_scope``). Instants are UTC ``YYYY-MM-DDTHH:MM:SSZ`` strings and compare as text.

The decisions are ``revoked``, ``not_revoked``, ``no_statement``, ``rejected`` (checks 1
to 3) and ``stale`` (check 4). The external-verifier contract: ``<verifier>
<case-dir>/case.json --json`` prints one JSON object carrying ``decision`` and ``reason``,
and exits 0 for ``revoked``, 1 for ``not_revoked``, 2 for ``no_statement``, 3 for
``rejected`` and 4 for ``stale``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from agent_evidence_vectors.anchoredchain import _fixture_error, _signed
from agent_evidence_vectors.monitorcoverage import _validated_entries, run_corpus

SUITE = "key-revocation-list/v1"
REVOKED, NOT_REVOKED, NO_STATEMENT, REJECTED, STALE = (
    "revoked",
    "not_revoked",
    "no_statement",
    "rejected",
    "stale",
)
EXIT_FOR = {REVOKED: 0, NOT_REVOKED: 1, NO_STATEMENT: 2, REJECTED: 3, STALE: 4}
#: Every rule a case can force, in the order the reader applies them.
CHECKS = (
    "signer_not_trusted",
    "list_signature_invalid",
    "list_older_than_accepted",
    "list_stale",
    "keep_seen_revocations",
    "coverage_scope",
)
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-key-revocation-list"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-key-revocation-list"
)

Case = dict[str, Any]


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def thumbprint(key_hex: str) -> str:
    """The SHA-256 thumbprint of a raw public key."""
    return hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()


def _rejection(case: Case, envelope: Any, skip: frozenset[str]) -> tuple[str, str] | None:
    """The first of checks 1 to 4 the list fails, as a decision and a reason."""
    signer = envelope["signer"]
    body = envelope["list"]
    if "signer_not_trusted" not in skip and thumbprint(signer["key"]) not in case["trusted"]:
        return REJECTED, "signer_not_trusted"
    if "list_signature_invalid" not in skip and not _signed(
        envelope, "list", bytes.fromhex(signer["key"])
    ):
        return REJECTED, "list_signature_invalid"
    last = case["prior"]["acceptedIssuedAt"]
    if "list_older_than_accepted" not in skip and last is not None and body["issuedAt"] < last:
        return REJECTED, "list_older_than_accepted"
    if "list_stale" not in skip and case["now"] > body["nextUpdate"]:
        return STALE, "list_stale"
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case = _load(case_path)
    envelope = _load(case_path.parent / case["list"])
    rejected = _rejection(case, envelope, skip)
    if rejected is not None:
        return {"decision": rejected[0], "reason": rejected[1]}
    body, key, at = envelope["list"], case["query"]["key"], case["query"]["at"]
    entries = {e["thumbprint"]: e["effectiveFrom"] for e in body["revoked"]}
    kept: dict[str, str] = {}
    if "keep_seen_revocations" not in skip:
        kept = {e["thumbprint"]: e["effectiveFrom"] for e in case["prior"]["seen"]}
    if key in entries and entries[key] <= at:
        return {"decision": REVOKED, "reason": "revoked_in_list"}
    if key in kept and kept[key] <= at:
        return {"decision": REVOKED, "reason": "revoked_kept_from_earlier_list"}
    if key in entries or key in kept:
        return {"decision": NOT_REVOKED, "reason": "revocation_not_yet_effective"}
    if "coverage_scope" not in skip and key not in body["keysCovered"]:
        return {"decision": NO_STATEMENT, "reason": "key_not_covered"}
    return {"decision": NOT_REVOKED, "reason": "covered_no_entry"}


def retained(case_path: Path) -> dict[str, Any]:
    """The facts the manifest declares about a case, recomputed from its bytes."""
    case = _load(case_path)
    envelope = _load(case_path.parent / case["list"])
    signer = envelope["signer"]
    return {
        "signerThumbprintHonest": signer["thumbprint"] == thumbprint(signer["key"]),
        "signatureVerifiesUnderCarriedKey": _signed(envelope, "list", bytes.fromhex(signer["key"])),
    }


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
    """Check every case, through the named verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, SUITE)
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
        if retained(case_path) != entry["retained"]:
            errors.append(f"{name}: declared signature facts do not hold")
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
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


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
