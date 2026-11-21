"""Judge a signed statement that a ledger recorded no revocation of a credential in an interval.

A relying party asks a revocation ledger it does not run one question: was this
credential revoked between two positions of the ledger? The ledger answers with a
signed statement. The statement names the credential and the two positions, lists the
events it found for the credential inside them (the list may be empty) and carries a
signed, timestamped checkpoint over the ledger's head. The reader decides how far that
answer establishes the question, with the evaluation time the case states.

The five values are the ``revocation_establishment`` term of the vocabulary:
``recorded``, ``not_recorded``, ``query_failed``, ``cross_federation_unsynchronised``
and ``undetermined``. ``undetermined`` is the fallback for every failed check, so a
statement that does not verify is never read as an empty interval. The reader checks in
a fixed order and names the first check that fails:

1. the query returned an answer (``query_failed``, ``ledger_query_failed``);
2. the ledger's federation is the verifier's, or a synchronisation record bridges to
   it (``cross_federation_unsynchronised``, ``federation_not_synchronised``);
3. the statement verifies under the ledger key (``statement_signature_invalid``);
4. the statement is about the credential, the ledger and the two positions asked about
   (``statement_for_other_interval``);
5. the checkpoint verifies under the ledger key (``checkpoint_signature_invalid``);
6. the checkpoint carries a signing time (``checkpoint_not_timestamped``);
7. the checkpoint covers the end of the interval
   (``checkpoint_does_not_cover_range``);
8. every event up to the checkpoint verifies under the ledger key
   (``ledger_event_invalid``);
9. every event names the digest of the line before it, at its own position
   (``chain_link_broken``);
10. the checkpoint names the digest of the event it points at
    (``checkpoint_head_mismatch``).

A statement that passes all ten is read against the ledger itself, never against the
statement's own list. A revocation of the credential inside the interval is
``recorded``: ``revocation_recorded`` when the statement lists every one,
``statement_omits_recorded_event`` when it lists fewer. No revocation is
``not_recorded``, with reason ``no_revocation_in_covered_interval``. ``not_recorded``
says that the checked ledger holds no revocation in the interval; a revocation decided
and never logged cannot show, so the value is never read as "not revoked".

The external-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one
JSON object carrying ``decision`` and ``reason``, and exits 0 for ``recorded``, 1 for
``not_recorded``, 2 for ``query_failed``, 3 for ``cross_federation_unsynchronised`` and 4
for ``undetermined``.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictjson
from agent_evidence_vectors.anchoredchain import _fixture_error, _sha, _signed
from agent_evidence_vectors.monitorcoverage import _validated_entries, run_corpus

SUITE = "empty-interval-statement/v1"
RECORDED, NOT_RECORDED, QUERY_FAILED, UNSYNCHRONISED, UNDETERMINED = (
    "recorded",
    "not_recorded",
    "query_failed",
    "cross_federation_unsynchronised",
    "undetermined",
)
EXIT_FOR = {RECORDED: 0, NOT_RECORDED: 1, QUERY_FAILED: 2, UNSYNCHRONISED: 3, UNDETERMINED: 4}
GENESIS = "0" * 64
#: Each check in order; every failure after the second is the fallback value.
CHECKS = (
    "ledger_query_failed",
    "federation_not_synchronised",
    "statement_signature_invalid",
    "statement_for_other_interval",
    "checkpoint_signature_invalid",
    "checkpoint_not_timestamped",
    "checkpoint_does_not_cover_range",
    "ledger_event_invalid",
    "chain_link_broken",
    "checkpoint_head_mismatch",
)
_OUTCOME = {
    "ledger_query_failed": QUERY_FAILED,
    "federation_not_synchronised": UNSYNCHRONISED,
}
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-empty-interval-statement"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-empty-interval-statement"
)

Case = dict[str, Any]


def _load(path: Path) -> Any:
    return strictjson.loads(path.read_text(encoding="utf-8"))


def _statement(case: Case, case_dir: Path) -> Any:
    """The statement envelope, or an empty one where the query returned none."""
    return _load(case_dir / case["statement"]) if case["statement"] else {}


def _events(case_dir: Path, case: Case) -> tuple[list[bytes], list[Any]]:
    raw = (case_dir / case["ledger"]).read_bytes().split(b"\n")
    lines = [line for line in raw if line]
    return lines, [strictjson.loads(line) for line in lines]


def _covered(case: Case, statement: Case) -> bool:
    checkpoint = statement.get("checkpoint", {}).get("checkpoint", {})
    index = checkpoint.get("index")
    return isinstance(index, int) and index >= case["query"]["toIndex"]


def _failures(case: Case, case_dir: Path) -> dict[str, Callable[[], bool]]:
    """The predicate of every check from the third on, each total on its own."""
    key = bytes.fromhex(case["keys"]["ledger"])
    query = case["query"]
    envelope = _statement(case, case_dir)
    body = envelope.get("statement", {})
    checkpoint = body.get("checkpoint", {})
    lines, events = _events(case_dir, case)
    cp = checkpoint.get("checkpoint", {})
    upto = min(len(lines), int(cp.get("index", -1)) + 1) if isinstance(cp, dict) else 0

    def bad_event() -> bool:
        return any(not _signed(events[i], "record", key) for i in range(upto))

    def bad_chain() -> bool:
        for i in range(upto):
            record = events[i].get("record", {})
            want = GENESIS if i == 0 else _sha(lines[i - 1])
            if record.get("prev") != want or record.get("index") != i:
                return True
        return False

    def bad_head() -> bool:
        index = cp.get("index")
        return not isinstance(index, int) or index >= len(lines) or _sha(lines[index]) != cp.get(
            "head"
        )

    return {
        "statement_signature_invalid": lambda: not _signed(envelope, "statement", key),
        "statement_for_other_interval": lambda: any(
            body.get(name) != query[name]
            for name in ("credential", "ledger", "fromIndex", "toIndex")
        ),
        "checkpoint_signature_invalid": lambda: not _signed(checkpoint, "checkpoint", key),
        "checkpoint_not_timestamped": lambda: not _INSTANT.fullmatch(str(cp.get("signedAt", ""))),
        "checkpoint_does_not_cover_range": lambda: not _covered(case, body),
        "ledger_event_invalid": bad_event,
        "chain_link_broken": bad_chain,
        "checkpoint_head_mismatch": bad_head,
    }


def _first_failure(
    case: Case, case_dir: Path, skip: frozenset[str] = frozenset()
) -> tuple[str, str] | None:
    """Name the first check in ``CHECKS`` the case fails, with its value, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each is
    forced by some member; a verifier never sets it.
    """
    if "ledger_query_failed" not in skip and case["response"]["status"] != "ok":
        return QUERY_FAILED, "ledger_query_failed"
    federation = case["federation"]
    if (
        "federation_not_synchronised" not in skip
        and federation["ledger"] != federation["verifier"]
        and federation["ledger"] not in federation["synchronisedWith"]
    ):
        return UNSYNCHRONISED, "federation_not_synchronised"
    failures = _failures(case, case_dir)
    for name in CHECKS[2:]:
        if name not in skip and failures[name]():
            return UNDETERMINED, name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case = _load(case_path)
    failure = _first_failure(case, case_path.parent, skip)
    if failure is not None:
        return {"decision": failure[0], "reason": failure[1]}
    query = case["query"]
    _, events = _events(case_path.parent, case)
    found = [
        event["record"]["index"]
        for event in events
        if event["record"]["kind"] == "revoked"
        and event["record"]["credential"] == query["credential"]
        and query["fromIndex"] <= event["record"]["index"] <= query["toIndex"]
    ]
    if not found:
        return {"decision": NOT_RECORDED, "reason": "no_revocation_in_covered_interval"}
    listed = _statement(case, case_path.parent)["statement"]["listed"]
    reason = (
        "revocation_recorded" if set(found) <= set(listed) else "statement_omits_recorded_event"
    )
    return {"decision": RECORDED, "reason": reason}


def retained(case_path: Path) -> dict[str, Any]:
    """The facts the manifest declares about a case, recomputed from its bytes."""
    case = _load(case_path)
    envelope = _statement(case, case_path.parent)
    if not envelope:
        return {"checkpointSigned": None, "statementSigned": None}
    key = bytes.fromhex(case["keys"]["ledger"])
    checkpoint = envelope["statement"]["checkpoint"]
    return {
        "checkpointSigned": _signed(checkpoint, "checkpoint", key),
        "statementSigned": _signed(envelope, "statement", key),
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
        answer = strictjson.loads(result.stdout)
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
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
