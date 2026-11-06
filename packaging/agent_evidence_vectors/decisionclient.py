"""Judge one decision a client took when it asked a decision point whether to act.

A decision client sits in front of an action: it asks a remote decision point
whether the action may run, and runs it only on a clear allow. The answer can
fail to arrive or fail to mean anything: the point is unreachable, it times out,
it answers with an HTTP error, with a body that is not JSON, with a verdict
outside the vocabulary, or with no verdict at all. None of these is an allow. A
client that maps one of them to an allow, or records it as a policy decision,
lets an action run that nobody decided to run, and its record says it was
decided.

Every record is one client's account of one such decision: the request, the
client's configured mode, the facts of the exchange with the decision point
(reached or not, timed out or not, the HTTP status, whether the body parsed,
and the verdict it carried), the condition the client recorded, the decision
it took and its basis, and whether the action was performed. The reader checks
in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the decision-client-failure-modes contract
   (``contract_id_unknown``);
3. every member the contract requires is present with a value from its
   vocabulary (``record_malformed``);
4. the condition the client recorded is the one the exchange facts give
   (``condition_misclassified``);
5. a fault condition is recorded on a ``fallback`` basis, never as a policy
   decision (``fault_recorded_as_policy``);
6. a fault condition never allows the action (``fault_allowed``);
7. on a readable verdict the decision follows it: ``allow`` allows, ``block``
   and ``halt`` deny (``verdict_not_followed``);
8. a ``halt`` verdict is recorded as halted, and nothing else is
   (``halt_not_honoured``);
9. an action the client denied was not performed (``effect_on_deny``).

The condition the exchange facts give: ``unreachable`` when the point was not
reached, ``timeout`` when no reply came inside the client's timeout,
``unauthorized`` on HTTP 401 or 403, ``http-error`` on any other status outside
200-299, ``unparseable-body`` when the body is not a JSON object,
``missing-verdict`` when it carries no ``verdict`` member, ``unknown-verdict``
when the verdict is not ``allow``, ``block`` or ``halt``, and ``ok`` otherwise.
Every condition but ``ok`` is a fault. A record that passes all nine is
``allow`` with reason ``decision_sound``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``. The runtime contract, which drives a decision
client against a stub decision point and a counting effect sink, is in
``decisionclient_runtime``.
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

SUITE = "decision-client-failure-modes/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
               "decision-client-failure-modes")
ALLOW, DENY = "allow", "deny"
ALLOWED_REASON = "decision_sound"
EXIT_FOR = {ALLOW: 0, DENY: 1}
VERDICTS = ("allow", "block", "halt")
OUTCOMES = (ALLOW, DENY)
BASES = ("policy", "fallback")
MODES = ("default", "strict")
FAULTS = ("unreachable", "timeout", "unauthorized", "http-error", "unparseable-body",
          "missing-verdict", "unknown-verdict")
CONDITIONS = ("ok", *FAULTS)
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "record_malformed",
    "condition_misclassified",
    "fault_recorded_as_policy",
    "fault_allowed",
    "verdict_not_followed",
    "halt_not_honoured",
    "effect_on_deny",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-decision-client-failure-modes" if
        (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-decision-client-failure-modes")

Record = dict[str, Any]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def derived_condition(exchange: dict[str, Any]) -> str:
    """The condition the exchange facts give, in the order the contract states."""
    if not exchange["reached"]:
        return "unreachable"
    if exchange["timedOut"]:
        return "timeout"
    status = exchange["httpStatus"]
    if status in (401, 403):
        return "unauthorized"
    if not 200 <= status <= 299:
        return "http-error"
    if not exchange["bodyIsJsonObject"]:
        return "unparseable-body"
    if "verdict" not in exchange:
        return "missing-verdict"
    if exchange["verdict"] not in VERDICTS:
        return "unknown-verdict"
    return "ok"


def _integer(value: object) -> bool:
    """A JSON integer; ``true`` and ``false`` are not numbers here, as in JSON."""
    return isinstance(value, int) and not isinstance(value, bool)


def _number(value: object) -> bool:
    return _integer(value) or isinstance(value, float)


def _malformed(record: Record) -> bool:
    """Whether a required member is absent or holds a value outside its vocabulary."""
    try:
        request, client = record["request"], record["client"]
        exchange, decision = record["exchange"], record["decision"]
        checks = (
            isinstance(request["action"], str) and bool(request["action"]),
            isinstance(request["argsDigest"], str) and request["argsDigest"].startswith("sha256:"),
            client["mode"] in MODES,
            _number(client["timeoutMillis"]) and client["timeoutMillis"] > 0,
            isinstance(exchange["reached"], bool),
            isinstance(exchange["timedOut"], bool),
            exchange["httpStatus"] is None or _integer(exchange["httpStatus"]),
            isinstance(exchange["bodyIsJsonObject"], bool),
            "verdict" not in exchange or isinstance(exchange["verdict"], str),
            decision["outcome"] in OUTCOMES,
            decision["basis"] in BASES,
            decision["condition"] in CONDITIONS,
            isinstance(decision["halted"], bool),
            isinstance(record["effect"]["performed"], bool),
        )
    except (KeyError, TypeError):
        return True
    if not all(checks):
        return True
    # A reply that arrived carries a status; one that did not carries none.
    arrived = exchange["reached"] and not exchange["timedOut"]
    return arrived != (exchange["httpStatus"] is not None)


def _verdict_not_followed(record: Record) -> bool:
    decision = record["decision"]
    if decision["condition"] != "ok":
        return False
    wanted = ALLOW if record["exchange"].get("verdict") == "allow" else DENY
    return bool(decision["outcome"] != wanted or decision["basis"] != "policy")


def _halt_not_honoured(record: Record) -> bool:
    exchange, decision = record["exchange"], record["decision"]
    halt = decision["condition"] == "ok" and exchange.get("verdict") == "halt"
    return bool(decision["halted"] != halt)


def retained(record: Record) -> dict[str, Any]:
    """What a verifier keeps of a record: the action, mode, conditions and decision."""
    exchange = record["exchange"]
    return {
        "action": record["request"]["action"],
        "condition": derived_condition(exchange),
        "mode": record["client"]["mode"],
        "outcome": record["decision"]["outcome"],
        "performed": record["effect"]["performed"],
    }


def _load(record_path: Path) -> Record:
    loaded: Record = json.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. With
    ``record_malformed`` switched off, a malformed record passes, because the later
    checks read members it lacks.
    """
    decision = record.get("decision") or {}
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "record_malformed": lambda: _malformed(record),
        "condition_misclassified":
            lambda: decision["condition"] != derived_condition(record["exchange"]),
        "fault_recorded_as_policy":
            lambda: decision["condition"] != "ok" and decision["basis"] != "fallback",
        "fault_allowed": lambda: decision["condition"] != "ok" and decision["outcome"] != DENY,
        "verdict_not_followed": lambda: _verdict_not_followed(record),
        "halt_not_honoured": lambda: _halt_not_honoured(record),
        "effect_on_deny":
            lambda: decision["outcome"] == DENY and record["effect"]["performed"],
    }
    for name in CHECKS:
        if name in skip:
            if name == "record_malformed" and _malformed(record):
                return None
            continue
        if failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def scenarios(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The runtime scenarios the cases pair with, once each, in first-use order.

    Each case row carries its scenario whole, so the corpus digest over the rows
    covers what a client is driven through. Two rows that name one scenario with
    different bodies are a corpus error.
    """
    seen: dict[str, dict[str, Any]] = {}
    for entry in entries:
        scenario = entry["runtime"]["scenario"]
        if seen.setdefault(scenario["id"], scenario) != scenario:
            raise ValueError(f"scenario {scenario['id']} differs between cases")
    return list(seen.values())


def shipped_scenarios(root: Path = ROOT) -> list[dict[str, Any]]:
    """The runtime scenarios of the corpus this package carries."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    return scenarios(manifest["vectors"])


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
    scenarios(entries)
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
    whose retained fields differ from what its own members give is a corpus
    error, whichever verifier is under test.
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
        try:
            kept = retained(_load(record_path))
        except (KeyError, TypeError, ValueError):
            kept = None
        if kept != entry["retained"]:
            errors.append(f"{name}: declared retained fields do not hold")
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
