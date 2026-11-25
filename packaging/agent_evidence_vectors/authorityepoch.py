"""Judge a request against a signed, chained authority log that a signed head closes.

Every request names the epoch of the authority log it was made in. The log is a list
of signed events, each linked to the one before it by digest, and a signed head binds
its last event. The reader walks the log, checks the head, and then judges the
request: a request of a closed epoch is refused whatever its time, and a log or head
that cannot be read whole leaves the revocation state ``unknown``, never ``closed``.

Records are ``{"claims": {...}, "sig": "<base64>"}``. The signature is Ed25519 over
``DOMAIN || 0x00 || JCS(claims)`` (RFC 8785), where DOMAIN is the type URI with the
fragment ``#event``, ``#head`` or ``#request``.

The reader checks in a fixed order and stops at the first failure:

1. every file is a record of its type (``malformed``, decision ``no_verdict``);
2. a head is present (``epoch_unavailable``);
3. the log walks: contiguous sequence numbers from a genesis, one log id, digest
   links, epoch rules, kind rules and a signature under the current log key on every
   event (``log_invalid``);
4. the head is signed under the current key and binds the last event
   (``history_incomplete``);
5. the request's holder key is pinned (``unknown_holder``) and signs it
   (``request_signature_invalid``);
6. the request's epoch is the current one (``epoch_closed``, ``epoch_ahead``);
7. its approval was not consumed before (``approval_consumed``);
8. its grant is held by its subject (``no_grant``) and was not superseded by a
   re-registration (``grant_superseded``);
9. the subject's standing: a fork (``fork``), a revocation on the grant chain or of
   the subject (``parent_revoked``, ``revoked``, ``revoked_dispute_open``), a
   suspension (``suspended``), or ``authority_valid``.

``revocation_status`` is ``unknown`` at checks 1 to 4. After them it is read from the
log for the request's subject, also when checks 5 to 8 refuse: ``unknown`` while an
applying revocation is disputed, ``partial`` when every applying revocation stops only
new admissions, ``closed`` for any other revocation or a fork, ``suspended`` for a
suspension and ``live`` otherwise.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one
JSON object carrying ``decision``, ``reason`` and ``revocation_status``, and exits 0 for
``admit``, 1 for ``refuse`` and 2 for ``no_verdict``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictb64, strictjson
from agent_evidence_vectors.anchoredchain import _fixture_error, _rail
from agent_evidence_vectors.monitorcoverage import _validated_entries, run_corpus

SUITE = "authority-epoch-fence/v1"
TYPE_URI = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/authority-epoch-fence"
DOMAIN_EVENT, DOMAIN_HEAD, DOMAIN_REQUEST = (
    f"{TYPE_URI}#{name}".encode() for name in ("event", "head", "request")
)
ADMIT, REFUSE, NO_VERDICT = "admit", "refuse", "no_verdict"
EXIT_FOR = {ADMIT: 0, REFUSE: 1, NO_VERDICT: 2}
LIVE, SUSPENDED, PARTIAL, CLOSED, UNKNOWN = "live", "suspended", "partial", "closed", "unknown"
STATUSES = (LIVE, SUSPENDED, PARTIAL, CLOSED, UNKNOWN)
REASONS = (
    "authority_valid",
    "malformed",
    "epoch_unavailable",
    "log_invalid",
    "history_incomplete",
    "unknown_holder",
    "request_signature_invalid",
    "epoch_closed",
    "epoch_ahead",
    "approval_consumed",
    "no_grant",
    "grant_superseded",
    "fork",
    "parent_revoked",
    "revoked",
    "revoked_dispute_open",
    "suspended",
)
#: Every rule a case can force, in the order the reader applies them.
CHECKS = (
    "record_shape",
    "head_present",
    "log_sequence",
    "log_links",
    "log_epochs",
    "log_event_rules",
    "log_signatures",
    "head_binding",
    "holder_pinned",
    "request_signature",
    "epoch_fence",
    "approval_once",
    "grant_held",
    "grant_superseded",
    "fork",
    "revocation",
    "parent_order",
    "dispute_status",
    "scope_status",
    "suspension",
)
KINDS = (
    "genesis", "epoch_open", "grant", "revoke", "suspend", "resume", "approval_consumed",
    "fork", "dispute_open", "dispute_closed",
)
CAUSES = ("clock_acknowledged", "restart", "root_change", "re_registration", "owner_change")
SCOPES = ("all", "new_admissions")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-authority-epoch-fence"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-authority-epoch-fence"
)
_NS = re.compile(r"0|[1-9][0-9]*")
_HEX = re.compile(r"[0-9a-f]{64}")


class Malformed(ValueError):
    """A file is not a record of its type."""


def _one(x: Any) -> bool:
    return type(x) is int and x == 1


def _count(x: Any) -> bool:
    return type(x) is int and x >= 0


def _text(x: Any) -> bool:
    return isinstance(x, str)


def _named(x: Any) -> bool:
    return isinstance(x, str) and x != ""


def _ns(x: Any) -> bool:
    return isinstance(x, str) and _NS.fullmatch(x) is not None


def _hex(x: Any) -> bool:
    return isinstance(x, str) and _HEX.fullmatch(x) is not None


def _link(x: Any) -> bool:
    return x == "" or _hex(x)


def _kind(x: Any) -> bool:
    return isinstance(x, str) and x in KINDS


Rules = dict[str, Callable[[Any], bool]]
EVENT_RULES: Rules = {
    "v": _one, "log_id": _named, "seq": _count, "epoch": _count, "kind": _kind,
    "subject": _text, "ref": _text, "parent": _text, "cause": _text, "scope": _text,
    "at_ns": _ns, "previous": _link, "kid": _hex,
}
HEAD_RULES: Rules = {
    "v": _one, "log_id": _named, "seq": _count, "epoch": _count, "digest": _hex,
    "at_ns": _ns, "kid": _hex,
}
REQUEST_RULES: Rules = {
    "v": _one, "request_id": _named, "subject": _named, "grant_id": _named,
    "approval_id": _text, "epoch": _count, "at_ns": _ns, "kid": _hex,
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kid(key: bytes) -> str:
    """The key id of a raw Ed25519 public key: lowercase hex SHA-256."""
    return _sha(key)


def digest(wire: dict[str, Any]) -> str:
    """The digest a later event or the head binds: SHA-256 of the RFC 8785 wire object."""
    return _sha(_rail().jcs_dumps(wire))


def message(domain: bytes, claims: dict[str, Any]) -> bytes:
    """The bytes a record's signature covers."""
    return domain + b"\x00" + _rail().jcs_dumps(claims)


def _key(text: Any) -> bytes:
    try:
        raw = strictb64.std(text)
    except (ValueError, TypeError) as exc:
        raise Malformed("key is not canonical base64") from exc
    if len(raw) != 32:
        raise Malformed("key is not 32 bytes")
    return raw


def _record(wire: Any, rules: Rules, skip: frozenset[str]) -> dict[str, Any]:
    """The claims of a record, after its wire shape, members and types are checked."""
    if "record_shape" in skip:
        return wire["claims"]  # type: ignore[no-any-return]
    if not isinstance(wire, dict) or set(wire) != {"claims", "sig"}:
        raise Malformed("not a signed record")
    claims = wire["claims"]
    if not isinstance(claims, dict) or set(claims) != set(rules):
        raise Malformed("claims members differ from the record type")
    if not all(rule(claims[name]) for name, rule in rules.items()):
        raise Malformed("a member has the wrong type")
    try:
        sig = strictb64.std(wire["sig"])
    except (ValueError, TypeError) as exc:
        raise Malformed("signature is not canonical base64") from exc
    if len(sig) != 64:
        raise Malformed("signature is not 64 bytes")
    return claims


def _signed(wire: dict[str, Any], domain: bytes, key: bytes) -> bool:
    """Whether the record names this key and its signature verifies under it."""
    claims = wire["claims"]
    if claims.get("kid") != kid(key):
        return False
    try:
        sig = strictb64.std(wire["sig"])
    except (ValueError, TypeError):
        return False
    return bool(_rail().ed25519_verify(key, message(domain, claims), sig))


@dataclass
class Case:
    """One case's files, read and shape-checked."""

    log_id: str
    genesis: bytes
    holders: dict[str, Any]
    wires: list[dict[str, Any]]
    head: dict[str, Any] | None
    request: dict[str, Any]


def _json(path: Path) -> Any:
    try:
        return strictjson.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Malformed(f"{path.name} cannot be read") from exc


def _case_file(case: Any) -> None:
    members = {"v", "log_id", "keys", "events", "head", "request", "now_ns"}
    if not isinstance(case, dict) or set(case) != members or not _one(case["v"]):
        raise Malformed("case.json members")
    keys, events = case["keys"], case["events"]
    if not isinstance(keys, dict) or set(keys) != {"genesis", "holders"}:
        raise Malformed("case.json keys")
    if not isinstance(keys["holders"], dict) or not isinstance(events, list):
        raise Malformed("case.json holders or events")
    names = [*events, case["request"]] + ([] if case["head"] is None else [case["head"]])
    if not all(_named(n) and "/" not in n for n in names) or not _ns(case["now_ns"]):
        raise Malformed("case.json file names or clock")
    if not _named(case["log_id"]):
        raise Malformed("case.json log id")


def load(case_path: Path, skip: frozenset[str] = frozenset()) -> Case:
    """Read a case and every record it names; raise Malformed for any file of the wrong shape."""
    case = _json(case_path)
    _case_file(case)
    base = case_path.parent
    holders = {s: _key(k) for s, k in case["keys"]["holders"].items()}
    wires = [_json(base / name) for name in case["events"]]
    for wire in wires:
        _record(wire, EVENT_RULES, skip)
    head = None if case["head"] is None else _json(base / case["head"])
    if head is not None:
        _record(head, HEAD_RULES, skip)
    request = _json(base / case["request"])
    _record(request, REQUEST_RULES, skip)
    return Case(case["log_id"], _key(case["keys"]["genesis"]), holders, wires, head, request)


@dataclass
class Log:
    """A walked log: its events' claims, its last wire object and its current key."""

    events: list[dict[str, Any]] = field(default_factory=list)
    last: dict[str, Any] | None = None
    key: bytes = b""

    @property
    def epoch(self) -> int:
        return int(self.events[-1]["epoch"])

    def grant(self, grant_id: str) -> dict[str, Any] | None:
        return next((e for e in self.events if e["kind"] == "grant" and e["ref"] == grant_id), None)

    def of(self, kind: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["kind"] == kind]


def _sequence_ok(claims: dict[str, Any], index: int, log_id: str) -> bool:
    first = claims["kind"] == "genesis"
    return claims["seq"] == index and claims["log_id"] == log_id and first == (index == 0)


def _link_ok(claims: dict[str, Any], log: Log) -> bool:
    return claims["previous"] == ("" if log.last is None else digest(log.last))


def _epoch_ok(claims: dict[str, Any], log: Log) -> bool:
    if not log.events:
        return claims["epoch"] == 0
    step = 1 if claims["kind"] == "epoch_open" else 0
    return claims["epoch"] == log.epoch + step


def _open_disputes(log: Log) -> set[str]:
    """The revoke sequence numbers, as decimal strings, whose dispute is still open."""
    open_refs: set[str] = set()
    for event in log.events:
        if event["kind"] == "dispute_open":
            open_refs.add(event["ref"])
        elif event["kind"] == "dispute_closed":
            open_refs.discard(event["ref"])
    return open_refs


def _epoch_open_ok(c: dict[str, Any], log: Log) -> bool:
    if c["cause"] == "root_change":
        try:
            return len(strictb64.std(c["ref"])) == 32
        except (ValueError, TypeError):
            return False
    if c["cause"] in ("re_registration", "owner_change"):
        return bool(c["subject"])
    return c["cause"] in CAUSES


def _grant_ok(c: dict[str, Any], log: Log) -> bool:
    parent_ok = c["parent"] == "" or log.grant(c["parent"]) is not None
    return bool(c["ref"]) and bool(c["subject"]) and log.grant(c["ref"]) is None and parent_ok


def _revoke_ok(c: dict[str, Any], log: Log) -> bool:
    granted = log.grant(c["ref"]) if c["ref"] else None
    names = c["ref"] == "" or (granted is not None and granted["subject"] == c["subject"])
    return bool(c["subject"]) and c["scope"] in SCOPES and names


def _dispute_open_ok(c: dict[str, Any], log: Log) -> bool:
    revokes = {str(e["seq"]) for e in log.of("revoke")}
    return c["ref"] in revokes and c["ref"] not in _open_disputes(log)


def _dispute_closed_ok(c: dict[str, Any], log: Log) -> bool:
    return c["ref"] in _open_disputes(log) and c["cause"] in ("confirmed", "restored")


def _subject_ok(c: dict[str, Any], log: Log) -> bool:
    return bool(c["subject"])


def _ref_ok(c: dict[str, Any], log: Log) -> bool:
    return bool(c["ref"])


def _genesis_ok(c: dict[str, Any], log: Log) -> bool:
    return True


KIND_RULES: dict[str, Callable[[dict[str, Any], Log], bool]] = {
    "genesis": _genesis_ok,
    "epoch_open": _epoch_open_ok,
    "grant": _grant_ok,
    "revoke": _revoke_ok,
    "suspend": _subject_ok,
    "resume": _subject_ok,
    "approval_consumed": _ref_ok,
    "fork": _subject_ok,
    "dispute_open": _dispute_open_ok,
    "dispute_closed": _dispute_closed_ok,
}


def _event_fault(wire: dict[str, Any], index: int, log: Log, log_id: str,
                 skip: frozenset[str]) -> bool:
    """Whether one event breaks a rule of the walk."""
    c = wire["claims"]
    tests = (
        ("log_sequence", lambda: _sequence_ok(c, index, log_id)),
        ("log_links", lambda: _link_ok(c, log)),
        ("log_epochs", lambda: _epoch_ok(c, log)),
        ("log_event_rules", lambda: KIND_RULES[c["kind"]](c, log)),
        ("log_signatures", lambda: _signed(wire, DOMAIN_EVENT, log.key)),
    )
    return any(name not in skip and not test() for name, test in tests)


def walk(case: Case, skip: frozenset[str] = frozenset()) -> Log | None:
    """The walked log, or None when any event breaks a rule."""
    log = Log(key=case.genesis)
    for index, wire in enumerate(case.wires):
        if _event_fault(wire, index, log, case.log_id, skip):
            return None
        c = wire["claims"]
        log.events.append(c)
        log.last = wire
        if c["kind"] == "epoch_open" and c["cause"] == "root_change":
            log.key = strictb64.std(c["ref"])
    return log if log.events else None


def head_binds(case: Case, log: Log) -> bool:
    """Whether the head is signed under the current key and binds the last event."""
    head = case.head
    if head is None or log.last is None or not _signed(head, DOMAIN_HEAD, log.key):
        return False
    h, last = head["claims"], log.events[-1]
    same = h["log_id"] == case.log_id and h["seq"] == last["seq"] and h["epoch"] == last["epoch"]
    return same and h["digest"] == digest(log.last)


def _chain(log: Log, grant: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The grant and its ancestors through parent links."""
    chain: list[dict[str, Any]] = []
    while grant is not None and grant not in chain:
        chain.append(grant)
        grant = log.grant(grant["parent"]) if grant["parent"] else None
    return chain


def _applying(log: Log, subject: str, grant: dict[str, Any] | None) -> list[dict[str, Any]]:
    ids = {g["ref"] for g in _chain(log, grant)}
    return [
        r for r in log.of("revoke")
        if (r["ref"] == "" and r["subject"] == subject) or (r["ref"] and r["ref"] in ids)
    ]


def _revoked(log: Log, applying: list[dict[str, Any]], grant: dict[str, Any] | None,
             skip: frozenset[str]) -> tuple[str, str]:
    reason = "revoked"
    if grant is not None and "parent_order" not in skip:
        ancestors = {g["ref"] for g in _chain(log, grant)[1:]}
        if any(r["ref"] in ancestors and r["seq"] < grant["seq"] for r in applying):
            reason = "parent_revoked"
    disputed = _open_disputes(log)
    if "dispute_status" not in skip and any(str(r["seq"]) in disputed for r in applying):
        return "revoked_dispute_open", UNKNOWN
    if "scope_status" not in skip and all(r["scope"] == "new_admissions" for r in applying):
        return reason, PARTIAL
    return reason, CLOSED


def _suspended(log: Log, subject: str) -> bool:
    state = False
    for event in log.events:
        if event["subject"] == subject and event["kind"] in ("suspend", "resume"):
            state = event["kind"] == "suspend"
    return state


def standing(log: Log, subject: str, grant: dict[str, Any] | None,
             skip: frozenset[str] = frozenset()) -> tuple[str | None, str]:
    """The subject's refusal reason (None to admit) and revocation status."""
    if "fork" not in skip and any(f["subject"] == subject for f in log.of("fork")):
        return "fork", CLOSED
    applying = [] if "revocation" in skip else _applying(log, subject, grant)
    if applying:
        return _revoked(log, applying, grant, skip)
    if "suspension" not in skip and _suspended(log, subject):
        return "suspended", SUSPENDED
    return None, LIVE


def _holder_fault(case: Case, skip: frozenset[str]) -> str | None:
    claims = case.request["claims"]
    key = case.holders.get(claims["subject"])
    if "holder_pinned" not in skip and (key is None or claims["kid"] != kid(key)):
        return "unknown_holder"
    if "request_signature" not in skip and (
        key is None or not _signed_any_kid(case.request, key)
    ):
        return "request_signature_invalid"
    return None


def _signed_any_kid(wire: dict[str, Any], key: bytes) -> bool:
    try:
        sig = strictb64.std(wire["sig"])
    except (ValueError, TypeError):
        return False
    return bool(_rail().ed25519_verify(key, message(DOMAIN_REQUEST, wire["claims"]), sig))


def _grant_fault(log: Log, claims: dict[str, Any], skip: frozenset[str]) -> str | None:
    grant = log.grant(claims["grant_id"])
    if "grant_held" not in skip and (grant is None or grant["subject"] != claims["subject"]):
        return "no_grant"
    if grant is None or "grant_superseded" in skip:
        return None
    reregistered = any(
        e["cause"] == "re_registration" and e["subject"] == claims["subject"]
        and e["seq"] > grant["seq"]
        for e in log.of("epoch_open")
    )
    return "grant_superseded" if reregistered else None


def _request_fault(case: Case, log: Log, skip: frozenset[str]) -> str | None:
    """The first of checks 5 to 8 the request fails."""
    claims = case.request["claims"]
    fault = _holder_fault(case, skip)
    if fault is None and "epoch_fence" not in skip and claims["epoch"] != log.epoch:
        fault = "epoch_closed" if claims["epoch"] < log.epoch else "epoch_ahead"
    consumed = {e["ref"] for e in log.of("approval_consumed")}
    if fault is None and "approval_once" not in skip and claims["approval_id"] in consumed:
        fault = "approval_consumed"
    return fault if fault is not None else _grant_fault(log, claims, skip)


def _answer(decision: str, reason: str, status: str) -> dict[str, str]:
    return {"decision": decision, "reason": reason, "revocation_status": status}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision, reason and revocation status for one case."""
    try:
        case = load(case_path, skip)
    except Malformed:
        return _answer(NO_VERDICT, "malformed", UNKNOWN)
    if case.head is None and "head_present" not in skip:
        return _answer(REFUSE, "epoch_unavailable", UNKNOWN)
    log = walk(case, skip)
    if log is None:
        return _answer(REFUSE, "log_invalid", UNKNOWN)
    if "head_binding" not in skip and not head_binds(case, log):
        return _answer(REFUSE, "history_incomplete", UNKNOWN)
    claims = case.request["claims"]
    held = log.grant(claims["grant_id"])
    if held is not None and held["subject"] != claims["subject"] and "grant_held" not in skip:
        held = None
    reason, status = standing(log, claims["subject"], held, skip)
    fault = _request_fault(case, log, skip)
    if fault is not None:
        return _answer(REFUSE, fault, status)
    if reason is not None:
        return _answer(REFUSE, reason, status)
    return _answer(ADMIT, "authority_valid", status)


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(case_path), "--json"],
            capture_output=True, text=True, timeout=90, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason", "revocation_status")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def _reference_answer(case_path: Path, skip: frozenset[str]) -> dict[str, Any] | str:
    try:
        return verify(case_path, skip)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return f"the reader raised {type(exc).__name__}"


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
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, _reference_answer(case_path, skip)
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
            else f"{answer['decision']} {answer['reason']} {answer['revocation_status']}"
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
