"""Judge whether the acting-agent marker survives every hop of a delegated request.

A record is a chain of signed statements. The first is the origin: the issuer that
authenticated the user states the principals it sent. Every later statement is a hop:
one component states the principals it received and the principals it sent onward,
each in the native form of the protocol it spoke on that side. Two forms are read:

* ``rfc8693``: a JWT with its JOSE header, the claims carrying ``sub`` and nested
  ``act`` claims. RFC 8693 section 4.1: "The outermost "act" claim represents the
  current actor while nested "act" claims represent prior actors. The least recent
  actor is the most deeply nested." The ordered actor list, first actor first, is the
  nesting read from the innermost claim outward.
* ``a2a-actor-chain``: the ``actorChain`` member proposed for A2A ``Message.metadata``
  in a2aproject/A2A issue 2028: ``origin.sub`` and an ``actors`` list in which each
  delegating peer appends its own hop.

Each statement is signed with Ed25519 (RFC 8032) over its RFC 8785 canonical bytes.
The verifying key and the writer's role come from the trust bundle the verifier holds
(``TRUST.json`` beside the manifest), never from the record. A writer with role
``agent`` acts and must append itself; a writer with role ``relay`` (a gateway, a
queue, a protocol bridge) must forward the principals it received unchanged.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. it is this contract (``contract_id_unknown``);
3. the record has the shape below and every token decodes (``record_malformed``);
4. every writer is in the trust bundle with the role its statement needs
   (``statement_writer_unknown``);
5. every signature verifies under the writer's pinned key over the statement's
   RFC 8785 bytes (``statement_signature_invalid``);
6. every hop's ``prev`` is the SHA-256 of the previous statement's signed bytes
   (``hop_link_broken``);
7. every hop's writer is the audience the previous statement sent to
   (``audience_mismatch``);
8. every hop received exactly the token the previous statement sent
   (``received_not_sent``);
9. no hop acted on a token whose JOSE header lists a critical parameter this
   profile does not understand (``unknown_critical_attribute_ignored``; RFC 7515
   section 4.1.11);
10. no hop used a token after its ``exp`` (``principals_expired_at_use``);
11. no agent hop carried its own marker only in an unsigned transport header
    (``marker_unsigned``);
12. a deferred hop dispatched with the principals it stored
    (``deferred_dispatch_without_stored_principals``);
13. no hop changed the subject (``subject_replaced``);
14. no hop sent no actor when it owed at least one (``downgraded_to_user_alone``);
15. no hop dropped the earliest actors and kept a well-formed shorter chain
    (``chain_truncated``);
16. no hop dropped any other actor (``marker_stripped``);
17. no hop sent a different actor in an actor's place (``agent_replaced``);
18. no hop reordered the actors (``actor_order_changed``);
19. no hop added an actor it did not receive and is not (``actor_inserted``);
20. when the chain delivers the user alone, the origin carries user-presence
    evidence (``user_alone_without_human_evidence``).

A record that passes all twenty is ``accept`` / ``marker_survives``.

The verifier contract: ``<verifier> <case-dir>/record.json --trust <corpus>/TRUST.json
--json`` prints one JSON object with ``decision`` and ``reason`` and exits 0 for
``accept`` and 1 for ``reject``.

The hop contract (``--hop-command``) tests an implementation of one hop instead of a
verifier: the command reads one JSON object on standard input (``role``, ``self``,
``received`` with ``protocol`` and ``token``, ``send`` with ``protocol`` and ``to``,
and ``at``) and prints the ``{"protocol", "token"}`` it sends, or exits non-zero to
refuse. It is replayed through every hop of every accepted member and must send the
principals the corpus states; it is handed the received token of every member refused
for an unknown critical parameter and must refuse it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import _fixture_error, _validated_entries, run_corpus

from . import a2ajcs, strictjson

SUITE = "actor-marker-survival/v1"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/actor-marker-survival"
)
ACCEPT, REJECT = "accept", "reject"
ACCEPT_REASON = "marker_survives"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
PROTOCOLS = ("rfc8693", "a2a-actor-chain")
ROLES = ("agent", "relay")
#: Critical JOSE header parameters this profile understands: none.
KNOWN_CRITICAL: frozenset[str] = frozenset()
HUMAN_EVIDENCE_METHODS = ("user-presence",)
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "record_malformed",
    "statement_writer_unknown",
    "statement_signature_invalid",
    "hop_link_broken",
    "audience_mismatch",
    "received_not_sent",
    "unknown_critical_attribute_ignored",
    "principals_expired_at_use",
    "marker_unsigned",
    "deferred_dispatch_without_stored_principals",
    "subject_replaced",
    "downgraded_to_user_alone",
    "chain_truncated",
    "marker_stripped",
    "agent_replaced",
    "actor_order_changed",
    "actor_inserted",
    "user_alone_without_human_evidence",
)
#: The actor-list classes, by the check each one fails.
ACTOR_CLASSES = CHECKS[13:19]
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-actor-marker-survival"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-actor-marker-survival"
)
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")

Record = dict[str, Any]
Principals = tuple[str, tuple[str, ...]]


class Malformed(ValueError):
    """The record does not have the shape this contract reads."""


def _rail() -> Any:
    """The reference rail's pure-Python Ed25519, resolved at call time (the rail
    imports this module to dispatch the suite, so a module-level import is a cycle)."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "ed25519_verify"):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if hasattr(module, "ed25519_verify"):
            return module
    raise ImportError("the reference rail's Ed25519 primitive is unavailable")


@lru_cache(maxsize=16384)
def _ed25519_verify(key: bytes, message: bytes, sig: bytes) -> bool:
    return bool(_rail().ed25519_verify(key, message, sig))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url(data: bytes) -> str:
    """Unpadded base64url, the encoding of every key and signature here."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64url(text: Any, length: int) -> bytes | None:
    if not isinstance(text, str) or not _B64URL.match(text) or len(text) % 4 == 1:
        return None
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return data if len(data) == length and b64url(data) == text else None


def signing_input(statement: Any) -> bytes:
    """The bytes a statement's signature covers: its RFC 8785 canonical form."""
    return a2ajcs.canonicalize(statement)


def _seconds(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _need(condition: bool, what: str) -> None:
    if not condition:
        raise Malformed(what)


def _is_time(value: Any) -> bool:
    return isinstance(value, str) and bool(_TIME.match(value))


def _sub(holder: Any, where: str) -> str:
    _need(isinstance(holder, dict), f"{where} is not an object")
    value = holder.get("sub")
    _need(isinstance(value, str) and value != "", f"{where}.sub is not a non-empty string")
    return str(value)


def decode(part: Any) -> Principals:
    """The subject and the ordered actors (first actor first) of one token."""
    _need(isinstance(part, dict), "a token holder is not an object")
    protocol, token = part.get("protocol"), part.get("token")
    _need(isinstance(token, dict), "token is not an object")
    if protocol == "rfc8693":
        header, claims = token.get("header"), token.get("claims")
        _need(
            isinstance(header, dict) and isinstance(claims, dict),
            "rfc8693 token needs header and claims",
        )
        crit = header.get("crit", [])
        _need(
            isinstance(crit, list) and all(isinstance(c, str) for c in crit),
            "crit is not a string list",
        )
        exp = claims.get("exp")
        _need(
            exp is None or (isinstance(exp, int) and not isinstance(exp, bool)),
            "exp is not an integer",
        )
        subject, actors, act = _sub(claims, "claims"), [], claims.get("act")
        while act is not None:
            actors.append(_sub(act, "act"))
            act = act.get("act")
        return subject, tuple(reversed(actors))
    if protocol == "a2a-actor-chain":
        chain = token.get("actorChain")
        _need(isinstance(chain, dict), "actorChain is not an object")
        listed = chain.get("actors")
        _need(isinstance(listed, list), "actorChain.actors is not a list")
        return _sub(chain.get("origin"), "origin"), tuple(_sub(a, "actor") for a in listed)
    raise Malformed(f"protocol {protocol!r} is not one this contract reads")


def critical(part: dict[str, Any]) -> list[str]:
    """The critical JOSE header parameters a token lists."""
    if part["protocol"] != "rfc8693":
        return []
    return list(part["token"]["header"].get("crit", []))


def expiry(part: dict[str, Any]) -> int | None:
    if part["protocol"] != "rfc8693":
        return None
    exp = part["token"]["claims"].get("exp")
    return None if exp is None else int(exp)


def _shape_side(side: Any, where: str, *, to: bool) -> None:
    _need(isinstance(side, dict), f"{where} is not an object")
    _need(_is_time(side.get("at")), f"{where}.at is not an RFC 3339 UTC second")
    if to:
        _need(isinstance(side.get("to"), str) and side["to"] != "", f"{where}.to is not a string")
    decode(side)


def _shape(record: Record) -> None:
    """Raise Malformed unless the record has the shape this contract reads."""
    items = record.get("statements")
    _need(isinstance(items, list) and len(items) >= 2, "statements needs an origin and a hop")
    for index, item in enumerate(items):
        _need(isinstance(item, dict), "a statement entry is not an object")
        _need(isinstance(item.get("signature"), str), "signature is not a string")
        statement = item.get("statement")
        _need(isinstance(statement, dict), "statement is not an object")
        _need(isinstance(statement.get("writer"), str), "writer is not a string")
        transport = item.get("transport", {"headers": {}})
        _need(
            isinstance(transport, dict) and isinstance(transport.get("headers"), dict),
            "transport.headers",
        )
        _need(
            all(isinstance(v, str) for v in transport["headers"].values()),
            "a header is not a string",
        )
        kind = "origin" if index == 0 else "hop"
        _need(statement.get("kind") == kind, f"statement {index} is not an {kind} statement")
        _shape_side(statement.get("sent"), "sent", to=True)
        if kind == "origin":
            evidence = statement.get("humanEvidence")
            _need(
                evidence is None
                or (
                    isinstance(evidence, dict)
                    and isinstance(evidence.get("method"), str)
                    and _is_time(evidence.get("at"))
                ),
                "humanEvidence",
            )
            continue
        _need(
            isinstance(statement.get("prev"), str) and bool(_HEX64.match(statement["prev"])), "prev"
        )
        _shape_side(statement.get("received"), "received", to=False)
        deferred = statement.get("deferred")
        if deferred is not None:
            _need(
                isinstance(deferred, dict)
                and _is_time(deferred.get("enqueuedAt"))
                and _is_time(deferred.get("dispatchedAt")),
                "deferred",
            )
            _need(
                deferred["dispatchedAt"] == statement["sent"]["at"],
                "deferred dispatch is not the send",
            )
            _need(
                _seconds(deferred["enqueuedAt"]) <= _seconds(deferred["dispatchedAt"]),
                "deferred order",
            )


def _token_of(side: dict[str, Any]) -> bytes:
    return a2ajcs.canonicalize({"protocol": side["protocol"], "token": side["token"]})


def owed(statement: dict[str, Any], role: str) -> Principals:
    """The principals a hop owes onward: what it received, plus itself when it acts."""
    subject, actors = decode(statement["received"])
    return subject, actors + ((statement["writer"],) if role == "agent" else ())


def _is_subsequence(short: tuple[str, ...], long: tuple[str, ...]) -> bool:
    remaining = iter(long)
    return all(any(item == other for other in remaining) for item in short)


def classify(expected: tuple[str, ...], sent: tuple[str, ...]) -> str | None:
    """The actor-list check a sent list fails against the list owed, or None."""
    if sent == expected:
        return None
    if not sent:
        return "downgraded_to_user_alone"
    if Counter(sent) == Counter(expected):
        return "actor_order_changed"
    if len(sent) < len(expected) and _is_subsequence(sent, expected):
        return (
            "chain_truncated"
            if expected[len(expected) - len(sent) :] == sent
            else "marker_stripped"
        )
    if len(sent) > len(expected) and _is_subsequence(expected, sent):
        return "actor_inserted"
    return "agent_replaced"


class _Chain:
    """One shape-checked record read against one trust bundle."""

    def __init__(self, record: Record, trust: dict[str, Any]) -> None:
        self.items = record["statements"]
        self.statements = [item["statement"] for item in self.items]
        self.writers = trust["writers"]

    def role(self, statement: dict[str, Any]) -> str | None:
        writer = self.writers.get(statement["writer"])
        return writer["role"] if isinstance(writer, dict) else None

    def hops(self) -> list[tuple[int, dict[str, Any]]]:
        return list(enumerate(self.statements))[1:]

    def writer_unknown(self) -> bool:
        for index, statement in enumerate(self.statements):
            role = self.role(statement)
            if role is None or (role == "origin") != (index == 0) or (index and role not in ROLES):
                return True
        return False

    def signature_invalid(self) -> bool:
        for item in self.items:
            key = _unb64url(self.writers[item["statement"]["writer"]].get("key"), 32)
            signature = _unb64url(item["signature"], 64)
            if key is None or signature is None:
                return True
            if not _ed25519_verify(key, signing_input(item["statement"]), signature):
                return True
        return False

    def link_broken(self) -> bool:
        return any(s["prev"] != _sha(signing_input(self.statements[i - 1])) for i, s in self.hops())

    def audience_mismatch(self) -> bool:
        return any(s["writer"] != self.statements[i - 1]["sent"]["to"] for i, s in self.hops())

    def received_not_sent(self) -> bool:
        return any(
            _token_of(s["received"]) != _token_of(self.statements[i - 1]["sent"])
            for i, s in self.hops()
        )

    def critical_ignored(self) -> bool:
        return any(set(critical(s["received"])) - KNOWN_CRITICAL for _, s in self.hops())

    def expired(self) -> bool:
        for _, s in self.hops():
            exp = expiry(s["received"])
            if exp is not None and _seconds(s["sent"]["at"]) > exp:
                return True
        return False

    def unsigned_marker(self) -> bool:
        for i, s in self.hops():
            if self.role(s) == "agent" and s["writer"] not in decode(s["sent"])[1]:
                if (
                    s["writer"]
                    in self.items[i].get("transport", {"headers": {}})["headers"].values()
                ):
                    return True
        return False

    def deferred_changed(self) -> bool:
        return any(
            "deferred" in s and decode(s["sent"]) != owed(s, str(self.role(s)))
            for _, s in self.hops()
        )

    def subject_replaced(self) -> bool:
        return any(decode(s["sent"])[0] != decode(s["received"])[0] for _, s in self.hops())

    def actor_class(self, name: str) -> bool:
        return any(
            classify(owed(s, str(self.role(s)))[1], decode(s["sent"])[1]) == name
            for _, s in self.hops()
        )

    def user_alone_unevidenced(self) -> bool:
        if decode(self.statements[-1]["sent"])[1]:
            return False
        evidence = self.statements[0].get("humanEvidence")
        return evidence is None or evidence["method"] not in HUMAN_EVIDENCE_METHODS


def _first_failure(
    record: Record, trust: dict[str, Any], skip: frozenset[str] = frozenset()
) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each check is
    forced by some member; a verifier never sets it. A skipped shape check is replaced by
    a refusal-free read, so later checks still see a well-shaped record only.
    """
    if "contract_id_missing" not in skip and "contractId" not in record:
        return "contract_id_missing"
    if "contract_id_unknown" not in skip and record.get("contractId", CONTRACT_ID) != CONTRACT_ID:
        return "contract_id_unknown"
    try:
        _shape(record)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError):
        return None if "record_malformed" in skip else "record_malformed"
    chain = _Chain(record, trust)
    ordered: list[tuple[str, Callable[[], bool]]] = [
        ("statement_writer_unknown", chain.writer_unknown),
        ("statement_signature_invalid", chain.signature_invalid),
        ("hop_link_broken", chain.link_broken),
        ("audience_mismatch", chain.audience_mismatch),
        ("received_not_sent", chain.received_not_sent),
        ("unknown_critical_attribute_ignored", chain.critical_ignored),
        ("principals_expired_at_use", chain.expired),
        ("marker_unsigned", chain.unsigned_marker),
        ("deferred_dispatch_without_stored_principals", chain.deferred_changed),
        ("subject_replaced", chain.subject_replaced),
        *[(name, (lambda n=name: chain.actor_class(n))) for name in ACTOR_CLASSES],
        ("user_alone_without_human_evidence", chain.user_alone_unevidenced),
    ]
    for name, fails in ordered:
        if name in skip:
            continue
        if (
            name != "statement_writer_unknown"
            and "statement_writer_unknown" in skip
            and chain.writer_unknown()
        ):
            return None
        if fails():
            return name
    return None


def judge(
    record: Record, trust: dict[str, Any], skip: frozenset[str] = frozenset()
) -> dict[str, str]:
    failure = _first_failure(record, trust, skip)
    if failure is not None:
        return {"decision": REJECT, "reason": failure}
    return {"decision": ACCEPT, "reason": ACCEPT_REASON}


def _load(path: Path) -> Any:
    return strictjson.loads(path.read_text(encoding="utf-8"))


def verify(
    record_path: Path, trust_path: Path | None = None, skip: frozenset[str] = frozenset()
) -> dict[str, str]:
    """The reference reader's decision and reason for one record file."""
    trust = _load(trust_path or (record_path.parents[2] / "TRUST.json"))
    try:
        record = _load(record_path)
    except (ValueError, UnicodeDecodeError):
        return {"decision": REJECT, "reason": "record_malformed"}
    if not isinstance(record, dict):
        return {"decision": REJECT, "reason": "record_malformed"}
    return judge(record, trust, skip)


def retained(record: Record, trust: dict[str, Any]) -> dict[str, Any]:
    """What a verifier keeps: the delivered principals and each statement's digest."""
    try:
        _shape(record)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError):
        return {"delivered": None, "signingInputs": []}
    subject, actors = decode(record["statements"][-1]["statement"]["sent"])
    return {
        "delivered": {"actors": list(actors), "subject": subject},
        "signingInputs": [_sha(signing_input(i["statement"])) for i in record["statements"]],
    }


def _external_answer(
    command: list[str], record: Path, trust: Path
) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(record), "--trust", str(trust), "--json"],
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


def _load_corpus(root: Path) -> tuple[list[dict[str, Any]], Path, dict[str, Any]]:
    """The validated manifest rows, the trust path and the trust bundle, or ValueError."""
    entries, manifest_error = _validated_entries(root, SUITE)
    if manifest_error:
        raise ValueError(manifest_error)
    manifest = _load(root / "MANIFEST.json")
    trust_path = root / "TRUST.json"
    if _sha(trust_path.read_bytes()) != manifest["trustSha256"]:
        raise ValueError("TRUST.json does not match the digest the manifest pins")
    return entries, trust_path, _load(trust_path)


def _member_errors(
    entry: dict[str, Any],
    root: Path,
    trust_path: Path,
    trust: dict[str, Any],
    command: list[str] | None,
    skip: frozenset[str],
) -> tuple[bool, list[str]]:
    """(answered, errors) for one manifest row."""
    name, directory = entry["id"], root / entry["path"]
    fixture_error = _fixture_error(directory, entry)
    if fixture_error:
        return False, [f"{name}: {fixture_error}"]
    record_path = directory / "record.json"
    errors = []
    if retained(_load(record_path), trust) != entry["retained"]:
        errors.append(f"{name}: declared retained fields do not hold")
    observed: dict[str, Any] | str
    if command is None:
        ran, observed = True, verify(record_path, trust_path, skip)
    else:
        ran, observed = _external_answer(command, record_path, trust_path)
    if isinstance(observed, str):
        errors.append(f"{name}: {observed}")
    elif observed != entry["expected"]:
        errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return ran, errors


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT, skip: frozenset[str] = frozenset()
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    try:
        entries, trust_path, trust = _load_corpus(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        ran, found = _member_errors(entry, root, trust_path, trust, command, skip)
        answered += int(ran)
        errors.extend(found)
    return answered, errors


# The hop contract -------------------------------------------------------------------------


def encode(protocol: str, principals: Principals, exp: int | None = None) -> dict[str, Any]:
    """One token in a protocol's native form carrying the given principals."""
    subject, actors = principals
    if protocol == "a2a-actor-chain":
        return {"actorChain": {"actors": [{"sub": a} for a in actors], "origin": {"sub": subject}}}
    claims: dict[str, Any] = {"sub": subject}
    if exp is not None:
        claims["exp"] = exp
    holder = claims
    for actor in reversed(actors):
        holder["act"] = {"sub": actor}
        holder = holder["act"]
    return {"claims": claims, "header": {"typ": "JWT"}}


def reference_hop(request: dict[str, Any]) -> dict[str, Any] | None:
    """A correct hop: refuse an unknown critical parameter or an expired token, else
    forward what was received, appending itself when it acts. None is a refusal."""
    received = request["received"]
    principals = decode(received)
    exp = expiry(received)
    if set(critical(received)) - KNOWN_CRITICAL or (
        exp is not None and _seconds(request["at"]) > exp
    ):
        return None
    subject, actors = principals
    if request["role"] == "agent":
        actors = actors + (request["self"],)
    protocol = request["send"]["protocol"]
    return {"protocol": protocol, "token": encode(protocol, (subject, actors), exp)}


def hop_requests(root: Path = ROOT) -> list[tuple[str, dict[str, Any], Principals | None]]:
    """(label, request, principals owed or None for a refusal) for the hop contract."""
    manifest, trust = _load(root / "MANIFEST.json"), _load(root / "TRUST.json")
    out = []
    for entry in manifest["vectors"]:
        reason = entry["expected"]["reason"]
        if reason not in (ACCEPT_REASON, "unknown_critical_attribute_ignored"):
            continue
        record = _load(root / entry["path"] / "record.json")
        for index, item in enumerate(record["statements"][1:], start=1):
            statement = item["statement"]
            role = trust["writers"][statement["writer"]]["role"]
            request = {
                "at": statement["sent"]["at"],
                "received": copy.deepcopy(statement["received"]),
                "role": role,
                "self": statement["writer"],
                "send": {"protocol": statement["sent"]["protocol"], "to": statement["sent"]["to"]},
            }
            if reason == ACCEPT_REASON:
                out.append((f"{entry['id']}#{index}", request, decode(statement["sent"])))
            elif set(critical(statement["received"])) - KNOWN_CRITICAL:
                out.append((f"{entry['id']}#{index}", request, None))
    return out


def hop_check(command: str | list[str], root: Path = ROOT) -> tuple[int, int, list[str]]:
    """(answered, total, errors) of a hop implementation replayed through the corpus."""
    argv = shlex.split(command) if isinstance(command, str) else command
    requests = hop_requests(root)
    errors: list[str] = []
    answered = 0
    for label, request, owed_principals in requests:
        try:
            result = subprocess.run(
                argv,
                input=json.dumps(request, sort_keys=True),
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{label}: hop command did not run: {exc}")
            continue
        answered += 1
        if owed_principals is None:
            if result.returncode == 0:
                errors.append(
                    f"{label}: the hop forwarded a token with an unknown critical parameter"
                )
            continue
        if result.returncode != 0:
            errors.append(
                f"{label}: the hop refused a chain the corpus accepts (exit {result.returncode})"
            )
            continue
        try:
            sent = strictjson.loads(result.stdout)
            got = decode(sent)
            _need(sent.get("protocol") == request["send"]["protocol"], "sent in another protocol")
        except (Malformed, ValueError, KeyError, TypeError, AttributeError) as exc:
            errors.append(f"{label}: the hop's output does not decode: {exc}")
            continue
        if got != owed_principals:
            errors.append(f"{label}: sent {got}, owed {owed_principals}")
    return answered, len(requests), errors


def run_runtime(command: str, report_path: str, root: Path = ROOT) -> int:
    """Replay a hop implementation through the corpus and write its report.

    This is the corpus's runtime contract: ``agent-evidence-vectors runtime --corpus
    vectors-actor-marker-survival --runtime '<hop command>'``, and the Action's
    ``runtime`` input.
    """
    answered, total, errors = hop_check(command, root)
    for error in errors:
        print(error)
    print(f"{SUITE}: hop implementation answered {answered} of {total} hops, {len(errors)} failed")
    report = {
        "corpusDigest": _load(root / "MANIFEST.json")["corpusDigest"],
        "failures": errors,
        "rail": "runtime",
        "runtime": {"command": command, "hopsExecuted": answered},
        "suite": SUITE,
        "totals": {"conform": total - len(errors), "fail": len(errors), "hops": total},
    }
    Path(report_path).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not total or answered != total:
        return 2
    return 1 if errors else 0


def _reference_hop_main() -> int:
    answer = reference_hop(strictjson.loads(sys.stdin.read()))
    if answer is None:
        return 3
    print(json.dumps(answer, sort_keys=True))
    return 0


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="judge one record.json with the reference reader")
    parser.add_argument(
        "--trust", help="the trust bundle (default: TRUST.json of the record's corpus)"
    )
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    parser.add_argument("--hop-command", help="replay every hop through this hop implementation")
    parser.add_argument(
        "--reference-hop", action="store_true", help="act as the reference hop on stdin"
    )
    args = parser.parse_args(argv)
    if args.reference_hop:
        return _reference_hop_main()
    if args.record:
        answer = verify(Path(args.record), Path(args.trust) if args.trust else None)
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    if args.hop_command:
        answered, total, errors = hop_check(args.hop_command)
        for error in errors:
            print(error)
        print(f"hop implementation answered {answered} of {total} hops")
        return 1 if errors or answered != total else 0
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(_load(ROOT / "MANIFEST.json")["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
