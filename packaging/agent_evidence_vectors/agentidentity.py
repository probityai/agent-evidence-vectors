"""Judge a past decision against an agent's signed identity and status history.

``agent-identity-statement/v1`` (spec/predicates/agent-identity-statement.md). An issuer
signs one in-toto Statement for each version of an agent's identity document: the agent,
the version, the key set in force, the status (``active``, ``suspended`` or ``revoked``)
and the instant it takes effect, chained to the previous version by the SHA-256 of that
version's signed payload. A member is the consumer's pins (``context.json``: the issuer's
keys, the agent and the head of the history it holds), the history (``history.json``: a
list of DSSE envelopes in any order) and one past decision (``decision.json``: the instant
the relying party acted and the DSSE envelope the agent signed). The reader names the
first check that fails:

1. the history is a non-empty strict JSON list of DSSE envelopes carrying in-toto payloads
   (``history_malformed``);
2. every envelope is signed by a pinned issuer key (``statement_signature``);
3. each payload is a strict JSON object with exactly the four Statement members
   (``statement_malformed``), of in-toto Statement v1 (``statement_type_wrong``) and this
   predicate type (``predicate_type_wrong``), whose subject is one member with a lowercase
   SHA-256 (``subject_malformed``) and whose predicate is well formed
   (``predicate_malformed``);
4. no version is ``active`` with an empty key set (``active_without_keys``) or takes
   effect after it was issued (``effective_after_issued``);
5. every version names the pinned agent (``agent_mismatch``);
6. the versions form one chain from version 1: there is a version 1
   (``history_no_genesis``), no two versions name the same previous one
   (``history_forked``), every previous one is supplied (``history_previous_missing``),
   each version is its previous one's plus one (``version_not_incremented``,
   ``version_gap``), no time runs backwards (``history_time_reversed``), and nothing
   follows a revocation (``revoked_is_final``);
7. the chain ends at the head the consumer pinned (``history_head_mismatch``);
8. the decision is well formed (``decision_malformed``), its key is listed in some
   version (``key_unknown``) and signed the decision (``decision_signature``);
9. at the decision's instant a version was in force (``decision_before_history``), the
   agent was not suspended (``agent_suspended``) or revoked (``agent_revoked``), and the
   key was in that version's set (``key_not_in_force``).

A member that passes every check is ``accept`` with reason ``key_in_force``.

The external-verifier contract: ``<verifier> <suite> <case-dir> --json`` prints one JSON
object carrying ``decision`` and ``reason``, and exits 0 for ``accept`` and 1 for
``reject``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import strictb64, strictjson

SUITE = "agent-identity-statement/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://w3id.org/agent-evidence/predicate/v1/agent-identity-statement"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATUSES = ("active", "suspended", "revoked")
KEY_TYPES = ("Ed25519",)
ACCEPT, REJECT = "accept", "reject"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
PASS_REASON = "key_in_force"
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
HEX = re.compile(r"[0-9a-f]{64}")
MAX_VERSION = 2**53 - 1

CHECKS = (
    "history_malformed",
    "statement_signature",
    "statement_malformed",
    "statement_type_wrong",
    "predicate_type_wrong",
    "subject_malformed",
    "predicate_malformed",
    "active_without_keys",
    "effective_after_issued",
    "agent_mismatch",
    "history_no_genesis",
    "history_forked",
    "history_previous_missing",
    "version_not_incremented",
    "version_gap",
    "history_time_reversed",
    "revoked_is_final",
    "history_head_mismatch",
    "decision_malformed",
    "key_unknown",
    "decision_signature",
    "decision_before_history",
    "agent_suspended",
    "agent_revoked",
    "key_not_in_force",
)

_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-agent-identity-statement" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-agent-identity-statement")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "pae")


class Malformed(ValueError):
    """A value that breaks a shape rule; the caller names the check."""


def _rail() -> Any:
    """The rail module, resolved at call time; see receiptsignature._rail."""
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
    raise ImportError("the reference rail is not importable, so Ed25519 is unavailable")


def sha256_hex(data: bytes) -> str:
    """Lowercase hexadecimal SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _require(condition: bool, what: str) -> None:
    if not condition:
        raise Malformed(what)


def _strict(data: bytes | None) -> Any:
    _require(data is not None, "absent")
    try:
        return strictjson.loads(data or b"")
    except ValueError as exc:
        raise Malformed(str(exc)) from exc


def _members(value: Any, required: set[str], optional: frozenset[str] = frozenset()) -> None:
    _require(isinstance(value, dict), "not an object")
    present = set(value)
    _require(required <= present <= required | optional, f"members {sorted(present)}")


def parse_time(text: Any) -> datetime:
    """An RFC 3339 UTC time to whole seconds, ``YYYY-MM-DDTHH:MM:SSZ``."""
    _require(isinstance(text, str) and TIME.fullmatch(text) is not None, "time")
    try:
        return datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise Malformed(str(exc)) from exc


def _text(value: Any) -> str:
    _require(isinstance(value, str) and value != "", "non-empty text")
    return str(value)


def _https(value: Any) -> str:
    text = _text(value)
    _require(text.startswith("https://") and len(text) > len("https://"), "https URL")
    _require(not any(c in text for c in " #") and text.isascii(), "https URL")
    return text


def _principal(value: Any) -> dict[str, str]:
    _members(value, {"issuer", "subject"})
    return {"issuer": _https(value["issuer"]), "subject": _text(value["subject"])}


def _b64(text: Any) -> bytes:
    _require(isinstance(text, str), "base64 text")
    try:
        return strictb64.std(str(text))
    except ValueError as exc:
        raise Malformed("base64") from exc


# ---------------------------------------------------------------------------
# The history
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Envelope:
    """One DSSE envelope: its payload bytes and its signatures."""

    payload_type: str
    payload: bytes
    sigs: tuple[bytes, ...]

    @property
    def digest(self) -> str:
        return sha256_hex(self.payload)


@dataclass(frozen=True)
class Version:
    """One verified version of the identity document."""

    digest: str
    version: int
    previous: str | None
    issued: datetime
    effective: datetime
    status: str
    keys: frozenset[str]
    agent: dict[str, str]


def envelope(value: Any) -> Envelope:
    """A DSSE envelope with at least one signature; raise Malformed otherwise."""
    _members(value, {"payloadType", "payload", "signatures"})
    _require(isinstance(value["payloadType"], str), "payloadType")
    signatures = value["signatures"]
    _require(isinstance(signatures, list) and signatures != [], "signatures")
    sigs = []
    for item in signatures:
        _members(item, {"sig"}, frozenset({"keyid"}))
        if "keyid" in item:
            _require(isinstance(item["keyid"], str), "keyid")
        sigs.append(_b64(item["sig"]))
    return Envelope(str(value["payloadType"]), _b64(value["payload"]), tuple(sigs))


def history_envelopes(raw: bytes | None) -> list[Envelope]:
    """The history's envelopes, each carrying an in-toto payload; duplicates collapse."""
    value = _strict(raw)
    _require(isinstance(value, list) and value != [], "history is a non-empty list")
    out: dict[str, Envelope] = {}
    for item in value:
        env = envelope(item)
        _require(env.payload_type == PAYLOAD_TYPE, "payloadType")
        out.setdefault(env.digest, env)
    return list(out.values())


def public_key(hex_key: str) -> bytes:
    """The raw 32-byte key a 64-character lowercase hex text names."""
    _require(isinstance(hex_key, str) and HEX.fullmatch(hex_key) is not None, "public key")
    return bytes.fromhex(hex_key)


def key_id(raw: bytes) -> str:
    """A key's identifier: the SHA-256 of its raw bytes."""
    return sha256_hex(raw)


def signed_by(keys: list[bytes], env: Envelope) -> bytes | None:
    """The first of ``keys`` that signed ``env``, or None."""
    rail = _rail()
    message = rail.pae(env.payload_type, env.payload)
    for key in keys:
        if any(rail.ed25519_verify(key, message, sig) for sig in env.sigs):
            return key
    return None


def _keys(value: Any) -> frozenset[str]:
    _require(isinstance(value, list), "keys")
    hexes = []
    for item in value:
        _members(item, {"type", "publicKey"})
        _require(item["type"] in KEY_TYPES, "key type")
        public_key(item["publicKey"])
        hexes.append(item["publicKey"])
    _require(hexes == sorted(set(hexes)), "keys sorted and distinct")
    return frozenset(hexes)


def predicate_fields(predicate: Any) -> dict[str, Any]:
    """The predicate's members, checked for shape; raise Malformed otherwise."""
    _members(predicate, {"agent", "version", "issuedAt", "effectiveAt", "status", "keys"},
             frozenset({"previous", "reason"}))
    version = predicate["version"]
    _require(type(version) is int and 1 <= version <= MAX_VERSION, "version")
    _require(("previous" in predicate) == (version > 1), "previous iff version > 1")
    previous = None
    if "previous" in predicate:
        _members(predicate["previous"], {"sha256"})
        previous = predicate["previous"]["sha256"]
        _require(isinstance(previous, str) and HEX.fullmatch(previous) is not None, "previous")
    _require(predicate["status"] in STATUSES, "status")
    if "reason" in predicate:
        _text(predicate["reason"])
    return {"agent": _principal(predicate["agent"]), "version": version, "previous": previous,
            "issued": parse_time(predicate["issuedAt"]),
            "effective": parse_time(predicate["effectiveAt"]),
            "status": predicate["status"], "keys": _keys(predicate["keys"])}


def statement_failure(payload: bytes) -> tuple[str | None, dict[str, Any]]:
    """The first Statement-shape check that fails, and the predicate fields when none does."""
    try:
        statement = _strict(payload)
        _members(statement, {"_type", "subject", "predicateType", "predicate"})
    except Malformed:
        return "statement_malformed", {}
    if statement["_type"] != STATEMENT_TYPE:
        return "statement_type_wrong", {}
    if statement["predicateType"] != PREDICATE_TYPE:
        return "predicate_type_wrong", {}
    try:
        subject = statement["subject"]
        _require(isinstance(subject, list) and len(subject) == 1, "one subject")
        _members(subject[0], {"name", "digest"})
        _text(subject[0]["name"])
        _members(subject[0]["digest"], {"sha256"})
        _require(isinstance(subject[0]["digest"]["sha256"], str)
                 and HEX.fullmatch(subject[0]["digest"]["sha256"]) is not None, "digest")
    except Malformed:
        return "subject_malformed", {}
    try:
        return None, predicate_fields(statement["predicate"])
    except Malformed:
        return "predicate_malformed", {}


def _children(versions: list[Version]) -> dict[str | None, list[Version]]:
    children: dict[str | None, list[Version]] = {}
    for v in versions:
        children.setdefault(v.previous, []).append(v)
    return children


def _links(versions: list[Version]) -> list[tuple[Version, Version]]:
    """Each version paired with its supplied previous version; a missing one is skipped."""
    by_digest = {v.digest: v for v in versions}
    links: list[tuple[Version, Version]] = []
    for v in versions:
        parent = by_digest.get(v.previous) if v.previous is not None else None
        if parent is not None:
            links.append((v, parent))
    return links


def _no_genesis(versions: list[Version], head: str) -> str | None:
    return None if any(v.version == 1 for v in versions) else "history_no_genesis"


def _forked(versions: list[Version], head: str) -> str | None:
    forked = any(len(group) > 1 for group in _children(versions).values())
    return "history_forked" if forked else None


def _previous_missing(versions: list[Version], head: str) -> str | None:
    supplied = {v.digest for v in versions}
    missing = any(v.previous is not None and v.previous not in supplied for v in versions)
    return "history_previous_missing" if missing else None


def _version_step(versions: list[Version], head: str) -> str | None:
    for v, parent in _links(versions):
        if v.version <= parent.version:
            return "version_not_incremented"
        if v.version > parent.version + 1:
            return "version_gap"
    return None


def _time_reversed(versions: list[Version], head: str) -> str | None:
    reversed_ = any(v.effective < p.effective or v.issued < p.issued for v, p in _links(versions))
    return "history_time_reversed" if reversed_ else None


def _revoked_final(versions: list[Version], head: str) -> str | None:
    after_revocation = any(parent.status == "revoked" for _, parent in _links(versions))
    return "revoked_is_final" if after_revocation else None


def _head_mismatch(versions: list[Version], head: str) -> str | None:
    children = _children(versions)
    tips = [v.digest for v in versions if v.digest not in children]
    return None if tips == [head] else "history_head_mismatch"


# The chain checks in the order the specification names them; the first failure wins.
_CHAIN_CHECKS = (
    _no_genesis,
    _forked,
    _previous_missing,
    _version_step,
    _time_reversed,
    _revoked_final,
    _head_mismatch,
)


def chain_failure(versions: list[Version], head: str) -> str | None:
    """The first chain check that fails over verified, well-formed versions."""
    for check in _CHAIN_CHECKS:
        failure = check(versions, head)
        if failure is not None:
            return failure
    return None


def in_force(versions: list[Version], at: datetime) -> Version | None:
    """The version in force at ``at``: the highest whose effectiveAt is not after it."""
    standing = [v for v in versions if v.effective <= at]
    return max(standing, key=lambda v: v.version) if standing else None


# ---------------------------------------------------------------------------
# Judging one member
# ---------------------------------------------------------------------------


def _read(directory: Path, name: str) -> bytes | None:
    path = directory / name
    return path.read_bytes() if path.is_file() else None


def _context(directory: Path) -> tuple[list[bytes], dict[str, str], str]:
    context = _strict(_read(directory, "context.json"))
    _members(context, {"issuerKeys", "agent", "head"})
    keys = context["issuerKeys"]
    _require(isinstance(keys, list) and keys != [], "issuerKeys")
    head = context["head"]
    _members(head, {"sha256"})
    _require(isinstance(head["sha256"], str) and HEX.fullmatch(head["sha256"]) is not None, "head")
    return [public_key(k) for k in keys], _principal(context["agent"]), head["sha256"]


def _decision(raw: bytes | None) -> tuple[datetime, str, Envelope]:
    value = _strict(raw)
    _members(value, {"at", "envelope"})
    env_value = value["envelope"]
    env = envelope(env_value)
    signatures = env_value["signatures"]
    _require(len(signatures) == 1 and "keyid" in signatures[0], "one signature naming its key")
    keyid = signatures[0]["keyid"]
    _require(HEX.fullmatch(keyid) is not None, "keyid")
    return parse_time(value["at"]), keyid, env


class _Member:
    """The checks over one member; each reads only what the checks before it established."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.issuer_keys, self.agent, self.head = _context(directory)
        self.envelopes: list[Envelope] = []
        self.decision: tuple[datetime, str, Envelope] | None = None
        self._parsed: list[Version] | None = None
        self._shape_first: str | None = None
        self._chain: tuple[str | None] | None = None

    def malformed(self) -> bool:
        self.envelopes = history_envelopes(_read(self.directory, "history.json"))
        return False

    def bad_signature(self) -> bool:
        return any(signed_by(self.issuer_keys, env) is None for env in self.envelopes)

    def _parse_statements(self) -> list[Version]:
        if self._parsed is None:
            versions: list[Version] = []
            failures: list[str] = []
            for env in self.envelopes:
                failure, fields = statement_failure(env.payload)
                if failure is not None:
                    failures.append(failure)
                    continue
                versions.append(Version(env.digest, fields["version"], fields["previous"],
                                        fields["issued"], fields["effective"], fields["status"],
                                        fields["keys"], fields["agent"]))
            self._shape_first = min(failures, key=CHECKS.index) if failures else None
            self._parsed = versions
        return self._parsed

    def statement_check(self, code: str) -> Callable[[], bool]:
        def failing() -> bool:
            self._parse_statements()
            first = self._shape_first
            if first is not None and CHECKS.index(first) <= CHECKS.index(code):
                return first == code
            return False
        return failing

    def versions(self) -> list[Version]:
        parsed = self._parse_statements()
        if self._shape_first is not None:
            raise Malformed("a statement is malformed")
        return parsed

    def chain_check(self, code: str) -> Callable[[], bool]:
        def failing() -> bool:
            if self._chain is None:
                self._chain = (chain_failure(self.versions(), self.head),)
            return self._chain[0] == code
        return failing

    def active_without_keys(self) -> bool:
        return any(v.status == "active" and not v.keys for v in self.versions())

    def effective_after_issued(self) -> bool:
        return any(v.effective > v.issued for v in self.versions())

    def agent_mismatch(self) -> bool:
        return any(v.agent != self.agent for v in self.versions())

    def decision_malformed(self) -> bool:
        self.decision = _decision(_read(self.directory, "decision.json"))
        return False

    def _decided(self) -> tuple[datetime, str, Envelope]:
        if self.decision is None:
            raise Malformed("no decision has been read")
        return self.decision

    def _known_keys(self) -> dict[str, bytes]:
        return {key_id(public_key(k)): public_key(k) for v in self.versions() for k in v.keys}

    def key_unknown(self) -> bool:
        return self._decided()[1] not in self._known_keys()

    def decision_signature(self) -> bool:
        _, keyid, env = self._decided()
        return signed_by([self._known_keys()[keyid]], env) is None

    def _standing(self) -> Version | None:
        return in_force(self.versions(), self._decided()[0])

    def before_history(self) -> bool:
        return self._standing() is None

    def _standing_status(self, status: str) -> bool:
        current = self._standing()
        return current is not None and current.status == status

    def key_not_in_force(self) -> bool:
        current = self._standing()
        if current is None:
            raise Malformed("no version in force")
        return self._decided()[1] not in {key_id(public_key(k)) for k in current.keys}

    def checks(self) -> list[tuple[str, Callable[[], bool]]]:
        by_name: dict[str, Callable[[], bool]] = {
            "history_malformed": self.malformed,
            "statement_signature": self.bad_signature,
            "active_without_keys": self.active_without_keys,
            "effective_after_issued": self.effective_after_issued,
            "agent_mismatch": self.agent_mismatch,
            "decision_malformed": self.decision_malformed,
            "key_unknown": self.key_unknown,
            "decision_signature": self.decision_signature,
            "decision_before_history": self.before_history,
            "agent_suspended": lambda: self._standing_status("suspended"),
            "agent_revoked": lambda: self._standing_status("revoked"),
            "key_not_in_force": self.key_not_in_force,
        }
        for code in CHECKS[2:7]:
            by_name[code] = self.statement_check(code)
        for code in CHECKS[10:18]:
            by_name[code] = self.chain_check(code)
        return [(code, by_name[code]) for code in CHECKS]


def _checks(directory: Path) -> list[tuple[str, Callable[[], bool]]]:
    return _Member(directory).checks()


def verify(directory: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one member.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    try:
        checks = _checks(directory)
    except (Malformed, KeyError, TypeError, ValueError):
        return {"decision": REJECT, "reason": CHECKS[0]}
    for name, failing in checks:
        if name in skip:
            continue
        try:
            failed = failing()
        except (Malformed, KeyError, TypeError, IndexError, ValueError, AssertionError):
            failed = True
        if failed:
            return {"decision": REJECT, "reason": name}
    return {"decision": ACCEPT, "reason": PASS_REASON}


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------


def _manifest_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(sha256_hex((directory / n).read_bytes()) != d for n, d in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = strictjson.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if sha256_hex(_manifest_json(entries)) != manifest["corpusDigest"]:
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


def _external_answer(command: list[str], directory: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, SUITE, str(directory), "--json"],
                                capture_output=True, text=True, timeout=90, check=False)
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


def check(verifier: str | list[str] | None = None, root: Path | None = None,
          skip: frozenset[str] = frozenset()) -> tuple[int, list[str]]:
    """Check every member, through the named verifier or the reference reader.

    Returns the number of members answered and every disagreement.
    """
    base = ROOT if root is None else root
    try:
        entries, manifest_error = _validated_entries(base)
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
        name, directory = entry["id"], base / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(directory, skip)
        else:
            ran, observed = _external_answer(command, directory)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """The run function the package's harness calls for this suite."""
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
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("suite", choices=(SUITE,))
    parser.add_argument("case", nargs="?", help="judge one case directory")
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
