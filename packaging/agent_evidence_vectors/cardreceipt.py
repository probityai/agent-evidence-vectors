"""Judge agent-card receipts and the credential releases made on them.

Two suites share this reader, because a credential release is judged against
the receipt it names.

``agent-card-receipt/v1`` (spec/predicates/agent-card-receipt.md). A member is
an A2A Agent Card, an unsigned in-toto Statement carrying a receipt for it, the
issuer's signed revocation list and a context naming the time of the check and
the receipt signer's public key. The reader names the first check that fails:

1. the statement is strict JSON with exactly the four Statement members
   (``statement_malformed``);
2. ``_type`` is in-toto Statement v1 (``statement_type_wrong``);
3. ``predicateType`` is the agent-card-receipt URI (``predicate_type_wrong``);
4. ``subject`` is one member whose digest holds only a lowercase SHA-256
   (``subject_malformed``);
5. the predicate carries exactly its members, each well formed
   (``predicate_malformed``);
6. ``issuedAt`` is before ``validUntil`` (``validity_window_inverted``);
7. the card is an I-JSON object (``card_malformed``);
8. the subject digest is the SHA-256 of RFC 8785 of the card as served, without
   its top-level ``signatures`` (``card_digest_mismatch``);
9. the check time is inside the receipt's validity window
   (``receipt_not_yet_valid``, ``receipt_expired``);
10. a revocation list is present (``revocation_list_absent``), well formed
    (``revocation_list_malformed``), signed by the receipt signer's key
    (``revocation_list_signature``) and current at the check time
    (``revocation_list_stale``);
11. the list does not name the receipt (``receipt_revoked``).

A member that passes every check is ``accept`` with reason ``receipt_current``.

``credential-release/v1`` (spec/predicates/credential-release.md). A member is
the release Statement, the receipt Statement it names, the revocation list it
says it consulted and a context naming the receipt signer's key. Every time is
judged at the release's own ``releasedAt``. Checks 1 to 5 are the release's own
Statement checks, with ``credential_fields`` for a credential member outside the
closed set; then:

6. the receipt's bytes hash to the digest the release names
   (``receipt_digest_mismatch``), are a well formed agent-card receipt
   (``receipt_malformed``), and say what the release copied from them
   (``receipt_fields_differ``);
7. the release's subject is the receipt's subject (``subject_not_receipted``);
8. the receipt's result meets the release's minimum (``receipt_not_passing``);
9. the receipt was current when the credential was released
   (``receipt_not_current``);
10. the credential expires no later than the receipt
    (``credential_outlives_receipt``);
11. the consulted list hashes to the named digest
    (``revocation_list_digest_mismatch``), is well formed, signed by the receipt
    signer and current at ``releasedAt``, and does not name the receipt.

A member that passes is ``accept`` with reason ``release_bound``.

The external-verifier contract: ``<verifier> <suite> <case-dir> --json`` prints
one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``accept`` and 1 for ``reject``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agent_evidence_vectors import a2ajcs

RECEIPT_SUITE = "agent-card-receipt/v1"
RELEASE_SUITE = "credential-release/v1"
SUITES = (RECEIPT_SUITE, RELEASE_SUITE)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
RECEIPT_TYPE = "https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt"
RELEASE_TYPE = "https://w3id.org/agent-evidence/predicate/v1/credential-release"
REVOCATIONS_PAYLOAD_TYPE = "application/vnd.agent-evidence.agent-card-receipt-revocations.v1+json"
RESULTS = ("fail", "degraded", "pass_indirect", "pass")
PASSING = ("pass_indirect", "pass")
ACCEPT, REJECT = "accept", "reject"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
HEX = re.compile(r"[0-9a-f]{64}")
THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")

RECEIPT_CHECKS = (
    "statement_malformed", "statement_type_wrong", "predicate_type_wrong",
    "subject_malformed", "predicate_malformed", "validity_window_inverted",
    "card_malformed", "card_digest_mismatch", "receipt_not_yet_valid", "receipt_expired",
    "revocation_list_absent", "revocation_list_malformed", "revocation_list_signature",
    "revocation_list_stale", "receipt_revoked",
)
RELEASE_CHECKS = (
    "statement_malformed", "statement_type_wrong", "predicate_type_wrong",
    "subject_malformed", "credential_fields", "predicate_malformed",
    "receipt_digest_mismatch", "receipt_malformed", "receipt_fields_differ",
    "subject_not_receipted", "receipt_not_passing", "receipt_not_current",
    "credential_outlives_receipt", "revocation_list_digest_mismatch",
    "revocation_list_malformed", "revocation_list_signature", "revocation_list_stale",
    "receipt_revoked",
)
CHECKS = {RECEIPT_SUITE: RECEIPT_CHECKS, RELEASE_SUITE: RELEASE_CHECKS}
PASS_REASON = {RECEIPT_SUITE: "receipt_current", RELEASE_SUITE: "release_bound"}

_HERE = Path(__file__).resolve().parent
_IN_WHEEL = (_HERE / "corpora").exists()
ROOTS = {
    RECEIPT_SUITE: (_HERE / "corpora" / "vectors-agent-card-receipt" if _IN_WHEEL
                    else _HERE.parents[1] / "vectors-agent-card-receipt"),
    RELEASE_SUITE: (_HERE / "corpora" / "vectors-credential-release" if _IN_WHEEL
                    else _HERE.parents[1] / "vectors-credential-release"),
}
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
    raise ImportError("the reference rail is not importable, so Ed25519 and RFC 8785 "
                      "are unavailable")


def sha256_hex(data: bytes) -> str:
    """Lowercase hexadecimal SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _manifest_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Malformed(f"duplicate member {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise Malformed(f"{name} is not JSON")


def strict_object(data: bytes | None,
                  parse_int: Callable[[str], Any] | None = None) -> dict[str, Any]:
    """Parse strict JSON that must be an object; raise Malformed otherwise."""
    if data is None:
        raise Malformed("absent")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates,
                           parse_constant=_no_constant, parse_int=parse_int)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Malformed(str(exc)) from exc
    if not isinstance(value, dict):
        raise Malformed("not an object")
    return value


def parse_time(text: Any) -> datetime:
    """An RFC 3339 UTC time to whole seconds, ``YYYY-MM-DDTHH:MM:SSZ``."""
    if not isinstance(text, str) or not TIME.fullmatch(text):
        raise Malformed(f"time {text!r}")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise Malformed(str(exc)) from exc


def _require(condition: bool, what: str) -> None:
    if not condition:
        raise Malformed(what)


def _sha_digest(value: Any) -> str:
    _require(isinstance(value, dict) and list(value) == ["sha256"]
             and isinstance(value["sha256"], str) and bool(HEX.fullmatch(value["sha256"])),
             "digest")
    return str(value["sha256"])


def _members(value: Any, required: set[str], optional: frozenset[str] = frozenset()) -> None:
    _require(isinstance(value, dict), "not an object")
    keys = set(value)
    _require(required <= keys and keys <= required | optional, f"members {sorted(keys)}")


def _text(value: Any) -> str:
    _require(isinstance(value, str) and value != "", "empty or not text")
    return str(value)


def _https(value: Any) -> str:
    _require(isinstance(value, str) and value.startswith("https://") and len(value) > 8,
             "not an https URL")
    return str(value)


# ---------------------------------------------------------------------------
# The card digest
# ---------------------------------------------------------------------------

I_JSON_LIMIT = 2**53


def _bounded_int(text: str) -> int:
    value = int(text)
    _require(abs(value) < I_JSON_LIMIT, "integer outside the I-JSON range")
    return value


def card_payload(card_bytes: bytes) -> bytes:
    """RFC 8785 of the card as served, without its top-level ``signatures``.

    These are A2A section 8.4.1 rules 2 and 3, computed by the reader of the
    vendored a2a-jcs-v01 corpus, whose ``card-signing-input`` target is this
    function. Rule 1 (field presence) is not
    applied: it is open in a2aproject/A2A issue 2122, and its readings give
    different bytes for one card.
    """
    card = strict_object(card_bytes, parse_int=_bounded_int)
    try:
        return a2ajcs.signing_input(card)
    except (a2ajcs.Refusal, ValueError) as exc:
        raise Malformed(str(exc)) from exc


def card_digest(card_bytes: bytes) -> str:
    """The subject digest a receipt for this card carries."""
    return sha256_hex(card_payload(card_bytes))


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


def _statement(statement: dict[str, Any], predicate_type: str) -> str | None:
    """The first Statement-level check that fails, or None."""
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        return "statement_malformed"
    if statement["_type"] != STATEMENT_TYPE:
        return "statement_type_wrong"
    if statement["predicateType"] != predicate_type:
        return "predicate_type_wrong"
    subject = statement["subject"]
    try:
        _require(isinstance(subject, list) and len(subject) == 1, "one subject")
        _members(subject[0], {"name", "digest"})
        _text(subject[0]["name"])
        _sha_digest(subject[0]["digest"])
    except Malformed:
        return "subject_malformed"
    return None


def _thumbprints(value: Any) -> None:
    _require(isinstance(value, list) and value != [], "thumbprints")
    _require(all(isinstance(v, str) and THUMBPRINT.fullmatch(v) for v in value), "thumbprint")
    _require(value == sorted(set(value)), "thumbprints sorted and unique")


def receipt_predicate(predicate: Any) -> None:
    """Raise Malformed unless ``predicate`` is a well formed receipt predicate."""
    _members(predicate, {"run", "result", "registryDigest", "issuedAt", "validUntil",
                         "revocationList"}, frozenset({"agentKeyThumbprints"}))
    _members(predicate["run"], {"predicateType", "digest"})
    _https(predicate["run"]["predicateType"])
    _sha_digest(predicate["run"]["digest"])
    _require(predicate["result"] in RESULTS, "result")
    _sha_digest(predicate["registryDigest"])
    parse_time(predicate["issuedAt"])
    parse_time(predicate["validUntil"])
    _https(predicate["revocationList"])
    if "agentKeyThumbprints" in predicate:
        _thumbprints(predicate["agentKeyThumbprints"])


CREDENTIAL_MEMBERS = {"kind", "audience", "scope"}


def _credential(value: Any) -> None:
    _members(value, CREDENTIAL_MEMBERS)
    _text(value["kind"])
    _https(value["audience"])
    scope = value["scope"]
    _require(isinstance(scope, list) and scope != [], "scope")
    _require(all(isinstance(s, str) and s != "" for s in scope), "scope entry")
    _require(scope == sorted(set(scope)), "scope sorted and unique")


def release_predicate(predicate: Any) -> None:
    """Raise Malformed unless ``predicate`` is a well formed release predicate."""
    _members(predicate, {"releaseId", "releasedAt", "ttlSeconds", "receipt", "minResult",
                         "revocationList", "credential", "broker", "registryDigest"})
    _text(predicate["releaseId"])
    parse_time(predicate["releasedAt"])
    ttl = predicate["ttlSeconds"]
    _require(isinstance(ttl, int) and not isinstance(ttl, bool) and 0 < ttl < 2**31, "ttl")
    receipt = predicate["receipt"]
    _members(receipt, {"predicateType", "digest", "result", "validUntil"})
    _require(receipt["predicateType"] == RECEIPT_TYPE, "receipt type")
    _sha_digest(receipt["digest"])
    _require(receipt["result"] in RESULTS, "receipt result")
    parse_time(receipt["validUntil"])
    _require(predicate["minResult"] in PASSING, "minResult")
    _members(predicate["revocationList"], {"digest"})
    _sha_digest(predicate["revocationList"]["digest"])
    _credential(predicate["credential"])
    _members(predicate["broker"], {"id"})
    _https(predicate["broker"]["id"])
    _sha_digest(predicate["registryDigest"])


def _credential_fields(predicate: Any) -> bool:
    """True when the credential object has a member outside the closed set."""
    credential = predicate.get("credential") if isinstance(predicate, dict) else None
    return isinstance(credential, dict) and not set(credential) <= CREDENTIAL_MEMBERS


# ---------------------------------------------------------------------------
# The revocation list
# ---------------------------------------------------------------------------


def _b64(text: Any) -> bytes:
    _require(isinstance(text, str), "base64 text")
    try:
        return base64.b64decode(str(text), validate=True)
    except ValueError as exc:
        raise Malformed("base64") from exc


def revocation_payload(envelope_bytes: bytes) -> tuple[dict[str, Any], bytes, list[bytes]]:
    """Parse a revocation list envelope: (list, payload bytes, signatures)."""
    envelope = strict_object(envelope_bytes)
    _members(envelope, {"payloadType", "payload", "signatures"})
    _require(envelope["payloadType"] == REVOCATIONS_PAYLOAD_TYPE, "payloadType")
    payload = _b64(envelope["payload"])
    signatures = envelope["signatures"]
    _require(isinstance(signatures, list) and signatures != [], "signatures")
    sigs = []
    for item in signatures:
        _members(item, {"sig"}, frozenset({"keyid"}))
        sigs.append(_b64(item["sig"]))
    listing = strict_object(payload)
    _members(listing, {"issuedAt", "nextUpdate", "revoked"})
    _require(parse_time(listing["issuedAt"]) < parse_time(listing["nextUpdate"]), "window")
    revoked = listing["revoked"]
    _require(isinstance(revoked, list), "revoked")
    _require(all(isinstance(r, str) and HEX.fullmatch(r) for r in revoked), "revoked entry")
    _require(revoked == sorted(set(revoked)), "revoked sorted and unique")
    return listing, payload, sigs


def _signed_by(key: bytes, payload: bytes, sigs: list[bytes]) -> bool:
    rail = _rail()
    message = rail.pae(REVOCATIONS_PAYLOAD_TYPE, payload)
    return any(rail.ed25519_verify(key, message, sig) for sig in sigs)


def revocation_failure(envelope_bytes: bytes | None, key: bytes, at: datetime,
                       receipt_digest: str) -> str | None:
    """The first revocation-list check that fails, judged at ``at``."""
    if envelope_bytes is None:
        return "revocation_list_absent"
    try:
        listing, payload, sigs = revocation_payload(envelope_bytes)
    except Malformed:
        return "revocation_list_malformed"
    if not _signed_by(key, payload, sigs):
        return "revocation_list_signature"
    if not parse_time(listing["issuedAt"]) <= at < parse_time(listing["nextUpdate"]):
        return "revocation_list_stale"
    if receipt_digest in listing["revoked"]:
        return "receipt_revoked"
    return None


# ---------------------------------------------------------------------------
# Judging one member
# ---------------------------------------------------------------------------


def _read(directory: Path, name: str) -> bytes | None:
    path = directory / name
    return path.read_bytes() if path.is_file() else None


def _context(directory: Path) -> tuple[dict[str, Any], bytes]:
    context = strict_object(_read(directory, "context.json"))
    return context, _b64(context["issuerKey"])


def _receipt_failure(statement_bytes: bytes | None) -> tuple[str | None, dict[str, Any]]:
    """Statement and predicate checks of a receipt: (first failure, statement)."""
    try:
        statement = strict_object(statement_bytes)
    except Malformed:
        return "statement_malformed", {}
    failure = _statement(statement, RECEIPT_TYPE)
    if failure:
        return failure, statement
    try:
        receipt_predicate(statement["predicate"])
    except Malformed:
        return "predicate_malformed", statement
    return None, statement


def _time_or_none(predicate: Any, name: str) -> datetime | None:
    try:
        return parse_time(predicate[name])
    except (Malformed, KeyError, TypeError):
        return None


def _card_digest_or_none(raw: bytes | None) -> str | None:
    try:
        return card_digest(raw if raw is not None else b"")
    except Malformed:
        return None


def _receipt_checks(directory: Path) -> list[tuple[str, Callable[[], bool]]]:
    statement_bytes = _read(directory, "statement.json")
    failure, statement = _receipt_failure(statement_bytes)
    context, key = _context(directory)
    now = parse_time(context["now"])
    predicate: Any = statement.get("predicate")
    start, until = _time_or_none(predicate, "issuedAt"), _time_or_none(predicate, "validUntil")
    digest = _card_digest_or_none(_read(directory, "card.json"))
    revocation = revocation_failure(_read(directory, "revocations.json"), key, now,
                                    sha256_hex(statement_bytes or b""))
    early = [(name, (lambda name=name: failure == name)) for name in RECEIPT_CHECKS[:5]]
    return [
        *early,
        ("validity_window_inverted", lambda: start >= until),  # type: ignore[operator]
        ("card_malformed", lambda: digest is None),
        ("card_digest_mismatch",
         lambda: statement["subject"][0]["digest"]["sha256"] != digest),
        ("receipt_not_yet_valid", lambda: now < start),  # type: ignore[operator]
        ("receipt_expired", lambda: now >= until),  # type: ignore[operator]
        *[(code, (lambda code=code: revocation == code)) for code in RECEIPT_CHECKS[10:]],
    ]


def _release_statement_failure(raw: bytes | None) -> tuple[str | None, dict[str, Any]]:
    try:
        statement = strict_object(raw)
    except Malformed:
        return "statement_malformed", {}
    failure = _statement(statement, RELEASE_TYPE)
    if failure:
        return failure, statement
    if _credential_fields(statement["predicate"]):
        return "credential_fields", statement
    try:
        release_predicate(statement["predicate"])
    except Malformed:
        return "predicate_malformed", statement
    return None, statement


def _copied_differs(declared: dict[str, Any], receipt: dict[str, Any]) -> bool:
    predicate = receipt["predicate"]
    return bool(declared["result"] != predicate["result"]
                or declared["validUntil"] != predicate["validUntil"])


def _release_revocation(directory: Path, predicate: Any, key: bytes,
                        receipt_bytes: bytes) -> str | None:
    raw = _read(directory, "revocations.json")
    try:
        named = predicate["revocationList"]["digest"]["sha256"]
        at = parse_time(predicate["releasedAt"])
    except (Malformed, KeyError, TypeError):
        return "revocation_list_digest_mismatch"
    if raw is None or sha256_hex(raw) != named:
        return "revocation_list_digest_mismatch"
    return revocation_failure(raw, key, at, sha256_hex(receipt_bytes))


def _expiry(predicate: Any) -> datetime | None:
    at = _time_or_none(predicate, "releasedAt")
    try:
        return None if at is None else at + timedelta(seconds=int(predicate["ttlSeconds"]))
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _release_checks(directory: Path) -> list[tuple[str, Callable[[], bool]]]:
    failure, statement = _release_statement_failure(_read(directory, "statement.json"))
    receipt_bytes = _read(directory, "receipt.json") or b""
    receipt_failure, receipt = _receipt_failure(receipt_bytes)
    _, key = _context(directory)
    predicate: Any = statement.get("predicate")
    at, expiry = _time_or_none(predicate, "releasedAt"), _expiry(predicate)
    held = receipt.get("predicate")
    start, until = _time_or_none(held, "issuedAt"), _time_or_none(held, "validUntil")
    revocation = _release_revocation(directory, predicate, key, receipt_bytes)
    early = [(name, (lambda name=name: failure == name)) for name in RELEASE_CHECKS[:6]]
    return [
        *early,
        ("receipt_digest_mismatch",
         lambda: sha256_hex(receipt_bytes) != predicate["receipt"]["digest"]["sha256"]),
        ("receipt_malformed", lambda: receipt_failure is not None),
        ("receipt_fields_differ", lambda: _copied_differs(predicate["receipt"], receipt)),
        ("subject_not_receipted",
         lambda: statement["subject"][0]["digest"] != receipt["subject"][0]["digest"]),
        ("receipt_not_passing", lambda: RESULTS.index(predicate["receipt"]["result"])
         < RESULTS.index(predicate["minResult"])),
        ("receipt_not_current",
         lambda: not start <= at < until),  # type: ignore[operator]
        ("credential_outlives_receipt", lambda: expiry > until),  # type: ignore[operator]
        *[(code, (lambda code=code: revocation == code)) for code in RELEASE_CHECKS[13:]],
    ]


def verify(suite: str, directory: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one member.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    checks = _receipt_checks(directory) if suite == RECEIPT_SUITE else _release_checks(directory)
    for name, failing in checks:
        if name in skip:
            continue
        try:
            failed = failing()
        except (Malformed, KeyError, TypeError, IndexError, ValueError):
            failed = True
        if failed:
            return {"decision": REJECT, "reason": name}
    return {"decision": ACCEPT, "reason": PASS_REASON[suite]}


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(sha256_hex((directory / n).read_bytes()) != d for n, d in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(suite: str, root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if sha256_hex(_manifest_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != suite:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], suite: str,
                     directory: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, suite, str(directory), "--json"],
                                capture_output=True, text=True, timeout=90, check=False)
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


def check(suite: str, verifier: str | list[str] | None = None, root: Path | None = None,
          skip: frozenset[str] = frozenset()) -> tuple[int, list[str]]:
    """Check every member, through the named verifier or the reference reader.

    Returns the number of members answered and every disagreement.
    """
    base = ROOTS[suite] if root is None else root
    try:
        entries, manifest_error = _validated_entries(suite, base)
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
            ran, observed = True, verify(suite, directory, skip)
        else:
            ran, observed = _external_answer(command, suite, directory)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def runner(suite: str) -> Callable[[str, list[str] | None, str, str], int]:
    """The run function the package's harness calls for ``suite``."""
    def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
        directory = Path(root)
        answered, errors = check(suite, verifier, directory)
        try:
            manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
            total = len(manifest["vectors"])
        except (OSError, ValueError, KeyError, TypeError):
            manifest, total = {}, 0
        for error in errors:
            print(error)
        rail = "reference reader" if verifier is None else shlex.join(verifier)
        print(f"{suite}: {rail} answered {answered} of {total} cases, "
              f"{len(errors)} disagreements")
        if not answered or not total:
            print("no report written: no case was answered")
            return 2
        report = {
            "suite": suite, "rail": "own-reader" if verifier is None else "external",
            "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
            "corpusDigest": manifest["corpusDigest"],
            "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                       "suiteRefusals": 0},
            "failures": errors,
        }
        Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")
        return 1 if errors or answered != total else 0
    return run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("suite", choices=SUITES)
    parser.add_argument("case", nargs="?", help="judge one case directory")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(args.suite, Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.suite, args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOTS[args.suite] / "MANIFEST.json").read_text(
        encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
