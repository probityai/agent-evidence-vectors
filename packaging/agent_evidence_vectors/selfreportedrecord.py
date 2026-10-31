"""Judge vectors-self-reported-record/, the corpus for spec/self-reported-record/v1.md.

Each member is one in-toto statement carrying a record an agent runtime keeps
about itself. The reader applies the contract's six rules to every member and
requires the verdict and the codes to be the ones MANIFEST.json declares:

1. ``rule_wellformed``: the record can be read at all (``record-malformed``);
2. ``rule_turn_attestation``: every turn is signed by the attesting key
   (``turn-unsigned-by-attesting-key``);
3. ``rule_memory_digest_over_named_path``: a memory digest is the digest of the
   bytes at the path (``memory-digest-not-over-named-path``);
4. ``rule_attesting_key_disjoint``: the attesting key is not one the record puts
   inside the runtime (``attesting-key-in-self-signers``);
5. ``rule_ledgers_agree``: every ledger names the same change set
   (``ledger-members-disagree``);
6. ``rule_field_coverage``: a field claiming substrate coverage carries the
   covering signature (``field-claims-coverage-uncovered``).

Well-formedness is stage one and byte-pure; the five rules after it read members
for meaning and run only once it passes. Every rule that refuses a record is
reported, not only the first, so a reject member that trips two rules is named.

This is the Python rail for the reader in ``corpora/selfreported.go`` and prints
the lines ``aee-verify`` prints, so the two rails can be diffed. The rules are
restated here rather than imported from the corpus's own ``check_vectors.py``:
that file is a repository tool that needs ``cryptography``, and this module runs
from an installed wheel on the standard library alone. Where the Go reader and
``check_vectors.py`` differ on a record, this module answers as the Go reader
does, because the Go reader is the one the other packaged rail is diffed against.

Ed25519 and the RFC 8785 member order are borrowed from the reference rail's
standard-library implementation. A float anywhere in a signed preimage is
refused rather than spelled, as the Go encoder refuses it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUITE = "self-reported-record-conformance"

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/self-reported-record"
)
TURN_CONTEXT = "agent-evidence/self-reported-record/v1/turn"
FIELD_CONTEXT = "agent-evidence/self-reported-record/v1/field"

_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-self-reported-record"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "vectors-self-reported-record"
)

# Go's regexp ``$`` matches only at the end of the text, where Python's also
# matches before a final newline, and Go's ``\d`` is ASCII only. fullmatch with
# explicit classes keeps both readings identical.
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX_DIGITS = re.compile(r"(?:[0-9a-fA-F]{2})*")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

# The closed vocabularies, each a registered term in agent-evidence-vocabulary.
VOCABULARIES = {
    "originKind": ("self", "third-party-control-plane", "log-import"),
    "attestationTier": ("voluntary", "authoritative"),
    "observationVantage": ("substrate", "artifact"),
    "observationDirectness": ("intercepted", "reconstructed"),
}
FIELD_EVIDENCE = ("substrate_covered", "producer_asserted")

REQUIRED = (
    "recordId",
    "sessionId",
    "hashAlgorithm",
    "originKind",
    "attestationTier",
    "observationVantage",
    "observationDirectness",
    "attestingKey",
    "selfSigners",
    "turns",
    "memoryReads",
    "ledgers",
    "fields",
    "doesNotAssert",
    "issuedAt",
)

# In the order a verifier applies them.
RULES = (
    "rule_wellformed",
    "rule_turn_attestation",
    "rule_memory_digest_over_named_path",
    "rule_attesting_key_disjoint",
    "rule_ledgers_agree",
    "rule_field_coverage",
)

CODE_OF_RULE = {
    "rule_wellformed": "record-malformed",
    "rule_turn_attestation": "turn-unsigned-by-attesting-key",
    "rule_memory_digest_over_named_path": "memory-digest-not-over-named-path",
    "rule_attesting_key_disjoint": "attesting-key-in-self-signers",
    "rule_ledgers_agree": "ledger-members-disagree",
    "rule_field_coverage": "field-claims-coverage-uncovered",
}

_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify",)


class CorpusUnreadable(ValueError):
    """The corpus could not be read at all, which is exit 2 and never a finding."""


def _rail() -> Any:
    """The reference rail, resolved at call time: it imports this module to
    dispatch the suite, so a module-level import would be a cycle. The rule is
    the one ``receiptsignature`` documents."""
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
    raise ImportError(
        f"the reference rail is importable as neither {_RAIL_NAMES[0]} nor "
        f"{_RAIL_NAMES[1]}, so the Ed25519 verification this module borrows from it "
        "is unavailable"
    )


# --------------------------------------------------------------------------
# Reading a member the way the Go reader reads it
# --------------------------------------------------------------------------


class _Number:
    """A JSON number kept as the token it was written with.

    The Go reader decodes with ``json.Number``, so an integer is never a float,
    a float is never an integer, and neither is a string. Python's ``int`` also
    refuses a token past about four thousand digits, which Go reads without
    complaint. This is not a ``str`` subclass for the same reason: every
    ``isinstance(value, str)`` below must be false for a number.
    """

    __slots__ = ("is_float", "text")

    def __init__(self, text: str, is_float: bool) -> None:
        self.text = text
        self.is_float = is_float


def _int_token(text: str) -> _Number:
    return _Number(text, False)


def _float_token(text: str) -> _Number:
    return _Number(text, True)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid character in literal {name}")


def _scrub(value: Any) -> Any:
    """Replace each unpaired surrogate with U+FFFD, as Go's decoder does.

    Python keeps a lone ``\\ud800`` escape as a lone surrogate, which no later
    comparison can tell from a legitimately written one and which cannot be
    encoded. Go reads it as the replacement character, and so do the preimages
    this module builds.
    """
    if isinstance(value, str):
        return _LONE_SURROGATE.sub("�", value)
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, dict):
        return {_scrub(key): _scrub(item) for key, item in value.items()}
    return value


def decode_member(raw: bytes) -> Any:
    """The one JSON document in *raw*, numbers kept as tokens.

    *raw* must be UTF-8 and exactly one document: bytes after it, other than JSON
    whitespace, or a byte that is not UTF-8, are refused, because two files that
    differ only there would carry one statement under two digests. NaN and the
    infinities are refused too, which JSON has no spelling for.
    """
    text = raw.decode("utf-8").lstrip(" \t\n\r")
    decoder = json.JSONDecoder(
        parse_int=_int_token, parse_float=_float_token, parse_constant=_reject_constant
    )
    value, end = decoder.raw_decode(text)
    if text[end:].strip(" \t\n\r"):
        raise ValueError("extra data after the statement")
    return _scrub(value)


class _Refused(ValueError):
    """A value the canonical form below will not spell."""


def _utf16_key(name: str) -> bytes:
    return name.encode("utf-16-be")


def _canonical(value: Any) -> str:
    """RFC 8785 text for the value space this contract uses.

    Member names sort by UTF-16 code unit. A float is refused, as the Go encoder
    refuses it: CPython and Go spell some floats differently, and a guess here
    would be a silent wrong digest.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, _Number):
        if value.is_float:
            raise _Refused(f"{value.text} is a JSON float")
        # "-0" is the one integer token whose value has a different spelling.
        return "0" if value.text == "-0" else value.text
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        names = sorted(value, key=_utf16_key)
        return (
            "{"
            + ",".join(
                json.dumps(name, ensure_ascii=False) + ":" + _canonical(value[name])
                for name in names
            )
            + "}"
        )
    raise _Refused(f"unsupported type {type(value).__name__}")


def _preimage(members: dict[str, Any]) -> bytes | None:
    try:
        return _canonical(members).encode("utf-8")
    except _Refused:
        return None


# --------------------------------------------------------------------------
# Small helpers, named as the Go reader names them
# --------------------------------------------------------------------------


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _array(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def ed25519_ok(public_hex: str, payload: bytes, signature_b64: str) -> bool:
    """Verify, refusing rather than raising on anything the carried bytes get wrong.

    Hex is read as Go reads it (even length, either case, no spaces). The signature
    is standard base64 with padding and no line breaks; ``rule_wellformed`` refuses
    a record that spells one otherwise before any signature is checked.
    """
    if _HEX_DIGITS.fullmatch(public_hex) is None:
        return False
    public = bytes.fromhex(public_hex)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    return bool(_rail().ed25519_verify(public, payload, signature))


# --------------------------------------------------------------------------
# The six rules
# --------------------------------------------------------------------------


def _subject_wellformed(value: Any) -> bool:
    subject = _array(value)
    if len(subject) != 1:
        return False
    entry = _object(subject[0])
    if not isinstance(entry.get("name"), str):
        return False
    return _is_hex64(_object(entry.get("digest")).get("sha256"))


_SIGNATURE_ALPHABET = re.compile(r"[A-Za-z0-9+/=]*")
_CONTAINERS = ("selfSigners", "turns", "memoryReads", "ledgers", "fields")


def _signature_spelled(signature: str) -> bool:
    """A signature is standard base64 characters only: no line break, no space."""
    return _SIGNATURE_ALPHABET.fullmatch(signature) is not None


def _containers_ok(predicate: dict[str, Any]) -> bool:
    """Each repeated member is a JSON array; a string, number, object or null is not one."""
    return all(isinstance(predicate[name], list) for name in _CONTAINERS)


def _turns_wellformed(predicate: dict[str, Any]) -> bool:
    for item in _array(predicate["turns"]):
        row = _object(item)
        attested = _object(row.get("attestedBy"))
        if not isinstance(row.get("turnId"), str):
            return False
        signature = attested.get("sig")
        if not _is_hex64(attested.get("keyid")) or not isinstance(signature, str):
            return False
        if not _signature_spelled(signature):
            return False
        if not isinstance(row.get("changeIds"), list):
            return False
    return True


def _memory_wellformed(predicate: dict[str, Any]) -> bool:
    for item in _array(predicate["memoryReads"]):
        row = _object(item)
        if not isinstance(row.get("path"), str):
            return False
        if not _is_hex64(row.get("assertedDigest")) or not _is_hex64(row.get("pathDigest")):
            return False
    return True


def _ledgers_wellformed(predicate: dict[str, Any]) -> bool:
    for item in _array(predicate["ledgers"]):
        row = _object(item)
        if not isinstance(row.get("name"), str) or not isinstance(row.get("members"), list):
            return False
    return True


def _fields_wellformed(predicate: dict[str, Any]) -> bool:
    for item in _array(predicate["fields"]):
        row = _object(item)
        if not isinstance(row.get("name"), str) or not isinstance(row.get("value"), str):
            return False
        if _str(row.get("evidence")) not in FIELD_EVIDENCE:
            return False
        covering = _object(row.get("coveredBy")).get("sig")
        if isinstance(covering, str) and not _signature_spelled(covering):
            return False
    return True


def _scalars_wellformed(predicate: dict[str, Any]) -> bool:
    for member, allowed in VOCABULARIES.items():
        if _str(predicate[member]) not in allowed:
            return False
    if _str(predicate["hashAlgorithm"]) != "sha256":
        return False
    key = _object(predicate["attestingKey"])
    if not _is_hex64(key.get("keyid")) or not _is_hex64(key.get("publicKey")):
        return False
    if not all(_is_hex64(keyid) for keyid in _array(predicate["selfSigners"])):
        return False
    if len(_array(predicate["ledgers"])) < 2:
        return False
    return _RFC3339_UTC.fullmatch(_str(predicate["issuedAt"])) is not None


def rule_wellformed(statement: dict[str, Any]) -> bool:
    """Stage one: the record can be read at all, under the shape it declares."""
    if _str(statement.get("_type")) != STATEMENT_TYPE:
        return False
    if _str(statement.get("predicateType")) != PREDICATE_TYPE:
        return False
    if not _subject_wellformed(statement.get("subject")):
        return False
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False
    if any(member not in predicate for member in REQUIRED):
        return False
    return (
        _containers_ok(predicate)
        and _scalars_wellformed(predicate)
        and _turns_wellformed(predicate)
        and _memory_wellformed(predicate)
        and _ledgers_wellformed(predicate)
        and _fields_wellformed(predicate)
    )


def rule_turn_attestation(predicate: dict[str, Any]) -> bool:
    """srr-c-1: every turn is signed by the key the record names."""
    public = _str(_object(predicate["attestingKey"]).get("publicKey"))
    for item in _array(predicate["turns"]):
        row = _object(item)
        payload = _preimage(
            {
                "changeIds": row.get("changeIds"),
                "context": TURN_CONTEXT,
                "goalMarker": row.get("goalMarker"),
                "priorTurn": row.get("priorTurn"),
                "sessionId": predicate["sessionId"],
                "turnId": row.get("turnId"),
            }
        )
        signature = _str(_object(row.get("attestedBy")).get("sig"))
        if payload is None or not ed25519_ok(public, payload, signature):
            return False
    return True


def rule_memory_digest_over_named_path(predicate: dict[str, Any]) -> bool:
    """srr-c-2: the digest reported is the digest of the bytes at the path."""
    for item in _array(predicate["memoryReads"]):
        row = _object(item)
        if _str(row.get("assertedDigest")) != _str(row.get("pathDigest")):
            return False
    return True


def rule_attesting_key_disjoint(predicate: dict[str, Any]) -> bool:
    """srr-c-3: the attesting key is not one the record says the runtime holds."""
    keyid = _str(_object(predicate["attestingKey"]).get("keyid"))
    return all(_str(signer) != keyid for signer in _array(predicate["selfSigners"]))


def rule_ledgers_agree(predicate: dict[str, Any]) -> bool:
    """srr-c-4: every ledger names the same change set."""
    first: list[str] | None = None
    for item in _array(predicate["ledgers"]):
        members = sorted({_str(member) for member in _array(_object(item).get("members"))})
        if first is None:
            first = members
        elif members != first:
            return False
    return True


def _field_covered(row: dict[str, Any], predicate: dict[str, Any], self_signers: set[str]) -> bool:
    key = _object(row.get("coveredBy"))
    if not key or _str(key.get("keyid")) in self_signers:
        return False
    payload = _preimage(
        {
            "context": FIELD_CONTEXT,
            "name": row.get("name"),
            "recordId": predicate["recordId"],
            "value": row.get("value"),
        }
    )
    if payload is None:
        return False
    return ed25519_ok(_str(key.get("publicKey")), payload, _str(key.get("sig")))


def rule_field_coverage(predicate: dict[str, Any]) -> bool:
    """srr-c-5: a field claiming substrate coverage carries the covering signature.

    A field declaring ``producer_asserted`` must carry no ``coveredBy`` at all,
    and a ``coveredBy`` that is present but null counts as carried, as in the Go
    reader.
    """
    self_signers = {_str(signer) for signer in _array(predicate["selfSigners"])}
    for item in _array(predicate["fields"]):
        row = _object(item)
        if _str(row.get("evidence")) == "producer_asserted":
            if "coveredBy" in row:
                return False
            continue
        if not _field_covered(row, predicate, self_signers):
            return False
    return True


_CHECKS = {
    "rule_turn_attestation": rule_turn_attestation,
    "rule_memory_digest_over_named_path": rule_memory_digest_over_named_path,
    "rule_attesting_key_disjoint": rule_attesting_key_disjoint,
    "rule_ledgers_agree": rule_ledgers_agree,
    "rule_field_coverage": rule_field_coverage,
}


def firing_rules(statement: dict[str, Any]) -> list[str]:
    """Every rule that refuses this statement, in application order.

    All of them and not the first: a corpus reporting only the first refusal
    cannot tell a member failing one rule from a member failing three. A statement
    that is not well formed is not handed to the five rules below, which read
    members for meaning that a malformed record does not have.
    """
    if not rule_wellformed(statement):
        return ["rule_wellformed"]
    predicate = _object(statement.get("predicate"))
    return [name for name in RULES[1:] if not _CHECKS[name](predicate)]


def verdict_of(firing: list[str]) -> tuple[str, list[str]]:
    """The verdict and the codes a verifier reaches over these bytes."""
    if not firing:
        return "valid", []
    codes = [CODE_OF_RULE[name] for name in firing]
    if firing == ["rule_wellformed"]:
        return "malformed", codes
    return "invalid", codes


# --------------------------------------------------------------------------
# The corpus judged against its own manifest
# --------------------------------------------------------------------------


@dataclass
class Judged:
    """One pass of this reader over the corpus: per-member findings and the corpus's own."""

    members: list[tuple[str, str, list[str]]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not self.findings and all(not found for _, _, found in self.members)


def _go_quote(text: str) -> str:
    """Go's ``%q`` for a string."""
    escapes = {
        "\\": "\\\\",
        '"': '\\"',
        "\a": "\\a",
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "\v": "\\v",
    }
    out = []
    for char in text:
        if char in escapes:
            out.append(escapes[char])
        elif char.isprintable():
            out.append(char)
        elif ord(char) < 0x80:
            out.append(f"\\x{ord(char):02x}")
        elif ord(char) <= 0xFFFF:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(f"\\U{ord(char):08x}")
    return '"' + "".join(out) + '"'


def _go_list(items: list[str]) -> str:
    return "[" + " ".join(items) + "]"


def _typed(value: Any, kind: type, default: Any, where: str) -> Any:
    """A manifest member of the type Go's decoder would put it in, or CorpusUnreadable."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, kind):
        raise CorpusUnreadable(f"{where} is not a {kind.__name__}")
    return value


def _string_map(value: Any, where: str) -> dict[str, str]:
    mapping = _typed(value, dict, {}, where)
    return {name: _typed(item, str, "", where) for name, item in mapping.items()}


def _string_list(value: Any, where: str) -> list[str]:
    return [_typed(item, str, "", where) for item in _typed(value, list, [], where)]


def _vector(entry: Any) -> dict[str, Any]:
    row = _typed(entry, dict, {}, "a vectors entry")
    expected = _typed(row.get("expected"), dict, {}, "expected")
    return {
        "id": _typed(row.get("id"), str, "", "id"),
        "kind": _typed(row.get("kind"), str, "", "kind"),
        "file": _typed(row.get("file"), str, "", "file"),
        "parent": _typed(row.get("parent"), str, "", "parent"),
        "conditions": _string_list(row.get("conditions"), "conditions"),
        "verdict": _typed(expected.get("verdict"), str, "", "expected.verdict"),
        "codes": _string_list(expected.get("codes"), "expected.codes"),
    }


def _manifest(directory: str) -> dict[str, Any]:
    path = os.path.join(directory, "MANIFEST.json")
    try:
        with open(path, "rb") as handle:
            decoded = json.loads(handle.read())
    except (OSError, ValueError) as exc:
        raise CorpusUnreadable(f"{path} does not parse: {exc}") from exc
    try:
        top = _typed(decoded, dict, {}, "the manifest")
        counts = _typed(top.get("counts"), dict, {}, "counts")
        for name, number in counts.items():
            _typed(number, int, 0, f"counts.{name}")
        return {
            "contract": _typed(top.get("contract"), str, "", "contract"),
            "contractDigest": _typed(top.get("contractDigest"), str, "", "contractDigest"),
            "conditions": _string_map(top.get("conditions"), "conditions"),
            "counts": {name: int(number or 0) for name, number in counts.items()},
            "corpusDigest": _typed(top.get("corpusDigest"), str, "", "corpusDigest"),
            "vectors": [
                _vector(entry) for entry in _typed(top.get("vectors"), list, [], "vectors")
            ],
        }
    except CorpusUnreadable as exc:
        raise CorpusUnreadable(f"{path} does not parse: {exc}") from exc


def _read(directory: str, rel: str) -> bytes | None:
    try:
        with open(os.path.normpath(os.path.join(directory, "." + os.sep + rel)), "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _member_findings(
    directory: str, manifest: dict[str, Any], v: dict[str, Any], accepts: set[str]
) -> list[str]:
    found: list[str] = []
    if v["kind"] not in ("accept", "reject"):
        found.append(f"declares kind {_go_quote(v['kind'])}")
    if not v["conditions"]:
        return [*found, "cites no condition"]
    found.extend(
        f"cites condition {name} the manifest does not define"
        for name in v["conditions"]
        if name not in manifest["conditions"]
    )
    if v["kind"] == "reject" and v["parent"] not in accepts:
        found.append("names a parent that is not an accepted member of this corpus")
    body = _read(directory, v["file"])
    if body is None:
        return [*found, "the manifest names a member file that cannot be read"]
    if "v" + hashlib.sha256(body).hexdigest()[:16] != v["id"]:
        found.append("identifier does not recompute from the member's own bytes")
    try:
        statement = decode_member(body)
    except (ValueError, RecursionError) as exc:
        return [*found, f"the member does not parse: {exc}"]
    return found + _contract_findings(_object(statement), v)


def _contract_findings(statement: dict[str, Any], v: dict[str, Any]) -> list[str]:
    """Run the contract. The manifest says what a verifier must decide, and only a
    verifier decides it."""
    firing = firing_rules(statement)
    verdict, codes = verdict_of(firing)
    found = []
    if verdict != v["verdict"]:
        found.append(
            f"declares verdict {v['verdict']} and this rail answers {verdict} "
            f"with codes {_go_list(codes)}"
        )
    if codes != v["codes"]:
        found.append(f"declares codes {_go_list(v['codes'])} and this rail names {_go_list(codes)}")
    if v["kind"] == "accept" and firing:
        found.append(f"is an accept member refused by {_go_list(firing)}")
    elif v["kind"] == "reject" and len(firing) != 1:
        found.append(
            f"is a reject member tripping {_go_list(firing)}. A member failing two rules "
            "cannot tell a reader which one its code refers to."
        )
    return found


def _render_counts(counts: dict[str, int]) -> str:
    return "{" + ", ".join(f"{kind}={counts[kind]}" for kind in sorted(counts)) + "}"


def _counts_disagree(declared: dict[str, int], measured: dict[str, int]) -> bool:
    """The Go reader's comparison: equal length, then each measured kind's count.

    A declared key the members never use passes when the lengths match, which is
    how ``countsDisagree`` reads it, so it is how this module reads it.
    """
    if len(declared) != len(measured):
        return True
    return any(declared.get(kind, 0) != number for kind, number in measured.items())


def _vendored_finding(directory: str, rel: str, pinned: str) -> str | None:
    """The contract sits above the corpus directory, so it resolves against the parent."""
    parent = os.path.dirname(os.path.abspath(directory))
    full = os.path.normpath(os.path.join(parent, "." + os.sep + rel))
    if not os.path.isfile(full):
        return (
            f"the vendored contract {rel} is missing, so nothing records what this "
            "corpus certifies against"
        )
    try:
        with open(full, "rb") as handle:
            body = handle.read()
    except OSError as exc:
        return f"the vendored contract {rel} is unreadable: {exc}"
    got = hashlib.sha256(body).hexdigest()
    if got != pinned:
        return (
            f"the vendored contract {rel} does not match its pinned digest "
            f"(pinned {pinned[:12]}, on disk {got[:12]}). "
            "Re-vendor from upstream instead of editing the copy."
        )
    return None


def _corpus_findings(directory: str, manifest: dict[str, Any]) -> list[str]:
    vectors = manifest["vectors"]
    accepted = {c for v in vectors if v["kind"] == "accept" for c in v["conditions"]}
    rejected = {c for v in vectors if v["kind"] != "accept" for c in v["conditions"]}
    used = accepted | rejected
    found = []
    if orphan := sorted(rejected - accepted):
        found.append(
            f"conditions that reject and never accept: {_go_list(orphan)}. A verifier that "
            "refused every member would score full marks on them."
        )
    if idle := sorted(set(manifest["conditions"]) - used):
        found.append(f"conditions declared and carried by no member: {_go_list(idle)}")
    measured = {"accept": 0, "reject": 0}
    for v in vectors:
        if v["kind"] in measured:
            measured[v["kind"]] += 1
    if _counts_disagree(manifest["counts"], measured):
        found.append(
            f"counts disagree: manifest {_render_counts(manifest['counts'])}, "
            f"measured {_render_counts(measured)}"
        )
    digest = hashlib.sha256()
    for v in sorted(vectors, key=lambda entry: entry["id"]):
        digest.update(_read(directory, v["file"]) or b"")
    if digest.hexdigest() != manifest["corpusDigest"]:
        found.append("corpusDigest does not match the member files on disk")
    if bad := _vendored_finding(directory, manifest["contract"], manifest["contractDigest"]):
        found.append(bad)
    return found


def judge(directory: str | Path = ROOT) -> Judged:
    """Judge the corpus at *directory*: every member, then the claims about the corpus."""
    path = str(directory)
    manifest = _manifest(path)
    vectors = manifest["vectors"]
    accepts = {v["id"] for v in vectors if v["kind"] == "accept"}
    judged = Judged()
    seen: set[str] = set()
    for v in vectors:
        found = ["duplicate identifier"] if v["id"] in seen else []
        seen.add(v["id"])
        found.extend(_member_findings(path, manifest, v, accepts))
        judged.members.append((v["id"], v["kind"], found))
    judged.findings = _corpus_findings(path, manifest)
    return judged


def render(judged: Judged, suite: str = SUITE) -> str:
    """The lines ``aee-verify`` prints from the Go reader."""
    lines = [f"suite: {suite}", f"members: {len(judged.members)}"]
    counts: dict[str, int] = {}
    for _, kind, _ in judged.members:
        counts[kind] = counts.get(kind, 0) + 1
    lines += [f"  {kind}: {counts[kind]}" for kind in sorted(counts)]
    failed = 0
    for member_id, _, found in judged.members:
        failed += bool(found)
        lines += [f"FAIL {member_id}: {finding}" for finding in found]
    lines += [f"FAIL corpus: {finding}" for finding in judged.findings]
    if judged.ok():
        lines.append("verdict: every member behaves as MANIFEST.json declares")
    else:
        lines.append(
            f"verdict: {failed} member(s) and {len(judged.findings)} corpus-level claim(s) "
            "do not hold"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        judged = judge(args[0] if args else ROOT)
    except CorpusUnreadable as exc:
        print(f"aee-verify: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(render(judged))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
