#!/usr/bin/env python3
"""The Python rail for the self-reported-record corpus: a reference verifier for
`spec/self-reported-record/v1.md`, and the corpus's check of itself.

    uv run --extra generators python vectors-self-reported-record/check_vectors.py

Exit 0 when every member behaves as `MANIFEST.json` declares and every
corpus-level claim holds; 1 when one does not and is named.

Three questions, and the second and third are the ones a green corpus cannot
answer about itself.

**Does each member behave as declared?** The verifier runs over the committed
bytes and its verdict is compared with the manifest. `codes` is measured rather
than scored, for the reason the manifest's own comparison surface gives.

**Is the suite scoreable?** Every condition a reject member cites must also be
cited by a member that has to be ACCEPTED. Without that rule a corpus of
refusals gives full marks to a verifier that refuses everything.

**Does each refusal name the rule that caught it?** Every reject member must
trip EXACTLY ONE rule, and every accept member exactly none. A member failing
two rules cannot tell a reader which one its code refers to, which is the
property the whole code column exists for.

The Go rail in `corpusreaders/selfreported.go` restates the same six rules and is run
by `aee-verify vectors-self-reported-record/`. Two rails over one corpus is the
point: a rule both of them get wrong the same way is a rule neither of them
checks, and the only way to find that is to write it twice.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from canonical import decode_strict, jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from digest import corpus_digest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/self-reported-record"
)
TURN_CONTEXT = "agent-evidence/self-reported-record/v1/turn"
FIELD_CONTEXT = "agent-evidence/self-reported-record/v1/field"

# Go's regexp `$` matches only at the end of the text, where Python's also
# matches before a final newline, and Go's `\d` is ASCII only. fullmatch with
# explicit classes keeps both readings identical.
HEX64 = re.compile(r"[0-9a-f]{64}")
RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
HEX_DIGITS = re.compile(r"(?:[0-9a-fA-F]{2})*")
SIGNATURE_ALPHABET = re.compile(r"[A-Za-z0-9+/=]*")
CONTAINERS = ("selfSigners", "turns", "memoryReads", "ledgers", "fields")

# The closed vocabularies, each a registered term in agent-evidence-vocabulary.
# Spelled here as the contract spells them, so a value the registry does not
# carry is refused rather than read.
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

# In the order a verifier applies them. Well-formedness is stage one and
# byte-pure; the five below read members for meaning and only after it passes.
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


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------


def ed25519_ok(public_hex: str, payload: bytes, signature_b64: str) -> bool:
    """Verify, refusing rather than raising on anything the bytes get wrong.

    Hex is read as Go reads it (even length, either case, no spaces); the
    signature is standard base64 with padding and no line break.
    """
    if HEX_DIGITS.fullmatch(public_hex) is None:
        return False
    try:
        public = bytes.fromhex(public_hex)
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, payload)
    except (InvalidSignature, ValueError):
        return False
    return True


# A value of the wrong type reads as empty, so a rule never raises on it and the
# well-formedness rule, which runs first, is what refuses the record.


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _array(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _signature_spelled(signature: str) -> bool:
    """A signature is standard base64 characters only: no line break, no space."""
    return SIGNATURE_ALPHABET.fullmatch(signature) is not None


def _subject_wellformed(value: Any) -> bool:
    subject = _array(value)
    if len(subject) != 1:
        return False
    entry = _object(subject[0])
    if not isinstance(entry.get("name"), str):
        return False
    return _is_hex64(_object(entry.get("digest")).get("sha256"))


def _turns_wellformed(predicate: dict[str, Any]) -> bool:
    for item in _array(predicate["turns"]):
        row = _object(item)
        attested = _object(row.get("attestedBy"))
        signature = attested.get("sig")
        if not isinstance(row.get("turnId"), str):
            return False
        if not _is_hex64(attested.get("keyid")) or not isinstance(signature, str):
            return False
        if not _signature_spelled(signature) or not isinstance(row.get("changeIds"), list):
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
    return RFC3339_UTC.fullmatch(_str(predicate["issuedAt"])) is not None


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
    if not all(isinstance(predicate[name], list) for name in CONTAINERS):
        return False
    return (
        _scalars_wellformed(predicate)
        and _turns_wellformed(predicate)
        and _memory_wellformed(predicate)
        and _ledgers_wellformed(predicate)
        and _fields_wellformed(predicate)
    )


def _preimage(members: dict[str, Any]) -> bytes | None:
    try:
        return jcs(members)
    except TypeError:
        return None


def rule_turn_attestation(statement: dict[str, Any]) -> bool:
    """srr-c-1: every turn is signed by the key the record names."""
    predicate = statement["predicate"]
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


def rule_memory_digest_over_named_path(statement: dict[str, Any]) -> bool:
    """srr-c-2: the digest reported is the digest of the bytes at the path."""
    for item in _array(statement["predicate"]["memoryReads"]):
        row = _object(item)
        if _str(row.get("assertedDigest")) != _str(row.get("pathDigest")):
            return False
    return True


def rule_attesting_key_disjoint(statement: dict[str, Any]) -> bool:
    """srr-c-3: the attesting key is not one the record says the runtime holds."""
    predicate = statement["predicate"]
    keyid = _str(_object(predicate["attestingKey"]).get("keyid"))
    return all(_str(signer) != keyid for signer in _array(predicate["selfSigners"]))


def rule_ledgers_agree(statement: dict[str, Any]) -> bool:
    """srr-c-4: every ledger names the same change set."""
    sets = [
        frozenset(_str(member) for member in _array(_object(item).get("members")))
        for item in _array(statement["predicate"]["ledgers"])
    ]
    return all(members == sets[0] for members in sets)


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


def rule_field_coverage(statement: dict[str, Any]) -> bool:
    """srr-c-5: a field claiming substrate coverage carries the covering signature.

    A field declaring producer_asserted carries no coveredBy at all, and a
    coveredBy that is present but null counts as carried.
    """
    predicate = statement["predicate"]
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


CHECKS = {
    "rule_wellformed": rule_wellformed,
    "rule_turn_attestation": rule_turn_attestation,
    "rule_memory_digest_over_named_path": rule_memory_digest_over_named_path,
    "rule_attesting_key_disjoint": rule_attesting_key_disjoint,
    "rule_ledgers_agree": rule_ledgers_agree,
    "rule_field_coverage": rule_field_coverage,
}


def firing_rules(statement: dict[str, Any], disabled: frozenset[str] = frozenset()) -> list[str]:
    """Every rule that refuses this statement, in application order.

    All of them, not the first: a corpus that reports only the first refusal
    cannot tell a member failing one rule from a member failing three, and the
    second is a member whose published code does not name what caught it.

    A statement that is not well formed is not handed to the five rules below
    it. Those rules read members for meaning and a malformed record has no
    meaning to read, so running them would report a refusal produced by a type
    error rather than by the rule.
    """
    if "rule_wellformed" not in disabled and not rule_wellformed(statement):
        return ["rule_wellformed"]
    return [
        name
        for name in RULES[1:]
        if name not in disabled and not CHECKS[name](statement)
    ]


def verify(
    statement: dict[str, Any], disabled: frozenset[str] = frozenset()
) -> tuple[str, list[str]]:
    """The verdict and the codes a verifier reaches over these bytes."""
    firing = firing_rules(statement, disabled)
    if not firing:
        return "valid", []
    if firing == ["rule_wellformed"]:
        return "malformed", [CODE_OF_RULE["rule_wellformed"]]
    return "invalid", [CODE_OF_RULE[name] for name in firing]


def verify_bytes(raw: bytes) -> tuple[str, list[str]]:
    """The verdict over a member's bytes. Never raises.

    Bytes that are not exactly one JSON document in UTF-8 give ("unparsed", []):
    no verdict exists for them, and the corpus carries no such member. A
    document that is not a JSON object is record-malformed.
    """
    try:
        statement = decode_strict(raw)
    except (ValueError, RecursionError):
        return "unparsed", []
    return verify(_object(statement))


# ---------------------------------------------------------------------------
# the corpus's check of itself
# ---------------------------------------------------------------------------


def _member_findings(entry: dict[str, Any], statement: dict[str, Any]) -> list[str]:
    verdict, codes = verify(statement)
    findings = []
    if verdict != entry["expected"]["verdict"]:
        findings.append(
            f"{entry['id']}: declares verdict {entry['expected']['verdict']} and the "
            f"verifier answers {verdict} with codes {codes}"
        )
    if codes != entry["expected"]["codes"]:
        findings.append(
            f"{entry['id']}: declares codes {entry['expected']['codes']} and the "
            f"reference verifier names {codes}"
        )
    firing = firing_rules(statement)
    if entry["kind"] == "accept" and firing:
        findings.append(f"{entry['id']}: is an accept member refused by {firing}")
    if entry["kind"] == "reject" and len(firing) != 1:
        findings.append(
            f"{entry['id']}: is a reject member tripping {firing}. A member failing two "
            "rules cannot tell a reader which one its code refers to."
        )
    return findings


def _corpus_findings(manifest: dict[str, Any], bodies: dict[str, bytes]) -> list[str]:
    findings = []
    accepted = {c for e in manifest["vectors"] if e["kind"] == "accept" for c in e["conditions"]}
    rejected = {c for e in manifest["vectors"] if e["kind"] == "reject" for c in e["conditions"]}
    orphan = sorted(rejected - accepted)
    if orphan:
        findings.append(
            f"conditions that reject and never accept: {orphan}. A verifier that refused "
            "every member would score full marks on them."
        )
    used = {c for e in manifest["vectors"] for c in e["conditions"]}
    idle = sorted(set(manifest["conditions"]) - used)
    if idle:
        findings.append(f"conditions declared and carried by no member: {idle}")
    accepts = {e["id"] for e in manifest["vectors"] if e["kind"] == "accept"}
    for entry in manifest["vectors"]:
        if entry["kind"] == "reject" and entry.get("parent") not in accepts:
            findings.append(f"{entry['id']}: names a parent that is not an accepted member")
    findings.extend(_digest_findings(manifest, bodies))
    return findings


def _digest_findings(manifest: dict[str, Any], bodies: dict[str, bytes]) -> list[str]:
    """The claims about bytes: the counts, the corpus digest, the contract, the twins.

    Split from the claims about conditions above only because one function over
    both runs past this repository's complexity ceiling. The two halves are
    independent questions and read better apart.
    """
    findings = []
    measured = {"accept": 0, "reject": 0}
    for entry in manifest["vectors"]:
        measured[entry["kind"]] = measured.get(entry["kind"], 0) + 1
    if measured != manifest["counts"]:
        findings.append(f"counts disagree: manifest {manifest['counts']}, measured {measured}")
    if corpus_digest(manifest, str(HERE)) != manifest["corpusDigest"]:
        findings.append("corpusDigest does not match the member files on disk")
    contract = REPO / manifest["contract"]
    if not contract.is_file():
        findings.append(
            f"the manifest names the contract at {manifest['contract']}, and no such "
            "file is there, so the corpus measures a rule nobody can read"
        )
    elif hashlib.sha256(contract.read_bytes()).hexdigest() != manifest["contractDigest"]:
        findings.append("contractDigest does not match the contract on disk")
    seen: dict[bytes, str] = {}
    for vid, body in sorted(bodies.items()):
        if body in seen:
            findings.append(f"{vid} and {seen[body]} are byte-identical")
        seen[body] = vid
    return findings


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    findings: list[str] = []
    bodies: dict[str, bytes] = {}
    for entry in manifest["vectors"]:
        path = HERE / entry["file"]
        if not path.is_file():
            findings.append(f"{entry['id']}: names {entry['file']}, which is not on disk")
            continue
        body = path.read_bytes()
        bodies[entry["id"]] = body
        if "v" + hashlib.sha256(body).hexdigest()[:16] != entry["id"]:
            findings.append(f"{entry['id']}: does not recompute from its own bytes")
        try:
            statement = decode_strict(body)
        except (ValueError, RecursionError) as exc:
            findings.append(f"{entry['id']}: does not parse: {exc}")
            continue
        findings.extend(_member_findings(entry, _object(statement)))
    findings.extend(_corpus_findings(manifest, bodies))

    if findings:
        print(f"FAIL: {len(findings)} claim(s) do not hold:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(
        f"OK: {len(manifest['vectors'])} members over {len(manifest['conditions'])} "
        f"conditions behave as MANIFEST.json declares, every reject condition has an "
        f"accept twin, and every refusal trips exactly one rule."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
