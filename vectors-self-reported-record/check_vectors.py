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

The Go rail in `corpora/selfreported.go` restates the same six rules and is run
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

from canonical import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from digest import corpus_digest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/self-reported-record"
)
TURN_CONTEXT = "agent-evidence/self-reported-record/v1/turn"
FIELD_CONTEXT = "agent-evidence/self-reported-record/v1/field"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

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
    """Verify, refusing rather than raising on anything the bytes get wrong."""
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


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64.match(value))


def _subject_wellformed(statement: dict[str, Any]) -> bool:
    subject = statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1:
        return False
    entry = subject[0]
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
        return False
    digest = entry.get("digest")
    return isinstance(digest, dict) and _is_hex64(digest.get("sha256"))


def _turn_row_wellformed(row: Any) -> bool:
    if not isinstance(row, dict) or not isinstance(row.get("turnId"), str):
        return False
    attested = row.get("attestedBy")
    if not isinstance(attested, dict) or not isinstance(attested.get("sig"), str):
        return False
    return _is_hex64(attested.get("keyid")) and isinstance(row.get("changeIds"), list)


def _memory_row_wellformed(row: Any) -> bool:
    if not isinstance(row, dict) or not isinstance(row.get("path"), str):
        return False
    return _is_hex64(row.get("assertedDigest")) and _is_hex64(row.get("pathDigest"))


def _ledger_row_wellformed(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("name"), str)
        and isinstance(row.get("members"), list)
    )


def _field_row_wellformed(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("name"), str)
        and isinstance(row.get("value"), str)
        and row.get("evidence") in FIELD_EVIDENCE
    )


def _rows_wellformed(predicate: dict[str, Any]) -> bool:
    """Every carried row's own shape, one predicate per array.

    Split per array rather than written as one loop nest: a single function over
    four row shapes runs past this repository's complexity ceiling, and the four
    predicates are independently readable, which is the same reason the ceiling
    is there.
    """
    return (
        all(_turn_row_wellformed(row) for row in predicate["turns"])
        and all(_memory_row_wellformed(row) for row in predicate["memoryReads"])
        and all(_ledger_row_wellformed(row) for row in predicate["ledgers"])
        and all(_field_row_wellformed(row) for row in predicate["fields"])
    )


def _scalars_wellformed(predicate: dict[str, Any]) -> bool:
    """The predicate's own scalar members, apart from the carried rows."""
    for member, allowed in VOCABULARIES.items():
        if predicate[member] not in allowed:
            return False
    if predicate["hashAlgorithm"] != "sha256":
        return False
    key = predicate["attestingKey"]
    if not isinstance(key, dict):
        return False
    if not _is_hex64(key.get("keyid")) or not _is_hex64(key.get("publicKey")):
        return False
    if not isinstance(predicate["selfSigners"], list):
        return False
    if not all(_is_hex64(keyid) for keyid in predicate["selfSigners"]):
        return False
    if not isinstance(predicate["ledgers"], list) or len(predicate["ledgers"]) < 2:
        return False
    return bool(RFC3339_UTC.match(str(predicate["issuedAt"])))


def rule_wellformed(statement: dict[str, Any]) -> bool:
    """Stage one: the record can be read at all, under the shape it declares."""
    if statement.get("_type") != STATEMENT_TYPE:
        return False
    if statement.get("predicateType") != PREDICATE_TYPE:
        return False
    if not _subject_wellformed(statement):
        return False
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False
    if any(member not in predicate for member in REQUIRED):
        return False
    return _scalars_wellformed(predicate) and _rows_wellformed(predicate)


def rule_turn_attestation(statement: dict[str, Any]) -> bool:
    """srr-c-1: every turn is signed by the key the record names."""
    predicate = statement["predicate"]
    public = predicate["attestingKey"]["publicKey"]
    for row in predicate["turns"]:
        payload = jcs(
            {
                "changeIds": row["changeIds"],
                "context": TURN_CONTEXT,
                "goalMarker": row["goalMarker"],
                "priorTurn": row["priorTurn"],
                "sessionId": predicate["sessionId"],
                "turnId": row["turnId"],
            }
        )
        if not ed25519_ok(public, payload, row["attestedBy"]["sig"]):
            return False
    return True


def rule_memory_digest_over_named_path(statement: dict[str, Any]) -> bool:
    """srr-c-2: the digest reported is the digest of the bytes at the path."""
    return all(
        row["assertedDigest"] == row["pathDigest"]
        for row in statement["predicate"]["memoryReads"]
    )


def rule_attesting_key_disjoint(statement: dict[str, Any]) -> bool:
    """srr-c-3: the attesting key is not one the record says the runtime holds."""
    predicate = statement["predicate"]
    return predicate["attestingKey"]["keyid"] not in predicate["selfSigners"]


def rule_ledgers_agree(statement: dict[str, Any]) -> bool:
    """srr-c-4: every ledger names the same change set."""
    sets = [frozenset(row["members"]) for row in statement["predicate"]["ledgers"]]
    return all(members == sets[0] for members in sets)


def rule_field_coverage(statement: dict[str, Any]) -> bool:
    """srr-c-5: a field claiming substrate coverage carries the covering signature."""
    predicate = statement["predicate"]
    self_signers = set(predicate["selfSigners"])
    for row in predicate["fields"]:
        covered = row.get("coveredBy")
        if row["evidence"] == "producer_asserted":
            if covered is not None:
                return False
            continue
        if not isinstance(covered, dict):
            return False
        if covered.get("keyid") in self_signers:
            return False
        payload = jcs(
            {
                "context": FIELD_CONTEXT,
                "name": row["name"],
                "recordId": predicate["recordId"],
                "value": row["value"],
            }
        )
        if not ed25519_ok(str(covered.get("publicKey")), payload, str(covered.get("sig"))):
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
        findings.extend(_member_findings(entry, json.loads(body)))
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
