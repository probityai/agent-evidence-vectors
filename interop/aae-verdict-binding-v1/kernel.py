"""Independent AAE enforce and ratify kernel, written from draft-kroehl-agentic-trust-aae-02.

The kernel recomputes a verdict record (Sections 2.2.1-2.2.3, 2.5, 6.1, 6.2) and a
ratification record (Sections 6.3, 6.4) from their inputs alone. It reads no clock,
no network and no stored state. Every digest is
``"sha256:" + LOWERHEX(SHA-256(TAG || JCS(value)))`` with the domain tags the draft
states. The human-readable ``reason`` is returned beside each record and never
enters a digested core.

The draft does not spell out the names, ``field``, ``value`` and ``bound`` members of
the structural trace entries (Section 2.5.2 names only what they must cover). Those
members are digested, so this kernel follows the convention the published v1.4.0
vectors encode; PROFILE.md lists each one and FINDINGS.md records the gap. Where an
input lies outside every published vector and the draft is silent, the kernel fails
closed and PROFILE.md says how.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Any, TypeGuard

import rfc8785

TAG_ACTION = b"aae:enforce-action:v1\x00"
TAG_MANDATE = b"aae:enforce-mandate:v1\x00"
TAG_TRANSACTION = b"aae:enforce-transaction:v1\x00"
TAG_CORE = b"aae:enforce-core:v1\x00"
TAG_RATIFY_STATEMENT = b"aae:enforce-ratify-statement:v1\x00"
TAG_RATIFY_CORE = b"aae:enforce-ratify-core:v1\x00"
DOMAIN_TAGS = {
    "action": TAG_ACTION,
    "mandate": TAG_MANDATE,
    "transaction": TAG_TRANSACTION,
    "core": TAG_CORE,
    "statement": TAG_RATIFY_STATEMENT,
    "ratify_core": TAG_RATIFY_CORE,
}

ENFORCE_VERSION = "3.0"
RATIFY_VERSION = "3.0"
PERMIT, DENY, PENDING = "PERMIT", "DENY", "PENDING"
PASS, FAIL = "PASS", "FAIL"
APPROVED, DISAPPROVED = "APPROVED", "DISAPPROVED"
RATIFIED, REJECTED = "RATIFIED", "REJECTED"
DISPOSITIONS = ("allow", "hold", "forbid")

# Section 2.2.1 and 2.5.1 floors. The draft lets a verifier refuse beyond them.
MAX_GRANTS = 256
MAX_CONSTRAINTS = 64
MAX_ENUM_MEMBERS = 512
MAX_TYPE_FIELDS = 32
MAX_PATH_SEGMENTS = 8
MAX_ABS_INT = 10**15
MAX_RATIFICATION_AUTHORITIES = 64

DIGEST_FORM = re.compile(r"sha256:[0-9a-f]{64}")
CORE_MEMBERS = (
    "enforce_version",
    "mandate_digest",
    "transaction_digest",
    "action_digest",
    "verdict",
    "grant_index",
    "trace",
    "prev_core_digest",
)
TRACE_MEMBERS = ("predicate", "field", "value", "bound", "result")


class CallerError(ValueError):
    """Section 6.4 caller error: the request does not line up, so no record exists.

    ``code`` is a stable identifier; the message is diagnostic only.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Outcome:
    """A produced record: the digested core, its digest, and undigested diagnostics."""

    core: dict[str, Any]
    core_digest: str
    reason: str
    reasons: list[str] = field(default_factory=lambda: [])


def tagged_digest(tag: bytes, value: Any) -> str | None:
    """Return the draft's tagged digest of a JSON value, or None if JCS refuses it."""
    try:
        payload = rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError, RecursionError):
        return None
    return "sha256:" + hashlib.sha256(tag + payload).hexdigest()


def same_text(left: str, right: str) -> bool:
    """Compare two strings with hmac.compare_digest over their UTF-8 octets."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def is_digest(value: Any) -> bool:
    """True for a string of the form sha256: plus 64 lowercase hex characters."""
    return isinstance(value, str) and DIGEST_FORM.fullmatch(value) is not None


def is_bounded_int(value: Any) -> TypeGuard[int]:
    """Section 2.5.1 range values: an integer (never a boolean) within 10^15."""
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= MAX_ABS_INT


class Trace:
    """Ordered predicate trace (Section 2.5.2). Reasons are kept apart from the entries."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.reasons: list[str] = []

    def add(
        self,
        predicate: str,
        field_name: Any,
        result: str,
        reason: str,
        value: Any = None,
        bound: Any = None,
    ) -> dict[str, Any]:
        entry = {
            "predicate": predicate,
            "field": field_name,
            "value": value,
            "bound": bound,
            "result": result,
        }
        self.entries.append(entry)
        self.reasons.append(reason)
        return entry


# ----------------------------------------------------------------- Section 2.2.1


def type_fields_valid(names: Any) -> bool:
    """Non-empty, at most 32, non-empty strings, no repeat, containing verb."""
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_TYPE_FIELDS:
        return False
    if not all(isinstance(name, str) and name for name in names):
        return False
    return len(set(names)) == len(names) and "verb" in names


def grant_valid(grant: Any) -> bool:
    """The four REQUIRED grant members, each in its declared form."""
    if not isinstance(grant, dict):
        return False
    constraints = grant.get("constraints")
    return (
        is_digest(grant.get("action_binding"))
        and grant.get("disposition") in DISPOSITIONS
        and type_fields_valid(grant.get("type_fields"))
        and isinstance(constraints, list)
        and len(constraints) <= MAX_CONSTRAINTS
    )


def mandate_problem(mandate: Any) -> str | None:
    """Return why a mandate must be rejected (Section 2.2.1), or None."""
    if not isinstance(mandate, dict):
        return "the mandate is absent or not an object"
    grants = mandate.get("grants")
    if not isinstance(grants, list) or not grants:
        return "the mandate carries no non-empty grants array"
    if len(grants) > MAX_GRANTS:
        return "the mandate carries more grants than this verifier accepts"
    for index, grant in enumerate(grants):
        if not grant_valid(grant):
            return f"grant {index} is malformed"
    return None


# ---------------------------------------------------------------- Section 2.5.1


def resolve(transaction: dict[str, Any], path: Any) -> tuple[bool, Any]:
    """Resolve a dotted path by dictionary traversal only; (found, value)."""
    if not isinstance(path, str) or not path:
        return False, None
    segments = path.split(".")
    if len(segments) > MAX_PATH_SEGMENTS or "" in segments:
        return False, None
    current: Any = transaction
    for segment in segments:
        if not isinstance(current, dict) or segment not in current:
            return False, None
        current = current[segment]
    return True, current


def check_exact(trace: Trace, rule: dict[str, Any], transaction: dict[str, Any]) -> bool:
    """exact: byte-exact string equality, compared in constant time."""
    path, expected = rule.get("field"), rule.get("value")
    found, actual = resolve(transaction, path)
    if not isinstance(expected, str):
        trace.add("exact", path, FAIL, "the constraint value is not a string", None, expected)
        return False
    if not found:
        trace.add("exact", path, FAIL, "the field is absent", None, expected)
        return False
    if not isinstance(actual, str):
        trace.add("exact", path, FAIL, "the transaction value is not a string", actual, expected)
        return False
    ok = same_text(actual, expected)
    trace.add("exact", path, PASS if ok else FAIL, "exact comparison", actual, expected)
    return ok


def enum_hits(actual: str, members: list[Any]) -> int:
    """Compare every member, never stopping at the first hit (Section 2.5.1)."""
    hits = 0
    for member in members:
        hits += isinstance(member, str) and same_text(actual, member)
    return hits


def check_enum(trace: Trace, rule: dict[str, Any], transaction: dict[str, Any]) -> bool:
    """enum: the value equals one member of a non-empty string array."""
    path, members = rule.get("field"), rule.get("values")
    found, actual = resolve(transaction, path)
    if not isinstance(members, list) or not members:
        trace.add("enum", path, FAIL, "the values member is not a non-empty array", None, members)
        return False
    if len(members) > MAX_ENUM_MEMBERS:
        trace.add("enum", path, FAIL, "the values member is too long", None, len(members))
        return False
    if not found:
        trace.add("enum", path, FAIL, "the field is absent", None, members)
        return False
    if not isinstance(actual, str):
        trace.add("enum", path, FAIL, "the transaction value is not a string", actual, members)
        return False
    ok = enum_hits(actual, members) > 0
    trace.add("enum", path, PASS if ok else FAIL, "enumeration comparison", actual, members)
    return ok


def check_range(trace: Trace, rule: dict[str, Any], transaction: dict[str, Any]) -> bool:
    """range: integer bounds and value, both bounds inclusive, inverted bounds fail."""
    path, low, high = rule.get("field"), rule.get("lo"), rule.get("hi")
    bound = {"lo": low, "hi": high}
    found, actual = resolve(transaction, path)
    if not is_bounded_int(low) or not is_bounded_int(high):
        trace.add("range", path, FAIL, "a bound is not a bounded integer", None, bound)
        return False
    if low > high:
        trace.add("range", path, FAIL, "the bounds are inverted", None, bound)
        return False
    if not found:
        trace.add("range", path, FAIL, "the field is absent", None, bound)
        return False
    if not is_bounded_int(actual):
        trace.add("range", path, FAIL, "the value is not a bounded integer", actual, bound)
        return False
    ok = low <= actual <= high
    trace.add("range", path, PASS if ok else FAIL, "inclusive range comparison", actual, bound)
    return ok


CHECKS = {"exact": check_exact, "enum": check_enum, "range": check_range}


def check_constraint(trace: Trace, rule: Any, transaction: dict[str, Any]) -> bool:
    """Dispatch over the closed type set; any other type is a failed predicate."""
    if not isinstance(rule, dict):
        trace.add("unknown", None, FAIL, "the constraint is not an object")
        return False
    kind = rule.get("type")
    if isinstance(kind, str) and kind in CHECKS:
        return CHECKS[kind](trace, rule, transaction)
    label = kind if isinstance(kind, str) else "unknown"
    trace.add(label, rule.get("field"), FAIL, "the constraint type is outside the closed set")
    return False


# ---------------------------------------------------------------- Section 2.2.3


def type_matches(action: Any, names: list[str]) -> bool:
    """Section 2.2.2: the action is an object whose member names equal type_fields."""
    return isinstance(action, dict) and set(action) == set(names)


@dataclass
class Evaluation:
    """Mutable state of one Section 2.2.3 evaluation."""

    trace: Trace
    verdict: str = DENY
    grant_index: int | None = None
    reason: str = ""


def evaluate_grants(
    state: Evaluation, grants: list[dict[str, Any]], transaction: dict[str, Any], action_digest: str
) -> None:
    """Steps 2 to 7 of Section 2.2.3 over a structurally valid mandate."""
    action = transaction.get("action")
    keys = sorted(action) if isinstance(action, dict) else None
    typed = [i for i, grant in enumerate(grants) if type_matches(action, grant["type_fields"])]
    if not typed:
        state.reason = "no grant's type_fields matches the action's member names"
        state.trace.add("type_fields", "action", FAIL, state.reason, keys, grants[0]["type_fields"])
        return
    state.trace.add(
        "type_fields", "action", PASS, "the action carries a grant's type_fields", keys,
        grants[typed[0]]["type_fields"],
    )
    bindings = [same_text(grants[i]["action_binding"], action_digest) for i in typed]
    matched = [i for i, bound in zip(typed, bindings, strict=True) if bound]
    if not matched:
        state.reason = "unaddressed action: no grant's action_binding equals the digest"
        state.trace.add("action_binding", "action", FAIL, state.reason, action_digest, None)
        return
    state.trace.add("action_binding", "action", PASS, "a grant binds the action",
                    action_digest, action_digest)
    forbidden = [i for i in matched if grants[i]["disposition"] == "forbid"]
    if forbidden:
        state.grant_index = forbidden[0]
        state.reason = f"grant {forbidden[0]} forbids the action"
        state.trace.add("disposition", None, FAIL, state.reason, "forbid", None)
        return
    apply_dispositions(state, grants, matched, transaction)


def apply_dispositions(
    state: Evaluation, grants: list[dict[str, Any]], matched: list[int], transaction: dict[str, Any]
) -> None:
    """Steps 6 and 7: the first matched grant whose constraints all hold decides."""
    state.reason = "no matched grant had every constraint hold"
    for index in matched:
        results = [check_constraint(state.trace, rule, transaction)
                   for rule in grants[index]["constraints"]]
        if all(results):
            disposition = grants[index]["disposition"]
            state.grant_index = index
            state.verdict = PERMIT if disposition == "allow" else PENDING
            state.reason = f"grant {index} holds with disposition {disposition}"
            state.trace.add("disposition", None, PASS, state.reason, disposition, None)
            return


def checked_link(prev_core_digest: Any) -> str | None:
    """A caller-supplied predecessor is null or a well-formed digest."""
    if prev_core_digest is None:
        return None
    if is_digest(prev_core_digest):
        return str(prev_core_digest)
    raise CallerError("prev_core_digest_malformed", "prev_core_digest is neither null nor a digest")


def enforce_check(mandate: Any, transaction: Any, prev_core_digest: Any = None) -> Outcome:
    """Evaluate a transaction against a mandate and return the verdict record.

    Parameters
    ----------
    mandate, transaction : object
        Parsed JSON values. Anything structurally wrong yields DENY, never an error.
    prev_core_digest : str or None
        The caller-held chain link of Section 6.2.

    Returns
    -------
    Outcome
        The Section 2.5.3 core, its tagged digest and the undigested reasons.
    """
    link = checked_link(prev_core_digest)
    state = Evaluation(Trace())
    problem = mandate_problem(mandate)
    is_object = isinstance(transaction, dict)
    action_digest = tagged_digest(TAG_ACTION, transaction.get("action")) if is_object else None
    if problem is not None:
        state.reason = problem
        state.trace.add("mandate_present", None, FAIL, problem)
    elif not is_object:
        state.reason = "the transaction is absent or not an object"
        state.trace.add("transaction_present", None, FAIL, state.reason)
    elif action_digest is None:
        state.reason = "the action cannot be canonicalized"
        state.trace.add("action_binding", "action", FAIL, state.reason)
    else:
        state.trace.add("mandate_present", None, PASS, "the mandate is structurally valid")
        evaluate_grants(state, mandate["grants"], transaction, action_digest)
    core = {
        "enforce_version": ENFORCE_VERSION,
        "mandate_digest": tagged_digest(TAG_MANDATE, mandate),
        "transaction_digest": tagged_digest(TAG_TRANSACTION, transaction),
        "action_digest": action_digest,
        "verdict": state.verdict,
        "grant_index": state.grant_index,
        "trace": state.trace.entries,
        "prev_core_digest": link,
    }
    return seal(core, TAG_CORE, state.reason, state.trace.reasons)


def seal(core: dict[str, Any], tag: bytes, reason: str, reasons: list[str]) -> Outcome:
    """Digest a finished core; a core JCS cannot serialize is a defect, not a verdict."""
    digest = tagged_digest(tag, core)
    if digest is None:
        raise CallerError("core_not_canonicalizable", "the produced core cannot be canonicalized")
    return Outcome(core, digest, reason, reasons)


# ------------------------------------------------------------- Sections 6.3, 6.4


def authorities(mandate: Any) -> list[tuple[str, str, str]]:
    """(did, public_key, role) for the principal and each named authority with a key."""
    if not isinstance(mandate, dict):
        return []
    found: list[tuple[str, str, str]] = []
    principal = mandate.get("principal")
    if isinstance(principal, dict):
        found.extend(authority_entry(principal, "principal"))
    named = mandate.get("ratification_authorities")
    if isinstance(named, list):
        for entry in named[:MAX_RATIFICATION_AUTHORITIES]:
            found.extend(authority_entry(entry, None))
    return found


def authority_entry(entry: Any, role: str | None) -> list[tuple[str, str, str]]:
    """An entry contributes only with both a did string and a public_key string."""
    if not isinstance(entry, dict):
        return []
    did, key = entry.get("did"), entry.get("public_key")
    if not isinstance(did, str) or not isinstance(key, str):
        return []
    label = role if role is not None else entry.get("role")
    return [(did, key, label if isinstance(label, str) else "named_authority")]


def is_plain_did(value: Any) -> bool:
    """Section 6.4: a DID, not a DID URL carrying a path, query or fragment."""
    return isinstance(value, str) and value.startswith("did:") and not set(value) & set("/?#")


def match_authority(
    claimed: Any, allowed: list[tuple[str, str, str]]
) -> tuple[str, str, str] | None:
    """Exactly one entry whose DID equals the claim; every entry is compared."""
    if not is_plain_did(claimed):
        return None
    hits = [entry for entry in allowed if same_text(entry[0], claimed)]
    return hits[0] if len(hits) == 1 else None


def strict_hex(value: Any, octets: int) -> bytes | None:
    """Decode exactly 2*octets hexadecimal digits; anything else is a failed decode."""
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-fA-F]{{{2 * octets}}}", value):
        return None
    return bytes.fromhex(value)


def signature_holds(public_hex: str, signature_hex: Any, message: bytes) -> bool:
    """Raw Ed25519 under the mandate-held key; every decoding failure is a failed check."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public, signature = strict_hex(public_hex, 32), strict_hex(signature_hex, 64)
    if public is None or signature is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def statement_bytes(ratifies: str, decision: str, authority: str) -> bytes:
    """The Section 6.3 signed statement: tag, NUL, JCS of the four-member object."""
    statement = {
        "ratify_version": RATIFY_VERSION,
        "ratifies": ratifies,
        "decision": decision,
        "authority": authority,
    }
    return TAG_RATIFY_STATEMENT + rfc8785.dumps(statement)


def prior_core(prior_record: Any) -> tuple[dict[str, Any], str]:
    """The caller-error guards of Section 6.4 that concern the prior record itself."""
    if not isinstance(prior_record, dict):
        raise CallerError("prior_record_malformed", "the prior record is not an object")
    core, claimed = prior_record.get("core"), prior_record.get("core_digest")
    if not isinstance(core, dict) or not isinstance(claimed, str):
        raise CallerError("prior_record_malformed", "the prior record lacks core or core_digest")
    recomputed = tagged_digest(TAG_CORE, core)
    if recomputed is None or not same_text(recomputed, claimed):
        raise CallerError("prior_core_digest_mismatch", "core_digest does not match its core")
    verdict = core.get("verdict")
    if verdict == PERMIT:
        raise CallerError("prior_verdict_permit", "a PERMIT is not ratifiable")
    if verdict not in (DENY, PENDING):
        raise CallerError("prior_verdict_not_ratifiable", "only DENY and PENDING are ratifiable")
    if not is_digest(core.get("mandate_digest")):
        raise CallerError("prior_mandate_digest_missing", "the prior core has no mandate_digest")
    return core, claimed


def ratification_link(prev_core_digest: Any, claimed: str) -> str:
    """Section 6.2: the ratification's link equals the record it ratifies."""
    if prev_core_digest is None:
        return claimed
    if not isinstance(prev_core_digest, str) or not same_text(prev_core_digest, claimed):
        raise CallerError(
            "prev_core_digest_mismatch",
            "prev_core_digest names a record other than the ratified one",
        )
    return prev_core_digest


@dataclass
class Authority:
    """Mutable result of the authority checks of Section 6.4."""

    trace: Trace
    did: str | None = None
    status: str = REJECTED
    reason: str = "the authority was not established"


def check_authority(
    result: Authority, core: dict[str, Any], claimed: str, decision: str, proof: Any
) -> None:
    """Every rejection in Section 6.4 appears as a failed predicate in the trace."""
    if not isinstance(proof, dict):
        result.reason = "the authority proof is absent or not an object"
        result.trace.add("authority_proof", None, FAIL, result.reason)
        return
    mandate = proof.get("mandate")
    supplied = tagged_digest(TAG_MANDATE, mandate) if mandate is not None else None
    bound = supplied is not None and same_text(supplied, core["mandate_digest"])
    result.trace.add("mandate_binding", "mandate", PASS if bound else FAIL,
                     "the supplied mandate is compared with mandate_digest",
                     supplied, core["mandate_digest"])
    if not bound:
        result.reason = "the supplied mandate does not bind to the prior record"
        return
    allowed = authorities(mandate)
    claim = proof.get("authority")
    entry = match_authority(claim, allowed)
    result.trace.add("authority_in_mandate", "authority", PASS if entry else FAIL,
                     "the claimed authority is looked up in the mandate",
                     claim, [did for did, _key, _role in allowed])
    if entry is None:
        result.reason = "the claimed authority does not derive from the mandate"
        return
    did, key, role = entry
    ok = signature_holds(key, proof.get("signature"), statement_bytes(claimed, decision, did))
    result.trace.add("authority_signature", "signature", PASS if ok else FAIL,
                     "the signature is checked under the mandate-held key")
    if ok:
        result.did, result.status = did, RATIFIED
        result.reason = f"ratified by the {role} {did}"
    else:
        result.reason = "the signature does not verify under the mandate-held key"


def ratify(
    prior_record: Any, decision: Any, authority_proof: Any, prev_core_digest: Any = None
) -> Outcome:
    """Produce a ratification record, or raise CallerError where none may exist.

    Parameters
    ----------
    prior_record : object
        A verdict record, ``{"core": ..., "core_digest": ...}``.
    decision : object
        APPROVED or DISAPPROVED, a statement about the action (Section 6.3).
    authority_proof : object
        ``{"mandate", "authority", "signature"}``; the key always comes from the mandate.
    prev_core_digest : object
        None, or exactly the prior record's core digest.

    Raises
    ------
    CallerError
        For each caller error Section 6.4 lists; no record is produced.
    """
    if decision not in (APPROVED, DISAPPROVED):
        raise CallerError("decision_invalid", "decision is neither APPROVED nor DISAPPROVED")
    core, claimed = prior_core(prior_record)
    link = ratification_link(prev_core_digest, claimed)
    trace = Trace()
    trace.add("prior_ratifiable", None, PASS, "the prior verdict may be ratified", core["verdict"])
    result = Authority(trace)
    check_authority(result, core, claimed, decision, authority_proof)
    record = {
        "ratify_version": RATIFY_VERSION,
        "ratifies": claimed,
        "prior_verdict": core["verdict"],
        "decision": decision,
        "status": result.status,
        "authority": result.did,
        "mandate_digest": core["mandate_digest"],
        "trace": trace.entries,
        "prev_core_digest": link,
    }
    return seal(record, TAG_RATIFY_CORE, result.reason, trace.reasons)


def reversed_keys(value: Any) -> Any:
    """The same JSON value with every object's members in reverse order (Section 10)."""
    if isinstance(value, dict):
        return {key: reversed_keys(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reversed_keys(item) for item in value]
    return value
