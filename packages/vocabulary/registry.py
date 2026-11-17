"""Judge a record's values against the registry, by meta.open_value_rule.

    from agent_evidence_vocabulary import registry
    index = registry.load()
    registry.check_value(index, "observation_vantage", "substrate", record_digest)
    registry.resolve_verdict(index, {"class": "fail", "parent": "fail"}, record_digest)

``record_digest`` is the hex SHA-256 the record carries as registryDigest, or
None when it carries none. The rule has three cases: the record names the
registry this index was made from (exact), names none (exact, as before the
rule), or names another registry (tolerant, by the term's criticality). The
exact digests a verifier holds can be widened with ``known_digests``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib import resources
from urllib.parse import urlsplit

OK = "ok"
DEGRADED = "degraded"
IGNORED = "ignored"
MALFORMED = "malformed"


@dataclass(frozen=True)
class Judgement:
    """What a verifier does with one value. ``value`` is always preserved."""

    outcome: str
    value: str
    reason: str
    meaning: str | None = None


def load() -> dict:
    """The registry index shipped with this package."""
    return json.loads(resources.files(__package__ or "agent_evidence_vocabulary").joinpath("registry.json").read_text("utf-8"))


def digest_of(source: bytes) -> str:
    """The registryDigest of a registry file's exact bytes."""
    return hashlib.sha256(source).hexdigest()


def _exact(index: dict, record_digest: str | None, known_digests: frozenset[str]) -> bool:
    return record_digest is None or record_digest == index["source_sha256"] or record_digest in known_digests


def check_value(index: dict, term: str, value: str, record_digest: str | None,
                known_digests: frozenset[str] = frozenset()) -> Judgement:
    """Judge ``value`` of the closed term ``term``."""
    entry = index["terms"].get(term)
    if entry is None or entry["values"] is None:
        raise KeyError(f"{term} is not a term with registered values")
    if value in entry["values"]:
        return Judgement(OK, value, "registered", meaning=value)
    if _exact(index, record_digest, known_digests):
        return Judgement(MALFORMED, value, "unregistered under the registry the record names")
    if entry["criticality"] == "critical":
        return Judgement(DEGRADED, value, "unregistered value of a critical term under another registry")
    return Judgement(IGNORED, value, "unregistered value of an informational term under another registry")


def resolve_verdict(index: dict, verdict: dict, record_digest: str | None,
                    known_digests: frozenset[str] = frozenset()) -> Judgement:
    """Judge a verdict {class, parent}; ``meaning`` is the parent it counts as."""
    classes = index["verdict_classes"]
    code, parent = verdict.get("class"), verdict.get("parent")
    if parent not in classes["parents"]:
        return Judgement(MALFORMED, str(code), f"parent {parent!r} is not a value of {classes['parent_term']}")
    if code == parent:
        return Judgement(OK, code, "parent", meaning=parent)
    child = classes["children"].get(code)
    if child is not None:
        if child["parent"] != parent:
            return Judgement(MALFORMED, code, f"registered under {child['parent']}, carried under {parent}")
        return Judgement(OK, code, "registered child", meaning=parent)
    if _exact(index, record_digest, known_digests):
        return Judgement(MALFORMED, str(code), "unregistered child under the registry the record names")
    return Judgement(OK, str(code), "unregistered child read as its parent", meaning=parent)


_OKTA_SUFFIXES = (".okta.com", ".oktapreview.com", ".okta-emea.com", ".okta-gov.com")
_ENTRA_HOSTS = ("login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn",
                "sts.windows.net")
_ENTRA_SUFFIXES = (".ciamlogin.com",)
_AUTH0_SUFFIXES = (".auth0.com",)
_SELF_ISSUED = ("https://self-issued.me", "https://self-issued.me/v2")
_NAMED_PROVIDERS = ("okta", "entra", "auth0", "keycloak", "self_issued")


def _keycloak_path(path: str) -> bool:
    parts = [p for p in path.split("/") if p]
    if parts[:1] == ["auth"]:
        parts = parts[1:]
    return len(parts) == 2 and parts[0] == "realms"


def _derive_provider(host: str, path: str) -> str:
    if host.endswith(_OKTA_SUFFIXES):
        return "okta"
    if host in _ENTRA_HOSTS or host.endswith(_ENTRA_SUFFIXES):
        return "entra"
    if host.endswith(_AUTH0_SUFFIXES):
        return "auth0"
    if _keycloak_path(path):
        return "keycloak"
    return "other"


def identity_provider(issuer: str, declared: str | None = None,
                      self_issuers: frozenset[str] = frozenset()) -> Judgement:
    """Judge the identity_provider of a principal from its issuer URL.

    The value is derived from the issuer's host and path, checking self_issued
    first against ``self_issuers``, the issuers the relying party runs itself.
    A declared value that contradicts a derived named provider is malformed;
    on a custom domain (derived ``other``) a declared named value is accepted
    and the reason says it was declared. An issuer that is not https is malformed.
    """
    if declared is not None and declared not in (*_NAMED_PROVIDERS, "other"):
        return Judgement(MALFORMED, declared, "declared value is not a registered identity_provider")
    parts = urlsplit(issuer)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host:
        return Judgement(MALFORMED, issuer, "issuer is not an https URL")
    trimmed = issuer.rstrip("/")
    if trimmed in _SELF_ISSUED or issuer in self_issuers or trimmed in self_issuers:
        derived = "self_issued"
    else:
        derived = _derive_provider(host, parts.path)
    if derived != "other":
        if declared is not None and declared != derived:
            return Judgement(MALFORMED, declared, f"declared {declared} contradicts {derived}, derived from the issuer")
        return Judgement(OK, derived, "derived from the issuer", meaning=derived)
    if declared is not None and declared != "other":
        return Judgement(OK, declared, "declared for a custom-domain issuer, not derived", meaning=declared)
    return Judgement(OK, "other", "derived from the issuer", meaning="other")


# ---------------------------------------------------------------- decision_receipt

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_CODE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_NO_DECISION = "no-decision"


@dataclass(frozen=True)
class Derived:
    """A term value a verifier derives from a decision record, or the reason it refuses the record.

    ``value`` is the registered value, or None when ``refused``. ``reason`` is a stable code.
    """

    term: str
    value: str | None
    refused: bool
    reason: str


def _refuse(term: str, reason: str) -> Derived:
    return Derived(term, None, True, reason)


def _digest_field(decision: dict, key: str) -> tuple[str | None, str | None]:
    """(digest, refusal reason): an omitted field is (None, None); null, empty, malformed and zero-filled are refused."""
    if key not in decision:
        return None, None
    value = decision[key]
    if not isinstance(value, str) or not _HEX64.match(value):
        return None, f"{key}-not-a-sha256"
    if value == "0" * 64:
        return None, f"{key}-zero-filled"
    return value, None


def _commitment(term: str, key: str, absent: str, decision: dict, source: bytes | None) -> Derived:
    digest, problem = _digest_field(decision, key)
    if problem:
        return _refuse(term, problem)
    if digest is None:
        return Derived(term, absent, False, f"{key} omitted")
    if source is not None and hashlib.sha256(source).hexdigest() != digest:
        return _refuse(term, f"{key}-differs-from-the-bytes")
    return Derived(term, "committed", False, f"{key} carried")


def request_commitment(decision: dict, request: bytes | None = None) -> Derived:
    """Derive request_commitment; ``request`` is the canonical request bytes when the verifier holds them."""
    return _commitment("request_commitment", "requestHash", "uncanonicalizable", decision, request)


def policy_commitment(decision: dict, policy: bytes | None = None) -> Derived:
    """Derive policy_commitment; ``policy`` is the canonical policy configuration bytes when held."""
    return _commitment("policy_commitment", "policyDefinitionHash", "not_committed", decision, policy)


def trust_root_commitment(decision: dict, roots: bytes | None = None) -> Derived:
    """Derive trust_root_commitment; ``roots`` is the canonical sorted root set bytes when held."""
    return _commitment("trust_root_commitment", "trustedRootsHash", "not_committed", decision, roots)


def revocation_list_in_force(decision: dict, published: bytes | None = None) -> Derived:
    """Derive revocation_list_in_force from which of the digest and the version are present.

    A list that revoked nothing has a digest (of its canonical empty bytes) and so is never no_list_loaded.
    """
    term = "revocation_list_in_force"
    digest, problem = _digest_field(decision, "revocationListHash")
    if problem:
        return _refuse(term, problem)
    version = decision.get("revocationListVersion")
    has_version = "revocationListVersion" in decision
    if has_version and (isinstance(version, bool) or not isinstance(version, int) or version < 0):
        return _refuse(term, "revocationListVersion-not-a-count")
    if digest is None:
        return _refuse(term, "version-without-digest") if has_version else Derived(term, "no_list_loaded", False, "no list carried")
    if published is not None and hashlib.sha256(published).hexdigest() != digest:
        return _refuse(term, "revocationListHash-differs-from-the-bytes")
    return Derived(term, "versioned_list" if has_version else "unversioned_list", False, "list carried")


def receipt_digest(record: dict) -> str:
    """SHA-256 of a record's canonical JSON: sorted keys, compact separators, UTF-8."""
    text = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _previous(record: dict) -> tuple[str | None, str | None]:
    decision = record.get("decision") if isinstance(record, dict) else None
    if not isinstance(decision, dict):
        return None, "record-without-decision"
    return _digest_field(decision, "previousReceiptHash")


def receipt_chain_link(records: list[dict], anchor: dict | None = None) -> Derived:
    """Walk records in emission order and derive receipt_chain_link for the stream.

    The stream's value is ``first`` when it starts a chain and every later record links, and ``linked``
    when it starts mid-chain. The refusals are: a repeated record, a fork (two records naming one
    predecessor), a link that is not the digest of the record before it (``chain-order`` when it names
    another record of the stream, ``chain-link-broken`` when it names none), a record after the first
    with no link (``chain-reset``, reported as unchained), and an anchor, when supplied, that names a
    different last digest or count. Without an anchor the end is not established and the reason says so.
    """
    term = "receipt_chain_link"
    if not records:
        return _refuse(term, _NO_DECISION)
    digests = [receipt_digest(r) for r in records]
    if len(set(digests)) != len(digests):
        return _refuse(term, "duplicate-record")
    links = []
    for record in records:
        link, problem = _previous(record)
        if problem:
            return _refuse(term, problem)
        links.append(link)
    named = [link for link in links if link is not None]
    if len(set(named)) != len(named):
        return _refuse(term, "fork")
    if any(link is None for link in links[1:]):
        return Derived(term, "unchained", False, "chain-reset")
    for index in range(1, len(records)):
        if links[index] != digests[index - 1]:
            return _refuse(term, "chain-order" if links[index] in digests else "chain-link-broken")
    value = "first" if links[0] is None else "linked"
    if anchor is None:
        return Derived(term, value, False, "end-not-established: no head anchor supplied")
    if anchor.get("lastDigest") != digests[-1] or anchor.get("count") != len(records):
        return _refuse(term, "head-anchor-mismatch")
    return Derived(term, value, False, "end-established")


def possession_proof(decision: dict, seen: frozenset[str] = frozenset()) -> Derived:
    """Derive possession_proof. An allow without a proof of the signature's length, and a proof in ``seen``, are refused.

    The check of the signature itself is the verifier's, under the scheme the record's authority names.
    """
    term = "possession_proof"
    has = "possessionSignature" in decision
    value = decision.get("possessionSignature")
    if has and (not isinstance(value, str) or not _HEX128.match(value) or value == "0" * 128):
        return _refuse(term, "possessionSignature-malformed")
    if not has:
        if decision.get("verdict") == "allow":
            return _refuse(term, "allow-without-possession-proof")
        return Derived(term, "absent", False, "possessionSignature omitted")
    if value in seen:
        return _refuse(term, "possession-proof-replayed")
    return Derived(term, "bound", False, "possessionSignature carried")


def decision_code(decision: dict, known: frozenset[str] | None = None) -> Derived:
    """Judge decision.code against decision.verdict: a refusal carries a canonical code, an allow carries none."""
    term = "decision_code"
    verdict = decision.get("verdict")
    code = decision.get("code")
    if verdict == "allow":
        return _refuse(term, "code-on-allow") if "code" in decision else Derived(term, "none", False, "allow carries no code")
    if "code" not in decision:
        return _refuse(term, "refusal-without-code")
    if not isinstance(code, str) or len(code) > 64 or not _CODE.match(code):
        return _refuse(term, "code-not-canonical")
    if known is not None and code not in known:
        return _refuse(term, "code-not-in-the-list")
    return Derived(term, code, False, "canonical code")


def upstream_receipt(upstream: dict, fetched: dict | None, *, checked: bool = True) -> Derived:
    """Judge an upstream receipt against what the provider's re-check address returned.

    ``fetched`` is the provider's record of the call as a dict, or None when no record was obtained for
    any reason (the call is unknown, the record expired, the address answered with something that is not
    a record, the transport failed): every such case is ``unreachable`` with one reason, so the answer
    does not reveal which. ``checked=False`` means the verifier did not ask. Only ``agrees`` is a pass.
    """
    term = "upstream_receipt"
    for key in ("provider", "generationId", "recheckUrl"):
        if not isinstance(upstream.get(key), str) or not upstream[key]:
            return _refuse(term, f"{key}-missing")
    if not upstream["recheckUrl"].startswith("https://") or not urlsplit(upstream["recheckUrl"]).hostname:
        return _refuse(term, "recheckUrl-not-https")
    fact = upstream.get("fact")
    if not isinstance(fact, dict) or not fact:
        return _refuse(term, "fact-missing")
    if not checked:
        return Derived(term, "not_checked", False, "the verifier did not ask")
    if not isinstance(fetched, dict):
        return Derived(term, "unreachable", False, "no record obtained from the provider")
    if all(key in fetched and fetched[key] == value for key, value in fact.items()):
        return Derived(term, "agrees", False, "the provider's record matches the stated fact")
    return Derived(term, "disagrees", False, "the provider's record differs from the stated fact")


# ---------------------------------------------------------------- record_binding

_SAFE = 2 ** 53
_INTEGER_TOKEN = re.compile(r"^-?(0|[1-9][0-9]*)$")
_NUMBER_TOKEN = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$")


def number_in_profile(token: str, profile: str) -> Derived:
    """Judge one JSON number token against a canonicalization profile.

    ``rfc8785`` accepts every finite token; ``jcs_safe_integer_v1`` refuses a token whose nearest double
    is an integer of magnitude 2^53 or more, however it is written; ``jcs_integer_only_v1`` refuses any
    token that is not an integer written without fraction or exponent, whose magnitude is 2^53 or more, or
    that is ``-0`` (RFC 8785 writes it as ``0``, a rewrite the profile refuses). The whole string must be
    the token: a trailing line feed is not a number. A refusal here is a refusal by declared profile, never a
    canonicalization failure.
    """
    term = "canonicalization"
    if profile not in ("rfc8785", "jcs_safe_integer_v1", "jcs_integer_only_v1"):
        return _refuse(term, "profile-not-a-json-canonicalization")
    if not isinstance(token, str) or not _NUMBER_TOKEN.fullmatch(token):
        return _refuse(term, "not-a-json-number")
    double = float(token)
    if double in (float("inf"), float("-inf")):
        return _refuse(term, "number-not-finite")
    if profile == "jcs_integer_only_v1":
        if not _INTEGER_TOKEN.fullmatch(token):
            return _refuse(term, "outside-profile-not-an-integer")
        if token == "-0":
            return _refuse(term, "outside-profile-negative-zero")
        if abs(int(token)) >= _SAFE:
            return _refuse(term, "outside-profile-integer-range")
    if profile == "jcs_safe_integer_v1" and double.is_integer() and abs(double) >= _SAFE:
        return _refuse(term, "outside-profile-unsafe-integer")
    return Derived(term, profile, False, "in profile")


def sequence_numbers(seqs: list, start: int = 0) -> Derived:
    """Judge a stream's seq values: from ``start``, rising by exactly 1, each in 0 to 2^53-1.

    ``start`` (0, or the number a supplied anchor names) is held to the same range as every seq value.
    """
    term = "sequence_number"
    if isinstance(start, bool) or not isinstance(start, int) or not 0 <= start < _SAFE:
        return _refuse(term, "seq-start-not-a-safe-count")
    expected = start
    for seq in seqs:
        if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < _SAFE:
            return _refuse(term, "seq-not-a-safe-count")
        if seq != expected:
            return _refuse(term, "seq-repeats" if seq < expected else "seq-skips")
        expected += 1
    return Derived(term, str(expected - start), False, "contiguous")


def _safe_count(value) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 0 <= value < _SAFE


def key_history(history: list[dict], key_id: str, issued_at: int) -> Derived:
    """Derive key_history for ``key_id`` as of ``issued_at`` from a key history.

    Each history entry is {key, authorized_from, retired_at?, revoked_at?}; times are integers in 0 to
    2^53-1. A key may have several entries (re-authorization windows); every entry that names the key is
    read, never only the first. A revocation of the key in any entry applies at its effective time, which
    may precede its publication: at or before issuance it gives key_revoked. An entry that is not an object,
    or a window whose retired_at precedes its authorized_from, makes the history malformed. The key was authorized at
    issuance when some window [authorized_from, retired_at) holds it. It is key_current only when such a
    window is still open and no revocation is recorded; a retirement or a revocation effective after
    issuance gives key_rotated_out, and the record stays valid. An unnamed key is key_unknown.
    """
    term = "key_history"
    if not _safe_count(issued_at):
        return _refuse(term, "issued-at-outside-the-safe-range")
    if not isinstance(history, list) or not all(isinstance(e, dict) for e in history):
        return _refuse(term, "history-entry-malformed")
    entries = [e for e in history if e.get("key") == key_id]
    if not entries:
        return Derived(term, "key_unknown", False, "the history does not name the key")
    for entry in entries:
        times = [entry.get("authorized_from"), *(entry[k] for k in ("retired_at", "revoked_at")
                                                 if entry.get(k) is not None)]
        if not all(_safe_count(t) for t in times):
            return _refuse(term, "history-entry-malformed")
        if entry.get("retired_at") is not None and entry["retired_at"] < entry["authorized_from"]:
            return _refuse(term, "history-window-ends-before-it-starts")
    revocations = [e["revoked_at"] for e in entries if e.get("revoked_at") is not None]
    if any(r <= issued_at for r in revocations):
        return Derived(term, "key_revoked", False, "revoked at or before issuance")
    covering = [e for e in entries if e["authorized_from"] <= issued_at
                and (e.get("retired_at") is None or e["retired_at"] > issued_at)]
    if not covering:
        return Derived(term, "key_not_authorized_at_issue", False, "not authorized at issuance")
    if not revocations and any(e.get("retired_at") is None for e in covering):
        return Derived(term, "key_current", False, "authorized at issuance and still")
    return Derived(term, "key_rotated_out", False, "authorized at issuance, ended afterwards")


TRAJECTORY_HEAD_DOMAIN = b"agent-evidence/record-binding/v1/trajectory-head\n"


def trajectory_head_preimage(stream_id: str, last_digest: str, count: int) -> bytes:
    """The bytes a trajectory head signs: the head's own signing domain, then the stream identity, the last
    record's digest and the count, each on its own line. A record signature never verifies as a head."""
    if not stream_id or not last_digest or not _safe_count(count) or any(
            "\n" in field for field in (stream_id, last_digest)):
        raise ValueError("a head names a stream, a digest and a count in 0 to 2^53-1, none spanning a line")
    return TRAJECTORY_HEAD_DOMAIN + f"{stream_id}\n{last_digest}\n{count}".encode()


def trajectory_head(head: dict | None, stream_id: str, last_digest: str, count: int) -> Derived:
    """Derive trajectory_head for the stream ``stream_id`` the consumer asked for, walked to ``last_digest``
    over ``count`` records.

    ``head`` is None or {stream_id, digest, count, witness_verified, producer_verified}, where the two
    booleans say whether the head's signature over ``trajectory_head_preimage`` verifies under a pinned
    witness key the producer does not hold, or under the producer's own key. A head that names no stream,
    or another stream, does not close this one. A head whose digest or count differs from the walk is
    refused. A head whose fields trajectory_head_preimage cannot carry (a field spanning a line) has no signed
    bytes and is refused, whatever its booleans say. A head no key verifies is refused, never read as absent.
    """
    term = "trajectory_head"
    if head is None:
        return Derived(term, "absent", False, "no signed head; the end of the stream is not established")
    if not isinstance(head, dict):
        return _refuse(term, "head-not-an-object")
    if not head.get("stream_id") or not isinstance(head["stream_id"], str):
        return _refuse(term, "head-names-no-stream")
    if head["stream_id"] != stream_id:
        return _refuse(term, "head-names-another-stream")
    if not _safe_count(head.get("count")) or head["count"] != count:
        return _refuse(term, "head-count-differs-from-walk")
    if head.get("digest") != last_digest:
        return _refuse(term, "head-digest-differs-from-walk")
    try:
        trajectory_head_preimage(head["stream_id"], head["digest"], head["count"])
    except (ValueError, TypeError):
        return _refuse(term, "head-fields-have-no-signed-bytes")
    if head.get("witness_verified") is True:
        return Derived(term, "witnessed", False, "signed under a pinned witness key")
    if head.get("producer_verified") is True:
        return Derived(term, "producer_signed", False, "signed only by the producer")
    return _refuse(term, "head-signature-does-not-verify")


# ---------------------------------------------------------------- evaluation_claim

_DECISION_OF = {"accepted": 0, "rejected": 1, "indeterminate": 2}
_SCOPE_DIMENSIONS = ("currency", "amount", "merchant", "expiry", "action", "single_use")


def verification_decision(checks: list[str]) -> Derived:
    """Combine per-check results ('pass', 'fail', 'undecided') into accepted, rejected or indeterminate."""
    term = "verification_decision"
    if not checks or any(c not in ("pass", "fail", "undecided") for c in checks):
        return _refuse(term, "checks-not-registered-results")
    if "fail" in checks:
        return Derived(term, "rejected", False, "a check failed")
    if "undecided" in checks:
        return Derived(term, "indeterminate", False, "a check could not be decided")
    return Derived(term, "accepted", False, "every check passed")


def exit_status(decision: str) -> int:
    """The verifier exit status for a verification_decision value: 0, 1 or 2."""
    return _DECISION_OF[decision]


def check_outcomes(report: list[tuple[str, str]], profile: list[str]) -> Derived:
    """Hold a per-check report to the profile's order: every check named once, nothing passes after a fail.

    The report derives fail when a check failed, pass only when every check ran and passed, and
    not_evaluated when none failed and at least one did not run (its inputs were absent): a report whose
    checks did not run never reads as a pass.
    """
    term = "check_outcome"
    if [name for name, _ in report] != profile:
        return _refuse(term, "report-does-not-list-the-profile-in-order")
    failed = skipped = False
    for _, outcome in report:
        if outcome not in ("pass", "fail", "not_evaluated"):
            return _refuse(term, "outcome-not-registered")
        if failed and outcome != "not_evaluated":
            return _refuse(term, "check-after-a-failure-reported-as-run")
        failed = failed or outcome == "fail"
        skipped = skipped or outcome == "not_evaluated"
    if failed:
        return Derived(term, "fail", False, "report follows the profile; a check failed")
    if skipped:
        return Derived(term, "not_evaluated", False, "report follows the profile; a check did not run")
    return Derived(term, "pass", False, "report follows the profile; every check ran and passed")


_ISO_4217 = re.compile(r"[A-Z]{3}")
_SCOPE_TYPES = (("currency", "currency"), ("amount_ceiling_minor", "count"), ("merchants", "strings"),
                ("expires_at", "count"), ("actions", "strings"), ("single_use", "bool"))
_PAYMENT_TYPES = (("currency", "currency"), ("amount_minor", "count"), ("merchant", "string"),
                  ("at", "count"), ("action", "string"), ("prior_uses", "count"))
_TYPE_CHECKS = {
    "currency": lambda v: isinstance(v, str) and _ISO_4217.fullmatch(v) is not None,
    "count": _safe_count,
    "string": lambda v: isinstance(v, str),
    "strings": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    "bool": lambda v: isinstance(v, bool),
}


class MalformedInputs(ValueError):
    """An evaluator input is missing, of another type or outside its range; the record is malformed."""


def _require(obj, members: tuple, side: str) -> None:
    if not isinstance(obj, dict):
        raise MalformedInputs(f"{side} is not an object")
    for name, kind in members:
        if name not in obj or not _TYPE_CHECKS[kind](obj[name]):
            raise MalformedInputs(f"{side}.{name} is missing, of another type or outside its range")


def payment_scope_v1(scope: dict, payment: dict) -> tuple[str, str | None]:
    """The evaluator payment-scope/v1: (``within`` or ``outside``, the first failing dimension or None).

    ``scope``: currency, amount_ceiling_minor (int), merchants (list), expires_at (int), actions (list),
    single_use (bool). ``payment``: currency, amount_minor (int), merchant, at (int), action, prior_uses
    (int). Integers are 0 to 2^53-1 and never booleans, currencies are three uppercase letters, lists hold
    strings only. Any input that is missing, of another type or outside its range raises MalformedInputs;
    no default is filled. Dimensions are checked in the fixed order currency, amount, merchant, expiry,
    action, single_use.
    """
    _require(scope, _SCOPE_TYPES, "scope")
    _require(payment, _PAYMENT_TYPES, "payment")
    failing = {
        "currency": payment["currency"] != scope["currency"],
        "amount": payment["amount_minor"] > scope["amount_ceiling_minor"],
        "merchant": payment["merchant"] not in scope["merchants"],
        "expiry": payment["at"] > scope["expires_at"],
        "action": payment["action"] not in scope["actions"],
        "single_use": scope["single_use"] and payment["prior_uses"] > 0,
    }
    for dimension in _SCOPE_DIMENSIONS:
        if failing[dimension]:
            return "outside", dimension
    return "within", None


EVALUATORS = {
    "https://probityai.github.io/agent-evidence-vectors/evaluator/payment-scope/v1":
        lambda inputs: payment_scope_v1(inputs["scope"], inputs["payment"])[0],
}


def _absolute_https(name: object) -> bool:
    if not isinstance(name, str) or any(c.isspace() for c in name):
        return False
    parts = urlsplit(name)
    return parts.scheme == "https" and bool(parts.hostname)


def asserted_verdict(record: dict, evaluators: dict | None = None) -> Derived:
    """Re-derive a record's asserted verdict under the evaluator it names; never read the assertion as input.

    A named evaluator must be an absolute https URI with a host. Inputs the named evaluator holds as
    malformed (missing, of another type, out of range) refuse the record; they never re-derive a verdict.
    """
    term = "asserted_verdict"
    known = EVALUATORS if evaluators is None else evaluators
    name = record.get("evaluator")
    if name is not None and not _absolute_https(name):
        return _refuse(term, "evaluator-not-an-https-uri")
    if name not in known:
        return Derived(term, "evaluator_unknown", False, "no evaluator the verifier holds")
    inputs = record.get("inputs")
    if not isinstance(inputs, dict):
        return _refuse(term, "evaluator-inputs-malformed")
    try:
        rederived = known[name](inputs)
    except (MalformedInputs, KeyError, TypeError):
        return _refuse(term, "evaluator-inputs-malformed")
    if rederived == record.get("asserted"):
        return Derived(term, "rederived_agrees", False, "re-derived verdict equals the assertion")
    return Derived(term, "asserted_verdict_contradicted", False, "re-derived verdict differs")


def vacuity_witness(passed: bool, witness: bool | None) -> Derived:
    """Judge a property result with its reachability witness (None: no witness declared or run).

    A failing property with a falsified witness is refused: a property over an unreachable guarded state
    has no trace that can violate it, so the two results contradict each other.
    """
    term = "vacuity_witness"
    if witness is None:
        return Derived(term, "no_witness", False, "no witness")
    if passed and not witness:
        return Derived(term, "vacuous_pass", True, "the guarded state is unreachable")
    if not witness:
        return _refuse(term, "witness-contradicts-a-failing-property")
    return Derived(term, "witnessed", False, "the guarded state is reachable")


def signer_distinctness(named: list[dict], signatures: dict, required: int, issuer_key: str | None = None) -> Derived:
    """Count signers by distinct key and distinct authority.

    ``named``: [{id, key, authority}]; ``signatures``: {id: verifies (bool)}; ``issuer_key``: the issuer's
    own key, which never counts as a cosigner. Two named signers under one id share one signature, so the
    second is named and not signing. A count of distinct keys below ``required`` is one_key_two_ids when a
    key was listed twice and below_threshold otherwise.
    """
    term = "signer_distinctness"
    seen: set = set()
    for signer in named:
        if signer["id"] in seen:
            return Derived(term, "key_named_not_signing", True, f"{signer['id']} names two signers")
        seen.add(signer["id"])
        if signatures.get(signer["id"]) is not True:
            return Derived(term, "key_named_not_signing", True, f"{signer['id']} named and not signing")
    keys = [s["key"] for s in named]
    if len(set(keys)) < required:
        if len(set(keys)) < len(keys):
            return Derived(term, "one_key_two_ids", True, "one key counted twice")
        return Derived(term, "below_threshold", True, "fewer distinct signers than required")
    if issuer_key is not None and issuer_key in keys:
        return Derived(term, "own_key_as_cosigner", True, "the issuer's key counted as a cosigner")
    if len({s["authority"] for s in named}) < required:
        return Derived(term, "one_authority_threshold", True, "threshold met by one authority")
    return Derived(term, "distinct", False, "distinct keys and authorities")


_LIFECYCLE_KINDS = ("decision", "control", "execution")


def _group_state(group: list[dict], active: frozenset[str]) -> str:
    """The state of one (decision, instruction) group, decision records included."""
    if any(a["kind"] not in _LIFECYCLE_KINDS for a in group):
        raise MalformedInputs("an artifact kind is not decision, control or execution")
    ids = [a["id"] for a in group]
    if len(set(ids)) < len(ids):
        return "indeterminate"
    decisions = [a for a in group if a["kind"] == "decision"]
    authorize = [a for a in group if a["kind"] == "control"]
    execute = [a for a in group if a["kind"] == "execution"]
    if not authorize:
        return "not_evaluated" if execute else "missing"
    if not execute or not decisions:
        return "missing"
    if any(a["authenticated"] is not True for a in group):
        return "failure"
    if any(a["binding"] not in active for a in group):
        return "not_evaluated"
    digests = {a["digest"] for a in authorize} | {a["digest"] for a in execute}
    return "satisfied" if len(digests) == 1 else "failure"


LIFECYCLE_TAGS = frozenset(
    f"agent-evidence/lifecycle-binding/v1/{kind}/{purpose}"
    for kind in _LIFECYCLE_KINDS for purpose in ("hash", "signature"))


def lifecycle_preimage(artifact_type: str, purpose: str, canonical: bytes) -> bytes:
    """The domain-separated pre-image of one lifecycle artifact: tag, one 0x0A byte, canonical bytes.

    The tag is agent-evidence/lifecycle-binding/v1/TYPE/PURPOSE from a closed set of six; any other type or
    purpose raises MalformedInputs, so one signature never verifies as another artifact type or as a hash.
    """
    tag = f"agent-evidence/lifecycle-binding/v1/{artifact_type}/{purpose}"
    if tag not in LIFECYCLE_TAGS or not isinstance(canonical, bytes):
        raise MalformedInputs("the lifecycle pre-image tag is not registered")
    return tag.encode("ascii") + b"\n" + canonical


def lifecycle_binding(artifacts: list[dict], active_bindings: frozenset[str]) -> dict:
    """The lifecycle-binding state per (decision, instruction) group.

    Each artifact is {id, kind ('decision', 'control' or 'execution'), decision, instruction, digest,
    authenticated (bool: the signature verifies under the key its producer's binding names), binding}. Any
    other kind raises MalformedInputs: an unregistered artifact type fails closed. The rules apply in this
    order to every artifact of the group, the cited decision record included: two artifacts with one id
    give indeterminate; an execution no control covers gives not_evaluated; a group without a control, an
    execution or the decision record it cites is missing; an artifact that does not authenticate gives
    failure; one bound by a binding that is not active gives not_evaluated; otherwise every control digest
    must equal every execution digest. Returns {(decision, instruction): state}.
    """
    groups: dict[tuple, list[dict]] = {}
    for artifact in artifacts:
        groups.setdefault((artifact["decision"], artifact["instruction"]), []).append(artifact)
    return {key: _group_state(group, active_bindings) for key, group in groups.items()}


_TIME_PAST_AND_FUTURE = ("max_age", "uncertainty", "clock_skew_tolerance")
_TIME_ANCHOR = ("anchor_within", "block_time_allowance", "anchor_early_allowance")


def time_bounds(issued_at: int, check_time: int, anchor_time: int | None, profile: dict) -> Derived:
    """Asymmetric freshness and the late anchor bound, with every input range-checked before arithmetic.

    ``profile``: max_age, uncertainty, clock_skew_tolerance, and, when an anchor time is given,
    anchor_within, block_time_allowance and anchor_early_allowance (seconds). A profile missing a member the
    check needs is refused, never defaulted. Past bound: max_age plus uncertainty. Future bound:
    clock_skew_tolerance only. Anchor: at most anchor_within plus block_time_allowance after issuance, and at
    most anchor_early_allowance before it. Every bound admits equality.
    """
    term = "clock_skew_tolerance"
    needed = _TIME_PAST_AND_FUTURE + (_TIME_ANCHOR if anchor_time is not None else ())
    if any(name not in profile for name in needed):
        return _refuse(term, "time-profile-member-missing")
    values = [issued_at, check_time, *(v for v in [anchor_time] if v is not None), *profile.values()]
    if not all(_safe_count(v) for v in values):
        return _refuse(term, "time-member-outside-the-safe-range")
    if issued_at > check_time + profile["clock_skew_tolerance"]:
        return _refuse(term, "issued-in-the-future")
    if check_time - issued_at > profile["max_age"] + profile["uncertainty"]:
        return _refuse(term, "too-old")
    if anchor_time is not None and anchor_time > issued_at + profile["anchor_within"] + profile["block_time_allowance"]:
        return _refuse("anchor_within", "anchor-late")
    if anchor_time is not None and anchor_time + profile["anchor_early_allowance"] < issued_at:
        return _refuse("anchor_early_allowance", "anchor-before-issuance")
    return Derived(term, "in-bounds", False, "inside every bound")
