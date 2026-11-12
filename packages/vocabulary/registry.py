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
