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
