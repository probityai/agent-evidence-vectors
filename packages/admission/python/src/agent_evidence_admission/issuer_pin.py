"""Pin each token issuer's signing key by its RFC 7638 thumbprint before the first call.

A client that fetches an issuer's JWKS on first use trusts whoever answers that
fetch. ``PinnedIssuers`` takes every pin when it is built, before any call, and
never changes them afterwards. It refuses:

* a mixed configuration: an issuer the client calls with no pin while another
  issuer is pinned, a pin for an issuer the client does not call, or pins in a
  configuration declared unpinned;
* conflicting pins: one issuer given two different thumbprints;
* a key whose thumbprint differs from the pin, a kid the JWKS does not hold
  exactly once, a private or symmetric key, and a failed or malformed fetch,
  each with no fallback to the unpinned path.

``pinning`` reports the agent-evidence-vocabulary ``issuer_key_pinning`` value:
``pinned_before_first_call`` or ``unpinned``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from urllib.parse import urlsplit

PINNED = "pinned_before_first_call"
UNPINNED = "unpinned"

#: RFC 7638 section 3.2 and RFC 8037 section 2: the required members per key type.
_REQUIRED_MEMBERS = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "oct": ("k", "kty"),
}
_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth")
_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

Fetch = Callable[[str], Mapping]


class PinError(Exception):
    """The base of every refusal. ``code`` names the refusal."""

    code = "pin-error"


class MixedConfiguration(PinError):
    code = "pin-mixed-configuration"


class ConflictingPins(PinError):
    code = "pin-conflict"


class ThumbprintMismatch(PinError):
    code = "pin-thumbprint-mismatch"


class KeyNotFound(PinError):
    code = "pin-key-not-found"


class FetchFailed(PinError):
    code = "pin-fetch-failed"


class InvalidKey(PinError):
    code = "pin-invalid-key"


def jwk_thumbprint(jwk: Mapping) -> str:
    """The RFC 7638 SHA-256 thumbprint of ``jwk``, base64url without padding."""
    kty = jwk.get("kty")
    members = _REQUIRED_MEMBERS.get(kty) if isinstance(kty, str) else None
    if members is None:
        raise InvalidKey(f"unsupported key type {kty!r}")
    missing = [m for m in members if not isinstance(jwk.get(m), str) or not jwk.get(m)]
    if missing:
        raise InvalidKey(f"{kty} key lacks required member(s) {missing}")
    canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"),
                           sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _issuer_key(issuer: str) -> str:
    parts = urlsplit(issuer)
    if parts.scheme != "https" or not parts.hostname:
        raise PinError(f"issuer {issuer!r} is not an https URL")
    return issuer.rstrip("/")


def _thumbprint_value(value: object, issuer: str) -> str:
    if not isinstance(value, str) or len(value) != 43 or not set(value) <= _B64URL:
        raise PinError(f"pin for {issuer} is not a base64url SHA-256 thumbprint")
    return value


def https_fetch(issuer: str, timeout: float = 10.0) -> Mapping:
    """Read the issuer's JWKS through its OpenID discovery document, https only."""

    def get(url: str) -> Mapping:
        if urlsplit(url).scheme != "https":
            raise FetchFailed(f"refusing a non-https URL {url!r}")
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
                return json.loads(response.read())
        except (OSError, ValueError) as exc:
            raise FetchFailed(f"could not read {url}: {exc}") from exc

    discovery = get(issuer.rstrip("/") + "/.well-known/openid-configuration")
    if str(discovery.get("issuer", "")).rstrip("/") != issuer.rstrip("/"):
        raise FetchFailed(f"discovery names issuer {discovery.get('issuer')!r}, not {issuer!r}")
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise FetchFailed("discovery document has no jwks_uri")
    return get(jwks_uri)


def _pin_table(pins: Iterable[tuple[str, str]] | Mapping[str, str]) -> dict[str, str]:
    pairs = list(pins.items()) if isinstance(pins, Mapping) else list(pins)
    table: dict[str, str] = {}
    for issuer, thumbprint in pairs:
        key = _issuer_key(issuer)
        value = _thumbprint_value(thumbprint, issuer)
        if table.get(key, value) != value:
            raise ConflictingPins(f"{key} is pinned to both {table[key]} and {value}")
        table[key] = value
    return table


def _check_coverage(called: frozenset[str], table: dict[str, str], unpinned: bool) -> None:
    if not called:
        raise PinError("no issuer configured")
    stray = sorted(set(table) - called)
    if stray:
        raise MixedConfiguration(f"pins for issuers the client does not call: {stray}")
    if unpinned and table:
        raise MixedConfiguration("a configuration declared unpinned carries pins")
    bare = sorted(called - set(table))
    if not unpinned and bare:
        raise MixedConfiguration(f"issuers with no pin: {bare}")


class PinnedIssuers:
    """The issuers a client calls, each pinned by thumbprint, fixed at construction."""

    def __init__(self, issuers: Iterable[str],
                 pins: Iterable[tuple[str, str]] | Mapping[str, str] = (),
                 *, unpinned: bool = False, fetch: Fetch = https_fetch) -> None:
        table = _pin_table(pins)
        called = frozenset(_issuer_key(i) for i in issuers)
        _check_coverage(called, table, unpinned)
        self._issuers = called
        self._pins = table
        self._fetch = fetch

    @property
    def pinning(self) -> str:
        """The issuer_key_pinning value this configuration earns."""
        return PINNED if self._pins else UNPINNED

    def pin_for(self, issuer: str) -> str | None:
        return self._pins.get(_issuer_key(issuer))

    def _jwks(self, key: str) -> list:
        try:
            jwks = self._fetch(key)
        except PinError:
            raise
        except Exception as exc:  # every fetch failure refuses; there is no unpinned fallback
            raise FetchFailed(f"could not fetch the JWKS of {key}: {exc}") from exc
        keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
        if not isinstance(keys, list):
            raise FetchFailed(f"the JWKS of {key} has no keys array")
        return keys

    def key_for(self, issuer: str, kid: str) -> dict:
        """The issuer's public key ``kid``, checked against its pin before it is returned."""
        key = _issuer_key(issuer)
        if key not in self._issuers:
            raise PinError(f"{key} is not a configured issuer")
        matches = [k for k in self._jwks(key) if isinstance(k, Mapping) and k.get("kid") == kid]
        if len(matches) != 1:
            raise KeyNotFound(f"the JWKS of {key} holds {len(matches)} keys with kid {kid!r}")
        jwk = dict(matches[0])
        if jwk.get("kty") == "oct" or any(m in jwk for m in _PRIVATE_MEMBERS):
            raise InvalidKey(f"key {kid!r} of {key} is not a public asymmetric key")
        thumbprint = jwk_thumbprint(jwk)
        pin = self._pins.get(key)
        if pin is not None and thumbprint != pin:
            raise ThumbprintMismatch(f"key {kid!r} of {key} has thumbprint {thumbprint}, pinned {pin}")
        return jwk
