"""Pin each token issuer's signing keys by RFC 7638 thumbprint before the first call.

A client that fetches an issuer's JWKS on first use trusts whoever answers that
fetch. ``PinnedIssuers`` takes every pin when it is built, before any call. Each
issuer carries a ``PinSet``: the thumbprints of the keys it may sign with and an
epoch, a positive integer that only grows. A key verifies when its thumbprint is
in the issuer's current set, so an issuer can publish its next key before it
signs with it and a client accepts both during the overlap.

A pin set changes only by ``rotate``, which returns a new ``PinnedIssuers`` and
never changes the one it was called on. A rotation needs a strictly greater
epoch; the new set may hold fewer keys, which is how a retired or compromised key
leaves. The highest epoch each issuer has reached is the client's state:
``epochs`` reads it out, and a client restarting from stored configuration passes
it back as ``seen_epochs``, so an older configuration on disk cannot undo a
rotation the client already made. Everything refuses:

* a mixed configuration: an issuer the client calls with no pin set while another
  issuer is pinned, a pin set for an issuer the client does not call, or pins in a
  configuration declared unpinned;
* conflicting pins: one issuer given two different sets at the same epoch;
* a downgrade: a set whose epoch is lower than the issuer's current or seen
  epoch;
* an empty set, a non-positive or non-integer epoch, a malformed thumbprint;
* a key whose thumbprint is not in the set, a kid the JWKS does not hold exactly
  once, a private or symmetric key, and a failed or malformed fetch, each with no
  fallback to the unpinned path.

Thumbprints follow RFC 7638 section 3.2 (https://www.rfc-editor.org/rfc/rfc7638)
with the OKP members of RFC 8037 section 2 (https://www.rfc-editor.org/rfc/rfc8037).

``pinning`` reports the agent-evidence-vocabulary ``issuer_key_pinning`` value:
``pinned_before_first_call`` or ``unpinned``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
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


class PinDowngrade(PinError):
    code = "pin-downgrade"


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


@dataclass(frozen=True)
class PinSet:
    """The thumbprints one issuer may sign with, at one epoch."""

    epoch: int
    thumbprints: frozenset[str]

    @classmethod
    def of(cls, epoch: int, *thumbprints: str) -> PinSet:
        return cls(epoch, frozenset(thumbprints))

    def checked(self, issuer: str) -> PinSet:
        """This set, after refusing a bad epoch, an empty set or a malformed thumbprint."""
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or self.epoch < 1:
            raise PinError(f"pin set for {issuer} has epoch {self.epoch!r}, not a positive integer")
        if not isinstance(self.thumbprints, frozenset) or not self.thumbprints:
            raise PinError(f"pin set for {issuer} holds no thumbprint")
        for value in self.thumbprints:
            _thumbprint_value(value, issuer)
        return self


def https_fetch(issuer: str, timeout: float = 10.0) -> Mapping:
    """Read the issuer's JWKS through its OpenID discovery document, https only."""

    def get(url: str) -> Mapping:
        if urlsplit(url).scheme != "https":
            raise FetchFailed(f"refusing a non-https URL {url!r}")
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
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


def _pin_table(pins: Iterable[tuple[str, PinSet]] | Mapping[str, PinSet]) -> dict[str, PinSet]:
    pairs = list(pins.items()) if isinstance(pins, Mapping) else list(pins)
    table: dict[str, PinSet] = {}
    for issuer, pin_set in pairs:
        key = _issuer_key(issuer)
        if not isinstance(pin_set, PinSet):
            raise PinError(f"pin for {key} is not a PinSet")
        value = pin_set.checked(key)
        held = table.get(key)
        if held is not None and held != value:
            if held.epoch == value.epoch:
                raise ConflictingPins(f"{key} has two different pin sets at epoch {value.epoch}")
            raise ConflictingPins(f"{key} is configured at epochs {held.epoch} and {value.epoch}")
        table[key] = value
    return table


def _epoch_floor(seen: Mapping[str, int]) -> dict[str, int]:
    floor: dict[str, int] = {}
    for issuer, epoch in seen.items():
        key = _issuer_key(issuer)
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
            raise PinError(f"seen epoch for {key} is {epoch!r}, not a positive integer")
        floor[key] = max(epoch, floor.get(key, 0))
    return floor


def _check_coverage(called: frozenset[str], table: Mapping[str, PinSet], unpinned: bool) -> None:
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


def _check_floor(table: Mapping[str, PinSet], floor: Mapping[str, int], unpinned: bool) -> None:
    if unpinned and floor:
        raise PinDowngrade(f"issuers {sorted(floor)} were pinned before; an unpinned configuration would downgrade them")
    for key, pin_set in table.items():
        if pin_set.epoch < floor.get(key, 0):
            raise PinDowngrade(f"{key} is configured at epoch {pin_set.epoch}, below the epoch {floor[key]} it already reached")


class PinnedIssuers:
    """The issuers a client calls, each pinned to a set of thumbprints, fixed at construction."""

    def __init__(self, issuers: Iterable[str],
                 pins: Iterable[tuple[str, PinSet]] | Mapping[str, PinSet] = (),
                 *, unpinned: bool = False, seen_epochs: Mapping[str, int] | None = None,
                 fetch: Fetch = https_fetch) -> None:
        table = _pin_table(pins)
        called = frozenset(_issuer_key(i) for i in issuers)
        _check_coverage(called, table, unpinned)
        floor = _epoch_floor(seen_epochs or {})
        stray = sorted(set(floor) - called)
        if stray:
            raise MixedConfiguration(f"seen epochs for issuers the client does not call: {stray}")
        _check_floor(table, floor, unpinned)
        self._issuers = called
        self._pins = table
        self._fetch = fetch

    @property
    def pinning(self) -> str:
        """The issuer_key_pinning value this configuration earns."""
        return PINNED if self._pins else UNPINNED

    @property
    def epochs(self) -> dict[str, int]:
        """The epoch each pinned issuer is at: the state to store and pass back as ``seen_epochs``."""
        return {key: pin_set.epoch for key, pin_set in sorted(self._pins.items())}

    def pin_for(self, issuer: str) -> PinSet | None:
        return self._pins.get(_issuer_key(issuer))

    def rotate(self, issuer: str, pin_set: PinSet) -> PinnedIssuers:
        """A new client with ``issuer`` moved to ``pin_set``; this one is unchanged.

        The new epoch must be greater than the current one. The same set at the same
        epoch is accepted and changes nothing, so a repeated delivery of one rotation
        is harmless; a different set at the same epoch is a conflict.
        """
        key = _issuer_key(issuer)
        current = self._pins.get(key)
        if current is None:
            raise MixedConfiguration(f"{key} is not a pinned issuer; rotation cannot pin an unpinned issuer")
        value = pin_set.checked(key) if isinstance(pin_set, PinSet) else None
        if value is None:
            raise PinError(f"rotation for {key} is not a PinSet")
        if value.epoch < current.epoch:
            raise PinDowngrade(f"{key} is at epoch {current.epoch}; a set at epoch {value.epoch} would downgrade it")
        if value.epoch == current.epoch and value != current:
            raise ConflictingPins(f"{key} already has a different pin set at epoch {value.epoch}")
        pins = dict(self._pins)
        pins[key] = value
        return PinnedIssuers(self._issuers, pins, fetch=self._fetch)

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
        pin_set = self._pins.get(key)
        if pin_set is not None and thumbprint not in pin_set.thumbprints:
            raise ThumbprintMismatch(f"key {kid!r} of {key} has thumbprint {thumbprint}, "
                                     f"not in the epoch {pin_set.epoch} set {sorted(pin_set.thumbprints)}")
        return jwk
