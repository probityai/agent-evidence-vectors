"""An MCP server's decision on an OAuth access token: audience, issuer, resource, lifetime, binding.

The MCP authorization specification requires a server to accept only tokens issued for it, and
the audience-injection class (a token whose audience is the authorization server's own token
endpoint, which a confused client can be steered into requesting) shows why the comparison must be
exact. This rule set decides on the claims; the token's signature is checked by the server's key
authority before admission, and this set does not check it.

The document is the decoded token::

    {"header": {"typ": "at+jwt", ...}, "claims": {"iss": ..., "aud": ..., "exp": ...},
     "presentation": "bearer" | "dpop"}

Options carry what the server knows: ``resource`` (its canonical URI), ``issuers`` (the
authorization servers its protected-resource metadata advertises, RFC 9728), ``tokenEndpoints``
(their token endpoints), ``now`` (seconds since the epoch) and ``skew`` (seconds, default 60). A
decision the server cannot make for want of one of these is a refusal, never an admission: with no
``tokenEndpoints`` the audience check cannot tell a token whose ``aud`` array holds both this
resource and a token endpoint from a clean one, so it refuses ``token-endpoints-not-configured``
(pass ``[]`` to say there are none).

A token presented with DPoP must be bound to a key (``cnf.jkt``, RFC 9449 section 6.1): the
resource checks the proof's key against the bound one (section 7.1), and an unbound token offers
nothing to check against (``dpop-without-binding``).

Each comparison is exact, case-sensitive and without URI normalization: an audience that matches
only after a trailing slash or a case change is refused under its own code, so a log says which
confusion was tried. An option of the wrong type (``issuers`` given as one string, where a
membership test would match any substring of it) is refused as ``option-malformed``, never read.

The header's ``typ`` is the one place where comparison is not exact, because RFC 7515 section
4.1.9 makes it a media type: case-insensitive, with ``application/`` optional. RFC 9068 section 4
has a resource server refuse every ``typ`` but ``at+jwt``, so an identity assertion grant spelled
``application/oauth-id-jag+jwt`` or ``OAuth-ID-JAG+JWT`` is still refused as one, and an ID token
(``JWT``) or a token with no ``typ`` is refused as not an access token.
"""

from __future__ import annotations

from typing import Any

from .rules import Check, Context, RuleSet, register
from .strict_json import MAX_SAFE_INTEGER, Refusal

DEFAULT_SKEW = 60
ACCESS_TOKEN_TYPE = "at+jwt"
ID_JAG_TYPE = "oauth-id-jag+jwt"
#: The type each option must have; a value of another type is a configuration error, not a pass.
OPTION_TYPES: dict[str, str] = {
    "resource": "a non-empty string",
    "issuers": "a list of strings",
    "tokenEndpoints": "a list of strings",
    "now": "an integer",
    "skew": "a non-negative integer",
}


def _claims(context: Context) -> dict[str, Any]:
    document = context.document
    claims = document.get("claims") if isinstance(document, dict) else None
    if not isinstance(claims, dict):
        raise Refusal("token-shape-malformed", "/claims", "no claims object")
    return claims


def _well_typed(name: str, value: Any) -> bool:
    if name == "resource":
        return isinstance(value, str) and bool(value)
    if name in ("issuers", "tokenEndpoints"):
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    integer = isinstance(value, int) and not isinstance(value, bool)
    return integer and (name == "now" or value >= 0)


def _option(context: Context, name: str, code: str, default: Any = None) -> Any:
    value = context.options.get(name, default)
    if value is None:
        raise Refusal(code, "", f"the server's {name} was not configured, so this decision cannot be made")
    if not _well_typed(name, value):
        raise Refusal("option-malformed", "", f"the option {name} is {OPTION_TYPES[name]}, not {type(value).__name__}")
    return value


def media_type(typ: Any) -> str | None:
    """A ``typ`` header as RFC 7515 compares it: lowercased, ``application/`` dropped."""
    if not isinstance(typ, str):
        return None
    lowered = typ.lower()
    return lowered.removeprefix("application/")


def _normalized(uri: str) -> str:
    text = uri.strip().lower()
    while text.endswith("/"):
        text = text[:-1]
    return text


def _check_shape(context: Context) -> None:
    _claims(context)
    header = context.document.get("header", {})
    if not isinstance(header, dict):
        raise Refusal("token-shape-malformed", "/header", "the header is not an object")
    if context.document.get("presentation") not in ("bearer", "dpop"):
        raise Refusal("token-shape-malformed", "/presentation", "presentation is bearer or dpop")


def _check_issuer(context: Context) -> None:
    claims = _claims(context)
    issuers = _option(context, "issuers", "issuers-not-configured")
    if "iss" not in claims:
        raise Refusal("iss-missing", "/claims/iss", "the token names no issuer")
    if claims["iss"] not in issuers:
        raise Refusal("iss-not-advertised", "/claims/iss", "the issuer is not an authorization server this resource advertises")


def _audiences(claims: dict[str, Any]) -> list[str]:
    aud = claims.get("aud")
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list) and aud and all(isinstance(a, str) for a in aud):
        return list(aud)
    raise Refusal("aud-missing", "/claims/aud", "the token names no audience")


def _check_audience(context: Context) -> None:
    claims = _claims(context)
    resource = _option(context, "resource", "resource-not-configured")
    endpoints = _option(context, "tokenEndpoints", "token-endpoints-not-configured")
    audiences = _audiences(claims)
    if any(a in endpoints or _normalized(a) in {_normalized(e) for e in endpoints} for a in audiences):
        raise Refusal("aud-is-token-endpoint", "/claims/aud", "the audience is an authorization server's token endpoint")
    if resource in audiences:
        return
    if _normalized(resource) in {_normalized(a) for a in audiences}:
        raise Refusal("aud-matches-only-after-normalization", "/claims/aud", "the audience equals the resource only after normalization")
    raise Refusal("aud-mismatch", "/claims/aud", "the token was issued for another resource")


def _check_resource(context: Context) -> None:
    claims = _claims(context)
    if "resource" not in claims:
        return
    resource = _option(context, "resource", "resource-not-configured")
    named = claims["resource"]
    names = named if isinstance(named, list) else [named]
    if resource not in names:
        raise Refusal("resource-mismatch", "/claims/resource", "the resource indicator names another resource (RFC 8707)")


def _instant(claims: dict[str, Any], name: str) -> int | None:
    if name not in claims:
        return None
    value = claims[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise Refusal("time-member-malformed", f"/claims/{name}", f"{name} is not an integer NumericDate")
    if not 0 <= value <= MAX_SAFE_INTEGER:
        raise Refusal("time-member-out-of-range", f"/claims/{name}", f"{name} is outside 0..2**53 - 1")
    return value


def _check_lifetime(context: Context) -> None:
    claims = _claims(context)
    now = _option(context, "now", "clock-not-configured")
    skew = _option(context, "skew", "clock-not-configured", default=DEFAULT_SKEW)
    exp = _instant(claims, "exp")
    if exp is None:
        raise Refusal("exp-missing", "/claims/exp", "the token names no expiry")
    if now >= exp + skew:
        raise Refusal("token-expired", "/claims/exp", "the token has expired")
    nbf = _instant(claims, "nbf")
    if nbf is not None and nbf > now + skew:
        raise Refusal("token-not-yet-valid", "/claims/nbf", "the token is not valid yet")
    iat = _instant(claims, "iat")
    if iat is not None and iat > now + skew:
        raise Refusal("iat-in-future", "/claims/iat", "the token was issued in the future")


def _check_binding(context: Context) -> None:
    claims = _claims(context)
    header = context.document.get("header", {})
    typ = media_type(header.get("typ")) if isinstance(header, dict) else None
    if typ == ID_JAG_TYPE:
        raise Refusal("id-jag-at-resource", "/header/typ", "an identity assertion grant is for the authorization server, not a resource")
    if typ != ACCESS_TOKEN_TYPE:
        raise Refusal("typ-not-access-token", "/header/typ", "RFC 9068 section 4: a resource server takes only typ at+jwt")
    cnf = claims.get("cnf")
    presentation = context.document.get("presentation")
    if isinstance(cnf, dict) and "jkt" in cnf and presentation == "bearer":
        raise Refusal("bound-token-as-bearer", "/claims/cnf/jkt", "a DPoP-bound token was presented as a bearer token")
    if presentation == "dpop" and not (isinstance(cnf, dict) and isinstance(cnf.get("jkt"), str) and cnf["jkt"]):
        raise Refusal("dpop-without-binding", "/claims/cnf/jkt",
                      "RFC 9449 section 7.1: a DPoP presentation is checked against the key the token is bound to, and this token names none")


MCP_AUTHZ = register(
    RuleSet(
        name="mcp-authz",
        summary="an MCP server's token decision: issuer advertised, audience exact, resource, lifetime, binding",
        checks=(
            Check("shape", "header, claims and presentation are present", _check_shape),
            Check("issuer", "iss is an authorization server the resource advertises", _check_issuer),
            Check("audience", "aud names this resource exactly and no token endpoint", _check_audience),
            Check("resource", "a resource claim names this resource", _check_resource),
            Check("lifetime", "exp present and not passed, nbf and iat not in the future", _check_lifetime),
            Check("binding", "typ is at+jwt (no ID-JAG, no ID token), no DPoP-bound token as bearer, no unbound token as DPoP", _check_binding),
        ),
        option_help={
            "resource": "the server's canonical resource URI",
            "issuers": "the authorization servers its protected-resource metadata advertises",
            "tokenEndpoints": "those servers' token endpoints",
            "now": "the time of the decision, seconds since the epoch",
            "skew": "the clock skew tolerance in seconds (default 60)",
        },
    )
)
