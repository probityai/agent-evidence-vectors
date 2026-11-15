#!/usr/bin/env python3
"""Write issuer-pin-vectors.json: accept and reject cases for issuer key pin sets.

Each case configures a client, optionally rotates one issuer's pin set, and then
asks for one key. The expected outcome is ``accept`` or the refusal code of
``agent_evidence_admission.issuer_pin``. The keys are the published examples of
RFC 7638 section 3.1 (RSA), RFC 8037 appendix A.3 (OKP) and RFC 7517 appendix
A.1 (EC), so every thumbprint here can be checked against those documents.
Run it to regenerate; ``test_issuer_pin_vectors.py`` refuses a file that differs.
"""

from __future__ import annotations

import json
import pathlib

from agent_evidence_admission.issuer_pin import jwk_thumbprint

OUT = pathlib.Path(__file__).with_name("issuer-pin-vectors.json")
ISSUER = "https://example.okta.com/oauth2/default"
OTHER = "https://example.us.auth0.com"
KID = "signing"

RSA = {"kty": "RSA", "e": "AQAB", "n": (
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
    "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
    "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")}
OKP = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
EC = {"kty": "EC", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
KEYS = {"RSA": RSA, "OKP": OKP, "EC": EC}
T = {name: jwk_thumbprint(key) for name, key in (("rsa", RSA), ("okp", OKP), ("ec", EC))}


def pin(epoch: int, *names: str) -> dict:
    return {"epoch": epoch, "thumbprints": sorted(T[n] for n in names)}


def case(cid: str, summary: str, *, serves: str, pins: dict | None, expect: str,
         rotate: dict | None = None, seen: dict | None = None, unpinned: bool = False,
         issuers: tuple[str, ...] = (ISSUER,)) -> dict:
    return {"id": cid, "summary": summary, "issuers": list(issuers),
            "pins": {} if pins is None else {ISSUER: pins}, "unpinned": unpinned,
            "seen_epochs": seen or {}, "rotate": rotate,
            "jwks": {"keys": [dict(KEYS[serves], kid=KID)]},
            "verify": {"issuer": ISSUER, "kid": KID}, "expect": expect}


CASES = [
    case("single-pin-match", "one pinned key, and the issuer signs with it", serves="RSA",
         pins=pin(1, "rsa"), expect="accept"),
    case("single-pin-mismatch", "the issuer serves a key whose thumbprint is not pinned", serves="OKP",
         pins=pin(1, "rsa"), expect="pin-thumbprint-mismatch"),
    case("overlap-new-key", "a set pins the current and the next key; the next one verifies", serves="OKP",
         pins=pin(2, "rsa", "okp"), expect="accept"),
    case("overlap-old-key", "a set pins the current and the next key; the current one verifies", serves="RSA",
         pins=pin(2, "rsa", "okp"), expect="accept"),
    case("rotation-forward", "rotation to a newer epoch adds the next key", serves="EC", pins=pin(1, "rsa"),
         rotate=pin(2, "rsa", "ec"), expect="accept"),
    case("rotation-retires-key", "rotation to a newer epoch drops the old key, which no longer verifies",
         serves="RSA", pins=pin(2, "rsa", "ec"), rotate=pin(3, "ec"), expect="pin-thumbprint-mismatch"),
    case("rotation-downgrade", "rotation to an older epoch is refused", serves="RSA", pins=pin(3, "ec"),
         rotate=pin(2, "rsa", "ec"), expect="pin-downgrade"),
    case("rotation-same-epoch-shrink", "a smaller set at the same epoch is refused", serves="RSA",
         pins=pin(2, "rsa", "ec"), rotate=pin(2, "rsa"), expect="pin-conflict"),
    case("rotation-same-epoch-repeat", "the same set at the same epoch is a harmless repeat", serves="RSA",
         pins=pin(2, "rsa", "ec"), rotate=pin(2, "rsa", "ec"), expect="accept"),
    case("restart-below-seen-epoch", "a restart from configuration older than the epoch already reached",
         serves="RSA", pins=pin(1, "rsa"), seen={ISSUER: 2}, expect="pin-downgrade"),
    case("restart-at-seen-epoch", "a restart from configuration at the epoch already reached", serves="EC",
         pins=pin(2, "rsa", "ec"), seen={ISSUER: 2}, expect="accept"),
    case("restart-unpinned-after-pinning", "a restart declared unpinned after the issuer was pinned",
         serves="RSA", pins=None, unpinned=True, seen={ISSUER: 1}, expect="pin-downgrade"),
    case("empty-set", "a pin set with no thumbprint", serves="RSA", pins={"epoch": 1, "thumbprints": []},
         expect="pin-error"),
    case("zero-epoch", "a pin set at epoch zero", serves="RSA", pins={"epoch": 0, "thumbprints": [T["rsa"]]},
         expect="pin-error"),
    case("issuer-left-unpinned", "a second issuer is called with no pin set", serves="RSA", pins=pin(1, "rsa"),
         issuers=(ISSUER, OTHER), expect="pin-mixed-configuration"),
]


def document() -> str:
    body = {"suite": "issuer-pin-sets/v1",
            "rules": "agent_evidence_admission.issuer_pin; RFC 7638 section 3.2, RFC 8037 section 2",
            "thumbprints": T, "cases": CASES}
    return json.dumps(body, indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    OUT.write_text(document(), encoding="utf-8")
