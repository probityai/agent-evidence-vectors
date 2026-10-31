#!/usr/bin/env python3
"""Finite independent APS reader; does not import or call the APS SDK.

The pinned corpus deliberately contains printable ASCII JSON. This reader
supports that subset and refuses other canonicalization inputs. It does not
claim general RFC 8785 support or authenticate the supplied resolver history.
"""

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_SHA256 = "9fce76dbf13de9749a2ef52c8dedecce08e4874da0203b39a7d941eb479b5ac5"
ID_DOMAIN = b"APS-PASSPORT-ID-V2\0"
SIGNATURE_DOMAIN = b"APS-PASSPORT-SIG-V2\0"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
FIELDS = {
    "record_type",
    "version",
    "agent_id",
    "verification_method",
    "public_key_multibase",
    "issued_at",
    "expires_at",
    "nonce",
    "self_asserted",
    "passport_id",
    "signature",
}
ANNOTATED = {
    "expired",
    "not-yet-valid",
    "did-web-resolver-not-found",
    "version-changed",
    "record-type-changed",
}


class UnsupportedCanonicalInput(ValueError):
    """Input is outside this finite reader's documented JSON subset."""


def assert_ascii_json(value):
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and -(2**53 - 1) <= value <= 2**53 - 1:
        return
    if isinstance(value, str):
        if all(32 <= ord(char) <= 126 for char in value):
            return
        raise UnsupportedCanonicalInput("only printable ASCII strings are selected")
    if isinstance(value, list):
        for entry in value:
            assert_ascii_json(entry)
        return
    if isinstance(value, dict):
        for key, entry in value.items():
            if not isinstance(key, str):
                raise UnsupportedCanonicalInput("object key is not a string")
            assert_ascii_json(key)
            assert_ascii_json(entry)
        return
    raise UnsupportedCanonicalInput("unsupported JSON value or number")


def canonical_bytes(value):
    assert_ascii_json(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def public_key_bytes(multibase):
    if not isinstance(multibase, str) or not multibase.startswith("z"):
        raise ValueError("expected base58btc multibase key")
    encoded = multibase[1:]
    if not encoded or any(char not in BASE58 for char in encoded):
        raise ValueError("invalid base58btc key")
    number = 0
    for char in encoded:
        number = number * 58 + BASE58.index(char)
    leading = len(encoded) - len(encoded.lstrip("1"))
    decoded = b"\0" * leading + number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise ValueError("expected 32-byte Ed25519 multicodec key")
    return decoded[2:]


def utc_milliseconds(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value
    ):
        raise ValueError("timestamp does not have exact UTC millisecond form")
    result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )
    if result.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" != value:
        raise ValueError("timestamp is not a canonical calendar value")
    return result


def hex_field(value, size):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value) is not None
    )


def structure(passport):
    if not isinstance(passport, dict) or set(passport) != FIELDS:
        return "invalid", "closed wire object differs"
    assert_ascii_json(passport)
    if passport["record_type"] != "aps.agent-passport" or passport["version"] != "2.0":
        return "unsupported", "profile is outside the selected version"
    for name in FIELDS - {"self_asserted"}:
        if not isinstance(passport[name], str):
            return "invalid", "wire string field is not a string"
    if not re.fullmatch(r"did:[a-z0-9]+:.+", passport["agent_id"]):
        return "invalid", "agent DID syntax differs"
    if not passport["verification_method"].startswith(passport["agent_id"] + "#"):
        return "invalid", "verification method is outside the agent DID"
    try:
        public_key_bytes(passport["public_key_multibase"])
        issued = utc_milliseconds(passport["issued_at"])
        expires = utc_milliseconds(passport["expires_at"])
    except ValueError as exc:
        return "invalid", str(exc)
    if issued >= expires:
        return "invalid", "empty or reversed validity interval"
    if not all(
        hex_field(passport[name], size)
        for name, size in [("nonce", 32), ("passport_id", 64), ("signature", 128)]
    ):
        return "invalid", "hex field shape differs"
    claims = passport["self_asserted"]
    if not isinstance(claims, dict) or not {"capabilities"} <= set(claims) <= {
        "capabilities",
        "display_name",
    }:
        return "invalid", "self_asserted closed object differs"
    capabilities = claims["capabilities"]
    if not isinstance(capabilities, list) or any(
        not isinstance(item, str) for item in capabilities
    ):
        return "invalid", "capabilities must be strings in an array"
    if capabilities != sorted(set(capabilities), key=lambda item: item.encode("utf-8")):
        return "invalid", "capabilities are not sorted and unique"
    if "display_name" in claims and not isinstance(claims["display_name"], str):
        return "invalid", "display_name is not a string"
    return "supported", "selected profile wire object is well formed"


def raw_checks(passport):
    id_body = {
        key: value
        for key, value in passport.items()
        if key not in {"passport_id", "signature"}
    }
    signature_body = {
        key: value for key, value in passport.items() if key != "signature"
    }
    id_preimage = ID_DOMAIN + canonical_bytes(id_body)
    signature_preimage = SIGNATURE_DOMAIN + canonical_bytes(signature_body)
    derived_id = hashlib.sha256(id_preimage).hexdigest()
    key = public_key_bytes(passport["public_key_multibase"])
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(passport["signature"]), signature_preimage
        )
        signature_valid = True
    except InvalidSignature:
        signature_valid = False
    return {
        "passportIDMatches": derived_id == passport["passport_id"],
        "signatureValidForPresentedBytes": signature_valid,
        "derivedPassportID": derived_id,
        "publicKeyHex": key.hex(),
        "idPreimageHex": id_preimage.hex(),
        "signaturePreimageHex": signature_preimage.hex(),
    }


def read_case(case, entries):
    passport = case["passport"]
    raw = raw_checks(passport)
    classification, reason = structure(passport)
    layers = {
        "structure": "ok" if classification == "supported" else "rejected",
        "passport_id": "not_checked",
        "signature": "not_checked",
        "validity_window": "not_checked",
        "proof_of_possession": False,
        "key_authority": "not_checked",
    }
    requests = []
    outcome = classification
    if classification != "supported":
        pass
    elif not raw["passportIDMatches"]:
        layers["passport_id"] = "mismatch"
        outcome, reason = "invalid", "passport ID does not bind the presented body"
    else:
        layers["passport_id"] = "ok"
        layers["signature"] = (
            "ok" if raw["signatureValidForPresentedBytes"] else "invalid"
        )
        if not raw["signatureValidForPresentedBytes"]:
            outcome, reason = "invalid", "signature does not verify for presented bytes"
        else:
            layers["proof_of_possession"] = True
            if (
                not utc_milliseconds(passport["issued_at"])
                <= utc_milliseconds(case["now"])
                < utc_milliseconds(passport["expires_at"])
            ):
                layers["validity_window"] = "not_current"
                outcome, reason = (
                    "invalid",
                    "supplied evaluation time is outside the signed interval",
                )
            else:
                layers["validity_window"] = "ok"
                if passport["agent_id"].startswith("did:key:"):
                    key_id = "did:key:" + passport["public_key_multibase"]
                    bound = (
                        passport["agent_id"] == key_id
                        and passport["verification_method"]
                        == key_id + "#" + passport["public_key_multibase"]
                    )
                    layers["key_authority"] = "verified" if bound else "rejected"
                    outcome, reason = (
                        ("valid", "self-certifying identifier agrees")
                        if bound
                        else ("invalid", "identifier commits to a different key")
                    )
                elif case["resolver"] == "none":
                    layers["key_authority"] = "unresolved"
                    outcome, reason = (
                        "indeterminate",
                        "no resolver observation is supplied",
                    )
                elif case["resolver"] == "table":
                    request = {
                        "controller": passport["agent_id"],
                        "verification_method": passport["verification_method"],
                        "at": passport["issued_at"],
                    }
                    requests.append(request)
                    matches = [
                        entry
                        for entry in entries
                        if entry["controller"] == request["controller"]
                        and entry["verification_method"]
                        == request["verification_method"]
                    ]
                    if len(matches) > 1:
                        raise ValueError(
                            "ambiguous table is outside this pinned fixture"
                        )
                    answer = matches[0] if matches else {"outcome": "not_found"}
                    if answer["outcome"] != "resolved":
                        layers["key_authority"] = "unresolved"
                        outcome, reason = (
                            "indeterminate",
                            "table did not resolve a key: " + answer["outcome"],
                        )
                    else:
                        agrees = answer["public_key_hex"] == raw["publicKeyHex"]
                        layers["key_authority"] = "verified" if agrees else "rejected"
                        outcome, reason = (
                            ("valid", "supplied fixture resolver agrees")
                            if agrees
                            else (
                                "invalid",
                                "supplied fixture resolver names a different key",
                            )
                        )
                else:
                    raise ValueError("unsupported fixture resolver selection")
    return {
        "name": case["name"],
        "readerOutcome": outcome,
        "reason": reason,
        "admittedByThisFiniteReader": outcome == "valid",
        "layers": layers,
        "rawByteChecks": raw,
        "resolverRequests": requests,
        "historyAuthorityAuthenticated": False,
        "timeBasis": "signed issuer assertions and supplied synthetic evaluation time",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.fixture.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError("corrected immutable fixture bytes differ")
    fixture = json.loads(raw, object_pairs_hook=unique_object)
    cases = fixture["cases"]
    if len(cases) != 20 or len({case["name"] for case in cases}) != 20:
        raise ValueError("case population differs")
    if {case["name"] for case in cases if "sdk_observation" in case} != ANNOTATED:
        raise ValueError("five separate SDK annotations differ")
    rows = []
    mismatches = []
    for case in cases:
        row = read_case(case, fixture["key_resolver"]["entries"])
        row["publishedSDKObservation"] = case["verification"]
        row["draftAssignmentUndetermined"] = "sdk_observation" in case
        row["annotation"] = case.get("sdk_observation")
        row["diagnosticLayersAgree"] = row["layers"] == case["layers"]
        row["resolverRequestsAgree"] = row["resolverRequests"] == case.get(
            "resolver_requests", []
        )
        preimage = fixture["valid_cases_preimages"].get(case["name"])
        if preimage is not None:
            row["frozenPreimagesAgree"] = (
                row["rawByteChecks"]["idPreimageHex"]
                == preimage["passport_id_preimage_hex"]
                and row["rawByteChecks"]["signaturePreimageHex"]
                == preimage["signature_preimage_hex"]
                and row["rawByteChecks"]["derivedPassportID"]
                == preimage["derived"]["passport_id"]
                and row["rawByteChecks"]["publicKeyHex"]
                == preimage["derived"]["public_key_hex"]
            )
        row["readerOutcomeAgreesWithSDKObservation"] = (
            row["readerOutcome"] == case["verification"]["state"]
        )
        row["expectedOutcomeDivergence"] = case["name"] in {
            "did-web-resolver-not-found",
            "version-changed",
            "record-type-changed",
        }
        acceptable = (
            row["diagnosticLayersAgree"]
            and row["resolverRequestsAgree"]
            and row.get("frozenPreimagesAgree", True)
        )
        acceptable = acceptable and (
            row["readerOutcomeAgreesWithSDKObservation"]
            != row["expectedOutcomeDivergence"]
        )
        acceptable = acceptable and (
            row["admittedByThisFiniteReader"]
            == (case["verification"]["state"] == "valid")
        )
        if not acceptable:
            mismatches.append(case["name"])
        rows.append(row)
    report = {
        "schema": "probity.lab.aps-corrected20-independent-reader/v1",
        "at": datetime.now(timezone.utc).isoformat(),
        "fixtureCommit": "407ca2d5ad10c846860ad1b6faafc971ae9690e5",
        "fixtureSHA256": FIXTURE_SHA256,
        "fixtureAuthor": "APS/AEOESS",
        "readerOperator": "Probity",
        "readerImportsAPSSDK": False,
        "cryptographyVersion": cryptography.__version__,
        "cryptoBackend": backend.openssl_version_text(),
        "sourceObservations": dict(
            Counter(case["verification"]["state"] for case in cases)
        ),
        "readerOutcomes": dict(Counter(row["readerOutcome"] for row in rows)),
        "separateSDKAnnotations": sorted(ANNOTATED),
        "cases": rows,
        "mismatches": mismatches,
        "status": "PASS" if not mismatches else "ADVERSE",
        "limits": [
            "Finite printable-ASCII corpus reader; not general JCS conformance.",
            "Signature verification uses cryptography/OpenSSL; no independent cryptographic-backend claim.",
            "Diagnostic agreement does not force the five normatively undetermined SDK outcomes.",
            "Resolver answers are supplied synthetic data, without historical validity windows or authenticated lookup.",
            "No APS package qualification, principal binding, live DID lookup, host adoption, federation enrollment or commercial agreement.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(
        json.dumps(
            {"cases": len(rows), "mismatches": mismatches, "status": report["status"]}
        )
    )
    return bool(mismatches)


if __name__ == "__main__":
    raise SystemExit(main())
