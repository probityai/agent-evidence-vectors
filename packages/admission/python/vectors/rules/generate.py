"""Write the rule-set vectors: one manifest.json per rule set, every case inline.

Run from anywhere: ``python vectors/rules/generate.py`` rewrites the manifests beside this file;
``--check`` exits 1 when a committed manifest differs from what this script writes. Every case is
written here from the rule it tests, with synthetic keys, hosts and values; none is copied from
another project's files.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def case(case_id: str, verdict: str, code: str | None, why: str, **row: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"id": case_id}
    out.update(row)
    expect: dict[str, Any] = {"verdict": verdict}
    if code:
        expect["code"] = code
    out["expect"] = expect
    out["rationale"] = why
    return out


def text(value: str) -> dict[str, str]:
    return {"text": value}


# --------------------------------------------------------------------------
# ijson and ijson-integer-only
# --------------------------------------------------------------------------


def parse_cases(integer_only: bool) -> list[dict[str, Any]]:
    float_verdict = ("refuse", "value-not-representable") if integer_only else ("admit", None)
    deep = "[" * 65 + "]" * 65
    rows = [
        case("plain-object", *float_verdict, "an object of the common value kinds; 1.5 is a fraction",
             text='{"a":1,"b":[true,false,null,"x"],"c":1.5}'),
        case("integers-only", "admit", None, "integers, strings and nesting within the bounds",
             text='{"count":3,"ids":[1,2,3],"nested":{"k":"v"}}'),
        case("last-safe-integer", "admit", None, "2^53 - 1 is the largest exact I-JSON integer",
             text='{"n":9007199254740991}'),
        case("neg-last-safe-integer", "admit", None, "-(2^53 - 1) is the smallest", text='{"n":-9007199254740991}'),
        case("depth-64", "admit", None, "64 levels of nesting is the bound itself", text="[" * 64 + "]" * 64),
        case("duplicate-top", "refuse", "duplicate-member", "a repeated member keeps its last value in most decoders",
             text='{"role":"user","role":"admin"}'),
        case("duplicate-nested", "refuse", "duplicate-member", "a repeat three levels down",
             text='{"a":{"b":{"c":{"role":"user","role":"admin"}}}}'),
        case("duplicate-in-array", "refuse", "duplicate-member", "a repeat inside an array element",
             text='{"a":[{"x":1,"x":2}]}'),
        case("duplicate-escaped", "refuse", "duplicate-member", "the same name once escaped, once not",
             text='{"a":1,"\\u0061":2}'),
        case("case-variant", "refuse", "case-fold-collision", "a case-insensitive decoder reads Revoked as revoked",
             text='{"revoked":false,"Revoked":true}'),
        case("dotless-i", "refuse", "case-fold-collision", "U+0131 folds to i in locale-sensitive matchers",
             text='{"admin":false,"adm\\u0131n":true}'),
        case("dotted-capital-i", "refuse", "case-fold-collision", "U+0130 folds to i as well",
             text='{"ID":"a","\\u0130D":"b"}'),
        case("kelvin-sign", "refuse", "case-fold-collision", "U+212A folds to k", text='{"key":1,"\\u212aey":2}'),
        case("lone-high-surrogate", "refuse", "lone-surrogate", "no UTF-8 text carries U+D800",
             text='{"a":"\\ud800"}'),
        case("lone-low-surrogate-in-name", "refuse", "lone-surrogate", "a lone surrogate in a member name",
             text='{"\\udc00":1}'),
        case("paired-surrogates", "admit", None, "a surrogate pair is one scalar value", text='{"a":"\\ud83d\\ude00"}'),
        case("noncharacter", "refuse", "noncharacter", "RFC 7493 2.1 excludes noncharacters", text='{"a":"\\uffff"}'),
        case("noncharacter-fdd0", "refuse", "noncharacter", "U+FDD0 is a noncharacter", text='{"a":"\\ufdd0"}'),
        case("two-pow-53", "refuse", "unsafe-integer", "2^53 is outside +-(2^53 - 1)", text='{"n":9007199254740992}'),
        case("two-pow-53-plus-one", "refuse", "unsafe-integer", "2^53 + 1 rounds to 2^53 in a double",
             text='{"n":9007199254740993}'),
        case("u64-max", "refuse", "unsafe-integer", "a u64 reader takes it, a double reader rounds it",
             text='{"n":18446744073709551615}'),
        case("fraction-past-2-53", "refuse", "value-not-representable" if integer_only else "unsafe-integer",
             "a fraction whose double is the integer 12345678901234568, past 2^53",
             text='{"n":12345678901234567.5}'),
        case("exponent-overflow", "refuse", "value-not-representable", "1e400 has no finite double", text='{"n":1e400}'),
        case("nan", "refuse", "non-json-number", "NaN is not a JSON number", text='{"n":NaN}'),
        case("neg-infinity", "refuse", "non-json-number", "-Infinity is not a JSON number", text='{"n":-Infinity}'),
        case("long-token", "refuse", "number-token-too-long", "a 70-digit integer token, refused before conversion",
             text='{"n":' + "1" * 70 + "}"),
        case("negative-zero", "refuse", "negative-zero", "RFC 8785 writes -0 as 0", text='{"n":-0}'),
        case("not-utf8", "refuse", "not-utf8", "0xC3 0x28 is not UTF-8", base64=b64(b'{"a":"\xc3\x28"}')),
        case("encoded-surrogate", "refuse", "not-utf8", "a surrogate encoded in UTF-8 is not UTF-8",
             base64=b64(b'{"a":"\xed\xa0\x80"}')),
        case("byte-order-mark", "refuse", "not-utf8", "I-JSON text carries no byte-order mark",
             base64=b64(b'\xef\xbb\xbf{"a":1}')),
        case("too-deep", "refuse", "nesting-too-deep", "65 levels of nesting", text=deep),
        case("trailing-comma", "refuse", "not-parseable", "not JSON", text='{"a":1,}'),
        case("trailing-data", "refuse", "not-parseable", "two values", text='{"a":1} {"b":2}'),
    ]
    if integer_only:
        rows += [
            case("respelled-fraction", "refuse", "value-not-representable", "1000.0 is an integer respelled", text='{"n":1000.0}'),
            case("respelled-exponent", "refuse", "value-not-representable", "1e3 is an integer respelled", text='{"n":1e3}'),
            case("respelled-upper-exponent", "refuse", "value-not-representable", "1E3 likewise", text='{"n":1E3}'),
        ]
    else:
        rows += [
            case("negative-zero-fraction", "refuse", "negative-zero", "-0.0 is negative zero too", text='{"n":-0.0}'),
            case("small-fraction", "admit", None, "a fraction inside the range", text='{"n":0.000001}'),
        ]
    return rows


# --------------------------------------------------------------------------
# audit-freshness
# --------------------------------------------------------------------------

REPORTED = "2026-09-19T11:04:02Z"


def audit_statement(inputs: list[dict[str, Any]], status: str = "evaluated", unavailable: list[str] | None = None,
                    reported: str | None = REPORTED) -> dict[str, Any]:
    evaluation: dict[str, Any] = {"inputs": inputs, "status": status}
    if unavailable is not None:
        evaluation["unavailableInput"] = unavailable
    decision: dict[str, Any] = {"action": "write", "reported": "permit"}
    if reported is not None:
        decision["reportedAt"] = reported
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "record", "digest": {"sha256": "0" * 64}}],
        "predicateType": "https://example.org/agent-audit-record/v1",
        "predicate": {"decision": decision, "evaluation": evaluation},
    }


def entries(standing: str = "2026-09-19T10:30:00Z", standing_max: int = 3600, extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows = [
        {"input": "policy-source", "lastResult": "2026-09-19T10:00:00Z", "maxAge": 86400},
        {"input": "key-source", "lastResult": "2026-09-19T11:00:00Z", "maxAge": 3600},
        {"input": "standing-source", "lastResult": standing, "maxAge": standing_max},
    ]
    return rows + (extra or [])


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def max_age_raw(token: str) -> str:
    """FR1 with standing-source's maxAge written as the given token: bytes RFC 8785 cannot write."""
    return dumps(audit_statement(entries(standing_max=777777))).replace("777777", token)


def envelope(payload: bytes, signed: bool = True) -> str:
    return dumps({
        "payloadType": "application/vnd.in-toto+json",
        "payload": b64(payload),
        "signatures": [{"keyid": "test-key", "sig": b64(b"\x01" * 64)}] if signed else [],
    })


def audit_cases() -> list[dict[str, Any]]:
    stale = "2026-09-19T10:04:01Z"  # 3601 s before reportedAt
    return [
        case("fr1-every-input-fresh", "admit", None, "three entries, each inside its maxAge",
             text=dumps(audit_statement(entries()))),
        case("fr1-in-dsse", "admit", None, "the same record as a DSSE payload", text=envelope(dumps(audit_statement(entries())).encode())),
        case("fr2-age-equal-to-max-age", "admit", None, "an age equal to maxAge is fresh",
             text=dumps(audit_statement(entries(standing="2026-09-19T10:04:02Z")))),
        case("fr8-evaluated-beside-stale", "refuse", "evaluation-inconsistent", "one second past maxAge, recorded as evaluated",
             text=dumps(audit_statement(entries(standing=stale)))),
        case("fr3-not-evaluated-names-stale", "admit", None, "the stale input named as unavailable",
             text=dumps(audit_statement(entries(standing=stale), "not-evaluated", ["standing-source"]))),
        case("fr7-names-a-fresh-input", "refuse", "evaluation-inconsistent", "unavailableInput names a fresh input",
             text=dumps(audit_statement(entries(standing=stale), "not-evaluated", ["key-source"]))),
        case("never-held", "admit", None, "an input never held is unavailable",
             text=dumps(audit_statement(entries(standing="none"), "not-evaluated", ["standing-source"]))),
        case("fr9-after-decision-301", "refuse", "evaluation-result-after-decision",
             "301 s after reportedAt: the future bound takes the skew tolerance only",
             text=dumps(audit_statement(entries(standing="2026-09-19T11:09:03Z")))),
        case("fr18-after-decision-300", "admit", None, "exactly the skew tolerance after reportedAt",
             text=dumps(audit_statement(entries(standing="2026-09-19T11:09:02Z")))),
        case("future-inside-window", "refuse", "evaluation-result-after-decision",
             "an hour after reportedAt with a day's maxAge: a verifier that checks |age| <= maxAge admits it",
             text=dumps(audit_statement([{"input": "policy-source", "lastResult": "2026-09-19T12:04:02Z", "maxAge": 86400}]))),
        case("fr19-max-age-u64", "refuse", "unsafe-integer", "maxAge 2^64 - 1 is outside the I-JSON range",
             text=max_age_raw("18446744073709551615")),
        case("fr19-in-dsse", "refuse", "unsafe-integer", "the same inside a DSSE payload",
             text=envelope(max_age_raw("18446744073709551615").encode())),
        case("fr20-max-age-two-pow-53-plus-one", "refuse", "unsafe-integer", "2^53 + 1 reads as 2^53 in a double",
             text=max_age_raw("9007199254740993")),
        case("fr20a-max-age-two-pow-53", "refuse", "unsafe-integer", "the boundary 2^53 itself is outside the range",
             text=max_age_raw("9007199254740992")),
        case("fr20b-max-age-last-safe", "admit", None, "2^53 - 1, the last safe integer, so a verifier that refuses early is caught",
             text=max_age_raw("9007199254740991")),
        case("fr13-negative-max-age", "refuse", "evaluation-entry-malformed", "a negative maxAge",
             text=dumps(audit_statement(entries(standing_max=-1)))),
        case("max-age-fraction", "refuse", "evaluation-entry-malformed", "a maxAge that is not an integer",
             text=max_age_raw("3600.5")),
        case("fr10-input-repeated", "refuse", "evaluation-input-repeated", "one input in two entries",
             text=dumps(audit_statement(entries(extra=[{"input": "key-source", "lastResult": "2026-09-19T11:00:00Z", "maxAge": 3600}])))),
        case("fr11-fourth-member", "refuse", "evaluation-entry-malformed", "an entry with a member the format does not define",
             text=dumps(audit_statement(entries(extra=[{"input": "x-source", "lastResult": "2026-09-19T11:00:00Z", "maxAge": 1, "source": "y"}])))),
        case("fr5-entry-without-last-result", "refuse", "member-missing", "an entry without lastResult",
             text=dumps(audit_statement(entries(extra=[{"input": "x-source", "maxAge": 1}])))),
        case("fr16-no-reported-at", "refuse", "member-missing", "no reference time to measure any age to",
             text=dumps(audit_statement(entries(), reported=None))),
        case("reported-at-not-an-instant", "refuse", "instant-malformed", "a reference time with no zone",
             text=dumps(audit_statement(entries(), reported="2026-09-19T11:04:02"))),
        case("last-result-arabic-indic-digits", "refuse", "instant-malformed", "non-ASCII digits some parsers accept",
             text=dumps(audit_statement(entries(standing="2026-09-19T10:30:0٠Z")))),
        case("last-result-trailing-newline", "refuse", "instant-malformed", "a trailing LF some parsers strip",
             text=dumps(audit_statement(entries(standing="2026-09-19T10:30:00Z\n")))),
        case("duplicate-in-payload", "refuse", "duplicate-member", "the strict parse reaches into the DSSE payload",
             text=envelope(dumps(audit_statement(entries())).replace('"status":"evaluated"', '"status":"evaluated","status":"not-evaluated"').encode())),
    ]


# --------------------------------------------------------------------------
# catalog-attestations
# --------------------------------------------------------------------------

ARTIFACT = b'{"name":"invoice-reader","tools":[{"name":"extract"}]}\n'
SARIF = b'{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"example-scanner"}},"results":[]}]}\n'
ARTIFACT_URL = "https://tools.example.com/mcp/invoice-reader.json"
SCAN_URI = "https://tools.example.com/trust/invoice-reader.scan.sarif"
STATEMENT_URI = "https://tools.example.com/trust/invoice-reader.intoto.json"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def signed_statement(subject: dict[str, Any]) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [subject],
        "predicateType": "https://example.org/scan/v1",
        "predicate": {"result": "pass"},
    }
    return envelope(dumps(statement).encode()).encode()


def ard_entry(**changes: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "identifier": "urn:air:tools.example.com:server:invoice-reader",
        "type": "application/mcp-server-card+json",
        "url": ARTIFACT_URL,
        "digest": sha(ARTIFACT),
        "trustManifest": {
            "identity": "spiffe://tools.example.com/mcp/invoice-reader",
            "identityType": "spiffe",
            "attestations": [
                {"type": "agent-threat-scan", "uri": STATEMENT_URI, "mediaType": "application/vnd.dsse+json",
                 "digest": sha(GOOD_STATEMENT)},
            ],
        },
    }
    for key, value in changes.items():
        if value is None:
            entry.pop(key, None)
        else:
            entry[key] = value
    return entry


GOOD_STATEMENT = signed_statement({"name": "urn:air:tools.example.com:server:invoice-reader",
                                   "digest": {"sha256": hashlib.sha256(ARTIFACT).hexdigest()}})
OTHER_STATEMENT = signed_statement({"name": "urn:air:other.example:server:invoice-reader",
                                    "digest": {"sha256": "1" * 64}})
UNSIGNED_STATEMENT = envelope(base64.b64decode(json.loads(GOOD_STATEMENT)["payload"]), signed=False).encode()


def catalog(*entries_: dict[str, Any]) -> str:
    return dumps({"entries": list(entries_)})


def held(**files: bytes) -> dict[str, dict[str, str]]:
    names = {"artifact": ARTIFACT_URL, "statement": STATEMENT_URI, "scan": SCAN_URI}
    return {names[k]: {"base64": b64(v)} for k, v in files.items()}


def transplanted() -> dict[str, Any]:
    entry = ard_entry(identifier="urn:air:evil.example:server:invoice-reader", url="https://evil.example/mcp/invoice-reader.json", digest=None)
    entry["trustManifest"]["attestations"] = [{"type": "agent-threat-scan", "uri": SCAN_URI, "mediaType": "application/sarif+json", "digest": sha(SARIF)}]
    return entry


def ai_entry(manifest: dict[str, Any], **changes: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "identifier": "urn:air:tools.example.com:agent:finance",
        "type": "application/a2a-agent-card+json",
        "url": ARTIFACT_URL,
        "digest": sha(ARTIFACT),
        "version": "1.2.0",
        "trustManifests": [manifest],
    }
    for key, value in changes.items():
        if value is None:
            entry.pop(key, None)
        else:
            entry[key] = value
    return entry


def ai_manifest(**subject_changes: Any) -> dict[str, Any]:
    subject = {"identifier": "urn:air:tools.example.com:agent:finance", "type": "application/a2a-agent-card+json",
               "digest": sha(ARTIFACT), "version": "1.2.0"}
    for key, value in subject_changes.items():
        if value is None:
            subject.pop(key, None)
        else:
            subject[key] = value
    return {"contributor": "did:web:tools.example.com", "subject": subject,
            "signature": {"signer": "did:web:tools.example.com", "profile": "did-web", "issuedAt": "2026-11-01T00:00:00Z", "jws": "e30..c2ln"}}


def catalog_cases() -> list[dict[str, Any]]:
    inline = {"name": "inline-agent", "skills": [{"id": "a", "weight": 0.5}]}
    canonical_inline = b'{"name":"inline-agent","skills":[{"id":"a","weight":0.5}]}'
    data_uri = "data:application/vnd.dsse+json;base64," + b64(GOOD_STATEMENT)
    return [
        case("control-bound", "admit", None, "artifact and signed statement passed; the statement's subject names the entry and its digest",
             text=catalog(ard_entry()), files=held(artifact=ARTIFACT, statement=GOOD_STATEMENT)),
        case("transplanted-attestation", "refuse", "entry_digest_missing_for_url",
             "an attestation moved into another publisher's entry: its own pin still checks out, but nothing binds it to this entry",
             text=catalog(transplanted()), files=held(scan=SARIF)),
        case("transplanted-digest-warned", "refuse", "attestation_unsigned",
             "the same with the missing entry digest downgraded to a warning: the unsigned attestation still refuses",
             text=catalog(transplanted()), files=held(scan=SARIF), warn=["entry_digest_missing_for_url"]),
        case("transplanted-all-warned", "admit", None, "both downgraded to warnings, reported and not refused",
             text=catalog(transplanted()), files=held(scan=SARIF), warn=["entry_digest_missing_for_url", "attestation_unsigned"]),
        case("statement-for-another-entry", "refuse", "attestation_subject_mismatch", "a signed statement whose subject is another entry",
             text=catalog(ard_entry(trustManifest={"attestations": [{"type": "scan", "uri": STATEMENT_URI, "digest": sha(OTHER_STATEMENT)}]})),
             files=held(artifact=ARTIFACT, statement=OTHER_STATEMENT)),
        case("statement-unsigned-envelope", "refuse", "attestation_unsigned", "a DSSE envelope with no signature",
             text=catalog(ard_entry(trustManifest={"attestations": [{"type": "scan", "uri": STATEMENT_URI, "digest": sha(UNSIGNED_STATEMENT)}]})),
             files=held(artifact=ARTIFACT, statement=UNSIGNED_STATEMENT)),
        case("attestation-swapped", "refuse", "attestation_digest_mismatch", "the attestation bytes are not the pinned ones",
             text=catalog(ard_entry()), files=held(artifact=ARTIFACT, statement=OTHER_STATEMENT)),
        case("artifact-swapped", "refuse", "entry_digest_mismatch", "the artifact bytes are not the entry's",
             text=catalog(ard_entry()), files=held(artifact=ARTIFACT + b" ", statement=GOOD_STATEMENT)),
        case("size-exceeded", "refuse", "attestation_size_exceeded", "the attestation is larger than its stated size",
             text=catalog(ard_entry(trustManifest={"attestations": [{"type": "scan", "uri": STATEMENT_URI, "digest": sha(GOOD_STATEMENT), "size": 10}]})),
             files=held(artifact=ARTIFACT, statement=GOOD_STATEMENT)),
        case("inline-data-attestation", "admit", None, "an inline data: URI attestation is read directly",
             text=catalog(ard_entry(trustManifest={"attestations": [{"type": "scan", "uri": data_uri, "digest": sha(GOOD_STATEMENT)}]})),
             files=held(artifact=ARTIFACT)),
        case("not-passed", "refuse", "entry-bytes-not-evaluated", "nothing passed: a pin that could not be checked is not a pass",
             text=catalog(ard_entry())),
        case("not-passed-accepted", "admit", None, "the caller accepts the unchecked pins by name, and they are reported as warnings",
             text=catalog(ard_entry()), warn=["entry-bytes-not-evaluated", "attestation-pin-not-evaluated", "attestation-subject-not-evaluated"]),
        case("digest-uppercase", "refuse", "digest_malformed", "digests are lowercase hex",
             text=catalog(ard_entry(digest=sha(ARTIFACT).upper().replace("SHA256", "sha256"))), files=held(artifact=ARTIFACT, statement=GOOD_STATEMENT)),
        case("digest-sha1", "refuse", "digest_algorithm_weak", "an algorithm shorter than SHA-256",
             text=catalog(ard_entry(digest="sha1:" + hashlib.sha1(ARTIFACT).hexdigest())), files=held(artifact=ARTIFACT, statement=GOOD_STATEMENT)),
        case("url-and-data", "refuse", "entry_url_xor_data", "an entry carries exactly one of url and data",
             text=catalog(ard_entry(data={"name": "x"})), files=held(artifact=ARTIFACT, statement=GOOD_STATEMENT)),
        case("ai-signed-bound", "admit", None, "a signed manifest whose subject equals the entry",
             text=catalog(ai_entry(ai_manifest())), files=held(artifact=ARTIFACT)),
        case("ai-signed-no-subject", "refuse", "manifest_subject_missing", "a signed manifest with no subject",
             text=catalog(ai_entry({k: v for k, v in ai_manifest().items() if k != "subject"})), files=held(artifact=ARTIFACT)),
        case("ai-subject-version-differs", "refuse", "manifest_subject_mismatch", "subject.version differs from entry.version",
             text=catalog(ai_entry(ai_manifest(version="1.3.0"))), files=held(artifact=ARTIFACT)),
        case("ai-subject-version-absent", "refuse", "manifest_subject_mismatch", "subject.version absent while entry.version is present",
             text=catalog(ai_entry(ai_manifest(version=None))), files=held(artifact=ARTIFACT)),
        case("ai-signed-url-no-digest", "refuse", "entry_digest_missing_for_url", "a signed manifest on a url entry with no digest",
             text=catalog(ai_entry(ai_manifest(digest=None), digest=None))),
        case("ai-signed-data-no-digest", "refuse", "entry_digest_missing", "a signed manifest on an inline entry with no digest",
             text=catalog(ai_entry(ai_manifest(digest=None), digest=None, url=None, data=inline))),
        case("ai-data-digest", "admit", None, "an inline entry's digest is over the JCS bytes of data",
             text=catalog(ai_entry(ai_manifest(digest=sha(canonical_inline)), digest=sha(canonical_inline), url=None, data=inline))),
        case("ai-data-digest-wrong", "refuse", "entry_digest_mismatch", "a digest over the data as written, not its JCS bytes",
             text=catalog(ai_entry(ai_manifest(digest=sha(dumps(inline).encode() + b" ")), digest=sha(dumps(inline).encode() + b" "), url=None, data=inline))),
    ]


# --------------------------------------------------------------------------
# mcp-authz
# --------------------------------------------------------------------------

RESOURCE = "https://mcp.example.com/mcp"
ISSUER = "https://as.example.com"
NOW = 1800000000
OPTIONS = {"resource": RESOURCE, "issuers": [ISSUER], "tokenEndpoints": [ISSUER + "/token"], "now": NOW}


def token(presentation: str = "bearer", header: dict[str, Any] | None = None, **claims: Any) -> str:
    base: dict[str, Any] = {"iss": ISSUER, "aud": RESOURCE, "sub": "user-1", "exp": NOW + 600, "iat": NOW - 10}
    for key, value in claims.items():
        if value is None:
            base.pop(key, None)
        else:
            base[key] = value
    return dumps({"header": header or {"typ": "at+jwt", "alg": "ES256"}, "claims": base, "presentation": presentation})


def token_cases() -> list[dict[str, Any]]:
    rows = [
        case("valid", "admit", None, "issued by the advertised server for this resource, in its lifetime", text=token()),
        case("aud-array", "admit", None, "an audience array that names this resource", text=token(aud=["https://other.example", RESOURCE])),
        case("aud-wrong", "refuse", "aud-mismatch", "a token for another resource", text=token(aud="https://other.example/mcp")),
        case("aud-missing", "refuse", "aud-missing", "no audience at all", text=token(aud=None)),
        case("aud-empty-array", "refuse", "aud-missing", "an empty audience array", text=token(aud=[])),
        case("aud-token-endpoint", "refuse", "aud-is-token-endpoint",
             "the audience is the authorization server's token endpoint (the audience-injection class)", text=token(aud=ISSUER + "/token")),
        case("aud-trailing-slash", "refuse", "aud-matches-only-after-normalization", "equal only after a trailing slash is dropped",
             text=token(aud=RESOURCE + "/")),
        case("aud-case", "refuse", "aud-matches-only-after-normalization", "equal only after case folding",
             text=token(aud=RESOURCE.upper())),
        case("iss-wrong", "refuse", "iss-not-advertised", "an issuer the resource does not advertise", text=token(iss="https://evil.example")),
        case("iss-missing", "refuse", "iss-missing", "no issuer", text=token(iss=None)),
        case("resource-wrong", "refuse", "resource-mismatch", "a resource indicator for another server",
             text=token(resource="https://other.example/mcp")),
        case("resource-right", "admit", None, "a resource indicator naming this server", text=token(resource=RESOURCE)),
        case("expired", "refuse", "token-expired", "exp plus the skew tolerance has passed", text=token(exp=NOW - 60)),
        case("expiry-inside-skew", "admit", None, "exp passed by less than the skew tolerance", text=token(exp=NOW - 59)),
        case("exp-missing", "refuse", "exp-missing", "no expiry", text=token(exp=None)),
        case("exp-fraction", "refuse", "time-member-malformed", "a NumericDate that is not an integer", text=token(exp=NOW + 0.5)),
        case("exp-unsafe", "refuse", "unsafe-integer", "an expiry past 2^53", text=token().replace(str(NOW + 600), "9007199254740993")),
        case("not-yet-valid", "refuse", "token-not-yet-valid", "nbf past now plus the skew", text=token(nbf=NOW + 61)),
        case("issued-in-future", "refuse", "iat-in-future", "iat past now plus the skew", text=token(iat=NOW + 61)),
        case("dpop-as-bearer", "refuse", "bound-token-as-bearer", "a DPoP-bound token presented as a bearer token",
             text=token(cnf={"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"})),
        case("dpop-as-dpop", "admit", None, "the bound token presented with DPoP",
             text=token("dpop", cnf={"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"})),
        case("id-jag", "refuse", "id-jag-at-resource", "an identity assertion grant presented to a resource server",
             text=token(header={"typ": "oauth-id-jag+jwt", "alg": "ES256"}, resource=RESOURCE)),
        case("id-jag-wrong-resource", "refuse", "resource-mismatch", "an identity assertion grant for another resource",
             text=token(header={"typ": "oauth-id-jag+jwt", "alg": "ES256"}, resource="https://other.example/mcp")),
        case("no-presentation", "refuse", "token-shape-malformed", "how the token was presented is part of the decision",
             text=dumps({"header": {"typ": "at+jwt"}, "claims": json.loads(token())["claims"]})),
        case("no-clock", "refuse", "clock-not-configured", "a lifetime decision with no clock is not an admission",
             text=token(), options={k: v for k, v in OPTIONS.items() if k != "now"}),
        case("no-resource-configured", "refuse", "resource-not-configured", "an audience decision with no resource",
             text=token(), options={k: v for k, v in OPTIONS.items() if k != "resource"}),
        case("no-issuers-configured", "refuse", "issuers-not-configured", "an issuer decision with no advertised servers",
             text=token(), options={k: v for k, v in OPTIONS.items() if k != "issuers"}),
    ]
    return rows


# --------------------------------------------------------------------------
# co-signed-receipt
# --------------------------------------------------------------------------

HASH = hashlib.sha256(b"task").hexdigest()
RESULT = hashlib.sha256(b"result").hexdigest()
SIG = "ab" * 64


def receipt(**changes: Any) -> str:
    base: dict[str, Any] = {
        "formatVersion": "1",
        "agentDid": "did:web:agent.example",
        "toolName": "translate",
        "taskHash": HASH,
        "resultHash": RESULT,
        "success": True,
        "failureType": "",
        "latencyMs": 142,
        "timestamp": "2026-11-01T01:23:45.678Z",
        "signature": SIG,
    }
    for key, value in changes.items():
        if value is None:
            base.pop(key, None)
        else:
            base[key] = value
    return dumps(base)


def receipt_cases() -> list[dict[str, Any]]:
    return [
        case("valid", "admit", None, "every member, exact encodings, consistent outcome", text=receipt()),
        case("valid-co-signed", "admit", None, "a co-signature with the signer it is checked against",
             text=receipt(callerDid="did:web:caller.example", callerSignature="cd" * 64)),
        case("valid-failure", "admit", None, "a failure named on success false", text=receipt(success=False, failureType="timeout")),
        case("latency-last-safe", "admit", None, "latencyMs at 2^53 - 1", text=receipt(latencyMs=9007199254740991)),
        case("uppercase-hash", "refuse", "hash-not-lowercase-hex64", "an uppercase hash under a valid co-signature",
             text=receipt(taskHash=HASH.upper())),
        case("short-hash", "refuse", "hash-not-lowercase-hex64", "63 hex characters", text=receipt(resultHash=RESULT[:-1])),
        case("absent-task-hash", "refuse", "member-missing", "an absent hash is not a hash", text=receipt(taskHash=None)),
        case("absent-failure-type", "refuse", "member-missing", "an absent failureType is not an empty one", text=receipt(failureType=None)),
        case("unknown-version", "refuse", "version-unknown", "a version the verifier does not know is refused", text=receipt(formatVersion="2")),
        case("version-as-number", "refuse", "version-unknown", "formatVersion is the string \"1\"", text=receipt(formatVersion=1)),
        case("negative-latency", "refuse", "latency-out-of-range", "latencyMs below 0", text=receipt(latencyMs=-1)),
        case("fraction-latency", "refuse", "latency-out-of-range", "latencyMs is an integer", text=receipt(latencyMs=1.5)),
        case("signature-129", "refuse", "signature-not-lowercase-hex128",
             "129 hex characters: a lenient decoder truncates the odd character and the signature verifies", text=receipt(signature=SIG + "a")),
        case("signature-uppercase", "refuse", "signature-not-lowercase-hex128", "uppercase hex", text=receipt(signature=SIG.upper())),
        case("co-signature-malformed", "refuse", "signature-not-lowercase-hex128", "a co-signature of 127 characters",
             text=receipt(callerDid="did:web:caller.example", callerSignature=("cd" * 64)[:-1])),
        case("co-signature-without-signer", "refuse", "cosigner-missing", "a co-signature with no callerDid",
             text=receipt(callerSignature="cd" * 64)),
        case("success-with-failure-type", "refuse", "failure-type-inconsistent", "success true with a failure named",
             text=receipt(failureType="timeout")),
        case("failure-without-type", "refuse", "failure-type-inconsistent", "success false with no failure named",
             text=receipt(success=False)),
        case("timestamp-trailing-newline", "refuse", "instant-malformed", "a trailing LF some parsers strip",
             text=receipt(timestamp="2026-11-01T01:23:45.678Z\n")),
        case("duplicate-success", "refuse", "duplicate-member", "two success members: two decoders read two outcomes",
             text=receipt().replace('"success":true', '"success":false,"success":true')),
    ]


SETS = {
    "ijson": ("ijson", lambda: parse_cases(False), {}),
    "ijson-integer-only": ("ijson-integer-only", lambda: parse_cases(True), {}),
    "audit-freshness": ("audit-freshness", audit_cases, {}),
    "catalog-attestations": ("catalog-attestations", catalog_cases, {}),
    "mcp-authz": ("mcp-authz", token_cases, OPTIONS),
    "co-signed-receipt": ("co-signed-receipt", receipt_cases, {}),
}


def manifests() -> dict[Path, str]:
    out = {}
    for directory, (rule_set, build, options) in SETS.items():
        manifest: dict[str, Any] = {"ruleSet": rule_set}
        if options:
            manifest["options"] = options
        manifest["cases"] = build()
        out[HERE / directory / "manifest.json"] = json.dumps(manifest, indent=1, ensure_ascii=True) + "\n"
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 when a committed manifest differs")
    args = parser.parse_args(argv)
    stale = []
    for path, content in manifests().items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(str(path))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for path in stale:
        print(f"STALE {path}: run python vectors/rules/generate.py", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
