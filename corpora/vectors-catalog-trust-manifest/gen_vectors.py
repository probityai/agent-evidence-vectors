"""Build the catalog-trust-manifest cases byte-identically.

Every case is a catalog (ARD draft shape or AI Catalog shape), the DID documents an
offline resolver returns, the artifact the entry names, any vendored attestation
documents, and a context naming the construction, the object, the signer's claimed
role and the time of the check. Each rejected case is built so the check it names is
the first that fails; each accepted case is a control.

The case table is data: `CASES.json` is written from TABLE below and committed, and
`gen_vectors_independent.py`, which shares no code with this file or the package,
re-mints the corpus from `CASES.json` alone with `cryptography`. The corpus test
asserts both produce the same bytes. This file signs with the package's own
dependency-free P-256 (RFC 6979) and Ed25519.

Regenerate:

    uv run python corpora/vectors-catalog-trust-manifest/gen_vectors.py

TEST KEYS ONLY. Every key is derived from the SHA-256 of a public label.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import catalogtrust as reader  # noqa: E402
from agent_evidence_vectors import p256  # noqa: E402

PUB, ASSESSOR = "did:web:publisher.example", "did:web:assessor.example"
WWW, OTHER = "did:web:www.publisher.example", "did:web:other.example"
CARD_RECEIPT = "https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt"
OBSERVED = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect"
KEYS = {  # name: (DID, fragment, algorithm, label)
    "publisher": (PUB, "es256", "ES256", "catalog-trust-manifest publisher es256"),
    "publisher-ed": (PUB, "ed25519", "EdDSA", "catalog-trust-manifest publisher ed25519"),
    "assessor": (ASSESSOR, "es256", "ES256", "catalog-trust-manifest assessor es256"),
    "www": (WWW, "es256", "ES256", "catalog-trust-manifest www es256"),
    "other": (OTHER, "es256", "ES256", "catalog-trust-manifest other es256"),
}
AT, ISSUED, EXPIRES = "2026-11-16T00:00:00Z", "2026-11-01T00:00:00Z", "2027-11-01T00:00:00Z"
IDENTIFIER = "urn:air:publisher.example:agent:travel"
URL = "https://publisher.example/agents/travel/agent-card.json"
CARD_TYPE = "application/a2a-agent-card+json"


def _set(path: list[Any], value: Any) -> dict[str, Any]:
    return {"op": "set", "path": path, "value": value}


def _del(path: list[Any]) -> dict[str, Any]:
    return {"op": "del", "path": path}


TM = ["entries", 0, "trustManifest"]
M0 = ["entries", 0, "trustManifests", 0]
VM0 = [PUB, "verificationMethod", 0]
# Edits that turn the travel card into the billing card, the artifact the second entry names.
BILLING = [_set(["description"], "The billing agent."), _set(["name"], "billing agent"),
           _set(["url"], "https://publisher.example/agents/billing")]
# The publisher's ES256 x coordinate with a leading zero octet: the same integer in 33
# bytes, which RFC 7518 section 6.2.1.2 forbids (the coordinate is exactly 32 octets).
X_33_OCTETS = "AKwdeINUoV16NYPAMLEebdQI0FEvn-gu3ALp12AsIKSM"


def _did_alias(did: str) -> list[dict[str, Any]]:
    """A DID document for ``did`` carrying the other.example ES256 key as did#es256."""
    return [{"op": "copy", "from": [OTHER], "path": [did]}, _set([did, "id"], did),
            _set([did, "verificationMethod", 0, "id"], did + "#es256"),
            _set([did, "verificationMethod", 0, "controller"], did),
            _set([did, "assertionMethod"], [did + "#es256"])]


def _signed_by(did: str) -> list[dict[str, Any]]:
    return [_set(M0 + ["contributor"], did), _set(M0 + ["signature", "signer"], did)]


def _sign(construction: str, key: str = "publisher", **extra: Any) -> dict[str, Any]:
    spec = {"construction": construction, "entry": 0, "manifest": 0, "key": key,
            "header": {}, "form": "detached"}
    spec.update(extra)
    return spec


def _case(case_id: str, edit: str, decision: str, reason: str, shape: str,
          construction: str, sign: list[dict[str, Any]], **knobs: Any) -> dict[str, Any]:
    context = {"construction": construction, "entry": 0, "manifest": 0, "role": "publisher",
               "at": AT, "attestationFiles": []}
    context.update(knobs.pop("context", {}))
    case = {"id": case_id, "edit": edit, "expected": {"decision": decision, "reason": reason},
            "shape": shape, "assessor": False, "secondEntry": False, "sign": sign,
            "artifact": [], "artifactAfter": [], "attestations": [], "attestationAfter": [],
            "before": [], "after": [], "raw": [], "dids": [], "context": context,
            "contextAfter": []}
    case.update(knobs)
    return case


D, F, AIC, SNAP = reader.DRAFT, reader.FIELD, reader.AIC, reader.SNAPSHOT
OK, NO = "accept", "reject"
PASS, SNAP_PASS = "signature_covers_release", "snapshot_signature_valid"


def _contradictions() -> list[dict[str, Any]]:
    out = []
    for signed_as, verdicts in (
            ("draft", {D: (OK, PASS), F: (NO, "signature_invalid"),
                       AIC: (NO, "signature_missing"), SNAP: (NO, "signature_missing")}),
            ("whole-entry", {D: (NO, "signature_invalid"), F: (OK, PASS),
                             AIC: (NO, "signature_missing"), SNAP: (NO, "signature_missing")})):
        for construction, (decision, reason) in verdicts.items():
            out.append(_case(
                f"contradict-{signed_as}-signed-under-{construction}",
                f"one catalog signed over the {signed_as} input, judged under {construction}; "
                "the four contradict cases of this group carry byte-identical catalogs",
                decision, reason, "ard", construction, [_sign(D if signed_as == "draft" else F)]))
    return out


def _closed_terms() -> list[dict[str, Any]]:
    """Cases for the AI Catalog signer-profile rules and the closed terms of the context."""
    path, upper, port = ("did:web:other.example:team", "did:web:Other.example",
                         "did:web:other.example%3A8443")
    signer_cases = [
        _case(f"reject-aic-signer-{slug}", f"the signer is {did}, not a root did:web DID "
              "(lowercase ASCII domain, no port, no path)", NO, "signer_not_root_did_web",
              "aic", AIC, [_sign(AIC, "other", header={"kid": did + "#es256"})],
              before=_signed_by(did), dids=_did_alias(did), context={"role": "contributor"})
        for slug, did in (("path-did", path), ("uppercase-domain", upper), ("port", port),
                          ("ipv4", "did:web:192.0.2.1"), ("numeric-tld", "did:web:agents.2026"),
                          ("domain-past-253-octets", "did:web:" + ("a" * 63 + ".") * 3
                           + "b" * 63 + ".example"))]
    return [
        _case("reject-role-unknown", "the context names a role outside the closed term "
              "(publisher, contributor); a verifier that skips the publisher rule for it "
              "accepts an assessor as the publisher", NO, "role_unknown", "aic", AIC,
              [_sign(AIC), _sign(AIC, "assessor", manifest=1)], assessor=True,
              context={"manifest": 1, "role": "Publisher"}),
        _case("reject-catalog-not-json", "the catalog carries NaN, which is not JSON",
              NO, "json_invalid", "ard", D, [_sign(D)],
              raw=[["\"specVersion\": \"1.0\"", "\"specVersion\": NaN"]]),
        _case("reject-b64-not-boolean", "b64 is the string \"false\" (RFC 7797 section 3: "
              "the value is a boolean), declared critical", NO, "jws_malformed", "ard", D,
              [_sign(D, header={"b64": "false", "crit": ["b64"]})]),
        _case("reject-aic-profile-unsupported", "signature.profile names a procedure this "
              "verifier does not implement; AI Catalog consumers never infer another",
              NO, "profile_unsupported", "aic", AIC, [_sign(AIC)],
              before=[_set(M0 + ["signature", "profile"], "https://other.example/profile/v1")]),
        _case("reject-aic-profile-absent", "the Signature object has no profile member",
              NO, "profile_unsupported", "aic", AIC, [_sign(AIC)],
              before=[_del(M0 + ["signature", "profile"])]),
        _case("reject-snapshot-profile-unsupported", "the catalog signature names a profile "
              "this verifier does not implement", NO, "profile_unsupported", "snapshot", SNAP,
              [_sign(AIC), _sign(SNAP)],
              before=[_set(["signature", "profile"], "https://other.example/profile/v1")]),
        *signer_cases,
        _case("reject-snapshot-signer-path-did", "a catalog signature by a path-based did:web "
              "DID", NO, "signer_not_root_did_web", "snapshot", SNAP,
              [_sign(AIC), _sign(SNAP, "other", header={"kid": path + "#es256"})],
              before=[_set(["signature", "signer"], path)], dids=_did_alias(path)),
        _case("reject-verification-method-ambiguous", "two verification methods carry the kid "
              "as their id, the second holding another key that made the signature",
              NO, "verification_method_ambiguous", "aic", AIC,
              [_sign(AIC, "other", header={"kid": PUB + "#es256"})],
              dids=[{"op": "copy", "from": [OTHER, "verificationMethod", 0],
                     "path": [PUB, "verificationMethod", 1]},
                    _set([PUB, "verificationMethod", 1, "id"], PUB + "#es256"),
                    _set([PUB, "verificationMethod", 1, "controller"], PUB)]),
        _case("reject-aic-method-controller-other", "the selected method's controller is "
              "another DID than the signer", NO, "method_controller_mismatch", "aic", AIC,
              [_sign(AIC)], dids=[_set(VM0 + ["controller"], OTHER)]),
        *[_case(f"reject-jwk-{slug}", f"the method's JWK {what}", NO, "jwk_not_signing_key",
                "aic", AIC, [_sign(AIC)], dids=[_set(VM0 + ["publicKeyJwk", member], value)])
          for slug, what, member, value in (
              ("use-enc", "is marked for encryption (use enc)", "use", "enc"),
              ("private-member", "carries a private member d", "d", "AQ"),
              ("alg-other", "names ES384 while the header names ES256", "alg", "ES384"),
              ("key-ops-sign-only", "permits sign but not verify", "key_ops", ["sign"]),
              ("x-33-octets", "carries a 33-octet x coordinate holding the right integer", "x",
               X_33_OCTETS))],
        _case("reject-aic-issued-absent", "the Signature object has no issuedAt, which the AI "
              "Catalog requires", NO, "timestamp_invalid", "aic", AIC, [_sign(AIC)],
              before=[_del(M0 + ["signature", "issuedAt"])]),
        _case("reject-issued-not-a-date", "issuedAt is 2026-02-30, which matches the pattern "
              "and names no day", NO, "timestamp_invalid", "aic", AIC, [_sign(AIC)],
              before=[_set(M0 + ["signature", "issuedAt"], "2026-02-30T00:00:00Z")]),
        _case("reject-expires-not-after-issued", "expiresAt precedes issuedAt", NO,
              "timestamp_invalid", "aic", AIC, [_sign(AIC)],
              before=[_set(M0 + ["signature", "expiresAt"], "2026-10-01T00:00:00Z")]),
        _case("reject-draft-identifier-absent", "entry and subject both lack identifier, so "
              "the signed subject names no entry", NO, "subject_entry_mismatch", "ard", D,
              [_sign(D)], before=[_del(["entries", 0, "identifier"]),
                                  _del(TM + ["subject", "identifier"])],
              context={"role": "contributor"}),
        _case("reject-attestation-signer-document-not-identity", "the DID document served for "
              "the attestation key's DID carries another id", NO, "attestation_unsigned",
              "ard", D, [_sign(D)],
              attestations=[{"kind": "dsse", "predicate": CARD_RECEIPT, "subject": "artifact"}],
              dids=[_set([ASSESSOR, "id"], "did:web:evil.example")],
              context={"attestationFiles": ["attestation-0.dsse.json"]}),
        _case("accept-assertion-method-relative-reference", "control: assertionMethod names the "
              "key by the relative reference #es256, resolved against the document id (DID Core "
              "3.2.2)", OK, PASS, "aic", AIC, [_sign(AIC)],
              dids=[_set([PUB, "assertionMethod"], ["#es256", PUB + "#ed25519"])]),
        _case("reject-draft-url-and-data", "the entry carries both url and data; the draft "
              "requires exactly one", NO, "entry_delivery_not_one", "ard", D, [_sign(D)],
              before=[_set(["entries", 0, "data"], {"name": "travel agent"})]),
        _case("reject-draft-neither-url-nor-data", "the entry carries neither url nor data",
              NO, "entry_delivery_not_one", "ard", D, [_sign(D)],
              before=[_del(["entries", 0, "url"])]),
        _case("accept-kid-fragment-with-colon", "control: the kid fragment carries a colon, "
              "which an RFC 3986 fragment allows", OK, PASS, "aic", AIC,
              [_sign(AIC, header={"kid": PUB + "#key:es256"})],
              dids=[_set(VM0 + ["id"], PUB + "#key:es256"),
                    _set([PUB, "assertionMethod"], [PUB + "#key:es256", PUB + "#ed25519"])]),
        _case("reject-kid-fragment-bad-escape", "the kid fragment carries a malformed "
              "percent-escape", NO, "kid_not_under_identity", "aic", AIC,
              [_sign(AIC, header={"kid": PUB + "#key%zz"})],
              dids=[_set(VM0 + ["id"], PUB + "#key%zz"),
                    _set([PUB, "assertionMethod"], [PUB + "#key%zz", PUB + "#ed25519"])]),
        _case("accept-issued-with-fraction", "control: an RFC 3339 issuedAt with fractional "
              "seconds", OK, PASS, "aic", AIC, [_sign(AIC)],
              before=[_set(M0 + ["signature", "issuedAt"], "2026-11-01T00:00:00.000Z")]),
        _case("accept-issued-with-offset", "control: an RFC 3339 issuedAt with a numeric offset, "
              "compared as an instant", OK, PASS, "aic", AIC, [_sign(AIC)],
              before=[_set(M0 + ["signature", "issuedAt"], "2026-11-01T01:00:00+01:00")]),
        _case("accept-draft-inline-data", "control: an entry delivered as inline data has no url, "
              "so there is no origin to bind (draft 3.3, 6.2), and its digest is of the RFC 8785 "
              "bytes of data (AI Catalog digest)", OK, PASS, "ard", D, [_sign(D)],
              before=_inline()),
        *_round_four(),
    ]


def _inline() -> list[dict[str, Any]]:
    """Deliver the entry as inline data: the card itself (artifact_value(IDENTIFIER), written
    out because the interpreter below is defined after the table), digested over its RFC 8785
    bytes."""
    card = {"description": "The travel agent.", "name": "travel agent",
            "url": "https://publisher.example/agents/travel", "version": "1.0.0"}
    return [_del(["entries", 0, "url"]), _set(["entries", 0, "data"], card),
            _set(["entries", 0, "digest"], "$CARD_JCS"),
            _set(TM + ["subject", "digest"], "$CARD_JCS")]


def _deep(levels: int) -> list[list[str]]:
    """A raw edit adding a host-level member nested ``levels`` arrays deep, outside the
    signed bytes of a draft trust manifest."""
    return [['"specVersion": "1.0"',
             '"x-deep": ' + "[" * levels + "1" + "]" * levels + ', "specVersion": "1.0"']]


def _round_four() -> list[dict[str, Any]]:
    """Counter-examples from the fourth adversarial round: each verdict below was wrong in
    one reader or both before it."""
    dsse = [{"kind": "dsse", "predicate": CARD_RECEIPT + "?view=>>>", "subject": "artifact"}]
    files = {"attestationFiles": ["attestation-0.dsse.json"]}
    leap = [_set(M0 + ["signature", "issuedAt"], "2016-12-31T23:59:60Z")]
    return [
        _case("reject-draft-inline-data-swapped", "inline data changed after signing; the "
              "digest is of the RFC 8785 bytes of data, so it no longer matches (AI Catalog "
              "digest, draft 3.2 digest)", NO, "artifact_digest_mismatch", "ard", D, [_sign(D)],
              before=_inline(),
              after=[_set(["entries", 0, "data", "url"], "https://evil.example/agents/travel")]),
        _case("accept-dsse-url-safe-base64", "control: a DSSE envelope in URL-safe base64; DSSE "
              "verifiers MUST accept either alphabet (protocol.md)", OK, PASS, "ard", D,
              [_sign(D)], attestations=[{**dsse[0], "encoding": "url-safe"}], context=files),
        _case("accept-dsse-der-signature", "control: a DSSE ES256 signature in DER, as sigstore "
              "and in-toto signers write it", OK, PASS, "ard", D, [_sign(D)],
              attestations=[{**dsse[0], "encoding": "der"}], context=files),
        _case("reject-dsse-der-non-minimal", "a DER signature whose r carries a zero octet it "
              "does not need; DER has one encoding per value", NO, "attestation_unsigned",
              "ard", D, [_sign(D)], attestations=[{**dsse[0], "encoding": "der-non-minimal"}],
              context=files),
        _case("reject-dsse-payload-newline", "a DSSE payload with a line break inside the base64; "
              "RFC 4648 section 3.3 refuses characters outside the alphabet",
              NO, "attestation_unsigned", "ard", D, [_sign(D)],
              attestations=[{**dsse[0], "encoding": "newline"}], context=files),
        _case("reject-attestation-file-not-one-segment", "the context names the vendored file "
              "as ./attestation-0.dsse.json; a vendored file is named by one path segment",
              NO, "attestation_digest_mismatch", "ard", D, [_sign(D)], attestations=dsse,
              context=files,
              contextAfter=[_set(["attestationFiles", 0], "./attestation-0.dsse.json")]),
        _case("accept-nesting-at-the-limit", "control: 64 arrays and objects open at once",
              OK, PASS, "ard", D, [_sign(D)], raw=_deep(63)),
        _case("reject-nesting-past-the-limit", "65 arrays and objects open at once, outside "
              "the signed bytes; readers hold different values past a nesting limit",
              NO, "json_invalid", "ard", D, [_sign(D)], raw=_deep(64)),
        _case("accept-context-entry-integral-number", "control: the context names entry 1.0, "
              "the integer 1 (JSON does not tell 1.0 from 1)", OK, PASS, "ard", D,
              [_sign(D, entry=1)], secondEntry=True, artifact=BILLING, context={"entry": 1.0}),
        _case("reject-context-entry-negative", "the context names entry -1, which selects "
              "nothing (an index is a non-negative integer)", NO, "signature_missing", "ard", D,
              [_sign(D)], context={"entry": -1}),
        _case("reject-context-entry-boolean", "the context names entry true, which is not a "
              "number", NO, "signature_missing", "ard", D, [_sign(D, entry=1)],
              secondEntry=True, artifact=BILLING, context={"entry": True}),
        _case("reject-issued-second-60-not-leap", "issuedAt 2026-11-01T00:00:60Z: no leap "
              "second falls there, so it names no instant (RFC 3339 section 5.7)",
              NO, "timestamp_invalid", "aic", AIC, [_sign(AIC)],
              before=[_set(M0 + ["signature", "issuedAt"], "2026-11-01T00:00:60Z")]),
        _case("reject-issued-second-60-offset-not-leap", "issuedAt 2016-12-31T23:59:60+01:00 "
              "is 22:59:60 UTC, no leap second", NO, "timestamp_invalid", "aic", AIC,
              [_sign(AIC)], before=[_set(M0 + ["signature", "issuedAt"],
                                         "2016-12-31T23:59:60+01:00")]),
        _case("accept-issued-on-a-leap-second", "control: 2016-12-31T23:59:60Z, the last leap "
              "second in the IERS list", OK, PASS, "aic", AIC, [_sign(AIC)], before=leap),
        _case("accept-issued-on-a-leap-second-with-offset", "control: the same leap second "
              "written as 18:59:60-05:00", OK, PASS, "aic", AIC, [_sign(AIC)],
              before=[_set(M0 + ["signature", "issuedAt"], "2016-12-31T18:59:60-05:00")]),
        _case("accept-url-origin-case-and-default-port", "control: HTTPS://PUBLISHER.example:443 "
              "is the origin https://publisher.example (RFC 6454 section 4)", OK, PASS,
              "ard", D, [_sign(D)], before=[_set(["entries", 0, "url"],
                         "HTTPS://PUBLISHER.example:443/agents/travel/agent-card.json")]),
        _case("reject-url-userinfo", "a url with userinfo before the publisher host; a recipient "
              "treats https userinfo as an error (RFC 9110 section 4.2.4)",
              NO, "url_origin_unbound", "ard", D, [_sign(D)],
              before=[_set(["entries", 0, "url"],
                           "https://publisher.example@cdn.other.example/agent-card.json")]),
        _case("reject-aic-url-and-data", "an AI Catalog entry carrying both url and data; a "
              "Catalog Entry MUST contain exactly one", NO, "entry_delivery_not_one", "aic", AIC,
              [_sign(AIC)], before=[_set(["entries", 0, "data"], {"name": "travel agent"})]),
        _case("reject-aic-neither-url-nor-data", "an AI Catalog entry with neither url nor data, "
              "whose digest still names artifact.json", NO, "entry_delivery_not_one", "aic", AIC,
              [_sign(AIC)], before=[_del(["entries", 0, "url"])]),
        _case("reject-issued-one-second-in-future", "checked one second before issuedAt; "
              "the profile applies no clock-skew tolerance, so the verdict names the instant",
              NO, "issued_in_future", "aic", AIC, [_sign(AIC)],
              context={"at": "2026-10-31T23:59:59Z"}),
        _case("accept-checked-at-the-issued-instant", "control: checked at issuedAt itself, "
              "written with another offset", OK, PASS, "aic", AIC, [_sign(AIC)],
              context={"at": "2026-10-31T19:00:00-05:00"}),
        _case("reject-url-other-port", "a url on the publisher host at port 8443, another origin",
              NO, "url_origin_unbound", "ard", D, [_sign(D)],
              before=[_set(["entries", 0, "url"],
                           "https://publisher.example:8443/agents/travel/agent-card.json")]),
    ]


TABLE: list[dict[str, Any]] = [
    _case("accept-draft-es256", "control: ARD draft trust manifest, ES256, publisher DID",
          OK, PASS, "ard", D, [_sign(D)]),
    _case("accept-draft-eddsa", "control: the draft names ES256 as mandatory to implement, "
          "not as the only algorithm, so EdDSA is accepted under it", OK, PASS, "ard", D,
          [_sign(D, "publisher-ed")]),
    _case("accept-draft-b64-false-with-crit", "control: RFC 7797 unencoded payload declared "
          "critical; the draft does not forbid it", OK, PASS, "ard", D,
          [_sign(D, header={"b64": False, "crit": ["b64"]})]),
    _case("accept-draft-utf16-member-order", "control: member names that sort differently by "
          "UTF-16 code unit and by code point; RFC 8785 orders by UTF-16",
          OK, PASS, "ard", D, [_sign(D)],
          before=[_set(TM + ["x-order"], {"": 1, "\U0001f600": 2})]),
    _case("accept-field-whole-entry", "control: the whole-entry input measured in the field "
          "(entry minus trustManifest.signature)", OK, PASS, "ard", F, [_sign(F)]),
    _case("accept-cross-origin-url-bound", "control: url on another origin, and the artifact "
          "fetched from it declares the entry identifier (draft 6.2)", OK, PASS, "ard", D,
          [_sign(D)], before=[_set(["entries", 0, "url"],
                                   "https://cdn.other.example/travel/agent-card.json")],
          artifact=[_set(["identifier"], IDENTIFIER)]),
    _case("accept-attestations-dsse-bound", "control: two attestations, each a DSSE in-toto "
          "statement whose subject digest equals entry.digest, typed by the agent-card-receipt "
          "and observed-effect predicate URIs", OK, PASS, "ard", D, [_sign(D)],
          attestations=[{"kind": "dsse", "predicate": CARD_RECEIPT, "subject": "artifact"},
                        {"kind": "dsse", "predicate": OBSERVED, "subject": "artifact"}],
          context={"attestationFiles": ["attestation-0.dsse.json", "attestation-1.dsse.json"]}),
    _case("accept-aic-publisher", "control: AI Catalog trust manifest under the did:web "
          "Signer and Publisher Profiles", OK, PASS, "aic", AIC, [_sign(AIC)]),
    _case("accept-aic-assessor-as-contributor", "control: an assessor manifest beside the "
          "publisher's, judged in the contributor role", OK, PASS, "aic", AIC,
          [_sign(AIC), _sign(AIC, "assessor", manifest=1)], assessor=True,
          context={"manifest": 1, "role": "contributor"}),
    _case("accept-aic-publisher-beside-assessor", "control: the same catalog, the publisher's "
          "manifest in the publisher role", OK, PASS, "aic", AIC,
          [_sign(AIC), _sign(AIC, "assessor", manifest=1)], assessor=True),
    _case("accept-aic-nested-signature-kept", "control: members named signature and "
          "additionalSignatures below the manifest stay in the payload (exclusions are not "
          "recursive)", OK, PASS, "aic", AIC, [_sign(AIC)],
          before=[_set(M0 + ["x-extension"], {"signature": "kept",
                                               "additionalSignatures": ["kept"]})]),
    _case("accept-aic-additional-signatures-ignored", "control: the reserved immediate "
          "additionalSignatures member added after signing is outside the payload",
          OK, PASS, "aic", AIC, [_sign(AIC)],
          after=[_set(M0 + ["additionalSignatures"], [{"jws": "reserved"}])]),
    _case("accept-snapshot", "control: a whole-catalog snapshot signature over a catalog "
          "carrying a signed manifest", OK, SNAP_PASS, "snapshot", SNAP,
          [_sign(AIC), _sign(SNAP)]),
    *_contradictions(),
    _case("reject-construction-unknown", "the context names a construction outside the closed "
          "term", NO, "construction_unknown", "ard", D, [_sign(D)],
          context={"construction": "ai-catalog-pre-0028"}),
    _case("reject-duplicate-identifier", "a second identifier member in the entry; a "
          "last-wins parser reads another publisher", NO, "duplicate_member", "ard", D,
          [_sign(D)], raw=[["\"identifier\": \"urn:air:publisher.example:agent:travel\",",
                            "\"identifier\": \"urn:air:publisher.example:agent:travel\",\n"
                            "      \"identifier\": \"urn:air:evil.example:agent:travel\","]]),
    _case("reject-unsigned", "a trust manifest with no signature", NO, "signature_missing",
          "ard", D, []),
    _case("reject-jws-attached-payload", "the stored JWS carries its payload segment",
          NO, "jws_malformed", "ard", D, [_sign(D, form="attached")]),
    _case("reject-jws-padded-base64url", "the signature segment is padded base64url",
          NO, "jws_malformed", "ard", D, [_sign(D, form="padded")]),
    _case("reject-aic-typ-missing", "an AI Catalog manifest signature without typ",
          NO, "typ_missing_or_mismatched", "aic", AIC, [_sign(AIC, header={"typ": None})]),
    _case("reject-snapshot-typ-of-manifest", "a manifest-typed signature presented as the "
          "catalog snapshot signature", NO, "typ_missing_or_mismatched", "snapshot", SNAP,
          [_sign(AIC), _sign(SNAP, header={"typ": "ai-catalog-trust-manifest+jws"})]),
    _case("reject-alg-none", "alg none", NO, "alg_not_allowed_for_profile", "ard", D,
          [_sign(D, header={"alg": "none"})]),
    _case("reject-aic-eddsa", "EdDSA under the AI Catalog did:web Signer Profile, which "
          "allows ES256 only", NO, "alg_not_allowed_for_profile", "aic", AIC,
          [_sign(AIC, "publisher-ed")]),
    *[_case(f"reject-key-source-{name}", f"the protected header names a key source ({name})",
            NO, "key_source_in_header", "aic", AIC,
            [_sign(AIC, header={name: value})])
      for name, value in (("jku", "https://publisher.example/jwks.json"),
                          ("jwk", {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}),
                          ("x5u", "https://publisher.example/cert.pem"),
                          ("x5c", ["AA=="]))],
    _case("reject-aic-b64", "b64 in an AI Catalog protected header, even declared critical",
          NO, "b64_forbidden_for_profile", "aic", AIC,
          [_sign(AIC, header={"b64": False, "crit": ["b64"]})]),
    _case("reject-crit-unknown", "crit names a parameter the verifier does not implement",
          NO, "jws_crit_unsupported", "ard", D,
          [_sign(D, header={"crit": ["exp"], "exp": 1893456000})]),
    _case("reject-b64-without-crit", "b64 false without crit (RFC 7797 section 6): a verifier "
          "that ignores b64 checks other bytes", NO, "b64_without_crit", "ard", D,
          [_sign(D, header={"b64": False})]),
    _case("reject-kid-not-under-identity", "the kid names another DID than the manifest "
          "identity", NO, "kid_not_under_identity", "ard", D,
          [_sign(D, "other")]),
    _case("reject-did-document-not-identity", "the document served for the identity carries "
          "another id", NO, "did_document_not_identity", "ard", D, [_sign(D)],
          dids=[_set([PUB, "id"], "did:web:evil.example")]),
    _case("reject-kid-not-in-did-document", "the kid fragment names no verification method",
          NO, "kid_not_in_did_document", "ard", D,
          [_sign(D, header={"kid": PUB + "#missing"})]),
    _case("reject-key-not-assertion-method", "the key is listed under verificationMethod but "
          "not under assertionMethod", NO, "key_not_assertion_method", "aic", AIC, [_sign(AIC)],
          dids=[_set([PUB, "assertionMethod"], [PUB + "#ed25519"])]),
    _case("reject-alg-key-mismatch", "an ES256 header over a signature from the Ed25519 key",
          NO, "alg_key_mismatch", "ard", D,
          [_sign(D, "publisher-ed", header={"alg": "ES256"})]),
    _case("reject-number-not-interoperable", "the record carries 9007199254740993; the "
          "signature covers 9007199254740992, the double a parser reads it as",
          NO, "number_not_interoperable", "ard", D,
          [_sign(D)], before=[_set(TM + ["x-count"], 9007199254740992)],
          after=[_set(TM + ["x-count"], 9007199254740993)]),
    _case("reject-lone-surrogate", "a member value that is a lone surrogate has no UTF-8 form",
          NO, "no_canonical_form", "ard", D, [_sign(D)],
          before=[_set(TM + ["x-note"], "ok")], after=[_set(TM + ["x-note"], "\ud800")]),
    _case("reject-signature-invalid", "issuedAt changed after signing", NO, "signature_invalid",
          "ard", D, [_sign(D)], after=[_set(TM + ["issuedAt"], "2026-10-01T00:00:00Z")]),
    _case("reject-aic-signer-not-contributor", "the manifest names one contributor and is "
          "signed by another", NO, "signer_not_contributor", "aic", AIC, [_sign(AIC)],
          before=[_set(M0 + ["contributor"], ASSESSOR)]),
    _case("reject-subject-missing", "a signed trust manifest with no subject",
          NO, "subject_missing", "ard", D, [_sign(D)], before=[_del(TM + ["subject"])]),
    _case("reject-subject-version-absent", "the entry has a version and the subject does not",
          NO, "subject_entry_mismatch", "aic", AIC, [_sign(AIC)],
          before=[_del(M0 + ["subject", "version"])]),
    _case("reject-manifest-moved-to-other-release", "a valid manifest moved to an entry with "
          "the same identifier and another digest, whose artifact it names is served",
          NO, "subject_entry_mismatch", "ard", D, [_sign(D)], secondEntry=True,
          artifactAfter=BILLING,
          after=[{"op": "copy", "from": TM, "path": ["entries", 1, "trustManifest"]},
                 _set(["entries", 1, "identifier"], IDENTIFIER)],
          context={"entry": 1}),
    _case("reject-entry-digest-missing-for-url", "an entry referenced by url with no digest, "
          "and a subject with no digest", NO, "entry_digest_missing_for_url", "ard", D,
          [_sign(D)], before=[_del(["entries", 0, "digest"]), _del(TM + ["subject", "digest"])]),
    _case("reject-artifact-digest-mismatch", "the artifact bytes differ from entry.digest",
          NO, "artifact_digest_mismatch", "aic", AIC, [_sign(AIC)],
          artifactAfter=[_set(["version"], "1.0.1")]),
    _case("reject-url-origin-unbound", "url on another origin, and the artifact there does "
          "not declare the entry identifier (draft 6.2)", NO, "url_origin_unbound", "ard", D,
          [_sign(D)], before=[_set(["entries", 0, "url"],
                                   "https://cdn.other.example/travel/agent-card.json")]),
    _case("reject-attestation-digest-mismatch", "the vendored attestation differs from its "
          "signed digest", NO, "attestation_digest_mismatch", "ard", D, [_sign(D)],
          attestations=[{"kind": "dsse", "predicate": CARD_RECEIPT, "subject": "artifact"}],
          attestationAfter=[0], context={"attestationFiles": ["attestation-0.dsse.json"]}),
    _case("reject-attestation-unsigned", "an unsigned scan result: neither a signature over "
          "the artifact nor a signed subject (draft 3.5.2 item 1)", NO, "attestation_unsigned",
          "ard", D, [_sign(D)],
          attestations=[{"kind": "sarif", "predicate": "SARIF", "subject": "artifact"}],
          context={"attestationFiles": ["attestation-0.sarif.json"]}),
    _case("reject-attestation-transplanted", "a signed statement whose subject is another "
          "artifact", NO, "attestation_transplanted", "ard", D, [_sign(D)],
          attestations=[{"kind": "dsse", "predicate": CARD_RECEIPT, "subject": "other"}],
          context={"attestationFiles": ["attestation-0.dsse.json"]}),
    _case("reject-aic-www-signer", "a www. subdomain signer under the AI Catalog exact-match "
          "publisher rule", NO, "publisher_not_signer", "aic", AIC, [_sign(AIC, "www")],
          before=[_set(M0 + ["contributor"], WWW), _set(M0 + ["signature", "signer"], WWW)]),
    _case("reject-draft-www-signer", "a www. subdomain signer under the draft rule, with no "
          "authorization record offline", NO, "publisher_authorization_absent", "ard", D,
          [_sign(D, "www")], before=[_set(TM + ["identity"], WWW)]),
    _case("reject-assessor-presented-as-publisher", "a valid assessor manifest judged in the "
          "publisher role", NO, "publisher_not_signer", "aic", AIC,
          [_sign(AIC), _sign(AIC, "assessor", manifest=1)], assessor=True,
          context={"manifest": 1}),
    _case("reject-issued-in-future", "checked before issuedAt", NO, "issued_in_future",
          "aic", AIC, [_sign(AIC)], context={"at": "2026-10-01T00:00:00Z"}),
    _case("reject-manifest-expired", "checked at expiresAt", NO, "manifest_expired",
          "ard", D, [_sign(D)], context={"at": EXPIRES}),
    *_closed_terms(),
]


# --------------------------------------------------------------------------- interpreter

def enc(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def scalar(label: str) -> int:
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % (p256.N - 1) + 1


def seed(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def jwk(name: str) -> dict[str, str]:
    _, _, alg, label = KEYS[name]
    if alg == "EdDSA":
        return {"crv": "Ed25519", "kty": "OKP", "x": b64u(rail.ed25519_public_key(seed(label)))}
    x, y = p256.public_point(scalar(label))
    return {"crv": "P-256", "kty": "EC", "x": b64u(x.to_bytes(32, "big")),
            "y": b64u(y.to_bytes(32, "big"))}


def der(raw: bytes, non_minimal: bool = False) -> bytes:
    """A raw r || s ECDSA signature as a DER ECDSA-Sig-Value; ``non_minimal`` prefixes r
    with a zero octet it does not need."""
    def integer(value: bytes, pad: bool) -> bytes:
        body = value.lstrip(b"\x00") or b"\x00"
        if body[0] & 0x80:
            body = b"\x00" + body
        if pad:
            body = b"\x00" + body
        return bytes([0x02, len(body)]) + body
    inner = integer(raw[:32], non_minimal) + integer(raw[32:], False)
    return bytes([0x30, len(inner)]) + inner


def raw_sign(name: str, message: bytes) -> bytes:
    _, _, alg, label = KEYS[name]
    if alg == "EdDSA":
        return rail.ed25519_sign(seed(label), message)
    return p256.sign(scalar(label), message)


def did_documents() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, (did, fragment, _, _) in KEYS.items():
        doc = out.setdefault(did, {"@context": ["https://www.w3.org/ns/did/v1"], "id": did,
                                   "verificationMethod": [], "assertionMethod": []})
        kid = f"{did}#{fragment}"
        doc["verificationMethod"].append({"controller": did, "id": kid,
                                          "publicKeyJwk": jwk(name), "type": "JsonWebKey2020"})
        doc["assertionMethod"].append(kid)
    return out


def _resolve(value: Any, digests: dict[str, str]) -> Any:
    if isinstance(value, str) and value in digests:
        return digests[value]
    if isinstance(value, list):
        return [_resolve(v, digests) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, digests) for k, v in value.items()}
    return value


def _walk(doc: Any, path: list[Any]) -> Any:
    for token in path:
        doc = doc[token]
    return doc


def apply(doc: Any, ops: list[dict[str, Any]], digests: dict[str, str]) -> None:
    for op in ops:
        parent = _walk(doc, op["path"][:-1])
        last = op["path"][-1]
        if op["op"] == "del":
            del parent[last]
        elif op["op"] == "copy":
            parent[last] = copy.deepcopy(_walk(doc, op["from"]))
        else:
            parent[last] = _resolve(copy.deepcopy(op["value"]), digests)


def artifact_value(identifier: str) -> dict[str, Any]:
    name = identifier.rsplit(":", 1)[1]
    return {"description": f"The {name} agent.", "name": f"{name} agent",
            "url": f"https://publisher.example/agents/{name}", "version": "1.0.0"}


def entry_value(identifier: str, digest: str, construction: str, signer: str) -> dict[str, Any]:
    subject = {"digest": digest, "identifier": identifier, "type": CARD_TYPE, "version": "1.0.0"}
    entry: dict[str, Any] = {"digest": digest, "displayName": identifier.rsplit(":", 1)[1],
                             "identifier": identifier, "type": CARD_TYPE, "url": URL.replace(
                                 "travel", identifier.rsplit(":", 1)[1]), "version": "1.0.0"}
    if construction == "ard":
        entry["trustManifest"] = {"expiresAt": EXPIRES, "identity": signer, "issuedAt": ISSUED,
                                  "subject": subject}
    else:
        entry["trustManifests"] = [manifest_value(signer, subject)]
    return entry


def manifest_value(signer: str, subject: dict[str, Any]) -> dict[str, Any]:
    return {"contributor": signer, "subject": copy.deepcopy(subject),
            "signature": {"expiresAt": EXPIRES, "issuedAt": ISSUED, "profile": "did-web-v1",
                          "signer": signer}}


def attestation_file(spec: dict[str, Any], digests: dict[str, str]) -> bytes:
    """A vendored attestation; ``encoding`` writes the DSSE base64 fields standard (the
    default), URL-safe, or with a line break inside the payload, and the ES256 signature
    raw (the default), in DER, or in DER with a non-minimal integer."""
    target = digests["$ARTIFACT"] if spec["subject"] == "artifact" else digests["$OTHER"]
    if spec["kind"] == "sarif":
        return enc({"runs": [{"results": [], "tool": {"driver": {"name": "scanner"}}}],
                    "version": "2.1.0"})
    statement = {"_type": "https://in-toto.io/Statement/v1", "predicate": {"result": "pass"},
                 "predicateType": spec["predicate"],
                 "subject": [{"digest": {"sha256": target.split(":", 1)[1]},
                              "name": "agent-card.json"}]}
    body = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()
    kind = b"application/vnd.in-toto+json"
    pae = b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)
    signature = raw_sign("assessor", pae)
    encoding = spec.get("encoding", "standard")
    if encoding in ("der", "der-non-minimal"):
        signature = der(signature, encoding == "der-non-minimal")
    encode = base64.urlsafe_b64encode if encoding == "url-safe" else base64.b64encode
    text = encode(body).decode()
    if encoding == "newline":
        text = text[:8] + "\n" + text[8:]
    return enc({"payload": text, "payloadType": kind.decode(),
                "signatures": [{"keyid": ASSESSOR + "#es256",
                                "sig": encode(signature).decode()}]})


def place(catalog: dict[str, Any], spec: dict[str, Any], jws: str) -> None:
    construction = spec["construction"]
    if construction == SNAP:
        catalog["signature"]["jws"] = jws
    elif construction in (D, F):
        catalog["entries"][spec["entry"]]["trustManifest"]["signature"] = jws
    else:
        manifests = catalog["entries"][spec["entry"]]["trustManifests"]
        manifests[spec["manifest"]]["signature"]["jws"] = jws


def jws_for(catalog: dict[str, Any], spec: dict[str, Any]) -> str:
    did, fragment, alg, _ = KEYS[spec["key"]]
    header: dict[str, Any] = {"alg": alg, "kid": f"{did}#{fragment}"}
    if spec["construction"] in reader.TYP:
        header["typ"] = reader.TYP[spec["construction"]]
    for name, value in spec["header"].items():
        if value is None:
            header.pop(name, None)
        else:
            header[name] = value
    protected = b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    # The signer writes every integer a double holds exactly, as the independent generator
    # does; refusing a value past 2**53 - 1 is the verifier's rule (profile check 19).
    body = reader.canonical(reader.payload(spec["construction"], catalog, spec["entry"],
                                           spec["manifest"]), limit=2**53)
    encoded = body if header.get("b64") is False else b64u(body).encode()
    signature = raw_sign(spec["key"], protected.encode() + b"." + encoded)
    if spec["form"] == "attached":
        return f"{protected}.{b64u(body)}.{b64u(signature)}"
    if spec["form"] == "padded":
        return f"{protected}..{base64.urlsafe_b64encode(signature).decode()}"
    return f"{protected}..{b64u(signature)}"


def build(case: dict[str, Any]) -> dict[str, bytes]:
    shape = case["shape"]
    artifact = artifact_value(IDENTIFIER)
    apply(artifact, case["artifact"], {})
    artifact_bytes = enc(artifact)
    other_bytes = enc(artifact_value("urn:air:publisher.example:agent:billing"))
    digests = {"$ARTIFACT": "sha256:" + sha(artifact_bytes), "$OTHER": "sha256:" + sha(other_bytes),
               "$CARD_JCS": "sha256:" + sha(reader.canonical(artifact))}
    kind = "ard" if shape == "ard" else "aic"
    first = entry_value(IDENTIFIER, digests["$ARTIFACT"], kind, PUB)
    catalog: dict[str, Any] = {"entries": [first],
                               "host": {"displayName": "Publisher Example", "identifier": PUB},
                               "specVersion": "1.0"}
    if case["secondEntry"]:
        catalog["entries"].append(entry_value("urn:air:publisher.example:agent:billing",
                                              digests["$OTHER"], kind, PUB))
    if case["assessor"]:
        subject = catalog["entries"][0]["trustManifests"][0]["subject"]
        catalog["entries"][0]["trustManifests"].append(manifest_value(ASSESSOR, subject))
    if shape == "snapshot":
        catalog["signature"] = {"expiresAt": EXPIRES, "issuedAt": ISSUED,
                                "profile": "did-web-v1", "signer": PUB}
    files: dict[str, bytes] = {}
    items = []
    for index, spec in enumerate(case["attestations"]):
        data = attestation_file(spec, digests)
        name = case["context"]["attestationFiles"][index]
        files[name] = data
        items.append({"digest": "sha256:" + sha(data), "mediaType": "application/vnd.in-toto+json"
                      if spec["kind"] == "dsse" else "application/sarif+json",
                      "type": spec["predicate"],
                      "uri": f"https://assessor.example/evidence/{name}"})
    if items:
        holder = catalog["entries"][0]["trustManifest"] if kind == "ard" else \
            catalog["entries"][0]["trustManifests"][0]
        holder["attestations"] = items
    apply(catalog, case["before"], digests)
    for spec in case["sign"]:
        place(catalog, spec, jws_for(catalog, spec))
    apply(catalog, case["after"], digests)
    catalog_bytes = enc(catalog)
    for old, new in case["raw"]:
        if old not in catalog_bytes.decode("ascii"):
            raise ValueError(f"{case['id']}: raw anchor not found")
        catalog_bytes = catalog_bytes.decode("ascii").replace(old, new, 1).encode("ascii")
    for index in case["attestationAfter"]:
        name = case["context"]["attestationFiles"][index]
        files[name] = files[name] + b"\n"
    apply(artifact, case["artifactAfter"], {})
    dids = did_documents()
    apply(dids, case["dids"], digests)
    context = copy.deepcopy(case["context"])
    apply(context, case["contextAfter"], digests)
    files.update({"artifact.json": enc(artifact), "catalog.json": catalog_bytes,
                  "context.json": enc(context), "did-documents.json": enc(dids)})
    return files


def generate(out: Path) -> None:
    vectors = []
    for case in TABLE:
        files = build(case)
        directory = out / "cases" / case["id"]
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in sorted(files.items()):
            (directory / name).write_bytes(data)
        vectors.append({"edit": case["edit"], "expected": case["expected"],
                        "files": {name: sha(data) for name, data in sorted(files.items())},
                        "id": case["id"], "path": f"cases/{case['id']}"})
    counts = {"accept": sum(v["expected"]["decision"] == "accept" for v in vectors),
              "reject": sum(v["expected"]["decision"] == "reject" for v in vectors)}
    manifest = {"corpusDigest": sha(enc(vectors)), "counts": counts, "suite": reader.SUITE,
                "vectors": vectors}
    (out / "MANIFEST.json").write_bytes(enc(manifest))


def table_bytes() -> bytes:
    return enc({"cases": TABLE, "keys": KEYS, "suite": reader.SUITE})


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
    generate(target)
    if target == ROOT:
        (ROOT / "CASES.json").write_bytes(table_bytes())
