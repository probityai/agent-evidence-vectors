"""Build the deterministic agentic process evidence cases.

    uv run --extra generators python vectors-agentic-process-evidence/gen_vectors.py

Each member is one DSSE v1 envelope over an in-toto Statement v1 carrying the
Agentic Process Evidence predicate, version 0.1, with the consumer policy that
judges it. The supported members are the specification's own published
example (jfrog/agentic-process-evidence
``use_cases/autonomous_code_development/objects_examples/agentic-dev-process-evidence.json``
at commit 1d2feec9678919178520f1ecaeed185f12657f3f) and small variations the
specification allows; every refused member is one scripted mutation away from a
supported twin, and the mutation is the only difference. Every envelope is
signed here with the published test keys below, so every byte in the corpus is
a function of this file alone.

TEST KEYS ONLY. Each seed is the SHA-256 of a public label, so anyone can
re-derive the private key. Never trust these keys for anything else.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
_DIGEST = importlib.util.spec_from_file_location("agentic_process_digest", ROOT / "digest.py")
assert _DIGEST is not None and _DIGEST.loader is not None
_digest_module = importlib.util.module_from_spec(_DIGEST)
_DIGEST.loader.exec_module(_digest_module)
corpus_digest = _digest_module.corpus_digest
SUITE = "agentic-process-evidence/v0.1"
# The Type URI in-toto/attestation pull request 609 declares for the predicate.
PREDICATE = "https://in-toto.io/attestation/agentic-process/v0.1"
# The spelling the same pull request's schema block and example use.
PREDICATE_PR_EXAMPLE = "https://in-toto.io/attestation/agentic-process/v0.1.0"
# The type every example in jfrog/agentic-process-evidence carries.
PREDICATE_JFROG = "https://jfrog.com/evidence/agentic-process/v0.1"
INTOTO_TYPE = "application/vnd.in-toto+json"
STATEMENT = "https://in-toto.io/Statement/v1"
ISSUER_LABEL = "agentic-process-evidence/v0.1 test issuer key"
OTHER_LABEL = "agentic-process-evidence/v0.1 test key that no policy pins"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    """Canonical JSON for the signed bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def public_raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def keyid(k: Ed25519PrivateKey) -> str:
    """The SHA-256 of the raw 32-byte public key, lowercase hex."""
    return _sha(public_raw(k))


ISSUER, OTHER = key(ISSUER_LABEL), key(OTHER_LABEL)


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def signature(k: Ed25519PrivateKey, payload_type: str, body: bytes,
              kid: str | None = None) -> dict[str, str]:
    return {"keyid": kid or keyid(k), "sig": _b64(k.sign(pae(payload_type, body)))}


def envelope(payload_type: str, body: bytes, signatures: list[dict[str, str]]) -> dict[str, Any]:
    return {"payload": _b64(body), "payloadType": payload_type, "signatures": signatures}


COMMIT = "bf02510c8ce0b804a099797510afc19325acfb979538c5b521304c83cde63892"
BASE_COMMIT = "1b94ebd1ef32a4be4480dc70ed8ec2c6d55a2a0c"


def statement(predicate_type: str = PREDICATE) -> dict[str, Any]:
    """The specification's published development-process example, field for field."""
    return {
        "_type": STATEMENT,
        "subject": [{"uri": f"https://github.com/MYORG/orders/commit/{COMMIT}",
                     "digest": {"gitCommit": COMMIT}}],
        "predicateType": predicate_type,
        "predicate": {
            "processType": "code-development",
            "providers": [{
                "harness": {"name": "cursor", "version": "3.5.33"},
                "agent": {"id": "stable-agent-id", "name": "cursor-agent", "version": "1.0"},
                "languageModels": [{"inferenceProvider": "anthropic/claude-opus-4-8",
                                    "resolved": "anthropic/claude-opus-4-8-20260701"}],
            }],
            "traceId": "feature/fin-3678-rate-limit-bf02510",
            "sessionsLogs": [{
                "uri": ("https://myorg.jfrog.io/artifactory/agentic-session-logs/"
                        "a1b2c3d4-e5f6-7890-abcd-ef1234567890.json"),
                "digest": {"sha256": "7c3a1f8e2d94b0c6a15e89d3f4b2a7c0"
                                     "e91d6b48a3f5c2e7d1b9a0c4e6f8d2a1"},
            }],
            "tools": [{"name": "Read", "version": "cursor-native"},
                      {"name": "Write", "version": "cursor-native"}],
            "contextArtifacts": [
                {"tags": ["policy"],
                 "uri": "https://myorg.jfrog.io/artifactory/policies/development-guidelines.md",
                 "digest": {"sha256": "3b1f9c2a7e4d80b6c5a192f8e0d47b3c"
                                      "1a6e5f90d2c8b4a7e3f1c0d9b8a75621"}},
                {"tags": ["guideline"],
                 "uri": "https://myorg.jfrog.io/artifactory/policies/architecture-guidelines.md",
                 "digest": {"sha256": "9e2a4c1b8f6d03a7e5c192b0d4f8a6c3"
                                      "e1b7d590a2f4c8e6b0d3a1f7c5e49280"}},
            ],
            "custom": {
                "baseCommit": {"uri": f"https://github.com/MYORG/orders/commit/{BASE_COMMIT}",
                               "digest": {"gitCommit": BASE_COMMIT}},
                "requirements": [{"issue": "https://myorg.atlassian.net/browse/FIN-3678",
                                  "title": "Rate limit POST /api/orders"}],
            },
            "result": "COMPLETED",
            "intents": ["Implement token-bucket rate limiting on POST /api/orders"],
            "processSummary": ("One IDE session on feature branch fin-3678-rate-limit produced "
                               "commit bf02510. Developer and Cursor agent implemented rate "
                               "limiting and committed for pre-merge review."),
            "owner": "ada@myorg.com",
            "startTimestamp": "2026-04-08T08:51:02.114Z",
            "endTimestamp": "2026-04-08T09:10:44.000Z",
        },
        "createdAt": "2026-04-08T09:11:02.000Z",
        "createdBy": "agent-runtime-tool",
    }


class Member:
    """One case before it is written: the Statement, the envelope edits and the policy."""

    def __init__(self) -> None:
        self.body: Any = statement()
        self.payload_type = INTOTO_TYPE
        self.policy_predicate = PREDICATE
        self.signer, self.signer_kid = ISSUER, keyid(ISSUER)
        self.extra_signatures: list[dict[str, str]] = []
        self.post: Callable[[dict[str, Any]], None] | None = None
        self.raw_envelope: bytes | None = None

    def payload(self) -> bytes:
        return canonical(self.body)

    def envelope_bytes(self) -> bytes:
        if self.raw_envelope is not None:
            return self.raw_envelope
        body = self.payload()
        sigs = [*self.extra_signatures,
                signature(self.signer, self.payload_type, body, self.signer_kid)]
        env = envelope(self.payload_type, body, sigs)
        if self.post is not None:
            self.post(env)
        return canonical(env)


Mutation = Callable[[Member], None]


def _stmt(edit: Callable[[dict[str, Any]], None]) -> Mutation:
    def mutate(m: Member) -> None:
        edit(m.body)
    return mutate


def _pred(edit: Callable[[dict[str, Any]], None]) -> Mutation:
    return _stmt(lambda s: edit(s["predicate"]))


def _set(field: str, value: Any) -> Mutation:
    return _pred(lambda p: p.__setitem__(field, value))


def _drop(field: str) -> Mutation:
    return _pred(lambda p: p.pop(field))


def _set_top(field: str, value: Any) -> Mutation:
    return _stmt(lambda s: s.__setitem__(field, value))


def _drop_top(field: str) -> Mutation:
    return _stmt(lambda s: s.pop(field))


def _provider(edit: Callable[[dict[str, Any]], None]) -> Mutation:
    return _pred(lambda p: edit(p["providers"][0]))


def _artifact(index: int, edit: Callable[[dict[str, Any]], None]) -> Mutation:
    return _pred(lambda p: edit(p["contextArtifacts"][index]))


def _tamper_payload(m: Member) -> None:
    forged = json.loads(m.payload())
    forged["predicate"]["owner"] = "mallory@myorg.com"

    def post(env: dict[str, Any]) -> None:
        env["payload"] = _b64(canonical(forged))
    m.post = post


def _tamper_signature(m: Member) -> None:
    def post(env: dict[str, Any]) -> None:
        raw = bytearray(base64.b64decode(env["signatures"][-1]["sig"]))
        raw[0] ^= 0x01
        env["signatures"][-1]["sig"] = _b64(bytes(raw))
    m.post = post


def _wrong_key(m: Member) -> None:
    m.signer, m.signer_kid = OTHER, keyid(OTHER)


def _wrong_key_claims_pinned_keyid(m: Member) -> None:
    m.signer, m.signer_kid = OTHER, keyid(ISSUER)


def _rotation(m: Member) -> None:
    m.extra_signatures = [signature(OTHER, m.payload_type, m.payload())]


def _payload_type(value: str) -> Mutation:
    def mutate(m: Member) -> None:
        m.payload_type = value
    return mutate


def _not_object(m: Member) -> None:
    m.body = [m.body]


def _raw(data: bytes) -> Mutation:
    def mutate(m: Member) -> None:
        m.raw_envelope = data
    return mutate


def _jfrog_type(m: Member) -> None:
    m.body["predicateType"] = PREDICATE_JFROG
    m.policy_predicate = PREDICATE_JFROG


def _minimal(s: dict[str, Any]) -> None:
    keep = ("processType", "providers", "result", "owner", "startTimestamp", "endTimestamp")
    s["predicate"] = {k: v for k, v in s["predicate"].items() if k in keep}
    s["predicate"]["providers"] = [{"harness": s["predicate"]["providers"][0]["harness"]}]


def _session_subject(s: dict[str, Any]) -> None:
    """A single-session process: the session log is the subject, sessionsLogs is omitted."""
    s["subject"] = [copy.deepcopy(s["predicate"]["sessionsLogs"][0])]
    s["predicate"].pop("sessionsLogs")
    s["predicate"]["processType"] = "support-process"


def _unknown_fields(s: dict[str, Any]) -> None:
    s["predicate"]["tokenUsage"] = {"input": 18211, "output": 2405}
    s["predicate"]["sessionsLogs"][0]["digest"]["blake3"] = "an algorithm this reader skips"
    s["predicate"]["sessionsLogs"][0]["mediaType"] = "application/vnd.in-toto.session-chain+dsse"


def _inline_artifact(p: dict[str, Any]) -> None:
    artifact = p["contextArtifacts"][1]
    artifact.pop("uri")
    artifact["data"] = "Services expose rate limits through the shared gateway middleware."


def _both_uri_and_data(a: dict[str, Any]) -> None:
    """The first context artifact of the specification's own example carries both."""
    a["data"] = "The complete artifact document inline"


SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")
VERIFIED = "process_evidence_verified"
TWIN = "published-example"

# (id, mutation or None, decision, reason, what the mutation does)
MEMBERS: tuple[tuple[str, Mutation | None, str, str, str], ...] = (
    ("published-example", None, SUPPORTED, VERIFIED,
     "the specification's published development-process example, signed as issued"),
    ("minimal-required-fields", _stmt(_minimal), SUPPORTED, VERIFIED,
     "only the required predicate fields, and a provider with a harness alone"),
    ("session-as-subject", _stmt(_session_subject), SUPPORTED, VERIFIED,
     "a single-session process whose subject is the session log, sessionsLogs omitted"),
    ("unknown-fields-ignored", _stmt(_unknown_fields), SUPPORTED, VERIFIED,
     "an unknown predicate field, an unknown digest algorithm and a mediaType are ignored"),
    ("inline-context-artifact", _pred(_inline_artifact), SUPPORTED, VERIFIED,
     "a context artifact carried inline as data, with no uri"),
    ("result-misaligned", _set("result", "MISALIGNED"), SUPPORTED, VERIFIED,
     "a negative result is still verified evidence"),
    ("unpinned-cosigner", _rotation, SUPPORTED, VERIFIED,
     "a first signature by a key no policy pins is ignored; the pinned key's signature verifies"),
    ("jfrog-predicate-type", _jfrog_type, SUPPORTED, VERIFIED,
     "the type every jfrog/agentic-process-evidence example carries, under a policy pinning it"),
    ("tampered-payload", _tamper_payload, CONTRADICTED, "signature_invalid",
     "the owner changed in the payload after signing"),
    ("tampered-signature", _tamper_signature, CONTRADICTED, "signature_invalid",
     "one bit of the signature flipped"),
    ("wrong-key", _wrong_key, CONTRADICTED, "untrusted_key",
     "signed by a key the policy does not pin, under that key's own keyid"),
    ("wrong-key-claims-pinned-keyid", _wrong_key_claims_pinned_keyid, CONTRADICTED,
     "signature_invalid", "signed by an unpinned key that names the pinned keyid"),
    ("malformed-not-json", _raw(b"{\"payload\": "), NO_VERDICT, "malformed_envelope",
     "the envelope bytes are not JSON"),
    ("malformed-signature-not-base64",
     lambda m: setattr(m, "post", lambda env: env["signatures"][-1].__setitem__("sig", "%%%")),
     NO_VERDICT, "malformed_envelope", "a signature is not base64"),
    ("wrong-payload-type", _payload_type("application/json"), NOT_ESTABLISHED,
     "unsupported_payload_type", "signed under a payload type the policy does not pin"),
    ("payload-not-object", _not_object, NOT_ESTABLISHED, "payload_not_json_object",
     "the signed payload is a JSON array holding the Statement"),
    ("statement-type-v01", _set_top("_type", "https://in-toto.io/Statement/v0.1"),
     NOT_ESTABLISHED, "unsupported_statement_type",
     "the Statement names a superseded statement type"),
    ("predicate-type-pr-example-spelling", _set_top("predicateType", PREDICATE_PR_EXAMPLE),
     NOT_ESTABLISHED, "unsupported_predicate",
     "the v0.1.0 spelling of the pull request's example, under a policy pinning its v0.1 Type URI"),
    ("predicate-type-missing", _drop_top("predicateType"), NOT_ESTABLISHED,
     "unsupported_predicate", "the Statement names no predicate type"),
    ("created-at-missing", _drop_top("createdAt"), NOT_ESTABLISHED, "field_invalid:createdAt",
     "createdAt is absent"),
    ("created-at-placeholder", _set_top("createdAt", "ISO 8601 timestamp"), NOT_ESTABLISHED,
     "field_invalid:createdAt", "createdAt is the placeholder text, not a timestamp"),
    ("created-by-empty", _set_top("createdBy", ""), NOT_ESTABLISHED, "field_invalid:createdBy",
     "createdBy is an empty string"),
    ("subject-empty", _set_top("subject", []), NOT_ESTABLISHED, "field_invalid:subject",
     "the Statement names no subject"),
    ("subject-no-uri", _stmt(lambda s: s["subject"][0].pop("uri")), NOT_ESTABLISHED,
     "field_invalid:subject", "the subject has a digest and no uri"),
    ("subject-digest-empty", _stmt(lambda s: s["subject"][0].__setitem__("digest", {})),
     NOT_ESTABLISHED, "field_invalid:subject", "the subject's digest set names no algorithm"),
    ("subject-git-commit-elided",
     _stmt(lambda s: s["subject"][0]["digest"].__setitem__(
         "gitCommit", "bf02510c8ce0b804a099797510af...c19325acfb979538c5b521304c83cde63892")),
     NOT_ESTABLISHED, "field_invalid:subject",
     "the subject's gitCommit is elided with ..., as in the specification's schema example"),
    ("predicate-not-object", _set_top("predicate", ["code-development"]), NOT_ESTABLISHED,
     "field_invalid:predicate", "the predicate is an array"),
    ("process-type-missing", _drop("processType"), NOT_ESTABLISHED,
     "field_invalid:predicate.processType", "processType is absent"),
    ("process-type-empty", _set("processType", ""), NOT_ESTABLISHED,
     "field_invalid:predicate.processType", "processType is an empty string"),
    ("providers-empty", _set("providers", []), NOT_ESTABLISHED,
     "field_invalid:predicate.providers", "providers names no provider stack"),
    ("harness-missing", _provider(lambda p: p.pop("harness")), NOT_ESTABLISHED,
     "field_invalid:predicate.providers[].harness", "a provider has no harness"),
    ("harness-version-missing", _provider(lambda p: p["harness"].pop("version")),
     NOT_ESTABLISHED, "field_invalid:predicate.providers[].harness",
     "the harness has a name and no version"),
    ("agent-name-empty", _provider(lambda p: p["agent"].__setitem__("name", "")),
     NOT_ESTABLISHED, "field_invalid:predicate.providers[].agent",
     "the agent's name is present and empty"),
    ("language-model-resolved-empty",
     _provider(lambda p: p["languageModels"][0].__setitem__("resolved", "")), NOT_ESTABLISHED,
     "field_invalid:predicate.providers[].languageModels",
     "a language model's resolved name is present and empty"),
    ("result-missing", _drop("result"), NOT_ESTABLISHED, "field_invalid:predicate.result",
     "result is absent"),
    ("result-not-listed", _set("result", "SUCCESS"), NOT_ESTABLISHED,
     "field_invalid:predicate.result", "result is not one of the seven process result values"),
    ("owner-missing", _drop("owner"), NOT_ESTABLISHED, "field_invalid:predicate.owner",
     "owner is absent: nobody is accountable"),
    ("start-timestamp-placeholder", _set("startTimestamp", "ISO 8601 timestamp"),
     NOT_ESTABLISHED, "field_invalid:predicate.startTimestamp",
     "startTimestamp is the placeholder text, not a timestamp"),
    ("end-timestamp-missing", _drop("endTimestamp"), NOT_ESTABLISHED,
     "field_invalid:predicate.endTimestamp", "endTimestamp is absent"),
    ("trace-id-empty", _set("traceId", ""), NOT_ESTABLISHED, "field_invalid:predicate.traceId",
     "traceId is present and empty"),
    ("session-log-no-digest", _pred(lambda p: p["sessionsLogs"][0].pop("digest")),
     NOT_ESTABLISHED, "field_invalid:predicate.sessionsLogs",
     "a session log reference has a uri and no digest"),
    ("session-log-uri-placeholder",
     _pred(lambda p: p["sessionsLogs"][0].__setitem__("uri", "session log url")),
     NOT_ESTABLISHED, "field_invalid:predicate.sessionsLogs",
     "a session log uri is the placeholder text, not a URI"),
    ("tool-name-missing", _pred(lambda p: p["tools"][0].pop("name")), NOT_ESTABLISHED,
     "field_invalid:predicate.tools", "a tool has a version and no name"),
    ("tool-version-empty", _pred(lambda p: p["tools"][1].__setitem__("version", "")),
     NOT_ESTABLISHED, "field_invalid:predicate.tools", "a tool's version is present and empty"),
    ("context-artifact-uri-and-data", _artifact(0, _both_uri_and_data), NOT_ESTABLISHED,
     "field_invalid:predicate.contextArtifacts",
     "a context artifact carries both uri and data, as in the specification's schema example"),
    ("context-artifact-neither", _artifact(1, lambda a: a.pop("uri")), NOT_ESTABLISHED,
     "field_invalid:predicate.contextArtifacts",
     "a context artifact carries neither uri nor data"),
    ("context-artifact-sha256-short",
     _artifact(0, lambda a: a.__setitem__("digest", {"sha256": "policy-sha256"})),
     NOT_ESTABLISHED, "field_invalid:predicate.contextArtifacts",
     "a context artifact's sha256 is not 64 hex characters"),
    ("context-artifact-tags-string", _artifact(0, lambda a: a.__setitem__("tags", "policy")),
     NOT_ESTABLISHED, "field_invalid:predicate.contextArtifacts",
     "a context artifact's tags is a string, not a list"),
    ("custom-not-object", _set("custom", ["baseCommit"]), NOT_ESTABLISHED,
     "field_invalid:predicate.custom", "custom is an array"),
    ("intents-not-strings", _set("intents", [{"intent": "rate limiting"}]), NOT_ESTABLISHED,
     "field_invalid:predicate.intents", "an intent is an object, not a string"),
    ("process-summary-not-string", _set("processSummary", ["one session"]), NOT_ESTABLISHED,
     "field_invalid:predicate.processSummary", "processSummary is an array"),
    ("reviewers-not-strings", _set("reviewers", [{"login": "ada"}]), NOT_ESTABLISHED,
     "field_invalid:predicate.reviewers", "a reviewer is an object, not a login or email"),
)


def _policy(m: Member) -> dict[str, Any]:
    return {"payload_type": INTOTO_TYPE, "predicate_type": m.policy_predicate,
            "trusted_keys": {keyid(ISSUER): _b64(public_raw(ISSUER))}}


def _write_case(root: Path, name: str, m: Member) -> dict[str, str]:
    directory = root / "cases" / name
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.iterdir():
        stale.unlink()
    files: dict[str, bytes] = {
        "envelope.json": m.envelope_bytes(),
        "case.json": _pretty({"envelope": "envelope.json", "policy": _policy(m)}),
    }
    for file, data in files.items():
        (directory / file).write_bytes(data)
    return {file: _sha(data) for file, data in sorted(files.items())}


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# Agentic process evidence vectors", "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.", "",
        f"Suite: `{SUITE}`. Predicate: `{PREDICATE}`", "",
        f"Issuer test keyid: `{keyid(ISSUER)}`", "",
        f"Corpus digest: `{digest}`", "",
        "| id | decision | reason | twin | mutation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        lines.append(f"| `{e['id']}` | {x['decision']} | `{x['reason']}` | "
                     f"{e.get('twin', '')} | {e['description']} |")
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest and the index."""
    entries = []
    for name, mutate, verdict, reason, description in MEMBERS:
        m = Member()
        if mutate is not None:
            mutate(m)
        entry: dict[str, Any] = {
            "id": name, "path": f"cases/{name}", "files": _write_case(root, name, m),
            "description": description, "expected": {"decision": verdict, "reason": reason},
        }
        if verdict != SUPPORTED:
            entry["twin"] = TWIN
        entries.append(entry)
    digest = _sha(_pretty(entries))
    manifest = {"suite": SUITE, "predicateType": PREDICATE, "vectors": entries,
                "issuerKeyid": keyid(ISSUER),
                "verifierContract": "verifier case.json --json", "corpusDigest": digest}
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_pretty(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    return manifest


if __name__ == "__main__":
    generate()
