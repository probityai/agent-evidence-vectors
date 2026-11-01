"""Build the OASF record cases byte-identically.

Every case is a directory with ``record.json``, an OASF record's bytes as its
producer wrote them, and ``case.json``, the digest the producer claims for the
record, the identity of the certificate that signed that digest, and the
identity the consumer's policy names. Each denied case departs from a
conformant case in one place. The digests of the ``digest-over-*`` cases are
computed over the output of an HTML-escaping serializer that orders keys by
UTF-8 bytes, which is how several general-purpose JSON encoders write a map;
the conformant digest is over the RFC 8785 bytes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import oasfrecord as reader  # noqa: E402

SUITE = reader.SUITE
POLICY = {"issuer": "https://accounts.example.com", "subject": "alice@example.com"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


# ---------------------------------------------------------------------------
# A general-purpose serializer, written out so the departure is visible: keys
# in UTF-8 byte order, "<", ">" and "&" escaped, U+2028 and U+2029 escaped, and
# negative zero printed with its sign. It is used only to compute the wrong
# digest a denied case claims.

_ESCAPED = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t",
            "<": "\\u003c", ">": "\\u003e", "&": "\\u0026",
            " ": "\\u2028", " ": "\\u2029"}


def _escaping_string(text: str) -> str:
    out = []
    for char in text:
        if char in _ESCAPED:
            out.append(_ESCAPED[char])
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def _escaping_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value == 0 and math.copysign(1.0, value) < 0:
        return "-0"
    if isinstance(value, (int, float)):
        return reader.canonicalize(value).decode()
    if isinstance(value, str):
        return _escaping_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_escaping_value(item) for item in value) + "]"
    keys = sorted(value, key=lambda key: key.encode("utf-8"))
    return "{" + ",".join(_escaping_string(k) + ":" + _escaping_value(value[k])
                          for k in keys) + "}"


def escaping_digest(record: Any) -> str:
    return "sha256:" + _sha(_escaping_value(record).encode("utf-8"))


# ---------------------------------------------------------------------------
# The records.

BASE: dict[str, Any] = {
    "authors": ["Example Maintainers <maintainers@example.com>"],
    "created_at": "2026-10-28T12:00:00Z",
    "description": "Triages support tickets and drafts first replies.",
    "name": "example.org/agents/ticket-triage",
    "schema_version": "1.0.0",
    "skills": [{"id": 10201,
                "name": "natural_language_processing/natural_language_generation/"
                        "text_completion"}],
    "version": "v1.2.0",
}


def rec(**changes: Any) -> dict[str, Any]:
    """The base record with top-level fields replaced; ``None`` removes one."""
    body = copy.deepcopy(BASE)
    for key, value in changes.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    return body


def module(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"data": data, "id": 10201, "name": "core/llm/model"}]


HTML = rec(description="R&D <beta> tools & more")
HTML_KEY = rec(annotations={"a<b": "c&d"})
LINE = rec(description="first line second line")
PARAGRAPH = rec(description="first paragraph second paragraph")
ORDER = rec(annotations={"": "private use", "\U0001F600": "emoji"})
NEG_ZERO = rec(modules=module({"temperature": -0.0}))
NESTED = rec(modules=module({"prompt": "Reply only with <answer> & stop"}))
FULL = rec(annotations={"team": "support"},
           domains=[{"id": 301, "name": "technology/software_engineering"}],
           locators=[{"type": "container_image", "url": "https://registry.example/triage"}],
           modules=module({"models": [{"model": "example-large", "provider": "example"}]}))


def pretty(record: Any) -> bytes:
    return (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def compact(record: Any) -> bytes:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def case(record: Any, *, raw: bytes | None = None, digest: str | None = None,
         signer: dict[str, str] | None = None, policy: dict[str, str] | None = None,
         contract: str | None = reader.CONTRACT_ID) -> tuple[dict[str, Any], bytes]:
    """One case; every argument is a departure from the conformant case."""
    data = raw if raw is not None else pretty(record)
    body: dict[str, Any] = {
        "policy": policy or dict(POLICY),
        "recordDigest": digest or reader.record_digest(record),
        "signer": signer or dict(POLICY),
    }
    if contract is not None:
        body["contractId"] = contract
    return body, data


def signer(subject: str = POLICY["subject"], issuer: str = POLICY["issuer"]) -> dict[str, str]:
    return {"issuer": issuer, "subject": subject}


BIG = rec(modules=module({"max_tokens": 9007199254740993}))
BIG_EDGE = rec(modules=module({"max_tokens": 9007199254740992}))
DUP = (b'{"name":"example.org/agents/ticket-triage","name":"example.org/agents/other",'
       + compact(rec(name=None))[1:])
BAD_UTF8 = compact(rec(description="placeholder")).replace(b"placeholder", b"bad \xff byte")
NAN = compact(rec(modules=module({"temperature": 0.5}))).replace(b"0.5", b"NaN")

Case = tuple[str, tuple[dict[str, Any], bytes], str, str, str]


def _allow() -> list[Case]:
    ok = "allow", reader.PASS_REASON
    return [
        ("allow-plain", case(BASE), *ok, "control: a conformant record and signer"),
        ("allow-html-characters", case(HTML), *ok,
         "control: '<', '>' and '&' in a value, digest over RFC 8785, which leaves them as is"),
        ("allow-html-characters-in-key", case(HTML_KEY), *ok,
         "control: '<' and '&' in a member name and its value"),
        ("allow-line-separator", case(LINE), *ok,
         "control: U+2028 in a value, digest over RFC 8785, which leaves it unescaped"),
        ("allow-paragraph-separator", case(PARAGRAPH), *ok,
         "control: U+2029 in a value"),
        ("allow-key-order-utf16", case(ORDER), *ok,
         "control: keys U+E000 and U+1F600, ordered by UTF-16 code units as RFC 8785 requires"),
        ("allow-negative-zero", case(NEG_ZERO), *ok,
         "control: -0.0 in a module's data, which RFC 8785 writes as 0"),
        ("allow-nested-html-characters", case(NESTED), *ok,
         "control: '<', '>' and '&' inside a module's data"),
        ("allow-compact-bytes", case(BASE, raw=compact(BASE)), *ok,
         "control: the same record written without whitespace has the same digest"),
        ("allow-optional-fields", case(FULL), *ok,
         "control: annotations, domains, locators and modules present"),
        ("allow-integer-at-exact-limit",
         case(rec(modules=module({"max_tokens": 9007199254740991}))), *ok,
         "control: the largest integer a double holds exactly"),
        ("allow-signer-plus-address",
         case(BASE, signer=signer("alice+ci@example.com"),
              policy=signer("alice+ci@example.com")), *ok,
         "control: a '+' in the subject, compared as text, not as a pattern"),
    ]


def _digest_denials() -> list[Case]:
    bad = "deny", "digest_mismatch"
    return [
        ("digest-over-escaped-html", case(HTML, digest=escaping_digest(HTML)), *bad,
         "the digest is over bytes that write '<', '>' and '&' as \\u003c, \\u003e, \\u0026"),
        ("digest-over-escaped-html-in-key", case(HTML_KEY, digest=escaping_digest(HTML_KEY)),
         *bad, "the digest is over bytes that escape '<' and '&' in a member name"),
        ("digest-over-escaped-line-separator", case(LINE, digest=escaping_digest(LINE)), *bad,
         "the digest is over bytes that write U+2028 as \\u2028"),
        ("digest-over-escaped-paragraph-separator",
         case(PARAGRAPH, digest=escaping_digest(PARAGRAPH)), *bad,
         "the digest is over bytes that write U+2029 as \\u2029"),
        ("digest-over-utf8-key-order", case(ORDER, digest=escaping_digest(ORDER)), *bad,
         "the digest is over bytes that order U+E000 before U+1F600, by UTF-8 bytes"),
        ("digest-over-negative-zero-text", case(NEG_ZERO, digest=escaping_digest(NEG_ZERO)),
         *bad, "the digest is over bytes that write negative zero as -0"),
        ("digest-over-nested-escaped-html", case(NESTED, digest=escaping_digest(NESTED)), *bad,
         "the digest is over bytes that escape '<', '>' and '&' inside a module's data"),
        ("digest-over-file-bytes",
         case(BASE, digest="sha256:" + _sha(pretty(BASE))), *bad,
         "the digest is over the file as written, not over its RFC 8785 bytes"),
        ("digest-of-another-record",
         case(BASE, digest=reader.record_digest(rec(version="v1.2.1"))), *bad,
         "the digest names the record's next version"),
    ]


def _identity_denials() -> list[Case]:
    bad = "deny", "signer_not_policy"
    return [
        ("signer-subject-contains-policy",
         case(BASE, signer=signer("malice@example.com")), *bad,
         "the signer is malice@example.com; the policy names alice@example.com, which it contains"),
        ("signer-domain-extended",
         case(BASE, signer=signer("alice@example.com.attacker.example")), *bad,
         "the signer's address extends the policy's domain"),
        ("signer-dot-as-wildcard",
         case(BASE, signer=signer("bob-smith@example.com"), policy=signer("bob.smith@example.com")),
         *bad, "the policy's '.' is a character, not a pattern that matches '-'"),
        ("signer-issuer-extended",
         case(BASE, signer=signer(issuer="https://accounts.example.com.attacker.example")), *bad,
         "the certificate's issuer extends the policy's issuer"),
        ("policy-written-as-pattern",
         case(BASE, signer=signer("alice@attacker.example"), policy=signer("alice@.*")), *bad,
         "the policy names the text 'alice@.*'; a signer it would match as a pattern is refused"),
        ("signer-another-user", case(BASE, signer=signer("bob@example.com")), *bad,
         "the signer is a different user of the same issuer"),
    ]


def _record_denials() -> list[Case]:
    shape = "deny", "oasf_required_field"
    return [
        ("record-duplicate-member", case(None, raw=DUP, digest=reader.record_digest(BASE)),
         "deny", "record_not_json", "the record bytes carry the member 'name' twice"),
        ("record-not-utf8", case(None, raw=BAD_UTF8, digest=reader.record_digest(BASE)),
         "deny", "record_not_json", "a string in the record carries the byte 0xff"),
        ("record-nan-literal", case(None, raw=NAN, digest=reader.record_digest(BASE)),
         "deny", "record_not_json", "a number in the record is the literal NaN"),
        ("integer-beyond-exact-range", case(BIG), "deny", "number_not_exact",
         "9007199254740993 reads as the double 9007199254740992, so two records share a digest"),
        ("integer-at-ambiguous-edge", case(BIG_EDGE), "deny", "number_not_exact",
         "9007199254740992 is a double that 9007199254740993 also reads as"),
        ("required-name-missing", case(rec(name=None)), *shape, "the record has no name"),
        ("required-description-missing", case(rec(description=None)), *shape,
         "the record has no description"),
        ("required-authors-empty", case(rec(authors=[])), *shape, "the authors list is empty"),
        ("required-skills-missing", case(rec(skills=None)), *shape, "the record has no skills"),
        ("required-skill-unnamed", case(rec(skills=[{"label": "triage"}])), *shape,
         "the one skill has neither a name nor an id"),
        ("required-created-at-not-rfc3339", case(rec(created_at="28 Oct 2026")), *shape,
         "created_at is not an RFC 3339 date-time"),
        ("required-schema-version-not-text", case(rec(schema_version=1)), *shape,
         "schema_version is a number, not text"),
    ]


def _case_denials() -> list[Case]:
    unprefixed = case(BASE)[0]["recordDigest"].removeprefix("sha256:")
    return [
        ("case-digest-unprefixed", case(BASE, digest=unprefixed), "deny", "malformed_case",
         "recordDigest omits its sha256: prefix"),
        ("case-signer-issuer-missing", case(BASE, signer={"subject": POLICY["subject"]}),
         "deny", "malformed_case", "the signer names no issuer"),
        ("contract-id-missing", case(BASE, contract=None), "deny", "contract_id_missing",
         "the case names no contract"),
        ("contract-id-unknown", case(BASE, contract=reader.CONTRACT_ID.replace("/v1", "/v0")),
         "deny", "contract_id_unknown", "the case names a contract version that does not exist"),
    ]


def cases() -> list[Case]:
    """Every case: id, (case.json, record.json bytes), decision, reason, departure."""
    return [*_allow(), *_digest_denials(), *_identity_denials(), *_record_denials(),
            *_case_denials()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, (body, record_bytes), decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "case.json").write_bytes(data)
        (directory / "record.json").write_bytes(record_bytes)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"case.json": _sha(data), "record.json": _sha(record_bytes)},
            "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    decisions = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: decisions.count(word) for word in sorted(set(decisions))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
