#!/usr/bin/env python3
"""Deterministic generator for the agent-decision conformance corpus.

Emits every file under `statements/` and `arguments/`, `MANIFEST.json` and
`INDEX.md`. Run it and the tree is byte-identical on any machine:

    uv run --extra generators python vectors-agent-decision/gen_vectors.py

The corpus tests the `tool_calls[].args_hash` rule of the agent-decision/v0.1
predicate proposed in in-toto/attestation#554, with the two things that thread
asked the rule to say: the hash is SHA-256 over the RFC 8785 bytes of the
argument object, and each call carries an `args_state` that keeps a redacted
call apart from one never recorded. README.md states every rule a member tests.

Determinism recipe, published so a stranger rebuilds rather than trusts:

  - Ed25519 signatures are deterministic, and the one key is derived from a
    published constant: seed = SHA-256("agent-evidence-agent-decision-test-key/producer/v1").
  - Every timestamp is a literal; every identifier and digest is derived.
  - A member's argument bytes are written exactly as listed below, spelling
    included, because the spelling of a number is what most members test.

Each member is built by an explicit call with keyword arguments, never by merging
overrides into a baseline, for the reason the sibling generators record: a merge
once kept a baseline object a member was built to omit, and the rule that member
existed to test had no exercising vector while the suite was green.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from canonical import admit_arguments, args_hash, canonical_bytes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from digest import corpus_digest

HERE = Path(__file__).resolve().parent
STATEMENTS = HERE / "statements"
ARGUMENTS = HERE / "arguments"

SUITE = "agent-decision-conformance"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://auxidus.dev/attestation/agent-decision/v0.1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_DOCUMENT = "https://github.com/in-toto/attestation/issues/554"
SOURCES = {
    "predicate": "https://github.com/in-toto/attestation/issues/554",
    "argsStateAndCanonicalization": (
        "https://github.com/in-toto/attestation/issues/554#issuecomment-4962035548"
    ),
    "numberForms": "https://github.com/in-toto/attestation/issues/554#issuecomment-5874454918",
}
KEY_RECIPE = 'sha256("agent-evidence-agent-decision-test-key/producer/v1")'
DECIDED_AT = "2026-10-04T00:00:00Z"
TOOL = "transfer_funds"
ID_HEX = 16

RULES = {
    "signature": "the envelope's one signature verifies under the producer key over PAE",
    "statement": "the payload is an in-toto Statement v1 naming the agent-decision predicate type",
    "predicate-shape": "every field the RFC marks required is present with its type",
    "args-state": "every tool call carries args_state from the closed set",
    "args-hash-presence": (
        "recorded and redacted calls carry args_hash; the other states carry none"
    ),
    "args-hash-format": "args_hash is sha256: followed by 64 lowercase hex digits",
    "arguments-json": "the disclosed arguments of a recorded call are one JSON object",
    "arguments-duplicate": "no object in the disclosed arguments repeats a member name",
    "arguments-integer": "an integer literal lies inside the RFC 7493 range, +-(2**53 - 1)",
    "arguments-overflow": "a number with a fraction or exponent is a finite double",
    "args-hash-match": "args_hash is SHA-256 over the RFC 8785 bytes of the disclosed arguments",
}
CODES = {
    "signature": "signature-invalid",
    "statement": "statement-malformed",
    "predicate-shape": "predicate-malformed",
    "args-hash-format": "args-hash-format",
    "arguments-json": "arguments-not-json",
    "arguments-duplicate": "arguments-duplicate-member",
    "arguments-integer": "arguments-integer-unsafe",
    "arguments-overflow": "arguments-number-overflow",
    "args-hash-match": "args-hash-mismatch",
}
STATE_CODES = ("args-state-missing", "args-state-unknown")
PRESENCE_CODES = ("args-hash-required", "args-hash-forbidden")
INVALID_CODES = ("signature-invalid", "args-hash-mismatch")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derived(kind: str) -> str:
    return f"{kind}-" + sha256_hex(f"agent-evidence-agent-decision/{kind}".encode())[:ID_HEX]


ACCOUNT = derived("account")
WITHHELD = {"amount": 980, "currency": "EUR", "to": derived("withheld-account")}


def producer_key() -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"agent-evidence-agent-decision-test-key/producer/v1").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def amount_arguments(literal: str) -> bytes:
    return f'{{"amount":{literal},"currency":"EUR","to":"{ACCOUNT}"}}\n'.encode()


def statement(
    tool_calls: list[dict[str, Any]],
    *,
    decision: str = "allow",
    statement_type: str = STATEMENT_TYPE,
) -> dict[str, Any]:
    return {
        "_type": statement_type,
        "subject": [{"name": TOOL, "digest": {"sha256": sha256_hex(canonical_bytes(tool_calls))}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "agent_id": derived("agent"),
            "principal": {"subject": derived("principal")},
            "policy_evaluations": [
                {
                    "policy": "payments-allowlist",
                    "decision": decision,
                    "reason": "tool and payee inside the allowlist",
                    "policy_ids": [derived("policy")],
                }
            ],
            "tool_calls": tool_calls,
            "decided_at": DECIDED_AT,
        },
    }


def call(state: str | None, digest: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {"name": TOOL}
    if state is not None:
        out["args_state"] = state
    if digest is not None:
        out["args_hash"] = digest
    return out


def envelope(
    stmt: dict[str, Any], key: Ed25519PrivateKey, *, sign_over: bytes | None = None
) -> dict[str, Any]:
    """A DSSE envelope over the statement's RFC 8785 bytes.

    `sign_over` signs different bytes than the payload carries, which is how the
    one signature member is built: a payload edited after signing.
    """
    payload = canonical_bytes(stmt)
    signed = payload if sign_over is None else sign_over
    public = key.public_key().public_bytes_raw()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": sha256_hex(public),
                "sig": base64.b64encode(key.sign(pae(PAYLOAD_TYPE, signed))).decode("ascii"),
            }
        ],
    }


def member(
    slug: str,
    row: str,
    *,
    tool_call: dict[str, Any] | None = None,
    arguments: bytes | None = None,
    code: str | None = None,
    parent: str | None = None,
    hashed_over: bytes | None = None,
    stmt: dict[str, Any] | None = None,
    sign_over_stmt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if stmt is None:
        assert tool_call is not None
        stmt = statement([tool_call])
    return {
        "slug": slug,
        "row": row,
        "statement": stmt,
        "signOver": sign_over_stmt,
        "arguments": arguments,
        "code": code,
        "parent": parent,
        "hashedOver": hashed_over,
    }


def recorded(slug: str, row: str, raw: bytes) -> dict[str, Any]:
    """An accept member: a recorded call whose hash is over the canonical bytes."""
    return member(
        slug, row, tool_call=call("recorded", args_hash(admit_arguments(raw))), arguments=raw
    )


def drifted(
    slug: str, row: str, raw: bytes, wrong: bytes, *, code: str, parent: str
) -> dict[str, Any]:
    """A reject member: a recorded call whose hash is over bytes a defect writes."""
    digest = "sha256:" + sha256_hex(wrong)
    return member(
        slug,
        row,
        tool_call=call("recorded", digest),
        arguments=raw,
        code=code,
        parent=parent,
        hashed_over=wrong,
    )


def respell(raw: bytes, canonical_token: bytes, wrong_token: bytes) -> bytes:
    """The canonical bytes of raw with one number token spelled the defective way."""
    canonical = canonical_bytes(admit_arguments(raw))
    needle = b'"amount":' + canonical_token
    if canonical.count(needle) != 1:
        raise SystemExit(f"{canonical!r} does not carry {needle!r} exactly once")
    wrong = canonical.replace(needle, b'"amount":' + wrong_token)
    if json.loads(wrong) != json.loads(canonical):
        raise SystemExit(f"{wrong!r} does not denote the value {canonical!r} denotes")
    return wrong


# Number forms: (slug, literal as written, canonical token, defective token, who writes it).
NUMBER_DRIFTS = (
    (
        "1e21",
        "1e21",
        b"1e+21",
        b"1000000000000000000000",
        "an integral double at 1e21 written as plain digits, the formatter defect reported on #554",
    ),
    (
        "1e16",
        "1e16",
        b"10000000000000000",
        b"1e+16",
        "Python's repr, which switches to exponent form at 1e16 where ECMA-262 waits for 1e21",
    ),
    (
        "1-point-0",
        "1.0",
        b"1",
        b"1.0",
        "Python's json.dumps, which keeps the .0 of an integral double",
    ),
    (
        "1e-6",
        "1e-6",
        b"0.000001",
        b"1e-06",
        "Python's json.dumps, which switches to exponent form below 1e-4 and pads the exponent",
    ),
    ("1e-7", "1e-7", b"1e-7", b"1e-07", "a printf-style exponent, padded to two digits"),
    (
        "negative-zero",
        "-0.0",
        b"0",
        b"-0.0",
        "Python's json.dumps, which keeps the sign of negative zero",
    ),
)
NUMBER_ACCEPTS = (
    ("1e20", "1e20", "the largest power of ten ECMA-262 still writes in plain digits"),
    ("max-double", "1.7976931348623157e308", "the largest finite double, written in exponent form"),
    ("min-subnormal", "5e-324", "the smallest positive subnormal double"),
)


def number_members() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for slug, literal, token, wrong_token, writer in NUMBER_DRIFTS:
        raw = amount_arguments(literal)
        canonical = canonical_bytes(admit_arguments(raw))
        if b'"amount":' + token not in canonical:
            raise SystemExit(f"{literal} does not canonicalize to {token!r}: {canonical!r}")
        accept = f"number-{slug}"
        out.append(
            recorded(
                accept,
                f"amount written {literal}, hashed over its RFC 8785 spelling {token.decode()}",
                raw,
            )
        )
        out.append(
            drifted(
                f"number-{slug}-drift",
                f"amount written {literal}, hashed over {wrong_token.decode()}: {writer}",
                raw,
                respell(raw, token, wrong_token),
                code="args-hash-mismatch",
                parent=accept,
            )
        )
    for slug, literal, note in NUMBER_ACCEPTS:
        out.append(
            recorded(
                f"number-{slug}", f"amount written {literal}: {note}", amount_arguments(literal)
            )
        )
    return out


def integer_members() -> list[dict[str, Any]]:
    """The 2**53 - 1 boundary, where libraries split between refusing and rounding."""
    safe = amount_arguments("9007199254740991")
    spelled = amount_arguments("9007199254740993.0")
    out = [
        recorded(
            "integer-max-safe",
            "amount is the integer literal 2**53 - 1, the last one RFC 7493 admits",
            safe,
        ),
        recorded(
            "integer-past-boundary-as-double",
            "amount written 9007199254740993.0: a fraction makes it a double by "
            "the writer's spelling, "
            "and it canonicalizes to the nearest double, 9007199254740992",
            spelled,
        ),
    ]
    rounding = (
        (
            "integer-2-53",
            "9007199254740992",
            b"9007199254740992",
            "the integer literal 2**53, hashed as the double a rounding library reads it as",
        ),
        (
            "integer-2-53-plus-1",
            "9007199254740993",
            b"9007199254740992",
            "the integer literal 2**53 + 1, which no double holds, hashed as 9007199254740992",
        ),
        (
            "integer-1e21-digits",
            "1000000000000000000000",
            b"1e+21",
            "the integer literal 10**21, hashed as the double 1e+21 a rounding library writes",
        ),
    )
    for slug, literal, wrong_token, row in rounding:
        raw = amount_arguments(literal)
        wrong = f'{{"amount":{wrong_token.decode()},"currency":"EUR","to":"{ACCOUNT}"}}'.encode()
        out.append(
            drifted(
                slug, row, raw, wrong, code="arguments-integer-unsafe", parent="integer-max-safe"
            )
        )
    return out


def admission_members() -> list[dict[str, Any]]:
    base = amount_arguments("250")
    overflow = amount_arguments("1e400")
    duplicate = f'{{"amount":250,"amount":25000,"currency":"EUR","to":"{ACCOUNT}"}}\n'.encode()
    array = b"[250]\n"
    return [
        recorded(
            "recorded-integer-amount",
            "a recorded call with an integer amount, the base of the state members",
            base,
        ),
        drifted(
            "overflow-1e400",
            "amount written 1e400, which no double holds, hashed as the null "
            "JSON.stringify writes for Infinity",
            overflow,
            f'{{"amount":null,"currency":"EUR","to":"{ACCOUNT}"}}'.encode(),
            code="arguments-number-overflow",
            parent="recorded-integer-amount",
        ),
        drifted(
            "duplicate-amount",
            "amount given twice, hashed over the last value as a last-wins parser keeps it",
            duplicate,
            f'{{"amount":25000,"currency":"EUR","to":"{ACCOUNT}"}}'.encode(),
            code="arguments-duplicate-member",
            parent="recorded-integer-amount",
        ),
        drifted(
            "arguments-not-an-object",
            "the disclosed arguments are a JSON array, hashed over its own canonical bytes",
            array,
            b"[250]",
            code="arguments-not-json",
            parent="recorded-integer-amount",
        ),
    ]


def ordering_members() -> list[dict[str, Any]]:
    """Member names ordered by UTF-16 code unit, not by code point."""
    value = {"＄": 250, "\U0001f4b6": "EUR", "to": ACCOUNT}
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    wrong = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    if wrong == canonical_bytes(admit_arguments(raw)):
        raise SystemExit(
            "code point order and UTF-16 order agree here, so the member tests nothing"
        )
    return [
        recorded(
            "member-order-utf16",
            "member names U+FF04 and U+1F4B6, which sort one way by code point "
            "and the other by UTF-16 code unit",
            raw,
        ),
        drifted(
            "member-order-code-point",
            "the same arguments hashed with member names in code point order, "
            "as Python's sort_keys writes them",
            raw,
            wrong,
            code="args-hash-mismatch",
            parent="member-order-utf16",
        ),
    ]


def state_members() -> list[dict[str, Any]]:
    base = amount_arguments("250")
    good = args_hash(admit_arguments(base))
    withheld = args_hash(WITHHELD)
    return [
        member(
            "redacted-with-hash",
            "redacted: arguments recorded and withheld, args_hash commits to them",
            tool_call=call("redacted", withheld),
        ),
        member(
            "unavailable",
            "unavailable: the producer could not read the arguments, no args_hash",
            tool_call=call("unavailable", None),
        ),
        member(
            "not-recorded",
            "not_recorded: the producer chose not to record the arguments, no args_hash",
            tool_call=call("not_recorded", None),
        ),
        member(
            "redacted-without-hash",
            "redacted with no args_hash: the same call as not-recorded except for "
            "the state, and refused",
            tool_call=call("redacted", None),
            code="args-hash-required",
            parent="redacted-with-hash",
        ),
        member(
            "recorded-without-hash",
            "recorded with the arguments disclosed and no args_hash",
            tool_call=call("recorded", None),
            arguments=base,
            code="args-hash-required",
            parent="recorded-integer-amount",
        ),
        member(
            "not-recorded-with-hash",
            "not_recorded carrying an args_hash, a commitment to arguments it says it never kept",
            tool_call=call("not_recorded", withheld),
            code="args-hash-forbidden",
            parent="not-recorded",
        ),
        member(
            "unavailable-with-hash",
            "unavailable carrying an args_hash over arguments it says it could not read",
            tool_call=call("unavailable", withheld),
            code="args-hash-forbidden",
            parent="unavailable",
        ),
        member(
            "state-absent",
            "args_hash with no args_state: the tool call exactly as the v0.1 RFC example writes it",
            tool_call=call(None, good),
            arguments=base,
            code="args-state-missing",
            parent="recorded-integer-amount",
        ),
        member(
            "state-unknown",
            "args_state of omitted, a value outside the closed set",
            tool_call=call("omitted", None),
            code="args-state-unknown",
            parent="not-recorded",
        ),
        member(
            "hash-uppercase",
            "args_hash in uppercase hex",
            tool_call=call("recorded", "sha256:" + good.split(":", 1)[1].upper()),
            arguments=base,
            code="args-hash-format",
            parent="recorded-integer-amount",
        ),
        member(
            "hash-unprefixed",
            "args_hash as bare hex with no sha256: prefix",
            tool_call=call("recorded", good.split(":", 1)[1]),
            arguments=base,
            code="args-hash-format",
            parent="recorded-integer-amount",
        ),
    ]


def envelope_members() -> list[dict[str, Any]]:
    base = amount_arguments("250")
    good = call("recorded", args_hash(admit_arguments(base)))
    edited = statement([good])
    edited["predicate"]["decided_at"] = "2026-10-04T00:00:01Z"
    return [
        member(
            "payload-edited-after-signing",
            "decided_at moved one second after the envelope was signed",
            stmt=edited,
            sign_over_stmt=statement([good]),
            arguments=base,
            code="signature-invalid",
            parent="recorded-integer-amount",
        ),
        member(
            "statement-type-v0-1",
            "the statement _type of in-toto Statement v0.1",
            stmt=statement([good], statement_type="https://in-toto.io/Statement/v0.1"),
            arguments=base,
            code="statement-malformed",
            parent="recorded-integer-amount",
        ),
        member(
            "decision-outside-set",
            "a policy evaluation whose decision is maybe",
            stmt=statement([good], decision="maybe"),
            arguments=base,
            code="predicate-malformed",
            parent="recorded-integer-amount",
        ),
        member(
            "tool-calls-empty",
            "a decision record naming no tool call",
            stmt=statement([]),
            code="predicate-malformed",
            parent="not-recorded",
        ),
    ]


def build_members() -> list[dict[str, Any]]:
    return (
        admission_members()
        + number_members()
        + integer_members()
        + ordering_members()
        + state_members()
        + envelope_members()
    )


def member_bytes(env: dict[str, Any]) -> bytes:
    return json.dumps(env, indent=2, sort_keys=True).encode() + b"\n"


def verdict_for(code: str | None) -> str:
    if code is None:
        return "valid"
    return "invalid" if code in INVALID_CODES else "malformed"


def identify(members: list[dict[str, Any]], key: Ed25519PrivateKey) -> dict[str, str]:
    """Sign every member and name it by its own bytes; returns slug -> id."""
    slugs = [m["slug"] for m in members]
    if len(set(slugs)) != len(slugs):
        raise SystemExit("two members share a slug")
    for m in members:
        sign_over = None if m["signOver"] is None else canonical_bytes(m["signOver"])
        m["body"] = member_bytes(envelope(m["statement"], key, sign_over=sign_over))
        # A member is the envelope and its disclosed arguments together: two
        # members may carry one envelope and differ only in the bytes disclosed.
        m["id"] = "v" + sha256_hex(m["body"] + (m["arguments"] or b""))[:ID_HEX]
    if len({m["id"] for m in members}) != len(members):
        raise SystemExit("two members share an identifier: refused rather than trusted to luck")
    return {m["slug"]: m["id"] for m in members}


def entry_for(m: dict[str, Any], by_slug: dict[str, str]) -> dict[str, Any]:
    """The manifest entry for one member, writing its files on the way."""
    (STATEMENTS / f"{m['id']}.json").write_bytes(m["body"])
    entry: dict[str, Any] = {
        "id": m["id"],
        "slug": m["slug"],
        "kind": "accept" if m["code"] is None else "reject",
        "file": f"statements/{m['id']}.json",
        "row": m["row"],
        "expected": {
            "verdict": verdict_for(m["code"]),
            "codes": [] if m["code"] is None else [m["code"]],
        },
    }
    if m["arguments"] is not None:
        (ARGUMENTS / f"{m['id']}.json").write_bytes(m["arguments"])
        entry["arguments"] = f"arguments/{m['id']}.json"
        try:
            entry["canonicalArguments"] = canonical_bytes(admit_arguments(m["arguments"])).decode()
        except ValueError:
            pass
    if m["hashedOver"] is not None:
        entry["hashedOver"] = m["hashedOver"].decode()
    if m["parent"] is not None:
        entry["parent"] = by_slug[m["parent"]]
    return entry


def manifest_for(entries: list[dict[str, Any]], key: Ed25519PrivateKey) -> dict[str, Any]:
    counts = {"accept": 0, "reject": 0}
    for entry in entries:
        counts[entry["kind"]] += 1
    public = key.public_key().public_bytes_raw()
    return {
        "suite": SUITE,
        "predicateType": PREDICATE_TYPE,
        "predicateDocument": PREDICATE_DOCUMENT,
        "sources": SOURCES,
        "payloadType": PAYLOAD_TYPE,
        "keyRecipe": KEY_RECIPE,
        "keys": {"producer": {"publicKey": public.hex(), "keyid": sha256_hex(public)}},
        "keyNote": (
            "PUBLISHED TEST KEY, derived from a fixed seed in gen_vectors.py. "
            "It signs every envelope."
        ),
        "counts": counts,
        "rules": RULES,
        "codes": {
            **CODES,
            "args-state": list(STATE_CODES),
            "args-hash-presence": list(PRESENCE_CODES),
        },
        "comparisonSurface": {
            "normative": ["verdict"],
            "measured": ["codes"],
            "note": (
                "A verifier conforms on a member when its verdict equals expected.verdict. The "
                "codes name the reference reader's first refusal so two implementations can "
                "compare where they stopped; the RFC defines none. canonicalArguments is the RFC "
                "8785 text of the disclosed arguments wherever they are admissible, so a "
                "canonicalizer can be scored on its bytes alone, one path at a time."
            ),
        },
        "note": (
            "Each member is one DSSE envelope; a member whose call is recorded also discloses "
            "its arguments, as the exact bytes the producer read, in the file its arguments "
            "field names. Every reject member names the accept member it is one change from "
            "in parent, and hashedOver is the text its args_hash was taken over where that "
            "text is what a known defect writes."
        ),
        "vectors": entries,
    }


def main() -> None:
    key = producer_key()
    members = build_members()
    by_slug = identify(members, key)
    for directory in (STATEMENTS, ARGUMENTS):
        directory.mkdir(exist_ok=True)
        for stale in sorted(directory.glob("*.json")):
            stale.unlink()
    entries = sorted((entry_for(m, by_slug) for m in members), key=lambda entry: entry["id"])
    manifest = manifest_for(entries, key)
    manifest["corpusDigest"] = corpus_digest(manifest, str(HERE))
    (HERE / "MANIFEST.json").write_bytes(
        json.dumps(manifest, indent=2, ensure_ascii=False).encode() + b"\n"
    )
    (HERE / "INDEX.md").write_text(index_markdown(manifest, by_slug), encoding="utf-8")
    print(json.dumps(manifest["counts"]), "corpusDigest", manifest["corpusDigest"])


def index_markdown(manifest: dict[str, Any], by_slug: dict[str, str]) -> str:
    """One row per member, emitted so the index cannot drift from the corpus."""
    lines = [
        "# Agent decision conformance vectors",
        "",
        "Emitted by `gen_vectors.py`. Do not edit: the next build overwrites it.",
        "",
        f"Predicate: `{manifest['predicateType']}`, proposed in "
        f"[in-toto/attestation#554]({manifest['predicateDocument']}).",
        "",
        f"Corpus digest: `{manifest['corpusDigest']}`",
        "",
        "| member | verdict | code | arguments | what it carries | parent |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    slug_of = {v: k for k, v in by_slug.items()}
    for entry in sorted(manifest["vectors"], key=lambda e: list(by_slug).index(e["slug"])):
        codes = " ".join(f"`{c}`" for c in entry["expected"]["codes"])
        args = f"[`{entry['id']}`]({entry['arguments']})" if "arguments" in entry else ""
        parent = f"`{slug_of[entry['parent']]}`" if "parent" in entry else ""
        row = entry["row"].replace("|", "\\|")
        lines.append(
            f"| [`{entry['slug']}`]({entry['file']}) | {entry['expected']['verdict']} | {codes} | "
            f"{args} | {row} | {parent} |"
        )
    lines += ["", "## Rules", "", "| rule | what it requires |", "| --- | --- |"]
    for name, text in manifest["rules"].items():
        lines.append(f"| `{name}` | {text} |")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
