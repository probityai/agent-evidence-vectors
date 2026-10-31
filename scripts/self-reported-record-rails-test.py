#!/usr/bin/env python3
"""The two self-reported-record rails agree, on the corpus and off it.

``corpora/selfreported.go`` (run through ``aee-verify``) and
``packaging/agent_evidence_vectors/selfreportedrecord.py`` restate one rule set
independently. This test holds them to one answer:

1. the committed corpus judges clean on the Python rail, every member to the
   verdict and codes MANIFEST.json declares, and both rails print the same bytes;
2. a corpus of several hundred mutated copies of the committed members is judged
   by both rails with every member declaring a verdict neither can match, so each
   rail's own verdict and codes for each case are printed, and the two outputs
   must be the same. A corpus pins the cases somebody wrote down; the mutants are
   where two rails that agree on every written case still part;
3. mutated members that should be refused are refused with the right reason;
4. this test itself goes red when the reader is replaced by one that accepts
   everything, refuses everything, or skips any one rule.

    uv run --extra generators python scripts/self-reported-record-rails-test.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "vectors-self-reported-record"
sys.path.insert(0, str(ROOT / "packaging"))

import run_vectors  # noqa: E402
from agent_evidence_vectors import selfreportedrecord as srr  # noqa: E402

Statement = dict[str, Any]

RICH = "v95b74832c6cc3173"  # two turns, a memory read, two covered fields
FLAT = "v9e808d2647227acf"  # twelve producer-asserted fields
UNPARSED = "the member does not parse:"


def key_seed(role: str) -> bytes:
    return hashlib.sha256(f"agent-evidence-srr-test-key/{role}/v1".encode()).digest()


def load_manifest() -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    return manifest


def load_statement(member: str) -> Statement:
    statement: Statement = json.loads(
        (CORPUS / "statements" / f"{member}.json").read_text(encoding="utf-8")
    )
    return statement


def sign(role: str, preimage: dict[str, Any]) -> str:
    message = run_vectors.jcs_dumps(preimage)
    return base64.b64encode(run_vectors.ed25519_sign(key_seed(role), message)).decode()


def resign(stmt: Statement) -> Statement:
    """Sign every turn and every covered field again, over the statement as it now stands."""
    predicate = stmt["predicate"]
    for row in predicate["turns"]:
        row["attestedBy"]["sig"] = sign(
            "session-attestor",
            {
                "changeIds": row["changeIds"],
                "context": srr.TURN_CONTEXT,
                "goalMarker": row.get("goalMarker"),
                "priorTurn": row.get("priorTurn"),
                "sessionId": predicate["sessionId"],
                "turnId": row["turnId"],
            },
        )
    for row in predicate["fields"]:
        if isinstance(row.get("coveredBy"), dict) and row["coveredBy"].get("sig"):
            row["coveredBy"]["sig"] = sign(
                "field-observer",
                {
                    "context": srr.FIELD_CONTEXT,
                    "name": row["name"],
                    "recordId": predicate["recordId"],
                    "value": row["value"],
                },
            )
    return stmt


def flip(signature: str) -> str:
    raw = bytearray(base64.b64decode(signature))
    raw[10] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


# --------------------------------------------------------------------------
# A corpus on disk
# --------------------------------------------------------------------------


def write_corpus(dest: Path, entries: list[dict[str, Any]]) -> Path:
    """Write *entries* as a corpus beside the real contract; return the corpus directory.

    An entry is ``kind``, ``body`` (bytes), optionally ``conditions``, ``verdict``
    and ``codes``. Identifiers, the counts and the corpus digest are recomputed,
    so what a rail reports is the judgement and not a stale pin.
    """
    base = load_manifest()
    corpus = dest / "vectors-self-reported-record"
    (corpus / "statements").mkdir(parents=True)
    (dest / "spec" / "self-reported-record").mkdir(parents=True)
    shutil.copy(ROOT / base["contract"], dest / base["contract"])
    vectors, seen = [], set()
    for entry in entries:
        ident = "v" + hashlib.sha256(entry["body"]).hexdigest()[:16]
        if ident in seen:
            continue
        seen.add(ident)
        (corpus / "statements" / f"{ident}.json").write_bytes(entry["body"])
        vectors.append(
            {
                "id": ident,
                "kind": entry["kind"],
                "file": f"statements/{ident}.json",
                "parent": RICH if entry["kind"] == "reject" else "",
                "conditions": entry.get("conditions", ["srr-c-1"]),
                "expected": {"verdict": entry["verdict"], "codes": entry.get("codes", [])},
            }
        )
    counts = {"accept": 0, "reject": 0}
    for vector in vectors:
        counts[vector["kind"]] += 1
    digest = hashlib.sha256()
    for vector in sorted(vectors, key=lambda v: v["id"]):
        digest.update((corpus / vector["file"]).read_bytes())
    manifest = dict(base, vectors=vectors, counts=counts, corpusDigest=digest.hexdigest())
    (corpus / "MANIFEST.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return corpus


def committed_entries() -> list[dict[str, Any]]:
    return [
        {
            "kind": v["kind"],
            "body": (CORPUS / v["file"]).read_bytes(),
            "conditions": v["conditions"],
            "verdict": v["expected"]["verdict"],
            "codes": v["expected"]["codes"],
        }
        for v in load_manifest()["vectors"]
    ]


# --------------------------------------------------------------------------
# The two rails
# --------------------------------------------------------------------------


def build_go(dest: Path) -> str:
    binary = str(dest / "aee-verify")
    env = dict(os.environ, GOWORK="off")
    subprocess.run(["go", "build", "-o", binary, "./cmd/aee-verify"], cwd=ROOT, check=True, env=env)
    return binary


def go_run(binary: str, corpus: Path) -> tuple[int, str]:
    proc = subprocess.run([binary, str(corpus)], capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout + proc.stderr


def py_run(corpus: Path) -> tuple[int, str]:
    judged = srr.judge(str(corpus))
    return (0 if judged.ok() else 1), srr.render(judged)


def comparable(output: str) -> str:
    """The output with each rail's own parser error text removed.

    The two JSON decoders word a syntax error differently, and the wording is not
    part of what the rails are held to; that the member is refused as unparsed is.
    """
    return "\n".join(
        line.split(UNPARSED)[0] + UNPARSED if UNPARSED in line else line
        for line in output.splitlines()
    )


# --------------------------------------------------------------------------
# Mutants
# --------------------------------------------------------------------------

Mutator = Callable[[Statement], Statement | None]


def dump(stmt: Statement) -> bytes:
    return json.dumps(stmt, sort_keys=True).encode()


def mutants_of(stmt: Statement) -> list[tuple[str, bytes]]:
    """Every mutation of one statement the table below describes, as member bytes."""
    out: list[tuple[str, bytes]] = []
    for label, mutate in structural_mutations():
        copied = copy.deepcopy(stmt)
        try:
            result = mutate(copied)
        except (KeyError, IndexError, TypeError):
            continue
        out.append((label, dump(result if result is not None else copied)))
    return out


def predicate_of(stmt: Statement) -> dict[str, Any]:
    predicate: dict[str, Any] = stmt["predicate"]
    return predicate


def set_member(name: str, value: Any) -> Mutator:
    def apply(stmt: Statement) -> None:
        predicate_of(stmt)[name] = value

    return apply


def drop_member(name: str) -> Mutator:
    def apply(stmt: Statement) -> None:
        del predicate_of(stmt)[name]

    return apply


def resigned(mutate: Mutator) -> Mutator:
    def apply(stmt: Statement) -> Statement:
        mutate(stmt)
        return resign(stmt)

    return apply


def turn(index: int = 0) -> Callable[[Statement], dict[str, Any]]:
    def pick(stmt: Statement) -> dict[str, Any]:
        row: dict[str, Any] = predicate_of(stmt)["turns"][index]
        return row

    return pick


def field(index: int = 0) -> Callable[[Statement], dict[str, Any]]:
    def pick(stmt: Statement) -> dict[str, Any]:
        row: dict[str, Any] = predicate_of(stmt)["fields"][index]
        return row

    return pick


def on(pick: Callable[[Statement], dict[str, Any]], name: str, value: Any) -> Mutator:
    def apply(stmt: Statement) -> None:
        pick(stmt)[name] = value

    return apply


def removing(pick: Callable[[Statement], dict[str, Any]], name: str) -> Mutator:
    def apply(stmt: Statement) -> None:
        del pick(stmt)[name]

    return apply


def flip_turn_sig(stmt: Statement) -> None:
    row = predicate_of(stmt)["turns"][0]["attestedBy"]
    row["sig"] = flip(row["sig"])


def flip_field_sig(stmt: Statement) -> None:
    row = predicate_of(stmt)["fields"][0]["coveredBy"]
    row["sig"] = flip(row["sig"])


def vocabulary_mutations() -> list[tuple[str, Mutator]]:
    bad: dict[str, list[Any]] = {
        "originKind": ["Self", "", "bogus", None, 3, ["self"]],
        "attestationTier": ["bogus", None],
        "observationVantage": ["bogus", ""],
        "observationDirectness": ["bogus", 0],
        "hashAlgorithm": ["sha512", "SHA256", None],
        "issuedAt": [
            "2026-09-20T00:00:05Z\n",
            "2026-09-20T00:00:05.5Z",
            "2026-09-20 00:00:05Z",
            "2026-09-20T00:00:05+00:00",
            "٢٠٢٦-09-20T00:00:05Z",
            None,
            20260920,
        ],
        "selfSigners": ["x", None, 3, {}, [3], ["A" * 64], ["a" * 63], [""], ["a" * 64 + "\n"]],
        "turns": [None, "x", {}, [3], [None], [{}], 3],
        "memoryReads": [None, "x", [3], [{}], [{"path": 1}]],
        "ledgers": [None, [], [{"name": "a", "members": []}], "ab", {}, [3, 4]],
        "fields": [
            None,
            "x",
            [3],
            [{}],
            [{"name": "a", "value": 3, "evidence": "producer_asserted"}],
        ],
        "attestingKey": [None, "x", {}, {"keyid": "a" * 64}, {"publicKey": "a" * 64}],
        "doesNotAssert": [None, "x", 3],
        "recordId": [None, 3, {"a": 1}, ["x"], True],
        "sessionId": [None, 3, {"b": 1}, ["x"], False],
    }
    return [
        (f"set {name}={value!r}", set_member(name, value))
        for name, values in bad.items()
        for value in values
    ]


def ledger_mutations() -> list[tuple[str, Mutator]]:
    def ledger(index: int, members: Any) -> Mutator:
        def apply(stmt: Statement) -> None:
            predicate_of(stmt)["ledgers"][index]["members"] = members

        return apply

    def third(members: list[Any]) -> Mutator:
        def apply(stmt: Statement) -> None:
            predicate_of(stmt)["ledgers"].append({"name": "third", "members": members})

        return apply

    return [
        ("ledger 0 empty", ledger(0, [])),
        ("ledger 1 extra member", ledger(1, ["x", "y"])),
        ("ledger members duplicated", ledger(0, ["a", "a"])),
        ("ledger members as numbers 1", ledger(0, [1, 2])),
        ("ledger members as numbers 2", ledger(1, [3, 4])),
        ("ledger members as null", ledger(1, [None])),
        ("ledger members not a list", ledger(1, "ab")),
        ("third ledger agrees", third([])),
        ("third ledger disagrees", third(["z"])),
    ]


def row_mutations() -> list[tuple[str, Mutator]]:
    def memory(name: str, value: Any) -> Mutator:
        def apply(stmt: Statement) -> None:
            predicate_of(stmt)["memoryReads"][0][name] = value

        return apply

    def cover(s: Statement) -> dict[str, Any]:
        covered: dict[str, Any] = field(0)(s)["coveredBy"]
        return covered

    pairs: list[tuple[str, Mutator]] = [
        ("flip turn signature", flip_turn_sig),
        ("flip field signature", flip_field_sig),
        ("turn without attestedBy", removing(turn(), "attestedBy")),
        ("turn attestedBy null", on(turn(), "attestedBy", None)),
        ("turn sig number", lambda s: turn()(s)["attestedBy"].__setitem__("sig", 5)),
        ("turn sig not base64", lambda s: turn()(s)["attestedBy"].__setitem__("sig", "!!")),
        (
            "turn sig with newline",
            lambda s: turn()(s)["attestedBy"].__setitem__(
                "sig",
                turn()(s)["attestedBy"]["sig"][:20] + "\n" + turn()(s)["attestedBy"]["sig"][20:],
            ),
        ),
        (
            "turn sig with carriage return",
            lambda s: turn()(s)["attestedBy"].__setitem__(
                "sig",
                turn()(s)["attestedBy"]["sig"][:20] + "\r\n" + turn()(s)["attestedBy"]["sig"][20:],
            ),
        ),
        (
            "turn sig unpadded",
            lambda s: turn()(s)["attestedBy"].__setitem__(
                "sig", turn()(s)["attestedBy"]["sig"].rstrip("=")
            ),
        ),
        (
            "turn sig extra padding",
            lambda s: turn()(s)["attestedBy"].__setitem__(
                "sig", turn()(s)["attestedBy"]["sig"] + "="
            ),
        ),
        (
            "turn sig urlsafe alphabet",
            lambda s: turn()(s)["attestedBy"].__setitem__(
                "sig", turn()(s)["attestedBy"]["sig"].replace("+", "-").replace("/", "_")
            ),
        ),
        (
            "turn sig truncated",
            lambda s: turn()(s)["attestedBy"].__setitem__(
                "sig",
                base64.b64encode(base64.b64decode(turn()(s)["attestedBy"]["sig"])[:63]).decode(),
            ),
        ),
        ("turn keyid short", lambda s: turn()(s)["attestedBy"].__setitem__("keyid", "ab")),
        ("turn changeIds changed", on(turn(), "changeIds", ["other"])),
        ("turn changeIds not a list", on(turn(), "changeIds", "x")),
        ("turn turnId number", on(turn(), "turnId", 7)),
        ("turn goalMarker changed", on(turn(), "goalMarker", "other")),
        ("memory pathDigest differs", memory("pathDigest", "0" * 64)),
        ("memory assertedDigest upper", memory("assertedDigest", "A" * 64)),
        ("memory path number", memory("path", 3)),
        ("field value changed", on(field(), "value", "other")),
        ("field evidence bogus", on(field(), "evidence", "bogus")),
        ("field coveredBy null", on(field(), "coveredBy", None)),
        ("field coveredBy empty", on(field(), "coveredBy", {})),
        ("field coveredBy string", on(field(), "coveredBy", "x")),
        ("field coveredBy removed", removing(field(), "coveredBy")),
        ("field value number", on(field(), "value", 12)),
        ("field producer asserted with coveredBy", on(field(), "evidence", "producer_asserted")),
        (
            "field cover keyid in selfSigners",
            lambda s: predicate_of(s)["selfSigners"].append(cover(s)["keyid"]),
        ),
        (
            "field cover publicKey upper",
            lambda s: cover(s).__setitem__("publicKey", cover(s)["publicKey"].upper()),
        ),
        (
            "field cover publicKey spaced",
            lambda s: cover(s).__setitem__("publicKey", " " + cover(s)["publicKey"][1:]),
        ),
        (
            "field cover publicKey odd",
            lambda s: cover(s).__setitem__("publicKey", cover(s)["publicKey"][:-1]),
        ),
        (
            "field cover publicKey short",
            lambda s: cover(s).__setitem__("publicKey", cover(s)["publicKey"][:60]),
        ),
        ("field cover sig missing", lambda s: cover(s).pop("sig")),
        ("field cover publicKey missing", lambda s: cover(s).pop("publicKey")),
        (
            "attesting key in selfSigners",
            lambda s: predicate_of(s)["selfSigners"].append(
                predicate_of(s)["attestingKey"]["keyid"]
            ),
        ),
        (
            "attesting publicKey other",
            lambda s: predicate_of(s)["attestingKey"].__setitem__("publicKey", "0" * 64),
        ),
        (
            "attesting publicKey upper",
            lambda s: predicate_of(s)["attestingKey"].__setitem__(
                "publicKey", predicate_of(s)["attestingKey"]["publicKey"].upper()
            ),
        ),
    ]
    return pairs


def envelope_mutations() -> list[tuple[str, Mutator]]:
    def top(name: str, value: Any) -> Mutator:
        def apply(stmt: Statement) -> None:
            stmt[name] = value

        return apply

    return [
        ("type changed", top("_type", "x")),
        ("type removed", lambda s: s.pop("_type")),
        ("predicateType changed", top("predicateType", "x")),
        ("predicateType number", top("predicateType", 3)),
        ("subject empty", top("subject", [])),
        ("subject two", lambda s: s["subject"].append(copy.deepcopy(s["subject"][0]))),
        ("subject name number", lambda s: s["subject"][0].__setitem__("name", 3)),
        ("subject name missing", lambda s: s["subject"][0].pop("name")),
        ("subject digest short", lambda s: s["subject"][0]["digest"].__setitem__("sha256", "ab")),
        ("subject digest missing", lambda s: s["subject"][0].pop("digest")),
        ("subject not a list", top("subject", {"name": "x"})),
        ("predicate null", top("predicate", None)),
        ("predicate list", top("predicate", [])),
        ("extra top member", top("extra", 1)),
        ("extra predicate member", set_member("extra", [1.5])),
    ]


def removal_mutations() -> list[tuple[str, Mutator]]:
    return [(f"drop {name}", drop_member(name)) for name in srr.REQUIRED]


def resigned_mutations() -> list[tuple[str, Mutator]]:
    """Mutations of what a turn signs, signed again so the signature is the only judge.

    Here the canonical form is what separates the rails: member order, escaping,
    integer spelling and absent members all reach the preimage.
    """
    astral = {"\U00010000": 1, "￿": 2, "b": 3, "a": {"é": 1, "z": [True, None]}}
    cases: list[tuple[str, Mutator]] = [
        ("sign: astral and high-BMP member names", on(turn(), "changeIds", [astral])),
        ("sign: control characters", on(turn(), "goalMarker", 'a\x00b\x1f\x7f"\\/\n\t')),
        ("sign: non-ASCII text", on(turn(), "goalMarker", "café \U0001f600  ")),
        ("sign: goalMarker null", on(turn(), "goalMarker", None)),
        ("sign: goalMarker absent", removing(turn(), "goalMarker")),
        ("sign: priorTurn absent", removing(turn(), "priorTurn")),
        ("sign: priorTurn number", on(turn(), "priorTurn", 12)),
        ("sign: changeIds big integer", on(turn(), "changeIds", [10**30, -(10**25), 0])),
        ("sign: changeIds nested", on(turn(), "changeIds", [[], {}, [[[]]], {"k": {}}])),
        ("sign: sessionId object", set_member("sessionId", {"b": [1], "a": None})),
        ("sign: sessionId number", set_member("sessionId", 77)),
        ("sign: sessionId empty", set_member("sessionId", "")),
        ("sign: turnId empty", on(turn(), "turnId", "")),
        ("sign: field value control", on(field(), "value", "x\u0001y")),
        ("sign: field name unicode", on(field(), "name", "provenance.é\U0001f600")),
        ("sign: recordId object", set_member("recordId", {"z": 1, "a": 2})),
        ("sign: recordId number", set_member("recordId", 5)),
    ]
    return [(label, resigned(mutate)) for label, mutate in cases]


def structural_mutations() -> list[tuple[str, Mutator]]:
    return [
        *removal_mutations(),
        *vocabulary_mutations(),
        *ledger_mutations(),
        *row_mutations(),
        *envelope_mutations(),
        *resigned_mutations(),
    ]


def text_mutants(stmt: Statement) -> list[tuple[str, bytes]]:
    """Mutations of the bytes rather than the structure: how a member is READ."""
    text = json.dumps(stmt, sort_keys=True)
    pretty = json.dumps(stmt, sort_keys=True, indent=2)
    # Integer spellings that reach a preimage. The signature is made over the
    # integer values, then the member text is edited to spell them the other ways.
    big = 10**30
    huge = int("9" * 4200)
    signed = copy.deepcopy(stmt)
    signed["predicate"]["turns"][0]["changeIds"] = [0, big, 7]
    marked = json.dumps(resign(signed), sort_keys=True)
    huge_signed = copy.deepcopy(stmt)
    huge_signed["predicate"]["turns"][0]["changeIds"] = [huge, 2, 3]
    huge_text = json.dumps(resign(huge_signed), sort_keys=True)
    unsigned = copy.deepcopy(stmt)
    unsigned["predicate"]["turns"][0]["changeIds"] = [1, 2, 3]
    plain = json.dumps(unsigned, sort_keys=True)
    # Text that each decoder must read as U+FFFD: the preimage is signed over it.
    replaced = copy.deepcopy(stmt)
    replaced["predicate"]["recordId"] = "record-\ufffdX"
    replaced_text = json.dumps(resign(replaced), sort_keys=True)
    replaced_raw = json.dumps(resign(copy.deepcopy(replaced)), sort_keys=True, ensure_ascii=False)
    cases: dict[str, bytes] = {
        "lone surrogate escape signed as U+FFFD": replaced_text.replace(
            "\\ufffd", "\\ud800"
        ).encode(),
        "invalid utf8 byte signed as U+FFFD": replaced_raw.encode().replace(
            b"\xef\xbf\xbd", b"\xff"
        ),
        "empty": b"",
        "whitespace only": b" \n",
        "leading whitespace": b"  \n" + text.encode(),
        "trailing whitespace": text.encode() + b"\n\n",
        "trailing garbage": text.encode() + b" garbage",
        "second value": text.encode() + b"\n" + text.encode(),
        "bom": b"\xef\xbb\xbf" + text.encode(),
        "top level array": b"[" + text.encode() + b"]",
        "top level string": b'"x"',
        "top level null": b"null",
        "top level zero": b"0",
        "leading zero number": b"01",
        "number then letters": b"123abc",
        "nan literal": text.replace("{", '{"x": NaN, ', 1).encode(),
        "infinity literal": text.replace("{", '{"x": -Infinity, ', 1).encode(),
        "truncated": text.encode()[:-5],
        "trailing comma": text.replace("}", ",}", 1).encode(),
        "single quotes": text.replace('"', "'").encode(),
        "invalid utf8 in string": text.encode().replace(b"record-", b"record-\xff", 1),
        "lone surrogate escape": text.replace("record-", "record-\\ud800", 1).encode(),
        "paired surrogate escape": text.replace("record-", "record-\\ud83d\\ude00", 1).encode(),
        "duplicate member": text.replace('"turns":', '"turns": [], "turns":', 1).encode(),
        "duplicate member last empty": text.replace(
            '"fields":', '"fields": [1], "fields":', 1
        ).encode(),
        "pretty printed": pretty.encode(),
        "unicode escaped names": text.replace('"turns"', '"tur\\u006es"', 1).encode(),
        "big exponent": text.replace('"doesNotAssert"', '"x": 1e400, "doesNotAssert"', 1).encode(),
        "raw tab in string": text.replace("record-", "record-\t", 1).encode(),
        "integer spelled -0 in a preimage": marked.replace("[0, ", "[-0, ", 1).encode(),
        "integers in a preimage": marked.encode(),
        "huge integer in a preimage": huge_text.encode(),
        "float in a preimage": plain.replace("[1, 2, 3]", "[1.5, 2, 3]").encode(),
        "integral float in a preimage": plain.replace("[1, 2, 3]", "[1.0, 2, 3]").encode(),
        "exponent in a preimage": plain.replace("[1, 2, 3]", "[1E2, 2, 3]").encode(),
        "negative exponent in a preimage": plain.replace("[1, 2, 3]", "[1e-2, 2, 3]").encode(),
    }
    return list(cases.items())


def differential_entries() -> list[dict[str, Any]]:
    """The committed members, then every mutant of the two richest ones.

    Every mutant declares a verdict no rail answers, so each rail's output names
    the verdict and codes it reached for that member.
    """
    entries = committed_entries()
    for member in (RICH, FLAT, "v6ba13900c29be2ca"):
        stmt = load_statement(member)
        pairs = mutants_of(stmt)
        if member == RICH:
            pairs += text_mutants(stmt)
        for index, (_, body) in enumerate(pairs):
            entries.append(
                {
                    "kind": "accept" if index % 3 == 0 else "reject",
                    "body": body,
                    "verdict": "unjudged",
                }
            )
    return entries


# --------------------------------------------------------------------------
# What the test asserts
# --------------------------------------------------------------------------


def committed_failures() -> list[str]:
    """The committed corpus judges clean, member by member, on the Python rail."""
    failures = []
    judged = srr.judge(str(CORPUS))
    for ident, _, findings in judged.members:
        failures += [f"{ident}: {finding}" for finding in findings]
    failures += [f"corpus: {finding}" for finding in judged.findings]
    return failures


def refusal(stmt: Statement) -> tuple[str, list[str]]:
    return srr.verdict_of(srr.firing_rules(srr.decode_member(dump(stmt))))


def negative_controls() -> list[tuple[str, Statement, str, list[str]]]:
    """A member changed in one place, and the verdict and codes that change must reach."""
    rich, flat = load_statement(RICH), load_statement(FLAT)
    cases: list[tuple[str, Statement, Mutator, str, list[str]]] = [
        (
            "flip a byte of a turn signature",
            rich,
            flip_turn_sig,
            "invalid",
            ["turn-unsigned-by-attesting-key"],
        ),
        (
            "change a signed turn field",
            rich,
            on(turn(), "changeIds", ["other"]),
            "invalid",
            ["turn-unsigned-by-attesting-key"],
        ),
        (
            "flip a byte of a field signature",
            rich,
            flip_field_sig,
            "invalid",
            ["field-claims-coverage-uncovered"],
        ),
        (
            "change a covered field value",
            rich,
            on(field(), "value", "other"),
            "invalid",
            ["field-claims-coverage-uncovered"],
        ),
        (
            "covered field without its cover",
            flat,
            on(field(), "evidence", "substrate_covered"),
            "invalid",
            ["field-claims-coverage-uncovered"],
        ),
        (
            "memory digests differ",
            rich,
            lambda s: predicate_of(s)["memoryReads"][0].__setitem__("pathDigest", "0" * 64),
            "invalid",
            ["memory-digest-not-over-named-path"],
        ),
        (
            "attesting key declared inside the runtime",
            rich,
            lambda s: predicate_of(s)["selfSigners"].append(
                predicate_of(s)["attestingKey"]["keyid"]
            ),
            "invalid",
            ["attesting-key-in-self-signers"],
        ),
        (
            "a ledger names another change",
            rich,
            lambda s: predicate_of(s)["ledgers"][1]["members"].append("other"),
            "invalid",
            ["ledger-members-disagree"],
        ),
        (
            "unregistered origin kind",
            rich,
            set_member("originKind", "bogus"),
            "malformed",
            ["record-malformed"],
        ),
        (
            "one ledger only",
            rich,
            lambda s: predicate_of(s)["ledgers"].pop(),
            "malformed",
            ["record-malformed"],
        ),
    ]
    out = []
    for label, base, mutate, verdict, codes in cases:
        stmt = copy.deepcopy(base)
        mutate(stmt)
        out.append((label, stmt, verdict, codes))
    return out


def negative_failures() -> list[str]:
    failures = []
    if refusal(load_statement(RICH)) != ("valid", []):
        failures.append("the untouched control member is not accepted")
    for label, stmt, verdict, codes in negative_controls():
        got = refusal(stmt)
        if got != (verdict, codes):
            failures.append(f"{label}: expected {(verdict, codes)}, the reader answered {got}")
    return failures


def judged_negative_failures(work: Path) -> list[str]:
    """The same controls through a corpus that declares each one an accepted member."""
    failures = []
    for label, stmt, verdict, codes in negative_controls():
        corpus = write_corpus(
            work / hashlib.sha256(label.encode()).hexdigest()[:10],
            [{"kind": "accept", "body": dump(stmt), "verdict": "valid"}],
        )
        _, output = py_run(corpus)
        needle = f"this rail answers {verdict} with codes [{' '.join(codes)}]"
        if needle not in output:
            failures.append(f"{label}: the judged corpus does not say {needle!r}")
    return failures


MALFORMED = "this rail answers malformed with codes [record-malformed]"


def acceptance_cases() -> list[tuple[str, bytes, str]]:
    """Members a reader must refuse: (label, bytes, text each rail's output must carry).

    A container of the wrong JSON type, a signature spelled with a carriage return
    or a line feed, and bytes that are not exactly one JSON document in UTF-8 were
    each judged valid by both rails, because both read a wrong-typed container as
    empty, both skipped line breaks inside base64, and both stopped at the end of
    the first JSON value.
    """
    rich = load_statement(RICH)
    cases: list[tuple[str, bytes, str]] = []
    wrong_types: list[tuple[str, Any]] = [
        ("selfSigners", "x"),
        ("selfSigners", 3),
        ("turns", None),
        ("turns", {}),
        ("memoryReads", "x"),
        ("fields", None),
        ("ledgers", "x"),
        ("ledgers", {}),
    ]
    for name, value in wrong_types:
        stmt = copy.deepcopy(rich)
        stmt["predicate"][name] = value
        cases.append((f"{name} is {json.dumps(value)}", dump(stmt), MALFORMED))
    turn_sig = rich["predicate"]["turns"][0]["attestedBy"]["sig"]
    for label, gap in (
        ("a line feed", "\n"),
        ("a carriage return and line feed", "\r\n"),
        ("a carriage return", "\r"),
    ):
        stmt = copy.deepcopy(rich)
        stmt["predicate"]["turns"][0]["attestedBy"]["sig"] = turn_sig[:20] + gap + turn_sig[20:]
        cases.append((f"turn signature with {label}", dump(stmt), MALFORMED))
    covered = next(i for i, f in enumerate(rich["predicate"]["fields"]) if "coveredBy" in f)
    field_sig = rich["predicate"]["fields"][covered]["coveredBy"]["sig"]
    stmt = copy.deepcopy(rich)
    stmt["predicate"]["fields"][covered]["coveredBy"]["sig"] = (
        field_sig[:20] + "\n" + field_sig[20:]
    )
    cases.append(("field signature with a line feed", dump(stmt), MALFORMED))
    text = dump(rich)
    cases += [
        ("text after the statement", text + b" x", UNPARSED),
        ("a 0xff byte after the statement", text + b"\xff", UNPARSED),
        ("a second statement after the first", text + b"\n" + text, UNPARSED),
        (
            "invalid UTF-8 inside a string",
            text.replace(b"record-", b"record-\xff", 1),
            UNPARSED,
        ),
    ]
    return cases


def acceptance_failures(work: Path, binary: str | None) -> list[str]:
    """Each acceptance case, declared valid, must be refused by the Python rail and the Go rail."""
    failures = []
    for label, body, needle in acceptance_cases():
        corpus = write_corpus(
            work / hashlib.sha256(label.encode()).hexdigest()[:10],
            [{"kind": "accept", "body": body, "verdict": "valid"}],
        )
        outputs = {"python": py_run(corpus)[1]}
        if binary is not None:
            outputs["go"] = go_run(binary, corpus)[1]
        failures += [
            f"{label}: the {rail} rail does not say {needle!r}"
            for rail, out in outputs.items()
            if needle not in out
        ]
    return failures


def lenient_decode(raw: bytes) -> Any:
    """The reader's earlier decode: the first JSON value, whatever follows it."""
    text = raw.decode("utf-8", errors="replace").lstrip(" \t\n\r")
    decoder = json.JSONDecoder(
        parse_int=srr._int_token, parse_float=srr._float_token, parse_constant=srr._reject_constant
    )
    value, _ = decoder.raw_decode(text)
    return srr._scrub(value)


def acceptance_stub_failures(work: Path) -> list[str]:
    """Put each acceptance hole back in the Python rail; this test must notice every one."""
    problems = []
    original = (srr.decode_member, srr._containers_ok, srr._signature_spelled)
    try:
        srr.decode_member = lenient_decode
        if not acceptance_failures(work / "lenient", None):
            problems.append(
                "the test did not notice a reader that ignores bytes after the statement"
            )
        srr.decode_member = original[0]
        srr._containers_ok = lambda predicate: True
        if not acceptance_failures(work / "containers", None):
            problems.append("the test did not notice a reader that accepts wrong-typed containers")
        srr._containers_ok = original[1]
        srr._signature_spelled = lambda signature: True
        if not acceptance_failures(work / "spelling", None):
            problems.append(
                "the test did not notice a reader that accepts a line break in a signature"
            )
    finally:
        srr.decode_member, srr._containers_ok, srr._signature_spelled = original
    return problems


def exercise(work: Path) -> list[str]:
    return committed_failures() + negative_failures() + judged_negative_failures(work)


def stub_failures(work: Path) -> list[str]:
    """Replace the reader with wrong ones; this test must notice every one."""
    problems = []

    def must_fail(label: str) -> None:
        if not exercise(work / label.replace(" ", "-")):
            problems.append(f"the test did not notice: {label}")

    original = (srr.firing_rules, srr.rule_wellformed, dict(srr._CHECKS))
    try:
        srr.firing_rules = lambda statement: []
        must_fail("a reader that accepts everything")
        srr.firing_rules = lambda statement: ["rule_wellformed"]
        must_fail("a reader that refuses everything")
        srr.firing_rules = original[0]
        srr.rule_wellformed = lambda statement: True
        must_fail("a reader that skips rule_wellformed")
        srr.rule_wellformed = original[1]
        for name in srr.RULES[1:]:
            srr._CHECKS[name] = lambda predicate: True
            must_fail(f"a reader that skips {name}")
            srr._CHECKS[name] = original[2][name]
    finally:
        srr.firing_rules, srr.rule_wellformed = original[0], original[1]
        srr._CHECKS.update(original[2])
    return problems


def differential(binary: str, work: Path) -> tuple[list[str], dict[str, int]]:
    corpus = write_corpus(work / "differential", differential_entries())
    go_rc, go_out = go_run(binary, corpus)
    py_rc, py_out = py_run(corpus)
    stats = {"members": len(json.loads((corpus / "MANIFEST.json").read_text())["vectors"])}
    for verdict in ("valid", "invalid", "malformed"):
        stats[verdict] = py_out.count(f"this rail answers {verdict} ")
    stats["unparsed"] = py_out.count(UNPARSED)
    problems = []
    if go_rc != py_rc:
        problems.append(f"exit status: go {go_rc}, python {py_rc}")
    go_lines, py_lines = comparable(go_out).splitlines(), comparable(py_out).splitlines()
    problems += [f"go only: {line}" for line in go_lines if line not in py_lines]
    problems += [f"python only: {line}" for line in py_lines if line not in go_lines]
    if not problems and go_lines != py_lines:
        problems.append("the same lines in a different order")
    stats["lines"] = len(py_lines)
    return problems, stats


def differential_stub_failures(binary: str, work: Path) -> list[str]:
    """Move the Python rail off the Go rail in two small ways; the differential must see both."""
    problems = []
    original = (srr._HEX64, srr._utf16_key)
    try:
        srr._HEX64 = re.compile(r"[0-9a-fA-F]{64}")
        if not differential(binary, work / "upper-hex")[0]:
            problems.append("the differential did not notice a reader that accepts uppercase hex")
        srr._HEX64 = original[0]
        srr._utf16_key = lambda name: name.encode("utf-8")
        if not differential(binary, work / "code-point-order")[0]:
            problems.append("the differential did not notice member names sorted by code point")
    finally:
        srr._HEX64, srr._utf16_key = original
    return problems


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="srr-rails-") as tmp:
        work = Path(tmp)
        binary = build_go(work)

        failures += [f"committed corpus: {f}" for f in committed_failures()]
        go_rc, go_out = go_run(binary, CORPUS)
        py_rc, py_out = py_run(CORPUS)
        if (go_rc, go_out) != (py_rc, py_out) or py_rc != 0:
            failures.append(f"the rails differ on the committed corpus: go {go_rc}, python {py_rc}")
        print(
            f"committed: {len(load_manifest()['vectors'])} members, python exit {py_rc}, "
            f"go exit {go_rc}, output {'identical' if go_out == py_out else 'DIFFERENT'}"
        )

        problems, stats = differential(binary, work)
        failures += [f"differential: {p}" for p in problems]
        print(
            f"differential: {stats['members']} members, {stats['lines']} output lines compared, "
            f"{len(problems)} disagreements; verdicts valid={stats['valid']} "
            f"invalid={stats['invalid']} malformed={stats['malformed']} "
            f"unparsed={stats['unparsed']}"
        )
        if not (stats["valid"] and stats["invalid"] and stats["malformed"]):
            failures.append("the differential corpus did not reach all three verdicts")

        failures += [f"negative control: {f}" for f in negative_failures()]
        failures += [f"negative control: {f}" for f in judged_negative_failures(work / "judged")]
        print(f"negative controls: {len(negative_controls())} mutated members checked")

        failures += [f"acceptance: {f}" for f in acceptance_failures(work / "acceptance", binary)]
        print(f"acceptance: {len(acceptance_cases())} members both rails must refuse")

        problems = (
            stub_failures(work / "stubs")
            + differential_stub_failures(binary, work / "off")
            + acceptance_stub_failures(work / "acceptance-stubs")
        )
        failures += problems
        print(
            f"mutation check of this test: {len(srr.RULES) + 7} stub readers, "
            f"{len(problems)} unnoticed"
        )
    for failure in failures:
        print(f"FAIL {failure}")
    if not failures:
        print("PASS: the two self-reported-record rails agree")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
