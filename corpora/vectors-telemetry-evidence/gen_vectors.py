"""Write the telemetry-evidence corpus: digest cases, six-edit completeness cases with controls, and
the boundary.

Every byte is ours: keys come from seeds under ``agent-evidence-vectors/telemetry-evidence/v1/`` and
every body is written here. Each case names the requirement it exercises (``draftId``): OBS-5a, a
digest over declared canonical bytes; OBS-5b, the digest binds the copy the consumer reads, with a
denominator; OBS-5c, a signed digest set under a key the consumer pinned; OBS-7, an event log that
is whole, ordered and anchored.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import telemetryevidence as reader  # noqa: E402
from agent_evidence_vectors.monitorcoverage import _json, _sha  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/telemetry-evidence/v1/"
FIRST_PREV = hashlib.sha256(b"agent-evidence-vectors/telemetry-evidence/v1/genesis").hexdigest()


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _pub(label: str) -> bytes:
    return bytes(rail.ed25519_public_key(_seed(label)))


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jcs(value: Any) -> bytes:
    return bytes(rail.jcs_dumps(value))


BODIES = {
    f"e{i:03d}": {"route": "A" if i % 2 else "B", "status": "ok", "step": i} for i in range(1, 5)
}


def _text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _ref(item: str, data: bytes, form: str = "rfc8785", alg: str = "sha-256") -> dict:
    hashed = reader.canonical_bytes(form, data) if form != "raw" else data
    return {
        "id": item,
        "hash_alg": alg,
        "canonicalization": form,
        "digest": reader.HASHES[alg](hashed).hexdigest(),
    }


def _manifest(refs: list[dict], signer: str | None = None) -> str:
    body: dict[str, Any] = {"schema_version": reader.MANIFEST_SCHEMA, "refs": refs}
    if signer:
        message = reader.MANIFEST_SCHEMA.encode() + b"\x00" + _jcs(body)
        body["signature"] = {
            "alg": "Ed25519",
            "public_key": _b64u(_pub(signer)),
            "value": _b64u(bytes(rail.ed25519_sign(_seed(signer), message))),
        }
    return _text(body)


def _digest_record(
    consumed: dict[str, bytes | None],
    manifest: str,
    pins: list[str] | None = None,
    require_signature: bool = False,
) -> dict:
    copies = {
        k: (None if v is None else ({"text": v.decode()} if _is_text(v) else {"hex": v.hex()}))
        for k, v in consumed.items()
    }
    return {
        "claim": "evidence-digest",
        "consumed": copies,
        "manifest_text": manifest,
        "pinned_key_sha256": pins,
        "require_signature": require_signature,
    }


def _is_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _clean() -> tuple[dict[str, bytes], list[dict]]:
    consumed = {k: _text(v).encode() for k, v in BODIES.items()}
    return consumed, [_ref(k, v) for k, v in consumed.items()]


PINNED = [hashlib.sha256(_pub("witness")).hexdigest()]


def digest_cases() -> list[tuple[str, str, dict, str, str, str]]:
    """(id, draftId, record, decision, reason, edit)."""
    out = []
    consumed, refs = _clean()
    out.append(
        (
            "digest-jcs-positive",
            "OBS-5a",
            _digest_record(consumed, _manifest(refs)),
            "agrees",
            "digests_bind_consumed_copy",
            "control: four bodies, each digest over its RFC 8785 bytes",
        )
    )
    py = dict(consumed)
    py_refs = [dict(r) for r in refs]
    py_refs[0]["digest"] = hashlib.sha256(json.dumps(BODIES["e001"]).encode()).hexdigest()
    out.append(
        (
            "digest-python-default-separators",
            "OBS-5a",
            _digest_record(py, _manifest(py_refs)),
            "contradicted",
            "consumed_copy_bound",
            "the digest is over a default-separator serialization, not the declared RFC 8785 bytes",
        )
    )
    floats = {"x": _text({"ratio": 1.5, "tenth": 0.1, "small": 5e-7}).encode()}
    out.append(
        (
            "digest-float-positive",
            "OBS-5a",
            _digest_record(floats, _manifest([_ref("x", floats["x"])])),
            "agrees",
            "digests_bind_consumed_copy",
            "numbers hashed in their RFC 8785 spelling",
        )
    )
    wrong_float = [_ref("x", floats["x"])]
    wrong_float[0]["digest"] = hashlib.sha256(
        json.dumps(
            {"ratio": 1.5, "small": 5e-7, "tenth": 0.1}, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    out.append(
        (
            "digest-float-repr-negative",
            "OBS-5a",
            _digest_record(floats, _manifest(wrong_float)),
            "contradicted",
            "consumed_copy_bound",
            "sorted compact JSON spells 5e-7 as 5e-07, so it is not RFC 8785",
        )
    )
    nonascii = {"n": _text({"note": "café über"}).encode()}
    out.append(
        (
            "digest-non-ascii-positive",
            "OBS-5a",
            _digest_record(nonascii, _manifest([_ref("n", nonascii["n"])])),
            "agrees",
            "digests_bind_consumed_copy",
            "non-ASCII text hashed as UTF-8, not escaped",
        )
    )
    escaped = [_ref("n", nonascii["n"])]
    escaped[0]["digest"] = hashlib.sha256(
        json.dumps({"note": "café über"}, separators=(",", ":")).encode()
    ).hexdigest()
    out.append(
        (
            "digest-non-ascii-escaped-negative",
            "OBS-5a",
            _digest_record(nonascii, _manifest(escaped)),
            "contradicted",
            "consumed_copy_bound",
            "the digest is over \\u-escaped text, not UTF-8",
        )
    )
    astral = {"a": _text({"mark": "\U0001f600 and \U00010348"}).encode()}
    out.append(
        (
            "digest-astral-positive",
            "OBS-5a",
            _digest_record(astral, _manifest([_ref("a", astral["a"])])),
            "agrees",
            "digests_bind_consumed_copy",
            "astral characters hashed as four UTF-8 bytes each",
        )
    )
    empty = {"z": b"{}"}
    out.append(
        (
            "digest-empty-body-positive",
            "OBS-5a",
            _digest_record(empty, _manifest([_ref("z", empty["z"])])),
            "agrees",
            "digests_bind_consumed_copy",
            "an empty object is a body with a digest",
        )
    )
    cbor = {"c": bytes.fromhex("a26161016162820203")}
    out.append(
        (
            "digest-cbor-deterministic-positive",
            "OBS-5a",
            _digest_record(cbor, _manifest([_ref("c", cbor["c"], "cbor-deterministic")])),
            "agrees",
            "digests_bind_consumed_copy",
            "a deterministic CBOR map hashed as written",
        )
    )
    loose = {"c": bytes.fromhex("a1616118 01".replace(" ", ""))}
    loose_ref = {
        "id": "c",
        "hash_alg": "sha-256",
        "canonicalization": "cbor-deterministic",
        "digest": hashlib.sha256(loose["c"]).hexdigest(),
    }
    out.append(
        (
            "digest-cbor-non-shortest-negative",
            "OBS-5a",
            _digest_record(loose, _manifest([loose_ref])),
            "contradicted",
            "canonical_form",
            "the integer 1 in a two-byte argument is not deterministic",
        )
    )
    raw = {"r": b"\x00\xffbinary"}
    out.append(
        (
            "digest-raw-sha512-positive",
            "OBS-5a",
            _digest_record(raw, _manifest([_ref("r", raw["r"], "raw", "sha-512")])),
            "agrees",
            "digests_bind_consumed_copy",
            "raw bytes under SHA-512",
        )
    )
    undeclared = [dict(r) for r in refs]
    del undeclared[1]["canonicalization"]
    out.append(
        (
            "digest-undeclared-canonical-form",
            "OBS-5a",
            _digest_record(consumed, _manifest(undeclared)),
            "cannot-tell",
            "undeclared_canonical_form",
            "one reference declares no canonical form",
        )
    )
    dup = dict(consumed)
    dup["e004"] = b'{"route":"A","route":"B","status":"ok","step":4}'
    out.append(
        (
            "evidence-ref-duplicate-member",
            "OBS-5b",
            _digest_record(dup, _manifest(refs)),
            "contradicted",
            "no_duplicate_member",
            "a consumed body repeats a member: two readers act on different values",
        )
    )
    inline = dict(consumed)
    inline["e004"] = inline["e004"].replace(b'"B"', b'"A"')
    out.append(
        (
            "evidence-ref-consumed-copy-differs",
            "OBS-5b",
            _digest_record(inline, _manifest(refs)),
            "contradicted",
            "consumed_copy_bound",
            "the consumer reads an edited copy; the digest still matches the copy nobody reads",
        )
    )
    out.append(
        (
            "evidence-ref-zero-of-n",
            "OBS-5b",
            _digest_record(consumed, _manifest([])),
            "contradicted",
            "coverage",
            "every reference removed: 0 of 4 consumed items carry a digest",
        )
    )
    out.append(
        (
            "evidence-ref-zero-of-zero",
            "OBS-5b",
            _digest_record({}, _manifest([])),
            "cannot-tell",
            "empty_denominator",
            "no consumed item: 0 of 0 is never a pass",
        )
    )
    out.append(
        (
            "evidence-ref-duplicate-reference",
            "OBS-5b",
            _digest_record(consumed, _manifest(refs + refs[:1])),
            "contradicted",
            "no_duplicate_reference",
            "two references name one item",
        )
    )
    out.append(
        (
            "signed-id-self-carried-key",
            "OBS-5c",
            _digest_record(consumed, _manifest(refs, "forger"), PINNED),
            "contradicted",
            "signer_pinned",
            "the manifest verifies under the key it carries, which the consumer never pinned",
        )
    )
    out.append(
        (
            "signed-id-pinned-key",
            "OBS-5c",
            _digest_record(consumed, _manifest(refs, "witness"), PINNED, require_signature=True),
            "agrees",
            "digests_bind_consumed_copy",
            "control: the same manifest signed by the pinned key",
        )
    )
    out.append(
        (
            "signed-id-no-pin",
            "OBS-5c",
            _digest_record(consumed, _manifest(refs, "witness"), None),
            "cannot-tell",
            "signer_not_established",
            "a signed manifest and no pinned key",
        )
    )
    out.append(
        (
            "signed-id-unsigned-required",
            "OBS-5c",
            _digest_record(consumed, _manifest(refs), PINNED, require_signature=True),
            "cannot-tell",
            "unsigned_manifest",
            "a signature is required and absent",
        )
    )
    flipped = json.loads(_manifest(refs, "witness"))
    flipped["refs"][0]["digest"] = "0" * 64
    out.append(
        (
            "signed-id-flipped-reference",
            "OBS-5c",
            _digest_record(consumed, _text(flipped), PINNED),
            "contradicted",
            "signature",
            "a digest changed after signing",
        )
    )
    nulled = json.loads(_manifest(refs))
    nulled["signature"] = None
    out.append(
        (
            "signed-id-null-signature",
            "OBS-5c",
            _digest_record(consumed, _text(nulled), PINNED),
            "contradicted",
            "record_shape",
            "a null signature member, which a reader that tests for None reads as unsigned",
        )
    )
    return out


# --- OBS-7: the log -------------------------------------------------------------------------------


def _log(count: int = 6, first: int = 1, session: str = "s1") -> list[dict]:
    events, prev = [], FIRST_PREV
    for seq in range(first, first + count):
        event = {
            "seq": seq,
            "prev": prev,
            "session": session,
            "name": f"step-{seq}",
            "status": "ok",
        }
        events.append(event)
        prev = reader.event_digest(event)
    return events


def _relink(events: list[dict]) -> list[dict]:
    prev = FIRST_PREV
    for event in events:
        event["prev"] = prev
        prev = reader.event_digest(event)
    return events


def _head(events: list[dict], signer: str = "witness") -> str:
    payload = {
        "format": reader.HEAD_FORMAT,
        "count": len(events),
        "head": reader.event_digest(events[-1]),
    }
    message = reader.HEAD_FORMAT.encode() + b"\x00" + _jcs(payload)
    return _text(
        {
            **payload,
            "keyid": _pub(signer).hex(),
            "signature": base64.b64encode(
                bytes(rail.ed25519_sign(_seed(signer), message))
            ).decode(),
        }
    )


def _log_record(
    events: list[dict],
    head: str | None,
    coverage: dict | None = None,
    pins: list[str] | None = PINNED,
) -> dict:
    return {
        "claim": "event-log",
        "coverage": coverage or {"session": "s1", "first_seq": 1},
        "events_text": "".join(_text(e) + "\n" for e in events),
        "first_prev": FIRST_PREV,
        "head_text": head,
        "pinned_key_sha256": pins,
    }


def log_cases() -> list[tuple[str, str, dict, str, str, str]]:
    clean = _log()
    head = _head(clean)
    out = [
        (
            "log-clean",
            "OBS-7",
            _log_record(clean, head),
            "agrees",
            "event_log_complete",
            "control: six events, linked, with the retained head",
        )
    ]

    def edited(change: Any) -> list[dict]:
        events = [dict(e) for e in clean]
        change(events)
        return events

    def drop(e: list) -> None:
        del e[2]

    def swap(e: list) -> None:
        e[2], e[3] = e[3], e[2]

    def flip(e: list) -> None:
        e[2]["status"] = "error"

    def link(e: list) -> None:
        e[3]["prev"] = reader.event_digest(e[1])

    def body(e: list) -> None:
        e[4]["name"] = "step-x"

    def tail(e: list) -> None:
        del e[-1]

    for name, change, reason, edit in (
        ("log-drop", drop, "sequence", "edit 1 of 6: an event dropped"),
        ("log-swap", swap, "sequence", "edit 2 of 6: two events swapped"),
        ("log-status-flip", flip, "chain_order", "edit 3 of 6: a status flipped"),
        ("log-link-rewrite", link, "chain_order", "edit 4 of 6: a link rewritten"),
        ("log-body-edit", body, "chain_order", "edit 5 of 6: a body edited"),
        ("log-tail-truncation", tail, "head_anchor", "edit 6 of 6: the tail cut"),
    ):
        out.append((name, "OBS-7", _log_record(edited(change), head), "contradicted", reason, edit))
    rewritten = _relink(edited(body))
    out.append(
        (
            "log-relinked-rewrite",
            "OBS-7",
            _log_record(rewritten, head),
            "contradicted",
            "head_anchor",
            "control: a body edit relinked end to end still misses the retained head",
        )
    )
    out.append(
        (
            "log-resigned-other-key",
            "OBS-7",
            _log_record(rewritten, _head(rewritten, "forger")),
            "contradicted",
            "signer_pinned",
            "control: the rewrite re-signed by a key the consumer never pinned",
        )
    )
    out.append(
        (
            "log-no-head",
            "OBS-7",
            _log_record(clean, None),
            "cannot-tell",
            "head_not_anchored",
            "no head retained: a cut tail cannot be seen",
        )
    )
    out.append(
        (
            "log-empty",
            "OBS-7",
            _log_record([], None),
            "cannot-tell",
            "empty_denominator",
            "no events: never a pass",
        )
    )
    outside = _relink([dict(e) for e in clean[:-1]] + [dict(clean[-1], session="s2")])
    out.append(
        (
            "log-outside-coverage-boundary",
            "OBS-7",
            _log_record(outside, _head(outside)),
            "contradicted",
            "coverage_boundary",
            "coverage boundary: one event belongs to another session",
        )
    )
    offset = _log(first=10)
    out.append(
        (
            "log-boundary-first-seq-offset",
            "OBS-7",
            _log_record(offset, _head(offset), {"session": "s1", "first_seq": 10}),
            "agrees",
            "event_log_complete",
            "coverage boundary: a log that starts at the declared seq 10",
        )
    )
    return out


def cases() -> list[tuple[str, str, dict, str, str, str]]:
    return digest_cases() + log_cases()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, draft, record, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
        (directory / "record.json").write_bytes(data)
        entries.append(
            {
                "draftId": draft,
                "edit": edit,
                "expected": {"decision": decision, "reason": reason},
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
            }
        )
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": (
            "verifier record.json --json; exit 0 agrees, 1 contradicted, 2 cannot-tell"
        ),
        "vectors": entries,
    }
    words = [e["expected"]["decision"] for e in entries]
    manifest["counts"] = {w: words.count(w) for w in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    print(json.dumps(generate()["counts"], sort_keys=True))
