"""Judge a telemetry evidence record: does a digest bind the copy a consumer reads, and is an event
log whole?

Two record kinds share this corpus. An ``evidence-digest`` record carries a digest manifest (as the
exact text the producer wrote), the copies the consumer reads, and the consumer's pinned keys. An
``event-log`` record carries one session log, the head the consumer retained outside it, the
consumer's pinned first link and its coverage boundary.

The reader answers ``agrees`` (exit 0), ``contradicted`` (exit 1) or ``cannot-tell`` (exit 2), with
the reason the reference verifier ``agent-evidence-verify`` gives for ``evidence_digest/v1`` and
``event_log_completeness/v1``: the two share check order and codes with ``cbor_receipt_chain/v1``.

Digest rules, in order: ``record_shape`` (a repeated member anywhere is ``no_duplicate_member``),
``signature``, ``signer_pinned`` (the key the manifest carries agrees only when the consumer pinned
its SHA-256), then ``no_duplicate_reference``, ``coverage`` (N of N consumed items carry a digest; 0
of 0 is ``empty_denominator``), ``canonical_form`` and ``consumed_copy_bound``. Log rules:
``record_shape``, ``coverage_boundary``, ``signature``, ``signer_pinned``, ``no_duplicate_event``,
``sequence``, ``chain_order``, ``head_anchor``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json`` prints one JSON object
carrying ``decision`` and ``reason`` and exits 0, 1 or 2 as above.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_evidence_vectors import a2ajcs
from agent_evidence_vectors.monitorcoverage import _fixture_error, _validated_entries, run_corpus

SUITE = "telemetry-evidence/v1"
MANIFEST_SCHEMA = "evidence-digest-manifest/v1"
HEAD_FORMAT = "probity-witness-ledger-head-v0"
EXIT_FOR = {"agrees": 0, "contradicted": 1, "cannot-tell": 2}
HASHES = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512}
FORMS = ("rfc8785", "cbor-deterministic", "raw")
_HEX = frozenset("0123456789abcdef")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-telemetry-evidence"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-telemetry-evidence"
)
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")


def _rail() -> Any:
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    raise ImportError("the reference rail's Ed25519 and RFC 8785 primitives are unavailable")


class Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Unknown(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Refused("no_duplicate_member")
        out[key] = value
    return out


def _strict(text: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=lambda c: (_ for _ in ()).throw(Refused("record_shape")),
        )
    except Refused:
        raise
    except ValueError as exc:
        raise Refused("record_shape") from exc


def _hexd(value: Any, size: int) -> str:
    if not isinstance(value, str) or len(value) != size or set(value) - _HEX:
        raise Refused("record_shape")
    return value


# --- deterministic CBOR ---------------------------------------------------------------------------


def _cbor_argument(buf: bytes, pos: int, info: int) -> tuple[int, int]:
    if info < 24:
        return info, pos
    size = 1 << (info - 24)
    if pos + size > len(buf):
        raise Refused("canonical_form")
    return int.from_bytes(buf[pos : pos + size], "big"), pos + size


def _cbor_container(buf: bytes, pos: int, major: int, arg: int, depth: int) -> tuple[Any, int]:
    items = []
    for _ in range(arg * (2 if major == 5 else 1)):
        item, pos = _cbor_item(buf, pos, depth + 1)
        items.append(item)
    if major == 4:
        return items, pos
    keys = items[0::2]
    if len({repr(k) for k in keys}) != len(keys):
        raise Refused("no_duplicate_member")
    return ("m", list(zip(keys, items[1::2], strict=True))), pos


def _cbor_item(buf: bytes, pos: int, depth: int) -> tuple[Any, int]:
    if depth > 16 or pos >= len(buf):
        raise Refused("canonical_form")
    major, info = buf[pos] >> 5, buf[pos] & 31
    pos += 1
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], pos
    if major in (6, 7) or info > 27:
        raise Refused("canonical_form")
    arg, pos = _cbor_argument(buf, pos, info)
    if major in (0, 1):
        return (arg if major == 0 else -1 - arg), pos
    if major in (2, 3):
        if pos + arg > len(buf):
            raise Refused("canonical_form")
        raw = buf[pos : pos + arg]
        return (raw if major == 2 else ("t", raw)), pos + arg
    return _cbor_container(buf, pos, major, arg, depth)


def _cbor_head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([major << 5 | arg])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * size):
            return bytes([major << 5 | info]) + arg.to_bytes(size, "big")
    raise Refused("canonical_form")


def _cbor_encode(value: Any) -> bytes:
    if value is False or value is True or value is None:
        return {False: b"\xf4", True: b"\xf5", None: b"\xf6"}[value]
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(_cbor_encode(v) for v in value)
    tag, body = value
    if tag == "t":
        return _cbor_head(3, len(body)) + bytes(body)
    pairs = sorted((_cbor_encode(k), _cbor_encode(v)) for k, v in body)
    return _cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def canonical_bytes(form: str, data: bytes) -> bytes:
    if form == "raw":
        return data
    if form == "rfc8785":
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Refused("canonical_form") from exc
        try:
            return a2ajcs.canonicalize(_strict(text))
        except a2ajcs.Refusal as exc:
            raise Refused("canonical_form") from exc
    value, end = _cbor_item(data, 0, 0)
    if end != len(data) or _cbor_encode(value) != data:
        raise Refused("canonical_form")
    return data


def _copy(entry: Any) -> bytes | None:
    if entry is None:
        return None
    if not isinstance(entry, dict) or set(entry) not in ({"text"}, {"hex"}):
        raise ValueError("a consumed copy is {text} or {hex}")
    return entry["text"].encode("utf-8") if "text" in entry else bytes.fromhex(entry["hex"])


def _pinned(key: bytes, pins: list[str] | None) -> str | None:
    if pins is None:
        return "signer_not_established"
    if hashlib.sha256(key).hexdigest() not in pins:
        raise Refused("signer_pinned")
    return None


def _b64(text: Any, url: bool) -> bytes:
    if not isinstance(text, str):
        raise Refused("record_shape")
    try:
        if url:
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
            if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
                raise Refused("record_shape")
            return raw
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Refused("record_shape") from exc


def _manifest(text: str) -> dict[str, Any]:
    manifest = _strict(text)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != MANIFEST_SCHEMA
        or not isinstance(manifest.get("refs"), list)
        or set(manifest) - {"schema_version", "refs", "signature"}
    ):
        raise Refused("record_shape")
    return manifest


def _manifest_signer(manifest: dict[str, Any], record: dict[str, Any]) -> str | None:
    """The not-established reason the signature leaves, or None; a bad signature is refused."""
    signature = manifest.get("signature")
    if "signature" in manifest and signature is None:
        raise Refused("record_shape")
    if signature is None:
        return "unsigned_manifest" if record.get("require_signature") else None
    if (
        not isinstance(signature, dict)
        or set(signature) != {"alg", "public_key", "value"}
        or signature["alg"] != "Ed25519"
    ):
        raise Refused("record_shape")
    key = _b64(signature["public_key"], url=True)
    body = {k: v for k, v in manifest.items() if k != "signature"}
    message = MANIFEST_SCHEMA.encode() + b"\x00" + bytes(_rail().jcs_dumps(body))
    if len(key) != 32 or not _rail().ed25519_verify(
        key, message, _b64(signature["value"], url=True)
    ):
        raise Refused("signature")
    return _pinned(key, record.get("pinned_key_sha256"))


def _references(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    refs: dict[str, dict[str, Any]] = {}
    for ref in manifest["refs"]:
        if (
            not isinstance(ref, dict)
            or set(ref) - {"id", "hash_alg", "canonicalization", "digest"}
            or ref.get("hash_alg") not in HASHES
            or not isinstance(ref.get("id"), str)
            or ref.get("canonicalization", FORMS[0]) not in FORMS
        ):
            raise Refused("record_shape")
        _hexd(ref.get("digest"), HASHES[ref["hash_alg"]]().digest_size * 2)
        if ref["id"] in refs:
            raise Refused("no_duplicate_reference")
        refs[ref["id"]] = ref
    return refs


def _bind_copies(consumed: dict[str, bytes | None], refs: dict[str, dict[str, Any]]) -> str | None:
    """Recompute each digest over its consumed copy; return a not-established reason or None."""
    undeclared, unavailable = False, False
    for item, data in consumed.items():
        ref = refs[item]
        if "canonicalization" not in ref:
            undeclared = True
        elif data is None:
            unavailable = True
        elif (
            HASHES[ref["hash_alg"]](canonical_bytes(ref["canonicalization"], data)).hexdigest()
            != ref["digest"]
        ):
            raise Refused("consumed_copy_bound")
    if undeclared:
        return "undeclared_canonical_form"
    return "consumed_copy_unavailable" if unavailable else None


def judge_digest(record: dict[str, Any]) -> tuple[str, str]:
    consumed = {k: _copy(v) for k, v in record["consumed"].items()}
    manifest = _manifest(record["manifest_text"])
    pending = _manifest_signer(manifest, record)
    refs = _references(manifest)
    if not consumed:
        return "cannot-tell", "empty_denominator"
    if any(item not in refs for item in consumed):
        raise Refused("coverage")
    unbound = _bind_copies(consumed, refs)
    if unbound == "undeclared_canonical_form":
        return "cannot-tell", unbound
    if pending or unbound:
        return "cannot-tell", str(pending or unbound)
    return "agrees", "digests_bind_consumed_copy"


def event_digest(event: Any) -> str:
    return hashlib.sha256(bytes(_rail().jcs_dumps(event))).hexdigest()


def _events(text: str) -> list[dict[str, Any]]:
    events = []
    for line in text.split("\n"):
        if not line.strip(" \t\r"):
            continue
        event = _strict(line)
        seq = event.get("seq") if isinstance(event, dict) else None
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise Refused("record_shape")
        _hexd(event.get("prev"), 64)
        events.append(event)
    return events


def _head(record: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """The retained head and the not-established reason its key leaves; a bad head is refused."""
    if record.get("head_text") is None:
        return None, None
    head = _strict(record["head_text"])
    if (
        not isinstance(head, dict)
        or set(head) != {"format", "count", "head", "keyid", "signature"}
        or head["format"] != HEAD_FORMAT
        or isinstance(head["count"], bool)
        or not isinstance(head["count"], int)
    ):
        raise Refused("record_shape")
    key = bytes.fromhex(_hexd(head["keyid"], 64))
    payload = {k: head[k] for k in ("format", "count", "head")}
    message = HEAD_FORMAT.encode() + b"\x00" + bytes(_rail().jcs_dumps(payload))
    if not _rail().ed25519_verify(key, message, _b64(head["signature"], url=False)):
        raise Refused("signature")
    return head, _pinned(key, record.get("pinned_key_sha256"))


def _order(events: list[dict[str, Any]], digests: list[str], record: dict[str, Any]) -> None:
    if len(set(digests)) != len(digests):
        raise Refused("no_duplicate_event")
    first = record["coverage"]["first_seq"]
    if any(e["seq"] != first + i for i, e in enumerate(events)):
        raise Refused("sequence")
    for i, event in enumerate(events):
        if event["prev"] != (record["first_prev"] if i == 0 else digests[i - 1]):
            raise Refused("chain_order")


def judge_log(record: dict[str, Any]) -> tuple[str, str]:
    events = _events(record["events_text"])
    if not events:
        return "cannot-tell", "empty_denominator"
    coverage = record["coverage"]
    if "session" in coverage and any(e.get("session") != coverage["session"] for e in events):
        raise Refused("coverage_boundary")
    head, pending = _head(record)
    digests = [event_digest(e) for e in events]
    _order(events, digests, record)
    if head is None:
        return "cannot-tell", "head_not_anchored"
    if head["count"] != len(events) or head["head"] != digests[-1]:
        raise Refused("head_anchor")
    if pending:
        return "cannot-tell", pending
    return "agrees", "event_log_complete"


def judge(record: dict[str, Any]) -> dict[str, str]:
    try:
        decision, reason = (judge_digest if record["claim"] == "evidence-digest" else judge_log)(
            record
        )
    except Refused as refused:
        decision, reason = "contradicted", refused.code
    return {"decision": decision, "reason": reason}


def verify(record_path: Path) -> dict[str, str]:
    return judge(json.loads(record_path.read_text(encoding="utf-8")))


def _external(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(path), "--json"], capture_output=True, text=True, timeout=90, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(verifier: str | list[str] | None = None, root: Path = ROOT) -> tuple[int, list[str]]:
    """Check every record through the named verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, SUITE)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        path = directory / "record.json"
        ran, observed = (True, verify(path)) if command is None else _external(command, path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
