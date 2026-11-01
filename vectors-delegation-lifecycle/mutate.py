"""Mutate delegation lifecycle cases: the negative controls and the rail differential.

A mutation edits a copy of one case. It drops a record, flips one byte of a
signature, or moves a time inside a record and signs the record again with the
published test key that signed it, so the edited record is still a valid one and
only the fact it states has moved. ``tests/test_python_reader.py`` uses these to
show the reader refuses for the right reason, and
``scripts/delegation-lifecycle-rails-test.py`` judges every mutant on both rails.

Needs ``cryptography`` (the ``generators`` extra), like ``gen_vectors.py``.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
SHIFT = timedelta(hours=1)


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("delegation_lifecycle_generator_for_mutation", ROOT / "gen_vectors.py")


def _known_keys() -> list[Ed25519PrivateKey]:
    keys = [generator.REGISTRY, generator.RELYING_PARTY, generator.INTRUDER]
    identifiers = sorted(v for v in vars(generator).values()
                         if isinstance(v, str) and v.startswith("did:"))
    return [*keys, *(generator._identity_key(i) for i in identifiers)]


KEYS = _known_keys()
Mutation = Callable[[Path], None]


def read_envelope(path: Path) -> dict[str, Any] | None:
    """The envelope in a record file, or None when the file is not one."""
    try:
        doc = json.loads(path.read_bytes())
    except ValueError:
        return None
    return doc if isinstance(doc, dict) and "payload" in doc else None


def payload_of(envelope: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(base64.b64decode(envelope["payload"]))
    return payload


def _signing_key(sig: bytes, message: bytes) -> Ed25519PrivateKey | None:
    """The published test key whose signature ``sig`` is, or None for a corrupt one."""
    for key in KEYS:
        try:
            key.public_key().verify(sig, message)
        except InvalidSignature:
            continue
        return key
    return None


def rewrite(path: Path, edit: Callable[[dict[str, Any]], None]) -> None:
    """Edit a record's payload and sign it again with the keys that signed it.

    Each signature keeps the keyid it carried, so a record signed by a key that
    only poses as an identifier still poses as it. A signature that never
    verified stays as it was.
    """
    envelope = read_envelope(path)
    assert envelope is not None, path
    payload_type = envelope["payloadType"]
    old_message = generator.pae(payload_type, base64.b64decode(envelope["payload"]))
    payload = payload_of(envelope)
    edit(payload)
    body = generator.canonical(payload)
    message = generator.pae(payload_type, body)
    signatures = []
    for entry in envelope["signatures"]:
        raw = base64.b64decode(entry["sig"])
        key = _signing_key(raw, old_message)
        sig = entry["sig"] if key is None else generator._b64(key.sign(message))
        signatures.append({"keyid": entry["keyid"], "sig": sig})
    path.write_bytes(generator.canonical(
        {"payload": generator._b64(body), "payloadType": payload_type, "signatures": signatures}))


def flip_signature(path: Path, index: int = 0) -> None:
    """Flip the lowest bit of the first byte of one signature."""
    envelope = read_envelope(path)
    assert envelope is not None, path
    raw = bytearray(base64.b64decode(envelope["signatures"][index]["sig"]))
    raw[0] ^= 1
    envelope["signatures"][index]["sig"] = generator._b64(bytes(raw))
    path.write_bytes(generator.canonical(envelope))


def drop_record(case_dir: Path, name: str) -> None:
    """Remove a record from the case's list and from the directory."""
    case = json.loads((case_dir / "case.json").read_text())
    case["records"] = [n for n in case["records"] if n != name]
    (case_dir / "case.json").write_text(json.dumps(case, indent=2, sort_keys=True) + "\n")
    (case_dir / name).unlink()


def shift_time(path: Path, field: str, delta: timedelta) -> None:
    """Move one time field of a record by ``delta`` and sign the record again."""

    def edit(payload: dict[str, Any]) -> None:
        moved = datetime.fromisoformat(payload[field]).astimezone(UTC) + delta
        payload[field] = moved.strftime("%Y-%m-%dT%H:%M:%SZ")

    rewrite(path, edit)


def _time_fields(path: Path) -> list[str]:
    envelope = read_envelope(path)
    if envelope is None:
        return []
    return sorted(k for k, v in payload_of(envelope).items()
                  if k.endswith("_at") and isinstance(v, str))


def mutations(case_dir: Path) -> Iterator[tuple[str, Mutation]]:
    """Every mutation of one case, as a label and a function that applies it to a
    copy of the case directory. A record that is not an envelope is left alone."""
    case = json.loads((case_dir / "case.json").read_text())
    names = [*case["records"], case["presentation"]]
    for name in names:
        if read_envelope(case_dir / name) is None:
            continue
        if name != case["presentation"]:
            yield f"drop:{name}", partial(_drop, name)
        yield f"flip:{name}", partial(_flip, name)
        for field in _time_fields(case_dir / name):
            yield f"later:{name}:{field}", partial(_shift, name, field, SHIFT)
            yield f"earlier:{name}:{field}", partial(_shift, name, field, -SHIFT)


def _drop(name: str, case_dir: Path) -> None:
    drop_record(case_dir, name)


def _flip(name: str, case_dir: Path) -> None:
    flip_signature(case_dir / name)


def _shift(name: str, field: str, delta: timedelta, case_dir: Path) -> None:
    shift_time(case_dir / name, field, delta)
