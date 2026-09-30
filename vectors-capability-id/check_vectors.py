"""Reference checker for the capability-id corpus (draft).

A capability descriptor is the JSON object that names what a capability allows:
an ``action`` string and a ``resource`` object, optionally with constraints.
Its identifier is derived, never chosen:

    capability_id = "sha256:" + hex(SHA-256(RFC 8785 canonical bytes of the descriptor))

The descriptor is admitted before it is hashed, because two parsers that read one
text differently derive two identifiers for one capability. Admission refuses:

- a duplicate member name (``duplicate-member``);
- any number that is not an integer spelled as one (``number-not-integer``);
- an integer whose magnitude is 2**53 or more (``integer-not-ijson-safe``);
- a string carrying a lone surrogate (``ill-formed-string``);
- the constants NaN, Infinity and -Infinity (``not-parseable``).

The identifier is minted where the policy decision is made and copied by the
gateway that invokes the capability. A member pairs the decision record with the
invocation record and is judged:

- ``id-not-derived``: the decision's capability_id is not the digest of its descriptor;
- ``invoker-chosen-id``: the invocation's capability_id differs from the decision's;
- ``descriptor-mismatch``: the invocation carries the decision's id but describes a
  different capability.

Run: ``python3 vectors-capability-id/check_vectors.py``. Exit 0 when every member
is judged as MANIFEST.json expects.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
IJSON_LIMIT = 2**53


class Refused(Exception):
    """A descriptor or a member that is refused, with the reason code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise Refused("duplicate-member")
        seen[key] = value
    return seen


def _int(text: str) -> int:
    value = int(text)
    if abs(value) >= IJSON_LIMIT:
        raise Refused("integer-not-ijson-safe")
    return value


def _float(text: str) -> Any:
    raise Refused("number-not-integer")


def _constant(text: str) -> Any:
    raise Refused("not-parseable")


def _check_strings(node: Any) -> None:
    items: list[Any] = []
    if isinstance(node, dict):
        items = [*node.keys(), *node.values()]
    elif isinstance(node, list):
        items = list(node)
    elif isinstance(node, str):
        try:
            node.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise Refused("ill-formed-string") from exc
        return
    for item in items:
        _check_strings(item)


def admit(text: str) -> dict[str, Any]:
    """Parse a descriptor text under the admission rules."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_int,
            parse_float=_float,
            parse_constant=_constant,
        )
    except json.JSONDecodeError as exc:
        raise Refused("not-parseable") from exc
    if not isinstance(value, dict):
        raise Refused("not-an-object")
    _check_strings(value)
    return value


def canonical(value: Any) -> bytes:
    """RFC 8785 bytes for an admitted value.

    Admission leaves only objects, arrays, strings, safe integers, booleans and
    null. For those, RFC 8785 is: members sorted by the UTF-16 code units of their
    names, no insignificant whitespace, integers in plain decimal, and strings in
    the JSON escaping RFC 8785 prescribes, which ``json.dumps`` with
    ``ensure_ascii=False`` produces for well-formed strings.
    """
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        inner = b",".join(
            json.dumps(k, ensure_ascii=False).encode("utf-8") + b":" + canonical(value[k])
            for k in keys
        )
        return b"{" + inner + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(canonical(v) for v in value) + b"]"
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def capability_id(text: str) -> str:
    """The derived identifier for a descriptor text, or Refused."""
    return "sha256:" + hashlib.sha256(canonical(admit(text))).hexdigest()


def judge(member: dict[str, Any]) -> str:
    """'valid' or the refusal reason for one member."""
    decision = member["decision"]
    invocation = member["invocation"]
    try:
        derived = capability_id(decision["descriptor_text"])
        if decision["capability_id"] != derived:
            return "id-not-derived"
        if invocation["capability_id"] != decision["capability_id"]:
            return "invoker-chosen-id"
        if capability_id(invocation["descriptor_text"]) != derived:
            return "descriptor-mismatch"
    except Refused as refusal:
        return refusal.reason
    return "valid"


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    failures = []
    for entry in manifest["members"]:
        member = json.loads((HERE / "members" / f"{entry['id']}.json").read_text(encoding="utf-8"))
        got = judge(member)
        if got != entry["expect"]:
            failures.append(f"{entry['id']}: expected {entry['expect']}, judged {got}")
    for line in failures:
        print(f"FAIL {line}")
    if failures:
        return 1
    print(f"OK: {len(manifest['members'])} members judged as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
