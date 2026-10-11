"""Recompute an optional, unsigned, versioned action-tuple binding candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

PROFILE = "probity.action-tuple-framed.v1"
DOMAIN = b"PROBITY\x00action-tuple\x00v1\x00"
FIELDS = ("agent_id", "action_type", "scope")
MAX_STRING = 65536
MAX_FRAME = len(DOMAIN) + 3 * (4 + MAX_STRING) + 8
# Each scalar can require six JSON escape bytes per UTF-8 byte (e.g. NUL),
# while frame hex requires two more. The fixed envelope has its own allowance.
MAX_JSON = MAX_FRAME * 8 + 1024
MAX_DEPTH = 32
MAX_NODES = 4096
HEX = re.compile(r"(?:[0-9a-f]{2})*")
DIGEST = re.compile(r"[0-9a-f]{64}")


class Refusal(ValueError):
    """A named bounded input refusal; no input contents in diagnostics."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate-member")
        result[key] = value
    return result


def strict_json(data: bytes) -> Any:
    if len(data) > MAX_JSON:
        raise Refusal("json-size")
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Refusal("json-syntax") from exc
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise Refusal("json-depth-or-nodes")
        children = list(item.values()) if isinstance(item, dict) else item
        if isinstance(children, list):
            pending.extend((child, depth + 1) for child in children)
    return value


def invalid_constant(_value: str) -> Any:
    raise Refusal("json-syntax")


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as source:
        data = source.read(MAX_JSON + 1)
    if len(data) > MAX_JSON:
        raise Refusal("json-size")
    return data


def tuple_parts(value: Any) -> tuple[list[bytes], int]:
    if not isinstance(value, dict) or set(value) != {*FIELDS, "issued_at_ms"}:
        raise Refusal("tuple-shape")
    parts = []
    for name in FIELDS:
        text = value[name]
        if not isinstance(text, str):
            raise Refusal("tuple-string")
        try:
            raw = text.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise Refusal("tuple-unicode") from exc
        if len(raw) > MAX_STRING:
            raise Refusal("tuple-size")
        parts.append(raw)
    timestamp = value["issued_at_ms"]
    if type(timestamp) is not int or not -(2**63) <= timestamp < 2**63:
        raise Refusal("tuple-time")
    return parts, timestamp


def encode_tuple(value: Any) -> bytes:
    parts, timestamp = tuple_parts(value)
    return DOMAIN + b"".join(len(part).to_bytes(4, "big") + part for part in parts) + (
        timestamp.to_bytes(8, "big", signed=True)
    )


def decode_frame(frame: bytes) -> dict[str, Any]:
    if len(frame) > MAX_FRAME:
        raise Refusal("frame-size")
    if not frame.startswith(DOMAIN):
        raise Refusal("frame-domain")
    cursor = len(DOMAIN)
    result: dict[str, Any] = {}
    for name in FIELDS:
        if len(frame) - cursor < 4:
            raise Refusal("frame-length")
        size = int.from_bytes(frame[cursor:cursor + 4], "big")
        cursor += 4
        if size > MAX_STRING:
            raise Refusal("frame-size")
        if size > len(frame) - cursor:
            raise Refusal("frame-length")
        try:
            result[name] = frame[cursor:cursor + size].decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise Refusal("frame-unicode") from exc
        cursor += size
    if len(frame) - cursor != 8:
        raise Refusal("frame-tail")
    result["issued_at_ms"] = int.from_bytes(frame[cursor:], "big", signed=True)
    return result


def verify(data: bytes) -> dict[str, str]:
    packet = strict_json(data)
    if not isinstance(packet, dict) or set(packet) != {
        "profile", "tuple", "frame_hex", "digest"
    }:
        raise Refusal("packet-shape")
    if packet["profile"] != PROFILE:
        raise Refusal("profile")
    expected_frame = encode_tuple(packet["tuple"])
    frame_hex = packet["frame_hex"]
    if not isinstance(frame_hex, str) or not HEX.fullmatch(frame_hex):
        raise Refusal("frame-hex")
    frame = bytes.fromhex(frame_hex)
    decoded = decode_frame(frame)
    if decoded != packet["tuple"] or frame != expected_frame:
        raise Refusal("tuple-mismatch")
    digest = packet["digest"]
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise Refusal("digest-shape")
    observed_digest = sha256(frame)
    if digest != observed_digest:
        raise Refusal("digest-mismatch")
    return {"status": "accepted", "reason": "frame-and-digest-match", "digest": digest}


def pinned_bytes(root: Path, item: dict[str, Any]) -> bytes:
    relative = Path(item["path"])
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise Refusal("pin-path")
    # Only the components the manifest names are corpus members. The
    # directories above the manifest are where the checkout happens to live.
    for depth in range(1, len(relative.parts) + 1):
        if root.joinpath(*relative.parts[:depth]).is_symlink():
            raise Refusal("pin-symlink")
    path = root / relative
    data = read_bounded(path)
    if sha256(data) != item["sha256"]:
        raise Refusal("pin-digest")
    return data


def corpus(manifest_path: Path, selected_digest: str) -> dict[str, Any]:
    data = read_bounded(manifest_path)
    if manifest_path.is_symlink() or sha256(data) != selected_digest:
        raise Refusal("manifest-pin")
    manifest = strict_json(data)
    if manifest["profile"] != PROFILE:
        raise Refusal("manifest-profile")
    root = manifest_path.parent
    for item in manifest["sources"]:
        pinned_bytes(root, item)
    declared = {item["path"] for item in manifest["cases"]}
    if len(declared) != len(manifest["cases"]) or declared != {
        path.relative_to(root).as_posix() for path in (root / "cases").iterdir()
    }:
        raise Refusal("corpus-population")
    outcomes = []
    for item in manifest["cases"]:
        raw = pinned_bytes(root, item)
        try:
            result = verify(raw)
        except Refusal as exc:
            result = {"status": "refused", "reason": str(exc)}
        outcomes.append({"id": item["id"], **result, "matches": all(
            result[key] == item["expected"][key] for key in ("status", "reason")
        )})
    return {
        "profile": PROFILE, "manifest_sha256": selected_digest,
        "reader_sha256": sha256(Path(__file__).read_bytes()),
        "classification": "Probity-authored and operated candidate corpus run",
        "unsigned": True, "host_adoption": False, "outcomes": outcomes,
        "matched": sum(item["matches"] for item in outcomes), "planned": len(outcomes),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("packet", type=Path)
    run = commands.add_parser("corpus")
    run.add_argument("manifest", type=Path)
    run.add_argument("--manifest-sha256", required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "check":
            print(json.dumps(verify(read_bounded(args.packet)), sort_keys=True))
            return 0
        args.output_dir.mkdir(parents=True, exist_ok=False)
        report = corpus(args.manifest, args.manifest_sha256)
        destination = args.output_dir / "report.json"
        with destination.open("x", encoding="utf-8") as output:
            output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"report": str(destination)}, sort_keys=True))
        return 0 if report["matched"] == report["planned"] else 1
    except (Refusal, OSError, KeyError, TypeError, ValueError) as exc:
        failure: dict[str, Any] = {"status": "refused", "reason": str(exc)}
        if isinstance(exc, OSError):
            failure["errno"] = exc.errno
        print(json.dumps(failure), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
