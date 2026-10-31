"""Strict inputs for a finite offline evidence reader."""

import hashlib
import json
import os
import re
import stat
import unicodedata
from pathlib import Path

MAX_BYTES = 131_072
MAX_DEPTH = 64
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(ValueError):
    """A machine-readable refusal without rewriting the supplied evidence."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def digest(raw: bytes) -> str:
    """Name the exact bytes, without inferring historical existence."""
    return hashlib.sha256(raw).hexdigest()


def text(value, name: str, limit: int = 8192) -> str:
    """Require valid literal UTF-8 text; never normalize an identifier."""
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else None
    except UnicodeError:
        encoded = None
    if (
        not value
        or encoded is None
        or len(encoded) > limit
        or any(unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} for c in value)
    ):
        raise Refusal("TEXT_INVALID", name + " must be bounded literal UTF-8 text")
    return value


def operator(value) -> dict:
    value = text(value, "operator identity", 512)
    if value != value.strip() or value.startswith("--"):
        raise Refusal("OPERATOR_INVALID", "operator identity must be explicit")
    return {"identity": value, "source": "caller-declared", "authenticated": False}


def pin(value, name: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise Refusal("PIN_INVALID", name + " must be exactly 64 lowercase hex characters")
    return value


def _pairs(items):
    obj = {}
    for key, value in items:
        if key in obj:
            raise Refusal("JSON_MALFORMED", "duplicate JSON member")
        obj[key] = value
    return obj


def _constant(value):
    raise Refusal("JSON_MALFORMED", "non-JSON numeric constant: " + value)


def _bounded_nesting(document: str) -> None:
    """Limit containers before decoding, without counting brackets in strings."""
    depth = 0
    quoted = False
    escaped = False
    for character in document:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "{[":
            depth += 1
            if depth > MAX_DEPTH:
                raise Refusal("JSON_TOO_DEEP", "JSON exceeds 64 nested containers")
        elif character in "}]":
            depth -= 1


def parse(raw: bytes, name: str) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise Refusal("INPUT_TOO_LARGE", name + " must be bounded bytes")
    try:
        document = raw.decode("utf-8")
    except UnicodeError as error:
        raise Refusal("JSON_MALFORMED", name + " is not strict UTF-8 JSON") from error
    _bounded_nesting(document)
    try:
        obj = json.loads(document, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refusal("JSON_MALFORMED", name + " is not strict UTF-8 JSON") from error
    if not isinstance(obj, dict):
        raise Refusal("JSON_NOT_OBJECT", name + " must be a JSON object")
    return obj


def file_bytes(path: Path) -> bytes:
    """Read a bounded regular file without following the final symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise Refusal("INPUT_UNREADABLE", "cannot open evidence input") from error
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refusal("INPUT_NOT_REGULAR", "evidence input is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise Refusal("INPUT_TOO_LARGE", "evidence input exceeds the finite limit")
        return raw
    finally:
        os.close(fd)
