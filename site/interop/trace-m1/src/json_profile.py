"""Strict, bounded ASCII JSON profile for the frozen M1 synthetic population."""

import base64
import hashlib
import json


class Refusal(ValueError):
    """The requested binding cannot be established by this reader."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def shape(value, depth=0):
    require(depth <= 32, "json_too_deep")
    if type(value) is dict:
        require(len(value) <= 1024, "object_too_large")
        for key, item in value.items():
            require(type(key) is str, "json_object_key_must_be_string")
            shape(key, depth + 1)
            shape(item, depth + 1)
    elif type(value) is list:
        require(len(value) <= 1024, "array_too_large")
        for item in value:
            shape(item, depth + 1)
    elif type(value) is str:
        require(value.isascii(), "non_ascii_outside_profile")
    elif type(value) is int:
        require(abs(value) <= 2**53 - 1, "integer_outside_profile")
    else:
        require(value is None or type(value) is bool, "value_outside_profile")


def parse(raw):
    require(type(raw) is bytes and len(raw) <= 1_048_576, "invalid_json_bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Refusal("malformed_json") from exc
    shape(value)
    return value


def canonical(value):
    shape(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def decode(text):
    require(type(text) is str and len(text) <= 1_398_104, "invalid_base64_type_or_size")
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise Refusal("malformed_base64") from exc
    require(base64.b64encode(raw).decode("ascii") == text, "noncanonical_base64")
    return raw


def object_fields(value, required, optional=()):
    require(type(value) is dict, "object_required")
    require(set(required) <= value.keys(), "required_field_missing")
    require(value.keys() <= set(required) | set(optional), "unknown_field")


def text(value):
    require(type(value) is str and bool(value.strip()), "nonempty_text_required")
    return value


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value <= 2**53 - 1, "integer_required")
    return value
