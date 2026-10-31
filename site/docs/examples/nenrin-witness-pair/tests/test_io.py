"""Input refusal controls without identifier normalization or file aliases."""

import os

import pytest

from witness_case.io import MAX_BYTES, MAX_DEPTH, Refusal, file_bytes, operator, parse, pin, text


@pytest.mark.parametrize("value", [None, False, 12, "", "a\nb", "a\u200db", "\ud800", "x" * 8193])
def test_text_refuses_invalid_literals(value):
    with pytest.raises(Refusal) as error:
        text(value, "target")
    assert error.value.code == "TEXT_INVALID"


def test_literals_preserve_exact_bytes_and_operator_declaration():
    assert text(" https://example.test/a/ ", "target") == " https://example.test/a/ "
    assert operator("Pavlo / reader") == {
        "identity": "Pavlo / reader",
        "source": "caller-declared",
        "authenticated": False,
    }
    for value in (" leading", "trailing ", "--runner"):
        with pytest.raises(Refusal) as error:
            operator(value)
        assert error.value.code == "OPERATOR_INVALID"


@pytest.mark.parametrize("value", [None, "A" * 64, "a" * 63, "sha256:" + "a" * 64, 0])
def test_pin_has_one_explicit_encoding(value):
    with pytest.raises(Refusal) as error:
        pin(value, "pin")
    assert error.value.code == "PIN_INVALID"
    assert pin("a" * 64, "pin") == "a" * 64


@pytest.mark.parametrize(
    "raw",
    [b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b"\xef\xbb\xbf{}"],
)
def test_strict_json_refuses_ambiguous_or_invalid_documents(raw):
    with pytest.raises(Refusal) as error:
        parse(raw, "input")
    assert error.value.code == "JSON_MALFORMED"


def test_nesting_limit_is_explicit_and_ignores_quoted_brackets():
    within = b'{"x":' + b"[" * (MAX_DEPTH - 1) + b"0" + b"]" * (MAX_DEPTH - 1) + b"}"
    assert isinstance(parse(within, "input")["x"], list)
    for depth in (MAX_DEPTH, 2000):
        beyond = b'{"x":' + b"[" * depth + b"0" + b"]" * depth + b"}"
        with pytest.raises(Refusal) as error:
            parse(beyond, "input")
        assert error.value.code == "JSON_TOO_DEEP"
    brackets = "[" * 2000 + "]" * 2000
    raw = ('{"x":"\\"' + brackets + '\\\\"}').encode()
    assert parse(raw, "input") == {"x": '"' + brackets + "\\"}


def test_json_requires_bounded_objects():
    assert parse(b'{"result":null}', "input") == {"result": None}
    for raw, code in [
        (b"[]", "JSON_NOT_OBJECT"),
        (b"x" * (MAX_BYTES + 1), "INPUT_TOO_LARGE"),
        ("{}", "INPUT_TOO_LARGE"),
    ]:
        with pytest.raises(Refusal) as error:
            parse(raw, "input")
        assert error.value.code == code


def test_file_inputs_are_regular_bounded_and_not_symlinked(tmp_path):
    regular = tmp_path / "regular"
    regular.write_bytes(b"{}")
    assert file_bytes(regular) == b"{}"
    alias = tmp_path / "alias"
    alias.symlink_to(regular.name)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path, code in [
        (alias, "INPUT_UNREADABLE"),
        (tmp_path / "missing", "INPUT_UNREADABLE"),
        (fifo, "INPUT_NOT_REGULAR"),
        (tmp_path, "INPUT_NOT_REGULAR"),
    ]:
        with pytest.raises(Refusal) as error:
            file_bytes(path)
        assert error.value.code == code
    regular.write_bytes(b"x" * (MAX_BYTES + 1))
    with pytest.raises(Refusal) as error:
        file_bytes(regular)
    assert error.value.code == "INPUT_TOO_LARGE"
