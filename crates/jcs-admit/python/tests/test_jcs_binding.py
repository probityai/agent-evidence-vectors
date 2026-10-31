"""The binding's own contract: types in and out, every refusal mapped, options."""

from __future__ import annotations

import inspect

import pytest

from conftest import bound_crate
import jcs_admit as jcs
# _native is the compiled extension; the checker reads its .pyi stub and has no source for it
from jcs_admit import _native  # pyright: ignore[reportMissingModuleSource]


def refusal(fn, data, **kw) -> jcs.JcsError:
    with pytest.raises(jcs.JcsError) as info:
        fn(data, **kw)
    return info.value


def test_canonical_bytes_out():
    out = jcs.admit(b'{ "b": 1, "a": [1.0, 1e30] }')
    assert type(out) is bytes
    assert out == b'{"a":[1,1e+30],"b":1}'


@pytest.mark.parametrize("bad", ['{"a":1}', bytearray(b"{}"), memoryview(b"{}"), None, 1])
def test_only_bytes_are_admitted(bad):
    for fn in (jcs.admit, jcs.admit_ijson, jcs.admit_with, jcs.is_canonical, jcs.is_canonical_with):
        with pytest.raises(TypeError):
            fn(bad)


# Every variant the bound release can raise from a document, with the exact
# fields and message the crate produces. `Canonicalization` is unreachable for
# an admitted document by the crate's own account and is not listed.
CASES = [
    (jcs.admit, b"{", {}, "Syntax", None),
    (jcs.admit, b"1 2", {}, "TrailingContent", {"offset": 2}),
    (jcs.admit, b'{"a":1,"a":2}', {}, "DuplicateMember", {"name": "a", "offset": 7}),
    (jcs.admit, b'"\\ud800"', {}, "StringNotScalar", None),
    (jcs.admit_ijson, b"9007199254740993", {}, "UnsafeInteger", {"token": "9007199254740993"}),
    (jcs.admit_with, b"1.5", {"integers_only": True}, "NonIntegerNumber", {"token": "1.5"}),
    (jcs.admit, b"-1e400", {}, "NonFiniteNumber", {"token": "-1e400"}),
    (jcs.admit, b"[" * 129 + b"]" * 129, {}, "TooDeep", {"limit": 128, "offset": 128}),
    (jcs.admit_with, b"[1]", {"max_bytes": 2}, "TooLarge", {"len": 3, "limit": 2}),
]


@pytest.mark.parametrize(("fn", "data", "kw", "variant", "fields"), CASES, ids=[c[3] for c in CASES])
def test_every_refusal_carries_the_native_variant_and_fields(fn, data, kw, variant, fields):
    err = refusal(fn, data, **kw)
    assert isinstance(err, ValueError)
    assert err.variant == variant
    if fields is not None:
        assert err.fields == fields
    else:
        assert set(err.fields) == {"offset", "reason"}
        assert isinstance(err.fields["offset"], int)
    assert str(err) == err.args[0]


def test_the_message_is_the_crates_display_text():
    assert str(refusal(jcs.admit, b'{"a":1,"a":2}')) == 'duplicate object member "a" at byte 7'


def test_refused_message_is_bounded_like_the_crates():
    name = "x" * 100_000
    err = refusal(jcs.admit, f'{{"{name}":1,"{name}":2}}'.encode())
    assert err.fields["name"] == name  # the data is whole
    assert len(str(err)) < 200  # the message is clipped by the crate


def test_rfc8785_admits_an_inexact_integer_and_ijson_refuses_it():
    assert jcs.admit(b"9007199254740993") == b"9007199254740992"
    assert refusal(jcs.admit_ijson, b"9007199254740993").variant == "UnsafeInteger"


def test_noncharacter_is_rfc8785_canonical_and_ijson_refused():
    doc = '"\ufffe"'.encode()
    assert jcs.is_canonical(doc)
    assert not jcs.is_canonical_with(doc, reject_noncharacters=True)
    assert refusal(jcs.admit_ijson, doc).variant == "StringNotScalar"


def test_depth_cap_saturates_at_the_supported_ceiling():
    deep = b"[" * (jcs.MAX_SUPPORTED_DEPTH + 1) + b"]" * (jcs.MAX_SUPPORTED_DEPTH + 1)
    err = refusal(jcs.admit_with, deep, max_depth=10**9)
    assert err.fields["limit"] == jcs.MAX_SUPPORTED_DEPTH


def test_size_cap_can_be_removed():
    big = b"[" + b"0," * (jcs.DEFAULT_MAX_BYTES // 2) + b"0]"
    assert refusal(jcs.admit, big).variant == "TooLarge"
    assert jcs.admit_with(big, max_bytes=None) == big


def test_is_canonical_is_false_for_refused_and_for_non_canonical_input():
    assert jcs.is_canonical(b'{"a":1}')
    assert not jcs.is_canonical(b'{ "a":1}')
    assert not jcs.is_canonical(b'{"a":1,"a":1}')


def test_defaults_match_the_crate():
    assert (jcs.DEFAULT_MAX_DEPTH, jcs.MAX_SUPPORTED_DEPTH, jcs.DEFAULT_MAX_BYTES) == (128, 512, 20 << 20)


def test_the_reported_version_is_the_version_cargo_linked():
    assert jcs.JCS_ADMIT_VERSION == bound_crate("jcs-admit").version


def test_exception_lives_where_users_import_it():
    assert jcs.JcsError is _native.JcsError
    assert jcs.JcsError.__module__ == "jcs_admit"


@pytest.mark.parametrize("fn", [jcs.admit_with, jcs.is_canonical_with])
def test_the_shown_signature_defaults_are_the_crates_constants(fn):
    params = inspect.signature(fn).parameters
    assert params["max_depth"].default == jcs.DEFAULT_MAX_DEPTH
    assert params["max_bytes"].default == jcs.DEFAULT_MAX_BYTES
    for flag in ("safe_integers", "integers_only", "reject_noncharacters"):
        assert params[flag].default is False



def test_the_distribution_is_jcs_admit_and_installs_only_jcs_admit():
    # The name `probityai` belongs to the `probity` command-line distribution. This
    # wheel must install beside it, so it carries no file outside `jcs_admit`.
    from importlib.metadata import distribution

    dist = distribution("jcs-admit")
    assert dist.metadata["Name"] == "jcs-admit"
    assert jcs.__version__ == dist.version
    tops = {f.parts[0] for f in dist.files or ()}
    assert not tops & {"probityai", "probityai.pth"}, sorted(tops)
