"""Synthetic signed controls for exact name-key extraction and consumer pins."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st
from map_reader import (
    InputError,
    canonicalize,
    capture_digest,
    decode_base64url,
    definition_digest,
    encode_base64url,
    evaluate,
    extract_pin,
    load_json,
    tool_key,
)

PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEY = {
    "kty": "OKP",
    "crv": "Ed25519",
    "alg": "EdDSA",
    "kid": "synthetic-test",
    "x": encode_base64url(PRIVATE.public_key().public_bytes_raw()),
}
ISSUER = "did:example:synthetic"
SUBJECT = "mcp:https://example.com/mcp"
TOOL = {
    "name": "approve invoice",
    "description": "Approve one reviewed invoice.",
    "inputSchema": {"type": "object"},
}
DIGEST = definition_digest(TOOL)
GATE = {
    "subject_id": SUBJECT,
    "tool_name": TOOL["name"],
    "observed_tool_digest": DIGEST,
    "evaluation_time": "2026-10-02T10:30:00Z",
}
PAYLOAD = {
    "issuer": {"id": ISSUER},
    "subject": {"id": SUBJECT},
    "issuedAt": "2026-10-02T10:00:00Z",
    "expiresAt": "2026-10-02T11:00:00Z",
    "scan": {"toolDigests": {tool_key(TOOL["name"]): DIGEST}},
}


def sign(payload: dict = PAYLOAD, header: dict | None = None, raw: bytes | None = None) -> str:
    """Sign a test payload; optional raw bytes exercise canonicality separately."""
    protected = encode_base64url(json.dumps(header or {"alg": "EdDSA", "kid": KEY["kid"]}).encode())
    encoded = encode_base64url(canonicalize(payload) if raw is None else raw)
    message = (protected + "." + encoded).encode()
    return protected + "." + encoded + "." + encode_base64url(PRIVATE.sign(message))


def assert_refusal(call, reason: str, caplog: pytest.LogCaptureFixture) -> None:
    """Require the exact exception and warning, so a crash cannot count as refusal."""
    with (
        caplog.at_level(logging.WARNING),
        pytest.raises(InputError, match=f"^{re.escape(reason)}$"),
    ):
        call()
    assert caplog.messages[-1] == reason


class TestMapReader:
    class TestPassingCases:
        @pytest.mark.parametrize(
            "name,expected",
            [
                ("plain", "tool:plain"),
                ("a=b", "tool:a%3Db"),
                ("x%y", "tool:x%25y"),
                ("read file", "tool:read%20file"),
                ("tab\there", "tool:tab%09here"),
                ("héllo", "tool:h%C3%A9llo"),
                ("search 🙂", "tool:search%20%F0%9F%99%82"),
                ("b" * 128, "tool:" + "b" * 128),
            ],
        )
        def test_untruncated_encoding(self, name: str, expected: str) -> None:
            assert tool_key(name) == expected

        @pytest.mark.parametrize(
            "name", ["c" * 129, "a" * 200, "é" * 50, "a" * 95 + "é" * 20, "a" * 94 + "é" * 20]
        )
        def test_long_key_keeps_plain_character_cut_and_raw_name_hash(self, name: str) -> None:
            from urllib.parse import quote

            safe = (
                "!\"#$&'()*+,-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
            )
            body = quote(name, safe=safe)
            assert (
                tool_key(name)
                == "tool:" + body[:96] + "~" + hashlib.sha256(name.encode()).hexdigest()[:16]
            )

        @given(
            st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=150)
        )
        def test_encoder_matches_separate_standard_library_derivation(self, name: str) -> None:
            from urllib.parse import quote

            safe = (
                "!\"#$&'()*+,-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
            )
            body = quote(name, safe=safe)
            expected = (
                body
                if len(body) <= 128
                else body[:96] + "~" + hashlib.sha256(name.encode()).hexdigest()[:16]
            )
            assert tool_key(name) == "tool:" + expected

        @given(st.binary(min_size=1, max_size=128))
        def test_base64url_round_trip(self, raw: bytes) -> None:
            assert decode_base64url(encode_base64url(raw)) == raw

        def test_signed_encoded_entry_extracts_historical_pin_shape(self) -> None:
            assert evaluate(sign(), KEY, ISSUER, GATE)["rely"]
            assert extract_pin(sign(), KEY, ISSUER, GATE) == {
                "endpoint": "https://example.com/mcp",
                "toolName": TOOL["name"],
                "toolDigest": DIGEST,
            }

        @pytest.mark.parametrize(
            "reference,expected",
            [
                ("2026-10-02T10:00:00Z", True),
                ("2026-10-02T11:00:00Z", False),
                ("2026-10-02T05:30:00-05:00", True),
                ("2026-10-02T09:59:59.999999Z", False),
            ],
        )
        def test_half_open_window_and_offsets(self, reference: str, expected: bool) -> None:
            assert (
                evaluate(sign(), KEY, ISSUER, {**GATE, "evaluation_time": reference})["fresh"]
                == expected
            )

        @pytest.mark.parametrize(
            "reference,expected",
            [
                ("2026-10-02T11:00:00.000Z", True),
                ("2026-10-02T11:00:00.000196Z", True),
                ("2026-10-02T11:00:00.000197Z", False),
            ],
        )
        def test_sub_millisecond_expiry_compares_instants(
            self, reference: str, expected: bool
        ) -> None:
            """The producer's boundary-fresh shape: a millisecond clock reading
            just inside a microsecond expiry is fresh, and a string or
            millisecond comparison would call it expired."""
            payload = {**PAYLOAD, "expiresAt": "2026-10-02T11:00:00.000197+00:00"}
            gate = {**GATE, "evaluation_time": reference}
            assert evaluate(sign(payload), KEY, ISSUER, gate)["fresh"] is expected

        def test_capture_definition_hash_reuses_unchanged_profile(self) -> None:
            assert capture_digest([TOOL], TOOL["name"]) == DIGEST
            assert (
                capture_digest([{**TOOL, "_meta": {"unhashed": "changed"}}], TOOL["name"]) == DIGEST
            )

    class TestFailingCases:
        @pytest.mark.parametrize(
            "name,reason",
            [
                ("", "tool name must be a nonempty string"),
                (None, "tool name must be a nonempty string"),
                ("\ud800", "tool name contains an invalid Unicode scalar"),
            ],
        )
        def test_invalid_name(self, name, reason: str, caplog: pytest.LogCaptureFixture) -> None:
            assert_refusal(lambda: tool_key(name), reason, caplog)

        def test_signed_map_never_falls_back_to_literal_name(
            self, caplog: pytest.LogCaptureFixture
        ) -> None:
            payload = {**PAYLOAD, "scan": {"toolDigests": {"tool:" + TOOL["name"]: DIGEST}}}
            result = evaluate(sign(payload), KEY, ISSUER, GATE)
            assert not result["tool_binds"] and result["tool_digest_binds"] == "not_evaluated"
            assert_refusal(
                lambda: extract_pin(sign(payload), KEY, ISSUER, GATE),
                "signed map cannot supply a usable definition pin",
                caplog,
            )

        @pytest.mark.parametrize(
            "patch,axis",
            [
                ({"subject_id": "mcp:https://other.example/mcp"}, "subject_binds"),
                ({"tool_name": "unknown"}, "tool_binds"),
                ({"observed_tool_digest": "sha256:" + "0" * 64}, "tool_digest_binds"),
                ({"evaluation_time": "2026-10-02T11:00:00Z"}, "fresh"),
            ],
        )
        def test_each_gate_axis_blocks_extraction(
            self, patch: dict, axis: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            gate = {**GATE, **patch}
            assert evaluate(sign(), KEY, ISSUER, gate)[axis] is False
            assert_refusal(
                lambda: extract_pin(sign(), KEY, ISSUER, gate),
                "signed map cannot supply a usable definition pin",
                caplog,
            )

        def test_wrong_selected_issuer(self, caplog: pytest.LogCaptureFixture) -> None:
            assert not evaluate(sign(), KEY, "did:example:other", GATE)["issuer_binds"]
            assert_refusal(
                lambda: extract_pin(sign(), KEY, "did:example:other", GATE),
                "signed map cannot supply a usable definition pin",
                caplog,
            )

        def test_tampered_signature_keeps_other_axes_separate(self) -> None:
            header, payload, _ = sign().split(".")
            candidate = header + "." + payload + "." + encode_base64url(bytes(64))
            result = evaluate(candidate, KEY, ISSUER, GATE)
            assert not result["signature_valid"] and not result["rely"]
            assert all(
                value is True
                for axis, value in result.items()
                if axis not in {"signature_valid", "rely"}
            )

        def test_valid_signature_on_noncanonical_payload_cannot_extract(
            self, caplog: pytest.LogCaptureFixture
        ) -> None:
            candidate = sign(raw=json.dumps(PAYLOAD, indent=2).encode())
            result = evaluate(candidate, KEY, ISSUER, GATE)
            assert result["signature_valid"] and not result["canonical_bytes"]
            assert_refusal(
                lambda: extract_pin(candidate, KEY, ISSUER, GATE),
                "signed map cannot supply a usable definition pin",
                caplog,
            )

        @pytest.mark.parametrize(
            "tools,reason",
            [
                ([TOOL, TOOL], "tools/list has ambiguous names or encoded keys"),
                ([], "selected tool is absent from tools/list"),
                (["bad"], "tools/list must be an array of objects"),
            ],
        )
        def test_ambiguous_and_missing_capture(
            self, tools: list, reason: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refusal(lambda: capture_digest(tools, TOOL["name"]), reason, caplog)

        def test_encoded_key_collision_refuses(
            self, monkeypatch, caplog: pytest.LogCaptureFixture
        ) -> None:
            monkeypatch.setattr("map_reader.tool_key", lambda name: "tool:collision")
            assert_refusal(
                lambda: capture_digest([TOOL, {**TOOL, "name": "other"}], TOOL["name"]),
                "tools/list has ambiguous names or encoded keys",
                caplog,
            )

        @pytest.mark.parametrize(
            "header,reason",
            [
                (
                    {"alg": "none", "kid": KEY["kid"]},
                    "JWS algorithm or kid differs from the pinned key",
                ),
                (
                    {"alg": "EdDSA", "kid": "other"},
                    "JWS algorithm or kid differs from the pinned key",
                ),
                (
                    {"alg": "EdDSA", "kid": KEY["kid"], "b64": False},
                    "unsupported JOSE header extension",
                ),
                (
                    {"alg": "EdDSA", "kid": KEY["kid"], "crit": []},
                    "unsupported JOSE header extension",
                ),
            ],
        )
        def test_jose_selection_controls(
            self, header: dict, reason: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refusal(lambda: evaluate(sign(header=header), KEY, ISSUER, GATE), reason, caplog)

        @pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"scan":{"x":1,"x":2}}'])
        def test_duplicate_members_refuse(
            self, raw: bytes, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refusal(lambda: load_json(raw), "duplicate JSON member", caplog)

        @pytest.mark.parametrize(
            "reference", ["2026-10-02", "2026-10-02T10:30:00", "2026-99-02T10:30:00Z"]
        )
        def test_unusable_reference_time(
            self, reference: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refusal(
                lambda: evaluate(sign(), KEY, ISSUER, {**GATE, "evaluation_time": reference}),
                "timestamp must be an ISO instant with a timezone",
                caplog,
            )

        @pytest.mark.parametrize("digest", [None, "", "SHA256:" + "0" * 64, "sha256:" + "0" * 63])
        def test_malformed_signed_digest(self, digest, caplog: pytest.LogCaptureFixture) -> None:
            payload = copy.deepcopy(PAYLOAD)
            payload["scan"]["toolDigests"][tool_key(TOOL["name"])] = digest
            assert_refusal(
                lambda: evaluate(sign(payload), KEY, ISSUER, GATE),
                "signed tool digest map has an invalid digest",
                caplog,
            )
