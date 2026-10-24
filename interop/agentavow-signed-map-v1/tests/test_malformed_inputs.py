"""Malformed signed packets must produce stable refusals rather than crashes."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from map_reader import capture_digest, encode_base64url, evaluate, load_json
from run_agentavow import check_population, selected_fixture
from test_map_reader import GATE, ISSUER, KEY, PAYLOAD, TOOL, assert_refusal, sign


class TestMalformedInputs:
    class TestPassingCases:
        def test_distinct_percent_and_literal_percent_names_remain_distinct(self) -> None:
            from map_reader import tool_key

            assert tool_key("a=b") != tool_key("a%3Db")
            assert tool_key("a b") != tool_key("a%20b")

        def test_definition_fields_remain_bound(self) -> None:
            changed = {**TOOL, "description": "changed after the grade"}
            assert capture_digest([changed], TOOL["name"]) != GATE["observed_tool_digest"]

    class TestFailingCases:
        @pytest.mark.parametrize("candidate", ["", "one.two", "one.two.three.four", None])
        def test_jws_segment_shape(self, candidate, caplog: pytest.LogCaptureFixture) -> None:
            assert_refusal(
                lambda: evaluate(candidate, KEY, ISSUER, GATE),
                "compact JWS must contain three segments",
                caplog,
            )

        @pytest.mark.parametrize(
            "key,reason",
            [
                ({**KEY, "kty": "RSA"}, "unsupported pinned public key"),
                ({**KEY, "kid": ""}, "pinned key must have a nonempty kid"),
                (
                    {**KEY, "x": encode_base64url(b"short")},
                    "Ed25519 key or signature length differs",
                ),
                ({**KEY, "x": "AA="}, "invalid base64url encoding"),
            ],
        )
        def test_key_selection(
            self, key: dict, reason: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refusal(lambda: evaluate(sign(), key, ISSUER, GATE), reason, caplog)

        def test_signature_length(self, caplog: pytest.LogCaptureFixture) -> None:
            header, payload, _ = sign().split(".")
            candidate = header + "." + payload + "." + encode_base64url(b"short")
            assert_refusal(
                lambda: evaluate(candidate, KEY, ISSUER, GATE),
                "Ed25519 key or signature length differs",
                caplog,
            )

        @pytest.mark.parametrize(
            "scan,reason",
            [
                (None, "signed payload must contain a tool digest map"),
                ({"toolDigests": []}, "signed payload must contain a tool digest map"),
                (
                    {"toolDigests": {"other": "sha256:" + "0" * 64}},
                    "signed tool digest map has an invalid key",
                ),
            ],
        )
        def test_signed_map_shape(
            self, scan, reason: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refusal(
                lambda: evaluate(sign({**PAYLOAD, "scan": scan}), KEY, ISSUER, GATE), reason, caplog
            )

        @pytest.mark.parametrize("field", ["subject", "issuer"])
        def test_identity_shape(self, field: str, caplog: pytest.LogCaptureFixture) -> None:
            assert_refusal(
                lambda: evaluate(sign({**PAYLOAD, field: {}}), KEY, ISSUER, GATE),
                f"signed {field} must contain an id",
                caplog,
            )

        def test_selected_issuer_shape(self, caplog: pytest.LogCaptureFixture) -> None:
            assert_refusal(
                lambda: evaluate(sign(), KEY, "", GATE),
                "selected issuer must be a nonempty string",
                caplog,
            )

        @pytest.mark.parametrize("gate", [None, {}, {**GATE, "extra": "unselected"}])
        def test_gate_population(self, gate, caplog: pytest.LogCaptureFixture) -> None:
            assert_refusal(
                lambda: evaluate(sign(), KEY, ISSUER, gate),
                "gate fields differ from the candidate contract",
                caplog,
            )

        def test_empty_signed_window(self, caplog: pytest.LogCaptureFixture) -> None:
            candidate = {**PAYLOAD, "expiresAt": PAYLOAD["issuedAt"]}
            assert_refusal(
                lambda: evaluate(sign(candidate), KEY, ISSUER, GATE),
                "signed validity window is empty or reversed",
                caplog,
            )

        @pytest.mark.parametrize(
            "raw,reason",
            [
                (b"[]", "JSON root must be an object"),
                (b"{", "invalid JSON encoding"),
                (b"\xff", "invalid JSON encoding"),
            ],
        )
        def test_raw_packet_shape(
            self, raw: bytes, reason: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            assert_refusal(lambda: load_json(raw), reason, caplog)

        def test_duplicate_signed_map_entry(self, caplog: pytest.LogCaptureFixture) -> None:
            raw = json.dumps(PAYLOAD).replace(
                '"tool:approve%20invoice":',
                '"tool:approve%20invoice":"sha256:' + "0" * 64 + '","tool:approve%20invoice":',
            )
            assert_refusal(
                lambda: evaluate(sign(raw=raw.encode()), KEY, ISSUER, GATE),
                "duplicate JSON member",
                caplog,
            )

        def test_definition_outside_existing_numeric_profile(
            self, caplog: pytest.LogCaptureFixture
        ) -> None:
            candidate = copy.deepcopy(TOOL)
            candidate["inputSchema"]["maximum"] = 2**53
            assert_refusal(
                lambda: capture_digest([candidate], TOOL["name"]),
                "served definition is outside the bounded digest profile",
                caplog,
            )

        @pytest.mark.parametrize(
            "field,count",
            [("key_encoding", 12), ("observed_tools", 4), ("vectors", 6), ("vectors", 8)],
        )
        def test_native_population_differs_from_lock(
            self, field: str, count: int, caplog: pytest.LogCaptureFixture
        ) -> None:
            lock = {"population": {"key_pairs": 13, "definitions": 3, "cases": 7}}
            sizes = {"key_encoding": 13, "observed_tools": 3, "vectors": 7, field: count}
            fixture = {name: [{}] * size for name, size in sizes.items()}
            found = {
                "key_pairs": sizes["key_encoding"],
                "definitions": sizes["observed_tools"],
                "cases": sizes["vectors"],
            }
            assert_refusal(
                lambda: check_population(fixture, lock),
                f"native population {found} differs from the selected {lock['population']}",
                caplog,
            )

        def test_native_packet_substitution(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            path = tmp_path / "substituted.json"
            path.write_text("{}")
            assert_refusal(
                lambda: selected_fixture(path),
                "native fixture digest differs from the selected source",
                caplog,
            )
