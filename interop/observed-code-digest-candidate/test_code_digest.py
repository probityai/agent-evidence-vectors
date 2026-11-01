"""Verify optional joins against signed fixtures, both Python readers and schema."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "packaging"))
sys.path.insert(0, str(HERE))

import generate  # noqa: E402
from agent_evidence_vectors import observedeffect as rail  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "code_join_reference", ROOT / "corpora/vectors-observed-effect/check_vectors.py"
)
assert SPEC is not None and SPEC.loader is not None
REFERENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE)
MANIFEST = json.loads((HERE / "MANIFEST.json").read_text())
RELEASED = json.loads((ROOT / "corpora/vectors-observed-effect/MANIFEST.json").read_text())
KEY = RELEASED["keys"]["observer"]["publicKey"]
SCHEMA = json.loads(
    (ROOT / "spec/schemas/observed-effect-code-digest-v0.5.schema.json").read_text()
)
VALIDATOR = Draft202012Validator(SCHEMA)
LOGGER = logging.getLogger(__name__)


def policy(expected: str = "") -> rail.Policy:
    """Create an external consumer policy from public test inputs.

    Parameters
    ----------
    expected : str
        SHA-256 chosen by this consumer. Empty means that no join is requested.

    Returns
    -------
    rail.Policy
        Observer test key and independently supplied expected code digest.
        Neither trust input is read from the statement under verification.
    """
    blob = rail.NARRATED_BLOB
    return rail.Policy(
        RELEASED["predicateType"], KEY, {hashlib.sha256(blob).hexdigest(): blob}, expected
    )


def verdicts(raw: bytes, expected: str = "") -> list[tuple[str, list[str]]]:
    """Read one envelope through both implementations without sharing rules."""
    report = rail.verify(raw, policy(expected))
    result = (report.verdict, report.codes)
    other = REFERENCE.verify(raw, KEY, REFERENCE.BLOBS, expected_code_digest=expected)
    return [result, other]


def candidate(value: Any) -> bytes:
    """Sign one producer-side mutation using only published fixture keys."""
    _, envelope = generate.make_case("property-case", value, "", "valid", [])
    return json.dumps(envelope).encode()


class TestCodeDigest:
    """Hold exact syntax, consumer joins and immutable old results separately."""

    class TestPassingCases:
        @pytest.mark.parametrize("row", MANIFEST["vectors"], ids=lambda row: row["id"])
        def test_signed_candidate_matches_both_readers(
            self, row: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            """All declared outcomes are rederived from pinned signed bytes."""
            raw = (HERE / row["file"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == row["sha256"]
            expected = (row["expected"]["verdict"], row["expected"]["codes"])
            with caplog.at_level(logging.INFO, logger=__name__):
                for actual in verdicts(raw, row["expectedCodeDigest"]):
                    LOGGER.info("%s: %s %s", row["id"], actual[0], actual[1])
                    assert actual == expected
            assert row["id"] + ": " + expected[0] in caplog.text

        @pytest.mark.parametrize("row", RELEASED["vectors"], ids=lambda row: row["id"])
        def test_released_verdicts_remain_unchanged(self, row: dict[str, Any]) -> None:
            """Absent optional fields preserve the published accept/reject/readings."""
            raw = (ROOT / "corpora" / "vectors-observed-effect" / row["file"]).read_bytes()
            allowed = {r["verdict"] for r in row.get("readings", [])}
            if not allowed:
                allowed = {row["expected"]["verdict"]}
            for verdict, codes in verdicts(raw):
                assert verdict in allowed
                if "expected" in row:
                    assert codes == row["expected"].get("codes", [])

        @given(st.binary(min_size=32, max_size=32))
        def test_every_sha256_value_can_match(self, digest: bytes) -> None:
            """No digest value has privileged treatment beyond exact comparison."""
            value = digest.hex()
            assert verdicts(candidate({"sha256": value}), value) == [("valid", []), ("valid", [])]

        def test_schema_definition_is_valid(self) -> None:
            Draft202012Validator.check_schema(SCHEMA)
            assert VALIDATOR.is_valid({"predicate": {}})
            assert VALIDATOR.is_valid({"predicate": {"codeDigest": {"sha256": generate.DIGEST}}})

    class TestFailingCases:
        @pytest.mark.parametrize(
            "value",
            [None, {}, [], "a" * 64, {"sha1": "a" * 40}, {"sha256": "a" * 64, "extra": True}],
        )
        def test_present_wrong_shape_fails_without_join_policy(self, value: Any) -> None:
            """Optional does not mean unchecked when present."""
            assert verdicts(candidate(value)) == [("malformed", ["code-digest-shape"])] * 2
            assert not VALIDATOR.is_valid({"predicate": {"codeDigest": value}})

        @pytest.mark.parametrize(
            "value", [None, 0, True, "", "a" * 63, "a" * 65, "A" * 64, "a" * 64 + "\n", "g" * 64]
        )
        def test_invalid_digest_values_fail_schema_and_readers(self, value: Any) -> None:
            """Length constraints prevent JSON Schema's end-anchor newline alias."""
            body = {"sha256": value}
            assert verdicts(candidate(body)) == [("malformed", ["code-digest-value"])] * 2
            assert not VALIDATOR.is_valid({"predicate": {"codeDigest": body}})

        @given(st.binary(min_size=32, max_size=32))
        def test_changed_external_code_pin_fails(self, digest: bytes) -> None:
            """A consumer's changed executable identity cannot reuse an old join."""
            altered = bytes([digest[0] ^ 1]) + digest[1:]
            raw = candidate({"sha256": digest.hex()})
            assert verdicts(raw, altered.hex()) == [("invalid", ["code-digest-mismatch"])] * 2

        @pytest.mark.parametrize(
            "rule,case",
            [
                ("code-digest-shape", "null-field"),
                ("code-digest-policy", "required-absent"),
            ],
        )
        def test_each_new_rule_is_load_bearing(self, rule: str, case: str) -> None:
            """Removing one rule frees its signed negative control."""
            row = next(row for row in MANIFEST["vectors"] if row["id"] == case)
            raw = (HERE / row["file"]).read_bytes()
            current = rail.verify(raw, policy(row["expectedCodeDigest"]))
            mutant = rail.verify(raw, policy(row["expectedCodeDigest"]), disabled=rule)
            assert current.verdict == row["expected"]["verdict"]
            assert mutant.verdict == "valid"

        def test_duplicate_digest_member_is_rejected(self) -> None:
            """Duplicate-key rejection remains earlier than the code join."""
            envelope = json.loads(candidate({"sha256": generate.DIGEST}))
            payload = base64.b64decode(envelope["payload"]).decode()
            original = '"codeDigest":{"sha256":"' + generate.DIGEST + '"}'
            duplicate = (
                '"codeDigest":{"sha256":"'
                + generate.DIGEST
                + '","sha256":"'
                + generate.DIGEST
                + '"}'
            )
            assert original in payload
            envelope["payload"] = base64.b64encode(
                payload.replace(original, duplicate).encode()
            ).decode()
            assert (
                verdicts(json.dumps(envelope).encode()) == [("malformed", ["duplicate-member"])] * 2
            )
