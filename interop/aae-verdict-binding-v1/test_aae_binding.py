"""Kernel, vector, input-profile and pin checks for the AAE verdict-binding package."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import kernel
import pins
import pytest
import reproduce
import strict_json

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "aae-v1.4.0"
VECTOR_FILES = sorted(FIXTURES.glob("*.json"))
REGISTRY = "did:web:example.com:registry"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def vector_named(prefix: str) -> dict[str, Any]:
    return load(next(path.name for path in VECTOR_FILES if path.name.startswith(prefix)))


PERMIT_GRANT = vector_named("01")["input"]["mandate"]
PERMIT_TX = vector_named("01")["input"]["transaction"]


class TestPublishedVectors:
    def test_the_set_has_twenty_six_vectors(self) -> None:
        assert len(VECTOR_FILES) == 26

    @pytest.mark.parametrize("path", VECTOR_FILES, ids=lambda path: path.name[:2])
    def test_vector_reproduces_from_input_alone(self, path: Path) -> None:
        vector = json.loads(path.read_text(encoding="utf-8"))
        result = reproduce.reproduce(path.name, vector, pins.trust_pins())
        assert result["checks"] and all(result["checks"].values()), result["checks"]

    def test_caller_errors_are_the_named_guards(self) -> None:
        for prefix, code in (("24", "prior_verdict_permit"), ("25", "prev_core_digest_mismatch")):
            given = vector_named(prefix)["input"]
            assert reproduce.caller_error(reproduce.ratify_arguments(given)) == code

    def test_stranger_signature_verifies_under_its_own_key_and_is_rejected(self) -> None:
        given = vector_named("23")["input"]
        stranger = pins.UNTRUSTED_KEYS[0]
        message = kernel.statement_bytes(
            given["prior_record"]["core_digest"], "APPROVED", stranger["did"]
        )
        assert kernel.signature_holds(
            stranger["public_key"], given["authority_proof"]["signature"], message
        )
        record = kernel.ratify(*reproduce.ratify_arguments(given))
        assert record.core["status"] == kernel.REJECTED
        assert record.core["authority"] is None

    def test_a_changed_expected_digest_is_not_reproduced(self) -> None:
        vector = vector_named("01")
        vector["expected"]["core_digest"] = "sha256:" + "0" * 64
        result = reproduce.reproduce("01", vector, pins.trust_pins())
        assert result["reproduced"] is False
        assert result["checks"]["core_digest"] is False

    def test_unpinned_authority_key_is_refused(self) -> None:
        vector = vector_named("22")
        vector["input"]["authority_proof"]["mandate"]["principal"]["public_key"] = "11" * 32
        with pytest.raises(strict_json.InputError, match="pin set"):
            reproduce.reproduce("22", vector, pins.trust_pins())

    def test_wrong_domain_tag_is_detected(self) -> None:
        vector = vector_named("01")
        vector["domain_tags"]["core"] = "aae:enforce-core:v2"
        result = reproduce.reproduce("01", vector, pins.trust_pins())
        assert result["checks"]["domain_tags"] is False


class TestDraftConstructions:
    def test_tag_octet_counts_match_the_draft(self) -> None:
        assert len(kernel.TAG_ACTION) == 21 + 1
        assert len(kernel.TAG_CORE) == 19 + 1
        assert len(kernel.TAG_RATIFY_CORE) == 26 + 1
        assert all(tag.endswith(b"\x00") for tag in kernel.DOMAIN_TAGS.values())

    def test_reason_is_never_digested(self) -> None:
        outcome = kernel.enforce_check(PERMIT_GRANT, PERMIT_TX)
        assert all(set(entry) == set(kernel.TRACE_MEMBERS) for entry in outcome.core["trace"])
        assert set(outcome.core) == set(kernel.CORE_MEMBERS)
        assert outcome.reason and "reason" not in json.dumps(outcome.core)

    def test_untagged_digest_is_not_the_core_digest(self) -> None:
        outcome = kernel.enforce_check(PERMIT_GRANT, PERMIT_TX)
        assert kernel.tagged_digest(b"", outcome.core) != outcome.core_digest

    def test_missing_transaction_denies(self) -> None:
        outcome = kernel.enforce_check(PERMIT_GRANT, None)
        assert outcome.core["verdict"] == kernel.DENY
        assert outcome.core["trace"][0]["predicate"] == "transaction_present"

    def test_absent_mandate_denies(self) -> None:
        outcome = kernel.enforce_check(None, PERMIT_TX)
        assert outcome.core["verdict"] == kernel.DENY
        assert outcome.core["trace"][0]["predicate"] == "mandate_present"

    def test_malformed_prev_core_digest_is_a_caller_error(self) -> None:
        with pytest.raises(kernel.CallerError):
            kernel.enforce_check(PERMIT_GRANT, PERMIT_TX, "sha256:ABC")

    def test_chain_link_enters_the_core(self) -> None:
        link = "sha256:" + "a" * 64
        assert kernel.enforce_check(PERMIT_GRANT, PERMIT_TX, link).core["prev_core_digest"] == link

    def test_grant_failing_each_shape_rule_is_malformed(self) -> None:
        grant = PERMIT_GRANT["grants"][0]
        broken = [
            {**grant, "action_binding": grant["action_binding"].upper()},
            {**grant, "disposition": "permit"},
            {**grant, "type_fields": ["verb", ""]},
            {**grant, "constraints": [{}] * 65},
            "not an object",
        ]
        for item in broken:
            assert kernel.mandate_problem({"grants": [item]}) is not None
        assert kernel.mandate_problem({"grants": []}) is not None
        assert kernel.mandate_problem({"grants": [grant] * 257}) is not None


def evaluate(rule: dict[str, Any], transaction: dict[str, Any]) -> dict[str, Any]:
    trace = kernel.Trace()
    kernel.check_constraint(trace, rule, transaction)
    return trace.entries[0]


class TestConstraintLanguage:
    @pytest.mark.parametrize("value", [500.0, True, "500", 10**16])
    def test_range_refuses_non_integers(self, value: Any) -> None:
        entry = evaluate({"type": "range", "field": "a", "lo": 0, "hi": 10**15}, {"a": value})
        assert entry["result"] == kernel.FAIL

    def test_range_inverted_bounds_fail(self) -> None:
        entry = evaluate({"type": "range", "field": "a", "lo": 5, "hi": 1}, {"a": 3})
        assert entry["result"] == kernel.FAIL and entry["value"] is None

    def test_range_float_bound_fails(self) -> None:
        entry = evaluate({"type": "range", "field": "a", "lo": 0.0, "hi": 9}, {"a": 3})
        assert entry["result"] == kernel.FAIL

    def test_exact_has_no_prefix_or_case_folding(self) -> None:
        for actual in ("0xABC", "0xabcd", "0xABCD "):
            entry = evaluate({"type": "exact", "field": "to", "value": "0xABCD"}, {"to": actual})
            assert entry["result"] == kernel.FAIL

    def test_exact_non_string_value_fails(self) -> None:
        assert evaluate({"type": "exact", "field": "a", "value": 1}, {"a": 1})["result"] == "FAIL"
        assert evaluate({"type": "exact", "field": "a", "value": "1"}, {"a": 1})["result"] == "FAIL"

    def test_enum_compares_every_member_and_counts_hits(self) -> None:
        assert kernel.enum_hits("x", ["x", "y", "x", 3]) == 2
        rule = {"type": "enum", "field": "a", "values": ["x"] * 513}
        assert evaluate(rule, {"a": "x"})["bound"] == 513
        empty = {"type": "enum", "field": "a", "values": []}
        assert evaluate(empty, {"a": "x"})["result"] == "FAIL"

    def test_path_rules(self) -> None:
        deep = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": "v"}}}}}}}}}
        assert kernel.resolve(deep, "a.b.c.d.e.f.g.h.i") == (False, None)
        assert kernel.resolve({"a": {"": "v"}}, "a.") == (False, None)
        assert kernel.resolve({"a": ["v"]}, "a.0") == (False, None)
        assert kernel.resolve({"a": {"b": 2}}, "a.b") == (True, 2)

    def test_unknown_types_fail_and_never_echo_python_spelling(self) -> None:
        assert evaluate({"type": "regex", "field": "a"}, {"a": "x"})["predicate"] == "regex"
        assert evaluate({"type": True, "field": "a"}, {"a": "x"})["predicate"] == "unknown"
        trace = kernel.Trace()
        assert kernel.check_constraint(trace, ["not", "an", "object"], {}) is False

    def test_hold_reaches_pending_only_through_a_bound_grant(self) -> None:
        mandate = copy.deepcopy(PERMIT_GRANT)
        mandate["grants"][0]["disposition"] = "hold"
        assert kernel.enforce_check(mandate, PERMIT_TX).core["verdict"] == kernel.PENDING
        unaddressed = {**PERMIT_TX, "action": {"verb": "burn", "asset": "USDC", "chain": "base"}}
        assert kernel.enforce_check(mandate, unaddressed).core["verdict"] == kernel.DENY


def ratify_input(prefix: str = "22") -> dict[str, Any]:
    return copy.deepcopy(vector_named(prefix)["input"])


class TestRatificationGuards:
    def test_invalid_decision_is_a_caller_error(self) -> None:
        given = ratify_input()
        given["decision"] = "MAYBE"
        with pytest.raises(kernel.CallerError, match="neither"):
            kernel.ratify(*reproduce.ratify_arguments(given))

    def test_mutated_prior_core_is_a_caller_error(self) -> None:
        given = ratify_input()
        given["prior_record"]["core"]["grant_index"] = 0
        code = reproduce.caller_error(reproduce.ratify_arguments(given))
        assert code == "prior_core_digest_mismatch"

    def test_prior_without_mandate_digest_is_a_caller_error(self) -> None:
        given = ratify_input()
        core = given["prior_record"]["core"]
        del core["mandate_digest"]
        given["prior_record"]["core_digest"] = kernel.tagged_digest(kernel.TAG_CORE, core)
        assert reproduce.caller_error(reproduce.ratify_arguments(given)) == (
            "prior_mandate_digest_missing"
        )

    def test_missing_proof_is_a_rejected_record(self) -> None:
        given = ratify_input()
        given["authority_proof"] = None
        record = kernel.ratify(*reproduce.ratify_arguments(given))
        assert record.core["status"] == kernel.REJECTED
        assert record.core["trace"][-1]["predicate"] == "authority_proof"

    def test_unbound_mandate_is_rejected(self) -> None:
        given = ratify_input()
        given["authority_proof"]["mandate"]["mandate_version"] = "1.1"
        record = kernel.ratify(*reproduce.ratify_arguments(given))
        assert record.core["status"] == kernel.REJECTED
        assert record.core["trace"][-1]["predicate"] == "mandate_binding"

    def test_bad_signature_is_rejected_not_raised(self) -> None:
        for signature in ("00" * 64, "zz", None, "02" * 63 + " 0"):
            given = ratify_input()
            given["authority_proof"]["signature"] = signature
            record = kernel.ratify(*reproduce.ratify_arguments(given))
            assert record.core["status"] == kernel.REJECTED

    def test_did_url_and_duplicate_did_fail_closed(self) -> None:
        allowed = [(REGISTRY, "aa" * 32, "principal")]
        assert kernel.match_authority(REGISTRY, allowed) is not None
        assert kernel.match_authority(REGISTRY + "#key-1", allowed) is None
        assert kernel.match_authority(REGISTRY, allowed * 2) is None
        assert kernel.match_authority(None, allowed) is None

    def test_authority_entries_need_both_did_and_key(self) -> None:
        mandate = {
            "principal": {"did": REGISTRY},
            "ratification_authorities": [{"did": "did:x:y", "public_key": "aa", "role": 7},
                                         {"did": "did:x:z"}, "junk"],
        }
        assert kernel.authorities(mandate) == [("did:x:y", "aa", "named_authority")]
        assert kernel.authorities({"ratification_authorities": {"did": "x"}}) == []

    def test_explicit_link_equals_the_implicit_one(self) -> None:
        given = ratify_input("26")
        explicit = kernel.ratify(*reproduce.ratify_arguments(given))
        given["prev_core_digest"] = None
        assert kernel.ratify(*reproduce.ratify_arguments(given)).core_digest == explicit.core_digest


class TestInputProfile:
    @pytest.mark.parametrize(
        "payload",
        [
            b'{"a": 1, "a": 2}',
            b'{"a": {"b": 1, "b": 1}}',
            b'{"a": 1.0}',
            b'{"a": 1e3}',
            b'{"a": NaN}',
            b'{"a": Infinity}',
            b'{"a": 9007199254740992}',
            b"\xef\xbb\xbf{}",
            b'{"a": "\\ud800"}',
            b"[1]",
            b"{",
            b"\xff",
            b'{"a": ' * 40 + b"1" + b"}" * 40,
        ],
    )
    def test_refused(self, payload: bytes) -> None:
        with pytest.raises(strict_json.InputError):
            strict_json.load_json(payload)

    def test_oversize_refused(self, tmp_path: Path) -> None:
        big = tmp_path / "big.json"
        big.write_bytes(b'{"a": "' + b"x" * strict_json.MAX_BYTES + b'"}')
        with pytest.raises(strict_json.InputError, match="byte budget"):
            strict_json.load_file(big)
        with pytest.raises(strict_json.InputError, match="byte budget"):
            strict_json.load_json(big.read_bytes())

    def test_accepted(self) -> None:
        assert strict_json.load_json(b'{"a": [1, "x", null, true, {"b": -9007199254740991}]}')


def package_copy(tmp_path: Path) -> Path:
    target = tmp_path / "package"
    shutil.copytree(HERE, target, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return target


class TestPins:
    def test_committed_pins_match_the_tree(self) -> None:
        document = pins.check_pins()
        assert (HERE / "INPUTS.json").read_text(encoding="ascii") == pins.render(pins.build())
        assert document["source"]["commit"] == "531f880155ea1ce993a7ca74137b12c255d5b2ee"

    def test_every_vector_is_pinned_to_its_upstream_path(self) -> None:
        entries = {item["path"]: item for item in pins.build()["files"]}
        for path in VECTOR_FILES:
            item = entries[f"fixtures/aae-v1.4.0/{path.name}"]
            assert item["source_path"] == f"vectors/enforce/{path.name}"

    def test_one_byte_change_is_refused(self, tmp_path: Path) -> None:
        root = package_copy(tmp_path)
        target = root / "fixtures" / "aae-v1.4.0" / VECTOR_FILES[0].name
        data = bytearray(target.read_bytes())
        data[-2] ^= 0x01
        target.write_bytes(bytes(data))
        with pytest.raises(strict_json.InputError, match="SHA-256 pin"):
            pins.check_pins(root)

    def test_unpinned_extra_file_is_refused(self, tmp_path: Path) -> None:
        root = package_copy(tmp_path)
        (root / "fixtures" / "extra.json").write_text("{}", encoding="ascii")
        with pytest.raises(strict_json.InputError, match="do not list"):
            pins.check_pins(root)

    def test_path_escape_is_refused(self, tmp_path: Path) -> None:
        root = package_copy(tmp_path)
        document = json.loads((root / "INPUTS.json").read_text(encoding="ascii"))
        document["files"][0]["path"] = "fixtures/../INPUTS.json"
        (root / "INPUTS.json").write_text(json.dumps(document), encoding="ascii")
        with pytest.raises(strict_json.InputError, match="outside the input tree"):
            pins.check_pins(root)
