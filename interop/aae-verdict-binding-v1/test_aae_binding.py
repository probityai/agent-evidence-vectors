"""Kernel, vector, input-profile and pin checks for the AAE verdict-binding package."""

from __future__ import annotations

import base64
import copy
import json
import shutil
from pathlib import Path
from typing import Any

import bind
import check_report
import gen_cases
import kernel
import pins
import pytest
import reproduce
import run_binding
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


CASES = sorted(path for path in (HERE / "cases").iterdir() if path.is_dir())


def case_inputs(directory: Path) -> tuple[dict[str, Any], bytes | None, Any]:
    record = json.loads((directory / "verdict-record.json").read_text(encoding="ascii"))
    evidence = directory / "evidence.dsse.json"
    ratification = directory / "ratification.json"
    return (
        record,
        evidence.read_bytes() if evidence.exists() else None,
        json.loads(ratification.read_text(encoding="ascii")) if ratification.exists() else None,
    )


def permit_record() -> dict[str, Any]:
    return case_inputs(HERE / "cases" / "B1-valid-binding")[0]


def envelope_with(statement: dict[str, Any]) -> bytes:
    payload = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    return json.dumps({"payload": payload, "payloadType": "x", "signatures": []}).encode()


class TestBindingCases:
    def test_three_cases_and_four_controls(self) -> None:
        roles = [json.loads((path / "expected.json").read_text())["role"] for path in CASES]
        assert roles.count("case") == 3 and roles.count("control") == 4

    @pytest.mark.parametrize("directory", CASES, ids=lambda path: path.name)
    def test_case_produces_its_declared_outcome(self, directory: Path) -> None:
        declared = json.loads((directory / "expected.json").read_text(encoding="ascii"))
        produced = bind.claim_values(bind.bind(*case_inputs(directory)))
        assert produced == declared["expect"]

    def test_cases_regenerate_byte_for_byte(self, tmp_path: Path) -> None:
        gen_cases.write_cases(tmp_path, gen_cases.generator())
        written = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*.json"))
        committed = sorted(path.relative_to(HERE / "cases")
                           for path in (HERE / "cases").rglob("*.json"))
        assert written == committed
        for relative in written:
            assert (tmp_path / relative).read_bytes() == (HERE / "cases" / relative).read_bytes()

    def test_b1_evidence_cites_the_record_digest_of_vector_01(self) -> None:
        record = permit_record()
        assert record["core_digest"] == vector_named("01")["expected"]["core_digest"]
        result = bind.bind(record, case_inputs(HERE / "cases" / "B1-valid-binding")[1])
        assert result["binding"]["cited"] == bind.record_digest(record)
        assert result["binding"]["field"] == "predicate.authorityDigest"

    def test_valid_authorization_never_sets_execution(self) -> None:
        result = bind.bind(permit_record(), None)
        assert result["authorization"]["core_digest_recomputed"] is True
        assert result["authorization"]["verdict"] == kernel.PERMIT
        assert result["execution"]["status"] == "UNKNOWN"

    def test_missing_record_never_fails_authorization(self) -> None:
        for directory in CASES:
            record, evidence, ratification = case_inputs(directory)
            with_evidence = bind.bind(record, evidence, ratification)["authorization"]
            alone = bind.bind(record, None, ratification)["authorization"]
            assert with_evidence == alone

    def test_execution_is_never_reported_as_proven(self) -> None:
        statuses = {bind.bind(*case_inputs(path))["execution"]["status"] for path in CASES}
        assert statuses <= {"CLAIMED_BY_BOUND_RECORD", "UNKNOWN"}
        assert bind.execution(False, True, "valid")["status"] == "UNKNOWN"
        assert "no observed mutation" in bind.execution(False, True, "valid")["reason"]


class TestBindingRefusals:
    @pytest.mark.parametrize(
        "change",
        [
            lambda record: record.update(extra=1),
            lambda record: record.pop("core_digest"),
            lambda record: record["core"].pop("trace"),
            lambda record: record["core"].update(verdict="ALLOW"),
            lambda record: record["core"].update(grant_index=-1),
            lambda record: record["core"].update(grant_index=True),
            lambda record: record["core"].update(grant_index=0.0),
            lambda record: record.update(core_digest="sha256:" + "A" * 64),
            lambda record: record["core"].update(trace={}),
        ],
    )
    def test_malformed_verdict_record(self, change: Any) -> None:
        record = permit_record()
        change(record)
        with pytest.raises(strict_json.InputError):
            bind.bind(record, None)

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"payload": "!!"}',
            b'{"payload": 5}',
            b'{"payload": "e30=", "payload": "e30="}',
            envelope_with({"predicateType": "https://example.com/other", "predicate": {}}),
            envelope_with({"predicateType": bind.OBSERVED_EFFECT_TYPE,
                           "predicate": {"authorityDigest": "AB" * 32}}),
            envelope_with({"predicateType": bind.OBSERVED_EFFECT_TYPE, "predicate": []}),
        ],
    )
    def test_malformed_evidence(self, raw: bytes) -> None:
        with pytest.raises(strict_json.InputError):
            bind.bind(permit_record(), raw)

    def test_ratification_with_unpinned_key_is_refused(self) -> None:
        record, _evidence, request = case_inputs(HERE / "cases" / "C3-ratification-link-elsewhere")
        request["authority_proof"]["mandate"]["principal"]["public_key"] = "22" * 32
        with pytest.raises(strict_json.InputError, match="pin set"):
            bind.bind(record, None, request)

    def test_ratification_with_unknown_member_is_refused(self) -> None:
        record, _evidence, request = case_inputs(HERE / "cases" / "C3-ratification-link-elsewhere")
        request["note"] = "x"
        with pytest.raises(strict_json.InputError, match="only decision"):
            bind.bind(record, None, request)

    def test_valid_ratification_of_the_deny_record(self) -> None:
        record, _evidence, request = case_inputs(HERE / "cases" / "C3-ratification-link-elsewhere")
        request["prev_core_digest"] = None
        result = bind.bind(record, None, request)["authorization"]
        assert result["ratification"]["status"] == kernel.RATIFIED
        assert result["verdict"] == kernel.DENY


def input_root(tmp_path: Path) -> Path:
    root = tmp_path / "inputs"
    for name in ("fixtures", "cases"):
        shutil.copytree(HERE / name, root / name)
    shutil.copy2(HERE / "INPUTS.json", root / "INPUTS.json")
    return root


def repin(root: Path) -> None:
    (root / "INPUTS.json").write_text(pins.render(pins.build(root)), encoding="ascii")


def run(root: Path | None, output: Path) -> int:
    arguments = ["--output-dir", str(output)]
    if root is not None:
        arguments += ["--input-root", str(root)]
    return run_binding.main(arguments)


def rewrite_json(path: Path, change: Any) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    change(value)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class TestRunContract:
    def test_fresh_run_passes_and_the_report_checks(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output = tmp_path / "attempt"
        assert run(None, output) == 0
        line = capsys.readouterr().out.strip()
        assert line.startswith("aae-verdict-binding: 26/26 vectors reproduced, 7/7 cases")
        check_report.check_report(output / "report.json")
        report = json.loads((output / "report.json").read_text(encoding="ascii"))
        assert report["profile"] == run_binding.PROFILE
        assert "execution" in report["not_established"]

    def test_existing_output_directory_is_refused(self, tmp_path: Path) -> None:
        output = tmp_path / "attempt"
        output.mkdir()
        assert run(None, output) == 2
        assert list(output.iterdir()) == []

    def test_missing_parent_is_refused(self, tmp_path: Path) -> None:
        assert run(None, tmp_path / "absent" / "attempt") == 2

    def test_one_byte_change_in_a_pinned_input_exits_2(self, tmp_path: Path) -> None:
        root = input_root(tmp_path)
        target = root / "cases" / "B1-valid-binding" / "verdict-record.json"
        data = bytearray(target.read_bytes())
        data[data.index(b"PERMIT")] ^= 0x01
        target.write_bytes(bytes(data))
        output = tmp_path / "attempt"
        assert run(root, output) == 2
        assert not (output / "report.json").exists()

    def test_flipped_verdict_exits_1(self, tmp_path: Path) -> None:
        root = input_root(tmp_path)

        def flip(record: dict[str, Any]) -> None:
            record["core"]["verdict"] = kernel.DENY
            record["core_digest"] = kernel.tagged_digest(kernel.TAG_CORE, record["core"])

        rewrite_json(root / "cases" / "B1-valid-binding" / "verdict-record.json", flip)
        repin(root)
        output = tmp_path / "attempt"
        assert run(root, output) == 1
        report = json.loads((output / "report.json").read_text(encoding="ascii"))
        b1 = next(case for case in report["cases"] if case["name"] == "B1-valid-binding")
        assert b1["produced"]["authorization.verdict"] == kernel.DENY
        assert b1["produced"]["binding.status"] == "MISMATCH"
        assert b1["matches_declaration"] is False
        with pytest.raises(strict_json.InputError):
            check_report.check_report(output / "report.json")

    def test_changed_vector_expectation_exits_1(self, tmp_path: Path) -> None:
        root = input_root(tmp_path)
        target = root / "fixtures" / "aae-v1.4.0" / VECTOR_FILES[0].name
        rewrite_json(target, lambda vector: vector["expected"].update(grant_index=1))
        repin(root)
        output = tmp_path / "attempt"
        assert run(root, output) == 1
        report = json.loads((output / "report.json").read_text(encoding="ascii"))
        assert report["vectors_reproduced"] == 25

    @pytest.mark.parametrize(
        "payload",
        [b'{"core": 1, "core": 2}', b'{"core": {}, "core_digest": 1.5}', b"{", b"[]"],
    )
    def test_malformed_pinned_input_exits_2(self, tmp_path: Path, payload: bytes) -> None:
        root = input_root(tmp_path)
        (root / "cases" / "B3-missing-receipt" / "verdict-record.json").write_bytes(payload)
        repin(root)
        assert run(root, tmp_path / "attempt") == 2

    def test_unexpected_case_file_exits_2(self, tmp_path: Path) -> None:
        root = input_root(tmp_path)
        (root / "cases" / "B3-missing-receipt" / "notes.json").write_text("{}", encoding="ascii")
        repin(root)
        assert run(root, tmp_path / "attempt") == 2

    def test_declaration_missing_a_claim_exits_2(self, tmp_path: Path) -> None:
        root = input_root(tmp_path)
        rewrite_json(root / "cases" / "B3-missing-receipt" / "expected.json",
                     lambda document: document["expect"].pop("execution.status"))
        repin(root)
        assert run(root, tmp_path / "attempt") == 2

    def test_unpinned_trust_key_exits_2(self, tmp_path: Path) -> None:
        root = input_root(tmp_path)
        target = root / "fixtures" / "aae-v1.4.0" / VECTOR_FILES[21].name
        rewrite_json(target, lambda vector: vector["input"]["authority_proof"]["mandate"][
            "principal"].update(public_key="33" * 32))
        repin(root)
        assert run(root, tmp_path / "attempt") == 2

    def test_report_checker_refusals(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            check_report.check_report(tmp_path / "missing.json")
        output = tmp_path / "attempt"
        assert run(None, output) == 0
        for change in (
            lambda report: report.update(cases_as_declared=6),
            lambda report: report["code_sha256"].update({"kernel.py": "0" * 64}),
            lambda report: report["not_established"].pop(),
            lambda report: report.update(profile="other"),
        ):
            copy_path = tmp_path / "changed.json"
            report = json.loads((output / "report.json").read_text(encoding="ascii"))
            change(report)
            copy_path.write_text(json.dumps(report), encoding="ascii")
            with pytest.raises(strict_json.InputError):
                check_report.check_report(copy_path)
        (tmp_path / "float.json").write_text('{"a": 1.5}', encoding="ascii")
        with pytest.raises(strict_json.InputError):
            check_report.load_report(tmp_path / "float.json")


def mandates(vector: dict[str, Any]) -> list[Any]:
    given = vector["input"]
    if vector["kernel"] == "enforce_check":
        return [given.get("mandate")]
    proof = given.get("authority_proof")
    return [proof.get("mandate")] if isinstance(proof, dict) else []


class TestRecordedObservations:
    def test_no_vector_mandate_carries_actions(self) -> None:
        """Section 2.2 and 2.2.1 make mandate.actions REQUIRED; no v1.4.0 mandate has it."""
        seen = [mandate for path in VECTOR_FILES
                for mandate in mandates(json.loads(path.read_text(encoding="utf-8")))]
        assert len([m for m in seen if isinstance(m, dict)]) == 26
        assert not any(isinstance(m, dict) and "actions" in m for m in seen)

    def test_vector_traces_name_only_predicate_and_result_for_structure(self) -> None:
        """The digest covers field, value and bound that structural entries never state."""
        structural = {"mandate_present", "type_fields", "action_binding", "disposition"}
        for path in VECTOR_FILES:
            for entry in json.loads(path.read_text(encoding="utf-8"))["expected"].get("trace", []):
                if entry["predicate"] in structural:
                    assert set(entry) == {"predicate", "result"}
