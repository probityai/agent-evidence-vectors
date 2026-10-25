"""The corpus regenerates, forces every check in order, and refuses a verifier that
compares anything other than the shown and executed bytes under RFC 8785."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-observer/contract/"
               "converted-argument-binding/v1")


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("converted_argument_corpus", ROOT / "check_vectors.py")
generator = _load("converted_argument_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import convertedargs  # noqa: E402

CHECKS = convertedargs.CHECKS
DENIED = {name: reason for name, _, decision, reason, _ in generator.cases()
          if decision == "deny"}
ALLOWED = [name for name, _, decision, _, _ in generator.cases() if decision == "allow"]


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import convertedargs as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _case(name: str) -> convertedargs.Case:
    return convertedargs.Case(ROOT / "cases" / name / "record.json")


def _first(case: convertedargs.Case, skip: frozenset[str] = frozenset()) -> str | None:
    return convertedargs._first_failure(case, skip)


class TestConvertedArgumentBindingCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_every_record_but_the_contract_cases_carries_the_contract_id(self) -> None:
            records = {p.parent.name: json.loads(p.read_text(encoding="utf-8"))
                       for p in (ROOT / "cases").glob("*/record.json")}
            assert "contractId" not in records["contract-id-missing"]
            assert records["contract-id-unknown"]["contractId"] != CONTRACT_ID
            others = {k: v for k, v in records.items()
                      if k not in {"contract-id-missing", "contract-id-unknown"}}
            assert others and all(r["contractId"] == CONTRACT_ID for r in others.values())
            assert convertedargs.CONTRACT_ID == CONTRACT_ID

        def test_both_verdicts_are_present(self) -> None:
            assert ALLOWED and DENIED

        def test_key_order_alone_does_not_separate_shown_from_executed(self) -> None:
            case = _case("executed-key-order-only")
            assert case.files["shown.json"] != case.files["executed.json"]
            assert convertedargs.shown_equals_executed(case)

        def test_every_shown_executed_denial_differs_in_a_member_not_in_order(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
            differing = {e["id"] for e in manifest["vectors"]
                         if not e["shownEqualsExecuted"] and e["expected"]["decision"] == "deny"}
            assert {n for n, r in DENIED.items() if r == "shown_not_executed"} <= differing

    class TestFailingCases:
        @pytest.mark.parametrize("name", sorted(DENIED))
        def test_each_denied_case_fails_exactly_its_named_check(self, name: str) -> None:
            case, reason = _case(name), DENIED[name]
            assert _first(case) == reason
            # Switching off the named check and every later one leaves only the
            # earlier checks, and the case passes all of them.
            assert _first(case, frozenset(CHECKS[CHECKS.index(reason):])) is None

        @pytest.mark.parametrize("name", sorted(DENIED))
        def test_switching_off_the_named_check_moves_the_verdict(self, name: str) -> None:
            assert _first(_case(name), frozenset({DENIED[name]})) != DENIED[name]

        @pytest.mark.parametrize("name", CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_compares_only_the_shown_digest_is_refused(self) -> None:
            skip = frozenset(CHECKS) - {"approval_not_bound_to_shown"}
            _, errors = corpus.check(skip=skip)
            assert _failed(errors) == {n for n, r in DENIED.items()
                                       if r != "approval_not_bound_to_shown"}

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "shown_not_executed"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert set(ALLOWED) <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "cases" / "allow-unchanged" / "executed.json"
            path.write_bytes(path.read_bytes() + b" ")
            _, errors = corpus.check(root=copied)
            assert "allow-unchanged: fixture digest mismatch" in errors

    class TestStorableBytes:
        @pytest.mark.parametrize("text", [
            b'{"a": 1, "a": 2}', b'{"a": NaN}', b'{"a": Infinity}', b'{"a": "\\ud800"}',
            b'{"a": 9007199254740993}', b'{"a": [1, {"b": -9007199254740992}]}',
            b'\xff', b'{"a": 1e999}'])
        def test_bytes_that_are_not_ijson_are_refused(self, text: bytes) -> None:
            with pytest.raises(ValueError):
                convertedargs.parse_ijson(text)
            assert convertedargs.canonical(text) is None

        def test_the_largest_safe_integer_is_storable(self) -> None:
            assert convertedargs.canonical(b'{"a": 9007199254740991}') is not None

        def test_canonical_form_orders_members_and_drops_whitespace(self) -> None:
            assert convertedargs.canonical(b'{ "b": 1.0, "a": [true] }') == b'{"a":[true],"b":1}'

    class TestDeclaredTypes:
        @pytest.mark.parametrize(("kind", "value", "holds"), [
            ("boolean", True, True), ("boolean", "true", False),
            ("integer", 1, True), ("integer", 1.5, False), ("integer", True, False),
            ("number", 1.5, True), ("number", True, False), ("number", "1", False),
            ("string", "x", True), ("string", 1, False),
            ("object", {}, True), ("object", "{}", False), ("array", [], False)])
        def test_type_check(self, kind: str, value: object, holds: bool) -> None:
            assert convertedargs._type_holds(kind, value) is holds

        def test_an_undeclared_member_makes_the_call_invalid(self) -> None:
            case = _case("allow-unchanged")
            case.files["raw.json"] = b'{"recipient": "x", "surprise": 1}'
            assert convertedargs._invalid_call(case)

        def test_a_replacement_that_adds_an_undeclared_member_is_not_a_full_call(self) -> None:
            case = _case("allow-modify-full-call")
            case.files["modified.json"] = b'{"dry_run": true, "extra": 1, "recipient": "x"}'
            assert convertedargs._not_full_call(case)

        def test_a_missing_replacement_is_not_a_full_call(self) -> None:
            case = _case("allow-modify-full-call")
            case.files["modified.json"] = None
            assert convertedargs._not_full_call(case)
