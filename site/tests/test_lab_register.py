"""Hostile checks for retained-byte integrity and measured lab claim bindings."""

from __future__ import annotations

import copy
import importlib.util
import json
import logging
import shutil
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, strategies as st

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("atlas_check_lab", ROOT / "tools" / "check_lab.py")
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


@pytest.fixture
def retained_register(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    """Copy all actual register artifacts so attacks cannot alter retained originals."""
    register = json.loads((ROOT / "data/lab-register.json").read_text(encoding="utf-8"))
    for artifact in (item for record in register["records"] for item in record["artifacts"]):
        source = CHECK.artifact_path(ROOT, artifact["path"])
        target = CHECK.artifact_path(tmp_path, artifact["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return register, tmp_path


def expect_refusal(register: dict[str, Any], root: Path, reason: str,
                   caplog: pytest.LogCaptureFixture) -> None:
    """Require the exact validation exception and its bounded logged reason."""
    with caplog.at_level(logging.ERROR, logger="atlas.lab_register"):
        with pytest.raises(ValueError, match=f"^{reason}$"):
            CHECK.validate_register(register, root)
    assert caplog.messages == [f"lab register refused: {reason}"]


class TestValidateRegister:
    class TestPassingCases:
        def test_actual_retained_record_passes(self, retained_register: tuple[dict[str, Any], Path]) -> None:
            register, root = retained_register
            CHECK.validate_register(register, root)
            assert register["records"][0]["roles"]["independentOperation"] == "not-established"

        def test_complete_coverage_binding_passes(self, retained_register: tuple[dict[str, Any], Path]) -> None:
            register, root = retained_register
            record = register["records"][0]
            report = json.loads(CHECK.artifact_path(root, record["report"]).read_text(encoding="utf-8"))
            claim = record["claimResults"][0]
            claim["recordedField"] = "/outcomes/coverage"
            claim["expectedValue"] = copy.deepcopy(report["outcomes"]["coverage"])
            CHECK.validate_register(register, root)

    class TestFailingCases:
        @pytest.mark.parametrize("provenance", [None, "", "../unretained.json", []])
        def test_provenance_must_name_a_retained_artifact(
                self, retained_register: tuple[dict[str, Any], Path],
                provenance: Any, caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            register["records"][0]["provenance"] = provenance
            expect_refusal(register, root, "record provenance is not a retained artifact", caplog)

        def test_missing_provenance_is_refused(
                self, retained_register: tuple[dict[str, Any], Path],
                caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            del register["records"][0]["provenance"]
            expect_refusal(register, root, "record provenance is not a retained artifact", caplog)

        @pytest.mark.parametrize("roles", [None, {}, [], {"runner": ""},
                                           {"": "author"}, {"runner": None},
                                           {"runner": "  "}, {"  ": "author"}])
        def test_roles_must_have_nonempty_names_and_declarations(
                self, retained_register: tuple[dict[str, Any], Path],
                roles: Any, caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            register["records"][0]["roles"] = roles
            expect_refusal(register, root, "record roles are invalid", caplog)

        def test_missing_roles_is_refused(
                self, retained_register: tuple[dict[str, Any], Path],
                caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            del register["records"][0]["roles"]
            expect_refusal(register, root, "record roles are invalid", caplog)

        @pytest.mark.parametrize("mutation", ["change", "remove"])
        def test_artifact_mutation_refused(self, retained_register: tuple[dict[str, Any], Path],
                                         mutation: str, caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            artifact = register["records"][0]["artifacts"][0]
            target = CHECK.artifact_path(root, artifact["path"])
            if mutation == "change":
                target.write_bytes(target.read_bytes() + b"\n")
                reason = "retained artifact differs from its SHA-256"
            else:
                target.unlink()
                reason = "retained artifact is missing"
            expect_refusal(register, root, reason, caplog)

        @pytest.mark.parametrize("digest", ["0" * 64, "A" * 64, "sha256:" + "0" * 64, "", None])
        def test_wrong_digest_refused(self, retained_register: tuple[dict[str, Any], Path],
                                    digest: Any, caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            register["records"][0]["artifacts"][0]["sha256"] = digest
            reason = "retained artifact differs from its SHA-256" if digest == "0" * 64 else "artifact SHA-256 is invalid"
            expect_refusal(register, root, reason, caplog)

        @pytest.mark.parametrize("pointer,reason", [
            ("outcomes/admissionStatus", "claim pointer is invalid"),
            ("/outcomes/~2invalid", "claim pointer is invalid"),
            ("/outcomes/absent", "claim pointer does not name a retained field"),
            ("/outcomes/admissionStatus/child", "claim pointer does not name a retained field"),
        ])
        def test_invalid_pointer_refused(self, retained_register: tuple[dict[str, Any], Path],
                                        pointer: str, reason: str,
                                        caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            register["records"][0]["claimResults"][0]["recordedField"] = pointer
            expect_refusal(register, root, reason, caplog)

        @pytest.mark.parametrize("expected", ["admitted", False, 1, None, {"status": "pass"}])
        def test_untrue_pass_refused(self, retained_register: tuple[dict[str, Any], Path],
                                   expected: Any, caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            register["records"][0]["claimResults"][0]["expectedValue"] = expected
            expect_refusal(register, root, "measured claim differs from the retained report", caplog)

        @pytest.mark.parametrize("pointer", ["/outcomes/coverage", "/outcomes"])
        def test_nested_boolean_integer_substitution_refused(
                self, retained_register: tuple[dict[str, Any], Path], pointer: str,
                caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            record = register["records"][0]
            report = json.loads(CHECK.artifact_path(root, record["report"]).read_text(encoding="utf-8"))
            claim = record["claimResults"][0]
            claim["recordedField"] = pointer
            expected = copy.deepcopy(CHECK.pointer_value(report, pointer))
            coverage = expected if pointer == "/outcomes/coverage" else expected["coverage"]
            assert coverage["noDetectedGap"] is True
            coverage["noDetectedGap"] = 1
            claim["expectedValue"] = expected
            expect_refusal(register, root, "measured claim differs from the retained report", caplog)

        @pytest.mark.parametrize("field", ["recordedField", "expectedValue"])
        def test_pass_without_binding_refused(self, retained_register: tuple[dict[str, Any], Path],
                                             field: str, caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            del register["records"][0]["claimResults"][0][field]
            expect_refusal(register, root, "measured claim has no retained-field binding", caplog)

        def test_unmeasured_custody_cannot_carry_a_pass_binding(self, retained_register: tuple[dict[str, Any], Path],
                                                              caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            claim = register["records"][0]["claimResults"][4]
            claim["recordedField"] = "/outcomes/admissionStatus"
            expect_refusal(register, root, "unmeasured claim carries a measured binding", caplog)

        @pytest.mark.parametrize("reference,reason", [
            ("/tmp/foreign-report.json", "artifact reference must be a relative local path"),
            ("../../foreign-report.json", "artifact reference escapes the repository"),
        ])
        def test_path_escape_refused(self, retained_register: tuple[dict[str, Any], Path],
                                    reference: str, reason: str,
                                    caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            register["records"][0]["artifacts"][0]["path"] = reference
            expect_refusal(register, root, reason, caplog)

        @pytest.mark.parametrize("kind,reason", [
            ("record", "register repeats a record id"),
            ("artifact", "record repeats an artifact reference"),
            ("claim", "record repeats a claim"),
        ])
        def test_duplicate_identity_refused(self, retained_register: tuple[dict[str, Any], Path],
                                           kind: str, reason: str,
                                           caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            record = register["records"][0]
            if kind == "record":
                register["records"].append(copy.deepcopy(record))
            elif kind == "artifact":
                record["artifacts"].append(copy.deepcopy(record["artifacts"][0]))
            else:
                record["claimResults"].append(copy.deepcopy(record["claimResults"][0]))
            expect_refusal(register, root, reason, caplog)


class TestPointerValue:
    class TestPassingCases:
        @given(key=st.text(max_size=80), value=st.one_of(st.none(), st.booleans(), st.integers(), st.text()))
        def test_escaped_member_round_trip(self, key: str, value: Any) -> None:
            pointer = "/" + key.replace("~", "~0").replace("/", "~1")
            assert CHECK.pointer_value({key: value}, pointer) == value

        @pytest.mark.parametrize("index", [0, 1, 2])
        def test_array_indices(self, index: int) -> None:
            assert CHECK.pointer_value({"array": ["first", "second", "third"]}, f"/array/{index}") == ["first", "second", "third"][index]

    class TestFailingCases:
        @pytest.mark.parametrize("index", ["-1", "01", "-", "3"])
        def test_invalid_array_index(self, retained_register: tuple[dict[str, Any], Path],
                                     index: str, caplog: pytest.LogCaptureFixture) -> None:
            register, root = retained_register
            register["records"][0]["claimResults"][0]["recordedField"] = f"/outcomes/coverage/knownGaps/{index}"
            reason = "claim pointer does not name a retained field" if index == "3" else "claim pointer array index is invalid"
            expect_refusal(register, root, reason, caplog)
