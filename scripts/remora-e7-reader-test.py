"""Challenge bounded E7 premises and the refusal behavior of package pinning."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.remora_e7.reader import (  # noqa: E402
    evaluate_case,
    load_object,
    run_package,
    verify_package,
)
from agent_evidence_vectors.remora_e7.run import main as run_main  # noqa: E402

UPSTREAM = PACKAGING / "agent_evidence_vectors/remora_e7/upstream"
FIXTURES = json.loads(
    (UPSTREAM / "artifacts/interop/runtime-surface-e7-v0.1/fixtures.json").read_text()
)


class TestReader:
    class TestPassingCases:
        @pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda case: case["id"])
        def test_native_fields(self, case: dict) -> None:
            actual = evaluate_case(case)
            assert {key: actual[key] for key in case["expected"]} == case["expected"]

        def test_complete_population_and_ceiling(self, caplog: pytest.LogCaptureFixture) -> None:
            with caplog.at_level("INFO"):
                report = run_package(UPSTREAM)
            assert len(report["results"]) == 5
            assert report["failures"] == []
            assert report["global_property"]["status"] == "NOT_ESTABLISHED"
            assert "Verified 5 package members" in caplog.text

        def test_expected_answers_do_not_drive_calculation(self) -> None:
            case = copy.deepcopy(FIXTURES["cases"][0])
            case["expected"] = {"claim_result": "CONTRADICTED"}
            assert evaluate_case(case)["claim_result"] == "ESTABLISHED"

        @pytest.mark.parametrize(
            "complete,result", [(True, "ESTABLISHED"), (False, "NOT_ESTABLISHED")]
        )
        def test_absent_effect_path_needs_complete_inventory(
            self, complete: bool, result: str
        ) -> None:
            case = {
                "id": "absence",
                "kind": "effect_path",
                "alternative_effect_paths": [],
                "path_inventory_complete": complete,
            }
            assert evaluate_case(case)["claim_result"] == result

    class TestFailingCases:
        @pytest.mark.parametrize(
            "key,value,reason",
            [
                ("runtime_identity", "different", "runtime_identity_mismatch"),
                ("complete", "true", "surface_incomplete"),
                ("complete", 1, "surface_incomplete"),
                ("observation_source", "cli", "observation_source_not_agent_runtime"),
                ("tools", None, "invalid_tool_inventory"),
                ("governed_tools", None, "invalid_governed_set"),
            ],
        )
        def test_unknown_premises(self, key: str, value: object, reason: str) -> None:
            case = copy.deepcopy(FIXTURES["cases"][0])
            case[key] = value
            result = evaluate_case(case)
            assert result["claim_result"] == "NOT_ESTABLISHED"
            assert reason in result["reasons"]

        def test_duplicate_tools(self) -> None:
            case = copy.deepcopy(FIXTURES["cases"][0])
            case["tools"] *= 2
            assert evaluate_case(case)["reasons"] == ["duplicate_tool_identity"]

        @pytest.mark.parametrize(
            "change,field",
            [
                ("missing", "missing_tools"),
                ("changed", "changed_definitions"),
            ],
        )
        def test_governed_disagreement(self, change: str, field: str) -> None:
            case = copy.deepcopy(FIXTURES["cases"][0])
            if change == "missing":
                case["tools"] = []
            else:
                case["tools"][0]["toolspec_hash"] = "different"
            result = evaluate_case(case)
            assert result["claim_result"] == "CONTRADICTED"
            assert result[field] == ["update_ticket"]

        @settings(max_examples=40)
        @given(
            name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=24).filter(
                lambda name: name != "update_ticket"
            )
        )
        def test_arbitrary_undeclared_callable_is_contradicted(self, name: str) -> None:
            case = copy.deepcopy(FIXTURES["cases"][0])
            injected = copy.deepcopy(case["tools"][0])
            injected["tool_id"] = name
            case["tools"].append(injected)
            result = evaluate_case(case)
            assert result["claim_result"] == "CONTRADICTED"
            assert result["unexpected_tools"] == [name]

        @pytest.mark.parametrize(
            "raw,message",
            [
                (b'{"a":1,"a":2}', "duplicate JSON member: a"),
                (b"[]", "expected a JSON object"),
            ],
        )
        def test_ambiguous_document(self, raw: bytes, message: str) -> None:
            with pytest.raises(ValueError, match=message):
                load_object(raw)

        def test_changed_fixture_bytes(self, tmp_path: Path) -> None:
            root = tmp_path / "upstream"
            shutil.copytree(UPSTREAM, root)
            p = root / "artifacts/interop/runtime-surface-e7-v0.1/fixtures.json"
            p.write_bytes(p.read_bytes() + b" ")
            with pytest.raises(ValueError, match="producer input digest mismatch: .*fixtures.json"):
                verify_package(root)

        def test_rehashed_substitution(self, tmp_path: Path) -> None:
            root = tmp_path / "upstream"
            shutil.copytree(UPSTREAM, root)
            p = root / "artifacts/interop/runtime-surface-e7-v0.1/manifest.json"
            manifest = json.loads(p.read_text())
            manifest["package_files"][0]["sha256"] = "0" * 64
            p.write_text(json.dumps(manifest))
            with pytest.raises(
                ValueError, match="producer package digest differs from the selected pin"
            ):
                verify_package(root)

        def test_reference_verifier_cannot_be_imported(self) -> None:
            source = """
import sys
from pathlib import Path
class RefuseProducer:
    def find_spec(self, fullname, path=None, target=None):
        top = fullname.split('.')[0].lower()
        if top.startswith('remora') or 'reference_verifier' in fullname:
            raise RuntimeError('producer import refused')
sys.meta_path.insert(0, RefuseProducer())
from agent_evidence_vectors.remora_e7.reader import run_package
assert not run_package(Path(sys.argv[1]))['failures']
"""
            result = subprocess.run(
                [sys.executable, "-c", source, str(UPSTREAM)],
                cwd=PACKAGING,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, result.stderr


class TestEntryPoint:
    def test_packaged_upstream_is_the_default(self, tmp_path: Path) -> None:
        out = tmp_path / "result"
        code = run_main(
            [
                "--output",
                str(out),
                "--reader-revision",
                "0" * 40,
                "--operator",
                "EXTERNAL",
                "--run-ref",
                "https://example.invalid/run",
            ]
        )
        assert code == 0
        record = json.loads((out / "external-run-record-v1.json").read_text())
        assert record["verifier"]["implementation_revision"] == "0" * 40
        assert len(record["results"]) == 5
        report = json.loads((out / "report.json").read_text())
        assert report["global_property"]["status"] == "NOT_ESTABLISHED"

    def test_short_revision_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            run_main(
                [
                    "--output",
                    str(tmp_path / "r"),
                    "--reader-revision",
                    "abc",
                    "--operator",
                    "AUTHOR",
                    "--run-ref",
                    "x",
                ]
            )

    def test_existing_output_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(FileExistsError):
            run_main(
                [
                    "--output",
                    str(tmp_path),
                    "--reader-revision",
                    "0" * 40,
                    "--operator",
                    "AUTHOR",
                    "--run-ref",
                    "x",
                ]
            )
