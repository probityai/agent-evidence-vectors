"""Hostile original-bound installed gate tests, including actual SHA reselection."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tools.check_installed_boundary import IDENTITY, encode
from tools.check_lab import artifact_path, validate_register
from imported_commits import here

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "1bdfce81e3afff4ec1c18afdfe3c7d423b693198"


@pytest.fixture
def retained(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    """Copy original selected bytes; every tamper remains isolated."""
    register = json.loads((ROOT / "data/lab-register.json").read_bytes())
    record = next(record for record in register["records"] if record["id"] == IDENTITY)
    paths = [artifact["path"] for artifact in record["artifacts"]]
    paths.append("../experiments/model-boundary-cpu-2026-10-02/report.json")
    for path in paths:
        target = artifact_path(tmp_path, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact_path(ROOT, path), target)
    return {"protocolVersion": "0.1", "records": [record]}, tmp_path


def reselect(register: dict[str, Any], root: Path, field: str, document: Any) -> None:
    """Write an attacker-modified receipt and reselect its real new digest."""
    record = register["records"][0]
    reference = record[field]
    raw = encode(document)
    artifact_path(root, reference).write_bytes(raw)
    next(artifact for artifact in record["artifacts"] if artifact["path"] == reference)[
        "sha256"
    ] = hashlib.sha256(raw).hexdigest()


def refuse(
    register: dict[str, Any], root: Path, reason: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Assert both the exact bounded refusal and the general admission log."""
    with caplog.at_level(logging.ERROR, logger="atlas.lab_register"):
        with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
            validate_register(register, root)
    assert caplog.messages == ["lab register refused: " + reason]


class TestInstalledBoundary:
    class TestPassingCases:
        def test_original_installed_gate_preserves_all_rows_pairs_and_resources(
            self, retained: tuple[dict[str, Any], Path]
        ) -> None:
            register, root = retained
            validate_register(register, root)
            report = json.loads(
                artifact_path(root, register["records"][0]["report"]).read_bytes()
            )
            rows = report["native"]["quality"]
            assert len(rows) == 24 and len(report["native"]["attempts"]) == 384
            assert (
                sum(row["schemaValid"] for row in rows if row["decoder"] == "schema")
                == 192
            )
            quality = report["upgrade"]["candidate-boundary-quality"]["gate"]
            assert quality["evidenceDecision"] == "verified"
            assert quality["publicationDecision"] == "hold-selected-score-or-resource"
            assert len(quality["policyFailures"]) == 16
            assert (
                len(
                    {
                        tuple(
                            row["row"][key]
                            for key in ("model", "configuration", "decoder", "family")
                        )
                        for row in quality["policyFailures"]
                    }
                )
                == 8
            )
            assert (
                quality["resources"]
                == report["upgrade"]["candidate-boundary"]["gate"]["resources"]
            )

        def test_all_sixteen_earlier_literal_records_and_artifact_bytes_preserved(
            self,
        ) -> None:
            before = subprocess.check_output(
                ["git", "show", here(BASELINE) + ":./data/lab-register.json"], cwd=ROOT
            )
            after = (ROOT / "data/lab-register.json").read_bytes()
            ending = b"\n  ]\n}\n"
            assert before.endswith(ending)
            assert after.startswith(before[: -len(ending)] + b",\n")
            previous = json.loads(before)["records"]
            assert len(previous) == 16 and json.loads(after)["records"][:16] == previous
            for record in previous:
                for artifact in record["artifacts"]:
                    path = artifact_path(ROOT, artifact["path"])
                    original = subprocess.check_output(
                        [
                            "git",
                            "show",
                            here(BASELINE) + ":./" + path.relative_to(ROOT).as_posix(),
                        ],
                        cwd=ROOT,
                    )
                    assert path.read_bytes() == original

    class TestFailingCases:
        @pytest.mark.parametrize("index", range(24))
        def test_every_original_semantic_row_cannot_be_promoted_or_demoted(
            self,
            index: int,
            retained: tuple[dict[str, Any], Path],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            register, root = retained
            claim = next(
                claim
                for claim in register["records"][0]["claimResults"]
                if claim.get("recordedField") == f"/native/quality/{index}"
            )
            claim["result"] = "fail" if claim["result"] == "pass" else "pass"
            refuse(
                register,
                root,
                "installed boundary measurement cannot promote quality action adoption or custody",
                caplog,
            )

        @pytest.mark.parametrize("index", [0, 1, 8, 15])
        def test_selected_case_and_pair_failures_cannot_borrow_schema_success(
            self,
            index: int,
            retained: tuple[dict[str, Any], Path],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            register, root = retained
            pointer = f"/upgrade/candidate-boundary-quality/gate/policyFailures/{index}"
            claim = next(
                claim
                for claim in register["records"][0]["claimResults"]
                if claim.get("recordedField") == pointer
            )
            claim["result"] = "pass"
            refuse(
                register,
                root,
                "installed boundary measurement cannot promote quality action adoption or custody",
                caplog,
            )

        @pytest.mark.parametrize(
            "name",
            [
                "external-host-recurring-adoption",
                "independent-effect-custody",
                "model-action-acceptance",
                "new-model-inference",
                "general-benchmark-performance",
            ],
        )
        def test_unexercised_claims_cannot_bind_truthful_publication_fields(
            self,
            name: str,
            retained: tuple[dict[str, Any], Path],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            register, root = retained
            record = register["records"][0]
            value = json.loads(artifact_path(root, record["report"]).read_bytes())[
                "native"
            ]["evidence"]["complete"]
            claim = next(
                claim for claim in record["claimResults"] if claim["claim"] == name
            )
            claim.update(
                result="pass",
                recordedField="/native/evidence/complete",
                expectedValue=value,
            )
            refuse(
                register,
                root,
                "installed boundary measurement cannot promote quality action adoption or custody",
                caplog,
            )

        @pytest.mark.parametrize(
            "mutation,reason",
            [
                ("source", "installed boundary reviewed source binding changed"),
                ("review", "installed boundary original provenance binding changed"),
                ("rerun", "installed boundary retention cannot invent inference"),
                ("custody", "installed boundary full original custody changed"),
                ("inventory", "installed boundary complete original inventory changed"),
                ("hidden-omission", "installed boundary omission disposition changed"),
                (
                    "omission-disclosure",
                    "installed boundary omission disclosure changed",
                ),
                (
                    "native-binding",
                    "installed boundary native original binding changed",
                ),
                (
                    "repository",
                    "installed boundary original provenance binding changed",
                ),
                (
                    "full-public",
                    "installed boundary original provenance binding changed",
                ),
                (
                    "native-boolean",
                    "installed boundary native original binding changed",
                ),
            ],
        )
        def test_reselected_provenance_still_refuses_source_custody_and_omission_attacks(
            self,
            mutation: str,
            reason: str,
            retained: tuple[dict[str, Any], Path],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            register, root = retained
            record = register["records"][0]
            provenance = json.loads(
                artifact_path(root, record["provenance"]).read_bytes()
            )
            omitted = next(
                member for member in provenance["members"] if not member["selected"]
            )
            changed = provenance["members"][-1]
            mutations = {
                "source": [
                    (record, "sourceRevision", "0" * 40),
                    (record, "readerRevision", "0" * 40),
                    (provenance, "sourceCommit", "0" * 40),
                    (provenance, "readerCommit", "0" * 40),
                ],
                "review": [(provenance, "reviewedHead", "0" * 40)],
                "rerun": [(provenance, "newInferenceExecuted", True)],
                "custody": [
                    (
                        provenance["fullOriginalRetention"],
                        "independentCustody",
                        "established",
                    )
                ],
                "inventory": [(changed, "bytes", changed["bytes"] + 1)],
                "hidden-omission": [(omitted, "selected", True)],
                "omission-disclosure": [(omitted, "reason", "complete public bytes")],
                "native-binding": [
                    (provenance["nativeOriginal"], "reportSha256", "0" * 64)
                ],
                "repository": [(provenance, "sourceRepository", "outside/reader")],
                "full-public": [
                    (
                        provenance,
                        "retention",
                        "complete-public-original-without-omissions",
                    )
                ],
                "native-boolean": [
                    (
                        provenance["nativeOriginal"],
                        "all871ProviderBoundaryPacketMembersEqualOriginal",
                        1,
                    )
                ],
            }
            for target, key, value in mutations[mutation]:
                target[key] = value
            reselect(register, root, "provenance", provenance)
            refuse(register, root, reason, caplog)

        @pytest.mark.parametrize(
            "field",
            [
                "quality-decision",
                "quality-failures",
                "pair-count",
                "case-correct",
                "resource",
            ],
        )
        def test_reselected_report_cannot_replace_original_policy_semantics(
            self,
            field: str,
            retained: tuple[dict[str, Any], Path],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            register, root = retained
            record = register["records"][0]
            report = json.loads(artifact_path(root, record["report"]).read_bytes())
            gate = report["upgrade"]["candidate-boundary-quality"]["gate"]
            if field == "quality-decision":
                gate["publicationDecision"] = "publish"
            elif field == "quality-failures":
                gate["policyFailures"] = []
            elif field == "pair-count":
                report["native"]["quality"][4]["fullyCorrectPairs"] = 8
            elif field == "case-correct":
                report["native"]["quality"][4]["correct"] = 16
            else:
                report["native"]["quality"][4]["resourceScope"] = (
                    "per-task allocated RAM"
                )
            from tools.check_installed_boundary import claim_results

            record["claimResults"] = claim_results(report)
            reselect(register, root, "report", report)
            refuse(
                register,
                root,
                "installed boundary report differs from original CI values",
                caplog,
            )

        @given(st.integers(min_value=0, max_value=23))
        @settings(deadline=None)
        def test_missing_row_claim_is_not_a_complete_population(
            self, index: int
        ) -> None:
            register = json.loads((ROOT / "data/lab-register.json").read_bytes())
            record = copy.deepcopy(
                next(row for row in register["records"] if row["id"] == IDENTITY)
            )
            record["claimResults"] = [
                claim
                for claim in record["claimResults"]
                if claim.get("recordedField") != f"/native/quality/{index}"
            ]
            with pytest.raises(
                ValueError,
                match="^installed boundary measurement cannot promote quality action adoption or custody$",
            ):
                validate_register({"protocolVersion": "0.1", "records": [record]}, ROOT)
