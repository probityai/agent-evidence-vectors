"""The manifest regenerates, the reader agrees with it from bytes alone, and each
mutation of a retained run turns the reader red."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
R2 = "source/j01-connected-20261028-r2"
R1 = "source/j01-connected-20261028-r1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("refund_connected_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import refundconnected as reader  # noqa: E402


@pytest.fixture()
def run(tmp_path: Path) -> Path:
    target = tmp_path / "run"
    shutil.copytree(ROOT / R2, target)
    return target


def _ok(root: Path) -> bool:
    return bool(reader.judge_run(root)["ok"])


def _edit(path: Path, old: bytes, new: bytes) -> None:
    data = path.read_bytes()
    assert old in data
    path.write_bytes(data.replace(old, new, 1))


def test_manifest_regenerates_byte_identically() -> None:
    committed = (ROOT / "MANIFEST.json").read_bytes()
    manifest = generator.generate(ROOT)
    assert (ROOT / "MANIFEST.json").read_bytes() == committed
    assert generator.corpus_digest(manifest, ROOT) == manifest["corpusDigest"]


def test_reader_agrees_with_every_manifest_entry() -> None:
    answered, errors = reader.check(ROOT)
    assert errors == []
    assert answered == len(json.loads((ROOT / "MANIFEST.json").read_text())["vectors"])


def test_r2_passes_and_r1_names_the_failed_steps() -> None:
    assert _ok(ROOT / R2)
    result = reader.judge_run(ROOT / R1)
    assert not result["ok"]
    assert result["cases"]["j01"]["execution"] == "NOT_ESTABLISHED:no-dispatch-attempt"


def test_the_source_run_has_one_effect_per_positive_case(run: Path) -> None:
    assert len((run / "executor/effects.jsonl").read_text().splitlines()) == 2


def test_one_proposal_byte_turns_it_red(run: Path) -> None:
    _edit(
        run / "cases/j01/inputs/pic-proposal.json", b'"amount_minor": 4000', b'"amount_minor": 4001'
    )
    assert not _ok(run)


def test_record_amount_turns_it_red(run: Path) -> None:
    _edit(run / "admission/state.json", b'"amount_minor":4000', b'"amount_minor":4001')
    assert not _ok(run)


def test_effect_bound_to_another_operation_turns_it_red(run: Path) -> None:
    path = run / "executor/effects.jsonl"
    first, second = path.read_text().splitlines()
    op_first = json.loads(first)["operation_id"]
    op_second = json.loads(second)["operation_id"]
    path.write_text(first.replace(op_first, op_second) + "\n" + second + "\n")
    assert not _ok(run)


def test_second_effect_for_a_key_turns_it_red(run: Path) -> None:
    path = run / "executor/effects.jsonl"
    first = path.read_text().splitlines()[0]
    with path.open("a") as handle:
        handle.write(first.replace('"eff-1"', '"eff-9"') + "\n")
    assert not _ok(run)


def test_a_resolution_presented_as_a_handoff_turns_it_red(run: Path) -> None:
    shutil.copyfile(run / "signer/n3.resolution.json", run / "signer/j01.handoff.json")
    assert not _ok(run)


def test_dropped_observation_turns_it_red(run: Path) -> None:
    path = run / "executor/observations.jsonl"
    path.write_text(
        path.read_text().splitlines()[0] + "\n"
        if False
        else "\n".join(path.read_text().splitlines()[:1]) + "\n"
    )
    assert not _ok(run)
