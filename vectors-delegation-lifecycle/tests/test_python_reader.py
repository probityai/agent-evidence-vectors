"""The Python reader judges every case as the manifest declares, refuses what it
exists to refuse, and every rule it applies is load-bearing."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "packaging"))

import run_vectors  # noqa: E402, F401  (the reader borrows its Ed25519)
from agent_evidence_vectors import delegationlifecycle as reader  # noqa: E402


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mutate = _load("delegation_lifecycle_mutate", ROOT / "mutate.py")
VECTORS = json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]


def _copy(tmp_path: Path, case: str) -> Path:
    target = tmp_path / case
    shutil.copytree(ROOT / "cases" / case, target)
    return target


def _decide(case: Path) -> tuple[str, str]:
    return reader.decide_dir(case)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_reader_derives_the_declared_outcome(vector: dict[str, Any]) -> None:
    expected = vector["expected"]
    assert _decide(ROOT / vector["path"]) == (expected["decision"], expected["reason"])


def test_corpus_judges_clean_and_prints_the_lines_aee_verify_prints() -> None:
    judged = reader.judge(ROOT)
    assert judged.ok()
    assert len(judged.members) == len(VECTORS)
    lines = reader.render(judged).splitlines()
    assert lines[:2] == ["suite: delegation-lifecycle/v1", f"members: {len(VECTORS)}"]
    assert lines[-1] == "verdict: every member behaves as MANIFEST.json declares"
    assert [ln.split(":")[0].strip() for ln in lines[2:-1]] == ["accept", "no_verdict", "reject"]


def test_the_harness_routes_the_corpus_to_this_reader() -> None:
    run = subprocess.run(
        [sys.executable, str(ROOT.parent / "packaging" / "run_vectors.py"),
         "--vectors", str(ROOT)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout == reader.render(reader.judge(ROOT))


def test_a_named_verifier_is_refused_not_scored() -> None:
    run = subprocess.run(
        [sys.executable, str(ROOT.parent / "packaging" / "run_vectors.py"),
         "--vectors", str(ROOT), "--verifier", "true"], capture_output=True, text=True,
        check=False)
    assert run.returncode == 2
    assert "no external-verifier contract" in run.stdout + run.stderr


def test_an_accept_all_reader_fails_the_corpus(monkeypatch: pytest.MonkeyPatch) -> None:
    """The judging above is not vacuous: a reader that accepts everything is caught."""
    monkeypatch.setattr(reader, "decide_dir", lambda *_a, **_k: ("accept", "authority_valid"))
    judged = reader.judge(ROOT)
    assert not judged.ok()
    declared = [v for v in VECTORS if v["expected"] != {"decision": "accept",
                                                        "reason": "authority_valid"}]
    assert sorted(m[0] for m in judged.members if m[2]) == sorted(v["id"] for v in declared)


# ---- negative controls: one edit to a case, and the reason the reader gives ----


def test_a_flipped_grant_signature_is_refused_by_name(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-chain-valid")
    assert _decide(case) == ("accept", "authority_valid")
    mutate.flip_signature(case / "07-grant-g-worker.json")
    assert _decide(case) == ("reject", "signature_invalid:grant")


def test_a_flipped_presenter_signature_is_refused_by_name(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-chain-valid")
    mutate.flip_signature(case / "presentation.json", 0)
    assert _decide(case) == ("reject", "signature_invalid:presentation")


def test_a_dropped_grant_breaks_the_chain(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-chain-valid")
    mutate.drop_record(case, "06-grant-g-planner.json")
    assert _decide(case) == ("reject", "chain_broken")


def test_a_dropped_registration_leaves_the_presenter_unattested(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-chain-valid")
    mutate.drop_record(case, "03-registration-worker.json")
    assert _decide(case) == ("reject", "signature_invalid:presentation")


def test_a_dropped_revocation_lifts_the_refusal(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-parent-revoked-child-presented")
    assert _decide(case) == ("reject", "grant_revoked")
    revocation = next(n for n in json.loads((case / "case.json").read_text())["records"]
                      if "-revocation-" in n)
    mutate.drop_record(case, revocation)
    assert _decide(case) == ("accept", "authority_valid")


def test_a_revocation_moved_past_the_observation_stops_nothing(tmp_path: Path) -> None:
    """Signed again by its initiator, so the record is valid and only its time moved."""
    case = _copy(tmp_path, "tree-parent-revoked-child-presented")
    revocation = next(n for n in json.loads((case / "case.json").read_text())["records"]
                      if "-revocation-" in n)
    mutate.shift_time(case / revocation, "effective_at", timedelta(hours=24))
    assert _decide(case) == ("accept", "authority_valid")


def test_a_revocation_edited_without_a_new_signature_counts_as_absent(tmp_path: Path) -> None:
    """The README rule: a record whose signature does not verify counts as absent."""
    case = _copy(tmp_path, "tree-parent-revoked-child-presented")
    revocation = next(n for n in json.loads((case / "case.json").read_text())["records"]
                      if "-revocation-" in n)
    mutate.flip_signature(case / revocation)
    assert _decide(case) == ("accept", "authority_valid")


def test_an_observation_moved_before_the_revocation_is_accepted(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-parent-revoked-child-presented")
    mutate.shift_time(case / "presentation.json", "observed_at", -timedelta(hours=24))
    assert _decide(case) == ("accept", "authority_valid")


def test_a_record_that_is_not_json_gives_no_verdict(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-chain-valid")
    (case / "06-grant-g-planner.json").write_bytes(b"{")
    assert _decide(case) == ("no_verdict", "malformed_record")


def test_a_time_that_does_not_parse_gives_no_verdict(tmp_path: Path) -> None:
    case = _copy(tmp_path, "tree-chain-valid")
    mutate.rewrite(case / "06-grant-g-planner.json",
                   lambda payload: payload.__setitem__("issued_at", "yesterday"))
    assert _decide(case) == ("no_verdict", "malformed_record")


# ---- every rule is load-bearing ----


def test_every_rule_changes_some_case() -> None:
    """Switching a rule off moves at least one case off its declared outcome."""
    declared = {v["id"]: (v["expected"]["decision"], v["expected"]["reason"]) for v in VECTORS}
    unforced = []
    for rule in reader.RULES:
        skip = frozenset({rule})
        moved = [v["id"] for v in VECTORS
                 if reader.decide_dir(ROOT / v["path"], skip) != declared[v["id"]]]
        if not moved:
            unforced.append(rule)
    assert unforced == []


def test_the_rule_list_matches_the_go_reader() -> None:
    go = (ROOT.parent / "corpora" / "delegationlifecycle.go").read_text()
    block = go[go.index("var dlRules"):go.index("func (delegationLifecycle) Judge")]
    names = tuple(part.strip().strip('",') for part in block.split("{", 1)[1].split("}")[0]
                  .replace("\n", " ").split(",") if part.strip())
    assert names == reader.RULES


def test_a_non_canonical_r_is_refused_as_the_go_reader_refuses_it() -> None:
    """The stdlib check decodes R where Go compares its encoding. A point has one
    canonical encoding, so a signature whose R decodes only non-canonically must
    fail here as it fails in Go (the same bytes are pinned in the Go tests)."""
    fixture = json.loads((ROOT / "tests" / "noncanonical-r.json").read_text())
    key, message = bytes.fromhex(fixture["public_key"]), bytes.fromhex(fixture["message"])
    verdicts = {
        s["id"]: (run_vectors.ed25519_verify(key, message, bytes.fromhex(s["signature"])), s["valid"])
        for s in fixture["signatures"]
    }
    assert verdicts and any(valid for _, valid in verdicts.values())
    assert {k: got for k, (got, _) in verdicts.items()} == {k: v for k, (_, v) in verdicts.items()}
