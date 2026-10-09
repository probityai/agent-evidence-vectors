"""The vendored a2a-jcs-v01 corpus stays upstream's bytes and replays through the rail.

Each replay test reads what the harness did, not only its exit status: which
rail ran, how many vectors the named verifier answered, and which vectors failed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parent
ROOT = CORPUS.parent
RAIL = ROOT / "packaging" / "run_vectors.py"
NAME = "vectors-a2a-jcs-v01"
GOOD = [sys.executable, "-m", "agent_evidence_vectors.a2ajcs"]
BAD = [sys.executable, str(HERE / "bad_verifier.py")]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "packaging")}
ENV.pop("A2A_JCS_TARGET", None)
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import a2ajcs  # noqa: E402


def _load_upstream() -> ModuleType:
    """The lock tool, by path: its name is not unique across the repository."""
    spec = importlib.util.spec_from_file_location("a2a_jcs_upstream", CORPUS / "upstream.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upstream = _load_upstream()


def rail(
    *args: str, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(RAIL), *args],
        cwd=str(cwd),
        env=env or ENV,
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_lock_matches_the_vendored_bytes() -> None:
    assert upstream.check(CORPUS, None) == []


def _copy(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(CORPUS, root / NAME, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(
        ROOT / "packaging", root / "packaging", ignore=shutil.ignore_patterns("__pycache__")
    )
    shutil.copy(ROOT / "RUNS.md", root / "RUNS.md")
    return root / NAME


def test_a_changed_vector_byte_is_drift(tmp_path: Path) -> None:
    copy = _copy(tmp_path)
    target = copy / "a5-number-serialization" / "A5-001.json"
    target.write_bytes(target.read_bytes().replace(b"7d", b"7e", 1))
    assert any("A5-001.json differs" in f for f in upstream.check(copy, None))


def test_an_added_vector_is_drift(tmp_path: Path) -> None:
    copy = _copy(tmp_path)
    shutil.copy(
        copy / "a5-number-serialization" / "A5-001.json",
        copy / "a5-number-serialization" / "A5-099.json",
    )
    assert any("A5-099.json is in the vendored tree" in f for f in upstream.check(copy, None))


def test_a_lock_runs_md_disagrees_with_is_drift(tmp_path: Path) -> None:
    copy = _copy(tmp_path)
    runs = copy.parent / "RUNS.md"
    runs.write_text(runs.read_text().replace("29b3f2c5a9c2e6b07dc7", "00b3f2c5a9c2e6b07dc7"))
    assert any("RUNS.md pins" in f for f in upstream.check(copy, None))


def test_the_digest_is_upstreams() -> None:
    lock = json.loads((CORPUS / "source-lock.json").read_text())
    assert (
        lock["corpusDigest"] == "29b3f2c5a9c2e6b07dc7e925b13c81563e2efd407a62ce05df513fca04e9361c"
    )
    assert a2ajcs.corpus_digest((CORPUS / "MANIFEST.json").read_bytes()) == lock["corpusDigest"]


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (1e-06, "0.000001"),
        (1e-07, "1e-7"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (-0.0, "0"),
        (123.456, "123.456"),
        (5e-324, "5e-324"),
        (2**53, "9007199254740992"),
    ],
)
def test_numbers_serialize_as_ecmascript_does(value: float, text: str) -> None:
    assert a2ajcs.canonicalize(value) == text.encode()


def test_the_rail_lists_the_corpus(tmp_path: Path) -> None:
    out = rail("--list-corpora", cwd=tmp_path)
    assert out.returncode == 0
    assert NAME in out.stdout.split()


def test_without_a_verifier_the_packaged_reader_judges_both_targets(tmp_path: Path) -> None:
    out = rail("--corpus", NAME, cwd=tmp_path)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "target rfc8785: 53 of 53 pass" in out.stdout
    assert "target card-signing-input: 57 of 57 pass" in out.stdout


def _replay(tmp_path: Path, verifier: list[str], target: str | None = None) -> tuple[int, dict]:
    env = dict(ENV)
    if target is not None:
        env["A2A_JCS_TARGET"] = target
    report = tmp_path / "report.json"
    out = rail(
        "--corpus",
        NAME,
        "--verifier",
        " ".join(verifier),
        "--report",
        str(report),
        cwd=tmp_path,
        env=env,
    )
    return out.returncode, json.loads(report.read_text()) if report.exists() else {}


def test_a_conformant_verifier_passes_every_signing_input_vector(tmp_path: Path) -> None:
    code, report = _replay(tmp_path, GOOD)
    assert code == 0
    assert report["rail"] == "external"
    assert report["target"] == "card-signing-input"
    assert report["verifier"]["vectorsExecuted"] == report["totals"]["vectors"] == 57
    assert report["totals"]["conform"] == 57


def test_the_primitive_target_scores_the_53_vectors_it_owns(tmp_path: Path) -> None:
    code, report = _replay(tmp_path, GOOD, "rfc8785")
    assert code == 0
    assert report["verifier"]["vectorsExecuted"] == report["totals"]["vectors"] == 53


def test_a_wrong_canonicalizer_fails(tmp_path: Path) -> None:
    code, report = _replay(tmp_path, BAD)
    assert code == 1
    failed = {row["id"]: row["outcome"] for row in report["vectors"] if row["status"] == "FAIL"}
    assert failed["A5-001"] == "diverged"
    assert failed["A2-001"] == "diverged"
    assert failed["A2-REJECT-003"] == "accepted"
    assert report["verifier"]["vectorsExecuted"] == 57


def test_a_verifier_that_cannot_run_is_not_a_pass(tmp_path: Path) -> None:
    code, report = _replay(tmp_path, [str(tmp_path / "no-such-verifier")])
    assert code == 2
    assert report == {}


def test_an_unknown_target_is_refused(tmp_path: Path) -> None:
    code, report = _replay(tmp_path, GOOD, "jws")
    assert code == 2
    assert report == {}
