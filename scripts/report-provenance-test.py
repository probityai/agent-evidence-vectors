#!/usr/bin/env python3
"""A conformance report names the corpus release and digest it ran.

Why this file exists
--------------------
Until this test existed a report said how a verifier scored and nothing about
which bytes it scored on. A reader holding two reports from two releases could
not tell them apart, and could not match either to the signed digest list a
release publishes. The report now carries a `corpus` block: the installed
release, the manifest's declared `corpusDigest`, and a sha256 of the manifest
bytes the run actually read.

Each case reads the fact it is about. The digest case compares the report
against `release/CORPUS-DIGESTS.txt`, the file the release signature covers,
for every corpus that file lists. The last case deletes the block in a copy of
the harness and requires this file to go red against the copy.

Usage: python3 scripts/report-provenance-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DIGEST_LIST = REPO_ROOT / "release" / "CORPUS-DIGESTS.txt"
SUMMARY = REPO_ROOT / "scripts" / "action-summary.py"
HARNESS = Path(os.environ.get("AEV_HARNESS_UNDER_TEST", REPO_ROOT / "packaging" / "run_vectors.py"))

MUTATION_ANCHOR = '        "corpus": corpus_provenance(suite_dir),\n'


def signed_lines() -> dict[str, str]:
    """Manifest path to declared digest, from the list a release signs."""
    out: dict[str, str] = {}
    for line in DIGEST_LIST.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        out[fields[1]] = fields[0]
    return out


def load_harness() -> ModuleType:
    sys.path.insert(0, str(REPO_ROOT / "packaging"))
    spec = importlib.util.spec_from_file_location("run_vectors_under_test", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_report(work: Path) -> dict[str, Any]:
    report = work / "report.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(HARNESS),
            "--vectors",
            str(REPO_ROOT / "vectors"),
            "--report",
            str(report),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not report.exists():
        raise AssertionError(f"harness exited {proc.returncode}: {proc.stderr[-400:]}")
    loaded: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
    return loaded


def case_report_names_signed_digest(work: Path) -> None:
    report = run_report(work)
    corpus = report.get("corpus")
    assert isinstance(corpus, dict), f"report has no corpus block: keys {sorted(report)}"
    want = signed_lines()["vectors/MANIFEST.json"]
    assert corpus.get("corpusDigest") == want, (
        f"corpusDigest {corpus.get('corpusDigest')} != signed {want}"
    )
    raw = (REPO_ROOT / "vectors" / "MANIFEST.json").read_bytes()
    assert corpus.get("manifestSha256") == hashlib.sha256(raw).hexdigest(), (
        "manifestSha256 is not the manifest's"
    )
    assert corpus.get("release") is None, (
        f"a checkout run claimed release {corpus.get('release')!r}"
    )


def case_every_signed_corpus_matches(work: Path) -> None:
    del work
    module = load_harness()
    lines = signed_lines()
    assert lines, "the signed digest list is empty, so this case would check nothing"
    for manifest_rel, digest in lines.items():
        suite = REPO_ROOT / Path(manifest_rel).parent
        got = module.corpus_provenance(str(suite))["corpusDigest"]
        assert got == digest, f"{manifest_rel}: report would say {got}, signed list says {digest}"


def case_installed_release_is_recorded(work: Path) -> None:
    del work
    module = load_harness()
    from importlib import metadata

    real_version = metadata.version
    module.__dict__["installed_layout"] = lambda: True

    def fake_version(distribution_name: str) -> str:
        if distribution_name == "agent-evidence-vectors":
            return "9.9.9"
        return real_version(distribution_name)

    metadata.version = fake_version
    try:
        got = module.corpus_provenance(str(REPO_ROOT / "vectors"))["release"]
    finally:
        metadata.version = real_version
    assert got == "9.9.9", f"installed layout recorded release {got!r}"


def case_unreadable_manifest_is_null_not_invented(work: Path) -> None:
    module = load_harness()
    got = module.corpus_provenance(str(work / "no-such-corpus"))
    assert got["corpusDigest"] is None and got["manifestSha256"] is None, got


def case_summary_shows_provenance(work: Path) -> None:
    report = run_report(work)
    summary = work / "summary.md"
    outputs = work / "outputs.txt"
    env = {
        **os.environ,
        "REPORT": str(work / "report.json"),
        "STATUS": "0",
        "CORPUS": "vectors",
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(outputs),
    }
    subprocess.run([sys.executable, str(SUMMARY)], env=env, check=True, capture_output=True)
    text = summary.read_text(encoding="utf-8")
    digest = report["corpus"]["corpusDigest"]
    assert digest in text, "the job summary does not show the corpus digest"
    assert "none (source checkout)" in text, "the job summary does not say the run had no release"


def case_mutation_goes_red(work: Path) -> None:
    """Without the block in the report, this file must fail."""
    if os.environ.get("AEV_HARNESS_UNDER_TEST"):
        return
    text = HARNESS.read_text(encoding="utf-8")
    assert MUTATION_ANCHOR in text, "mutation anchor moved; update this test"
    copy_dir = work / "packaging"
    shutil.copytree(REPO_ROOT / "packaging", copy_dir, ignore=shutil.ignore_patterns("__pycache__"))
    (copy_dir / "run_vectors.py").write_text(text.replace(MUTATION_ANCHOR, ""), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, __file__],
        env={**os.environ, "AEV_HARNESS_UNDER_TEST": str(copy_dir / "run_vectors.py")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, (
        "this test stayed green against a harness that writes no corpus block"
    )


CASES: list[Callable[[Path], None]] = [
    case_report_names_signed_digest,
    case_every_signed_corpus_matches,
    case_installed_release_is_recorded,
    case_unreadable_manifest_is_null_not_invented,
    case_summary_shows_provenance,
    case_mutation_goes_red,
]


def main() -> int:
    failed = 0
    for case in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                case(Path(tmp))
                print(f"ok   {case.__name__}")
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {case.__name__}: {exc}")
    print(f"{len(CASES) - failed}/{len(CASES)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
