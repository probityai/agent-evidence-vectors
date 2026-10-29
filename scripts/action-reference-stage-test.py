#!/usr/bin/env python3
"""The Action's default-on reference stage: its count, its wording and its pin.

Why this file exists
--------------------
action.yml runs a second stage after the candidate verifier: a pinned release of
the reference verifier (probity-verify) judges the corpus's members and the job
prints `reference-checked conformance N of M`, with `FULL-RELEASE` only when M is
above zero and N equals M. This file holds that logic and the wiring around it:
the stage cannot be switched off by an input or a condition, the reference is
installed by version and hash into a venv of its own, the package's metadata
names no dependency on it, and no public file names the company site.

The count cases run the stage's own functions with a stand-in cross-check. The
end-to-end cases run the script as the Action does, over the packaged done corpus
and over the default corpus, both routes the reference verifier covers, against
the real reference verifier, so they need the
`crosscheck` dependency group:

    uv run --group crosscheck python scripts/action-reference-stage-test.py

Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION = Path(os.environ.get("AEV_ACTION_UNDER_TEST", REPO_ROOT / "action.yml"))
LOCK = REPO_ROOT / "action-reference-requirements.txt"
STAGE = REPO_ROOT / "scripts" / "action-reference-stage.py"
INSTALL_STEP = "Install the reference verifier"
CHECK_STEP = "Check against the reference verifier"
RELEASE = "0.2.4"
WHEEL_SHA = "77bd7eaeebeef2d3bb881627a41e62991a416370930aa46f4d1d10612779e93b"
SDIST_SHA = "dc3d988886d4b1565e96560184c2f6679a729f4b77404d5987f92371841f514b"
FORBIDDEN_HOST = ".".join(["get" + "prob" + "ity", "dev"])


def load_stage() -> Any:
    spec = importlib.util.spec_from_file_location("aev_reference_stage", STAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def action_steps() -> list[dict[str, Any]]:
    loaded: dict[str, Any] = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    found: list[dict[str, Any]] = loaded["runs"]["steps"]
    return found


def step(name: str) -> dict[str, Any]:
    matches = [s for s in action_steps() if s.get("name") == name]
    assert len(matches) == 1, f"expected one {name!r} step, found {len(matches)}"
    return matches[0]


def fake_crosscheck(table: dict[str, Any]) -> Any:
    def compare(entry: dict[str, Any], member: Path) -> tuple[int, list[str]]:
        del member
        result = table[entry["id"]]
        if isinstance(result, Exception):
            raise result
        return result  # type: ignore[no-any-return]

    return SimpleNamespace(compare_member=compare, compare_contract=compare)


def routed(identifier: str) -> dict[str, Any]:
    return {"id": identifier, "path": identifier, "expected": {"checks": {}}}


def case_all_members_agree_is_a_full_release(work: Path) -> None:
    del work
    stage = load_stage()
    checked, total, notes = stage.tally(
        [routed("a"), routed("b")], Path("."), fake_crosscheck({"a": (2, []), "b": (1, [])})
    )
    assert (checked, total, notes) == (2, 2, [])
    assert stage.line(checked, total) == f"reference-checked conformance {checked} of {total}"
    assert stage.full_release(checked, total) is True


def case_one_disagreement_is_not_a_full_release(work: Path) -> None:
    del work
    stage = load_stage()
    table = {"a": (2, []), "b": (1, ["b: declared x, got y"])}
    cross = fake_crosscheck(table)
    checked, total, notes = stage.tally([routed("a"), routed("b")], Path("."), cross)
    assert (checked, total) == (1, 2)
    assert notes == ["b: declared x, got y"]
    assert stage.line(checked, total) == f"reference-checked conformance {checked} of {total}"
    assert stage.full_release(checked, total) is False


def case_a_member_with_no_reference_route_counts_in_m_only(work: Path) -> None:
    del work
    stage = load_stage()
    entries = [routed("a"), {"id": "u", "path": "u", "expected": {"verdict": "valid"}}]
    checked, total, _ = stage.tally(entries, Path("."), fake_crosscheck({"a": (1, [])}))
    assert (checked, total) == (1, 2)
    assert stage.full_release(checked, total) is False


def case_a_member_that_compared_nothing_is_not_checked(work: Path) -> None:
    del work
    stage = load_stage()
    checked, total, _ = stage.tally([routed("a")], Path("."), fake_crosscheck({"a": (0, [])}))
    assert (checked, total) == (0, 1)


def case_a_crash_is_one_unchecked_member_not_a_hidden_run(work: Path) -> None:
    del work
    stage = load_stage()
    table = {"a": RuntimeError("boom"), "b": (1, [])}
    cross = fake_crosscheck(table)
    checked, total, notes = stage.tally([routed("a"), routed("b")], Path("."), cross)
    assert (checked, total) == (1, 2)
    assert len(notes) == 1 and "could not run" in notes[0]


def case_an_empty_corpus_is_never_a_full_release(work: Path) -> None:
    del work
    assert load_stage().full_release(0, 0) is False


def case_stage_is_wired_after_the_replay_and_before_the_upload(work: Path) -> None:
    del work
    names = [s.get("name") for s in action_steps()]
    assert names.index("Replay the corpus") < names.index(INSTALL_STEP) < names.index(CHECK_STEP)
    assert names.index(CHECK_STEP) < names.index("Upload the report")


def case_stage_cannot_be_switched_off(work: Path) -> None:
    del work
    spec: dict[str, Any] = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    for name in spec["inputs"]:
        assert not re.search(r"reference|skip|disable|probity", name, re.I), (
            f"input {name!r} could switch the reference stage off"
        )
    for name in (INSTALL_STEP, CHECK_STEP):
        condition = str(step(name).get("if", "")).strip()
        assert condition == "${{ !cancelled() }}", (
            f"{name!r} is conditioned on {condition!r}, so it can be skipped"
        )
        assert "continue-on-error" not in step(name), f"{name!r} may fail without failing the job"


def case_reference_is_installed_by_hash_into_its_own_venv(work: Path) -> None:
    del work
    script = str(step(INSTALL_STEP)["run"])
    for flag in ("--require-hashes", "--only-binary :all:", "action-reference-requirements.txt"):
        assert flag in script, f"the reference install does not use {flag}"
    assert "-m venv" in script, "the reference verifier is not installed into a venv of its own"


def case_lock_pins_the_released_hashes(work: Path) -> None:
    del work
    text = LOCK.read_text(encoding="utf-8")
    block = re.search(r"^probity-verify==(\S+) \\\n((?:\s+--hash=sha256:\w+ ?\\?\n)+)", text, re.M)
    assert block is not None, "the lock does not pin probity-verify"
    assert block.group(1) == RELEASE, f"the lock pins probity-verify {block.group(1)}"
    hashes = set(re.findall(r"sha256:(\w+)", block.group(2)))
    assert hashes == {WHEEL_SHA, SDIST_SHA}, f"the lock's digests are {sorted(hashes)}"
    for entry in re.findall(r"^([A-Za-z0-9._-]+)==", text, re.M):
        assert re.search(rf"^{re.escape(entry)}==[^\n]*\\\n\s+--hash=sha256:", text, re.M), (
            f"{entry} is locked without a hash"
        )


def case_package_metadata_takes_no_dependency_on_the_product(work: Path) -> None:
    del work
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        declared.extend(extra)
    assert not [d for d in declared if "probity" in d.lower()], (
        f"package metadata names the product: {declared}"
    )


def case_no_public_file_names_the_company_site(work: Path) -> None:
    del work
    for path in (ACTION, STAGE, LOCK, Path(__file__)):
        assert FORBIDDEN_HOST not in path.read_text(encoding="utf-8"), f"{path} names the site"


_REFERENCE_PYTHON: list[str] = []


def reference_python() -> str:
    """A python with the locked reference verifier, installed as the Action installs it.

    The `crosscheck` group pins another probity-verify commit for the done-corpus
    readers, so the stage runs from a venv of its own built from the hashed lock.
    """
    if not _REFERENCE_PYTHON:
        venv = Path(tempfile.mkdtemp(prefix="aev-reference-venv-")) / "venv"
        subprocess.run(["uv", "venv", "--quiet", str(venv)], check=True)
        python = venv / "bin" / "python"
        subprocess.run(
            ["uv", "pip", "install", "--quiet", "--python", str(python), "--require-hashes",
             "--only-binary", ":all:", "-r", str(LOCK)],
            check=True,
        )
        _REFERENCE_PYTHON.append(str(python))
    return _REFERENCE_PYTHON[0]


def _run_stage(
    work: Path, corpus: str, total: int
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    report = work / "report.json"
    report.write_text(json.dumps({"totals": {"vectors": total}}), encoding="utf-8")
    env = {
        **os.environ,
        "REPORT": str(report),
        "CORPUS_DIR": str(REPO_ROOT / corpus),
        "GITHUB_STEP_SUMMARY": str(work / "summary.md"),
        "GITHUB_OUTPUT": str(work / "output.txt"),
    }
    proc = subprocess.run(
        [reference_python(), str(STAGE)], env=env, capture_output=True, text=True, check=False
    )
    return proc, json.loads(report.read_text(encoding="utf-8"))


def case_a_covered_corpus_is_reference_checked(work: Path) -> None:
    corpus = "vectors-done-receipt"
    total = len(json.loads((REPO_ROOT / corpus / "MANIFEST.json").read_text())["vectors"])
    proc, report = _run_stage(work, corpus, total)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    first = proc.stdout.splitlines()[0]
    match = re.fullmatch(r"reference-checked conformance (\d+) of (\d+)", first)
    assert match is not None, f"first line is {first!r}"
    checked, counted = int(match.group(1)), int(match.group(2))
    assert counted == total and checked > 0, first
    assert ("FULL-RELEASE" in proc.stdout.splitlines()) == (checked == counted)
    assert report["reference"]["checked"] == checked
    assert report["reference"]["total"] == counted
    assert report["reference"]["verifier"]["id"].startswith("https://")
    assert f"reference-checked={checked}" in (work / "output.txt").read_text()


def case_the_default_corpus_is_reference_checked_in_full(work: Path) -> None:
    manifest = json.loads((REPO_ROOT / "vectors" / "MANIFEST.json").read_text())
    total = len(manifest["vectors"])
    proc, report = _run_stage(work, "vectors", total)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0] == f"reference-checked conformance {total} of {total}", lines[:5]
    assert "FULL-RELEASE" in lines
    assert report["reference"]["fullRelease"] is True


def _default_corpus() -> tuple[list[dict[str, Any]], dict[str, int]]:
    manifest = json.loads((REPO_ROOT / "vectors" / "MANIFEST.json").read_text())
    return manifest["vectors"], manifest["counts"]


def case_dropping_a_member_kind_lowers_n(work: Path) -> None:
    """Each kind's route is load-bearing: without it, exactly that kind leaves N."""
    stage = load_stage()
    entries, counts = _default_corpus()
    full, total, _ = stage.aee_tally(entries, REPO_ROOT / "vectors")
    assert full == total
    every = stage.AEE_KINDS
    try:
        for kind in every:
            stage.AEE_KINDS = tuple(k for k in every if k != kind)
            checked, counted, _ = stage.aee_tally(entries, REPO_ROOT / "vectors")
            assert counted == total and checked == full - counts[kind], (kind, checked)
    finally:
        stage.AEE_KINDS = every


def case_the_expectation_comes_from_the_corpus(work: Path) -> None:
    """A member whose declared verdict is flipped stops counting: N reads the corpus."""
    stage = load_stage()
    entries, _ = _default_corpus()
    member = json.loads(json.dumps(next(e for e in entries if e["kind"] == "accept")))
    member["expected"]["verdict"] = "invalid"
    checked, total, notes = stage.aee_tally([member], REPO_ROOT / "vectors")
    assert (checked, total) == (0, 1) and notes, notes


def _mutation_goes_red(work: Path, anchor: str, replacement: str, reason: str) -> None:
    if os.environ.get("AEV_ACTION_UNDER_TEST"):
        return
    text = ACTION.read_text(encoding="utf-8")
    assert text.count(anchor) == 1, f"mutation anchor {anchor!r} moved; update this test"
    copy = work / "action.yml"
    copy.write_text(text.replace(anchor, replacement), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, __file__],
        env={**os.environ, "AEV_ACTION_UNDER_TEST": str(copy)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, f"this test stayed green with {replacement!r}"
    assert reason in proc.stdout, "mutation failed for a different reason"


def case_a_skippable_stage_goes_red(work: Path) -> None:
    """With the check step made conditional on an input, this file must fail."""
    head = "    - name: Check against the reference verifier\n      id: reference\n      if: "
    _mutation_goes_red(
        work,
        head + "${{ !cancelled() }}",
        head + "${{ inputs.verifier != '' }}",
        "so it can be skipped",
    )


def case_an_unhashed_reference_goes_red(work: Path) -> None:
    """With hash checking dropped from the reference install, this file must fail."""
    tail = ' --only-binary :all: \\\n          -r "$ACTION_PATH/action-reference-requirements.txt"'
    _mutation_goes_red(work, "--require-hashes" + tail, tail.lstrip(), "--require-hashes")


CASES: list[Callable[[Path], None]] = [
    case_all_members_agree_is_a_full_release,
    case_one_disagreement_is_not_a_full_release,
    case_a_member_with_no_reference_route_counts_in_m_only,
    case_a_member_that_compared_nothing_is_not_checked,
    case_a_crash_is_one_unchecked_member_not_a_hidden_run,
    case_an_empty_corpus_is_never_a_full_release,
    case_stage_is_wired_after_the_replay_and_before_the_upload,
    case_stage_cannot_be_switched_off,
    case_reference_is_installed_by_hash_into_its_own_venv,
    case_lock_pins_the_released_hashes,
    case_package_metadata_takes_no_dependency_on_the_product,
    case_no_public_file_names_the_company_site,
    case_a_covered_corpus_is_reference_checked,
    case_the_default_corpus_is_reference_checked_in_full,
    case_dropping_a_member_kind_lowers_n,
    case_the_expectation_comes_from_the_corpus,
    case_a_skippable_stage_goes_red,
    case_an_unhashed_reference_goes_red,
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
    if os.environ.get("AEV_REFERENCE_REEXEC") != "1":
        # Run every case, in-process ones included, under the locked reference verifier.
        python = reference_python()
        os.execve(python, [python, __file__], {**os.environ, "AEV_REFERENCE_REEXEC": "1"})
    raise SystemExit(main())
