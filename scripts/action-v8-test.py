#!/usr/bin/env python3
"""The action's declared profile, case counts, null controls, conformance mode,
python -S reference path, evaluation-claim producer class and mutation stage.

Why this file exists
--------------------
Each input closes a way a green run could say less than it looked: a failure
outside the profile a verifier declares (``profile``), a corpus a runner found
empty (``fail-on-no-vectors``), a listed case that went missing
(``fail-on-missing-case``), a corpus a constant answer passes (the null
controls), a project's own cases held to their own expected file (conformance
mode, ``python -S``, nothing installed), a claim record judged under a rule its
producer did not choose (``record-class: evaluation-claim``), and a mutant that
two verifiers judged differently or both accepted (``mutate``). Every case runs
the script the action runs. Three cases end by deleting a guard in a copy of
the script and requiring the case it protects to go red.

Usage: uv run --group crosscheck python scripts/action-v8-test.py
(the mutation cases need agent-evidence-verify; the rest need only the stdlib
and PyYAML). Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
FIXTURES = SCRIPTS / "fixtures" / "action-v8"
A2A = ROOT / "corpora" / "vectors-a2a-jcs-v01"
sys.path.insert(0, str(SCRIPTS))
import action_checks  # noqa: E402

Case = Callable[[Path], None]


def run(
    argv: list[str], env: dict[str, str] | None = None, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, env=env, cwd=cwd)  # noqa: S603


def outputs(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line
    )


def action() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))


def step(name: str) -> dict[str, Any]:
    for item in action()["runs"]["steps"]:
        if item.get("name") == name:
            return item
    raise AssertionError(f"action.yml has no step {name!r}")


# ---------------------------------------------------------------- action.yml shape


def case_inputs_exist_with_strict_defaults(work: Path) -> None:
    inputs = action()["inputs"]
    for name, default in (
        ("profile", ""),
        ("fail-on-no-vectors", "true"),
        ("fail-on-missing-case", "true"),
        ("expected-verdicts", ""),
        ("cases", "."),
        ("mutate", "none"),
        ("mutate-limit", "2000"),
    ):
        assert name in inputs, f"input {name} missing"
        assert inputs[name]["default"] == default, f"{name} default {inputs[name]['default']!r}"
    assert "evaluation-claim" in inputs["record-class"]["description"]


def case_conformance_mode_installs_nothing(work: Path) -> None:
    for name in ("Set up Python", "Install the suite"):
        assert "inputs.expected-verdicts == ''" in step(name)["if"], (
            f"{name} runs in conformance mode"
        )
    body = step("Run the verifier over the listed cases")["run"]
    assert '"$py" -S ' in body, "the conformance mode does not run under python -S"
    assert "-S" in step("Report the reference stage for the listed cases")["run"]


def case_the_summary_decides_the_replay_job(work: Path) -> None:
    gate = step("Fail the job when the replay did, or the verifier did not run")["if"]
    assert "steps.summary.outputs.result != 'pass'" in gate and "'no-verdict'" in gate
    summary_env = step("Write the job summary")["env"]
    for key in (
        "CORPUS_DIR",
        "PROFILE",
        "FAIL_ON_NO_VECTORS",
        "FAIL_ON_MISSING_CASE",
        "CONTROLS_DIR",
    ):
        assert key in summary_env, f"the summary step is not handed {key}"
    names = [s.get("name") for s in action()["runs"]["steps"]]
    assert names.index("Score the null controls") < names.index("Write the job summary")
    assert "inputs.mutate != 'none'" in step("Check mutants against the reference verifier")["if"]


# ---------------------------------------------------------------- profiles and counts


def case_a2a_float_inputs_are_out_of_integer_only(work: Path) -> None:
    features = action_checks.member_features(A2A)
    floats = sorted(k for k, v in features.items() if "non-integer-number" in v)
    assert len(floats) == 11, f"{len(floats)} float inputs: {floats}"
    split = action_checks.split_by_profile(
        {"vectors": [{"id": k, "status": "FAIL" if k in floats else "PASS"} for k in features]},
        features,
        action_checks.load_profile("integer-only"),
    )
    assert split["outOfProfile"] == {"vectors": 11, "pass": 0, "fail": 11}, split["outOfProfile"]
    assert split["inProfile"]["fail"] == 0 and not split["inProfileFailures"]


def case_a_profile_file_names_features_and_ids(work: Path) -> None:
    path = work / "profile.json"
    path.write_text(
        json.dumps({"name": "mine", "excludes": ["unsafe-integer"], "outOfProfile": ["A2-001"]})
    )
    profile = action_checks.load_profile(str(path))
    assert profile["ids"] == {"A2-001"} and profile["excludes"] == {"unsafe-integer"}
    path.write_text(json.dumps({"excludes": ["no-such-feature"]}))
    try:
        action_checks.load_profile(str(path))
    except ValueError:
        return
    raise AssertionError("a profile naming an unknown feature was accepted")


def case_counts_name_a_missing_case(work: Path) -> None:
    corpus = work / "a2a"
    shutil.copytree(A2A, corpus)
    first = action_checks.listed_members(action_checks.manifest_of(corpus) or {})[0]
    (corpus / first["path"]).unlink()
    counted = action_checks.count_cases(corpus)
    assert counted["missingOnDisk"] == [first["path"]], counted
    assert counted["present"] == counted["listed"] - 1
    report = {
        "vectors": [
            {"id": m["id"]}
            for m in action_checks.listed_members(action_checks.manifest_of(A2A) or {})[1:]
        ]
    }
    assert action_checks.count_cases(A2A, report)["missingFromReport"] == [first["id"]]


def _a2a_report(failing: set[str]) -> dict[str, Any]:
    ids = sorted(action_checks.member_features(A2A))
    rows = [
        {"id": i, "kind": "MUST-ACCEPT", "status": "FAIL" if i in failing else "PASS"} for i in ids
    ]
    passed = len(rows) - len(failing)
    return {
        "rail": "external",
        "target": "card-signing-input",
        "vectors": rows,
        "verifier": {"vectorsExecuted": len(rows)},
        "totals": {
            "vectors": len(rows),
            "pass": passed,
            "fail": len(failing),
            "conform": passed,
            "reasonParityMismatch": 0,
            "suiteRefusals": 0,
        },
    }


def summarize(work: Path, report: dict[str, Any], status: str, **env: str) -> dict[str, str]:
    report_path = work / "report.json"
    report_path.write_text(json.dumps(report))
    out = work / "out"
    out.write_text("")
    done = run(
        [sys.executable, str(SCRIPTS / "action-summary.py")],
        {
            **os.environ,
            "REPORT": str(report_path),
            "STATUS": status,
            "CORPUS_DIR": str(A2A),
            "GITHUB_STEP_SUMMARY": str(work / "summary.md"),
            "GITHUB_OUTPUT": str(out),
            **env,
        },
    )
    assert done.returncode == 0, done.stderr
    return outputs(out)


def case_profile_excuses_only_out_of_profile_failures(work: Path) -> None:
    floats = {k for k, v in action_checks.member_features(A2A).items() if "non-integer-number" in v}
    got = summarize(work, _a2a_report(floats), "1", PROFILE="integer-only")
    assert got["result"] == "pass" and got["out-of-profile"] == "11", got
    assert summarize(work, _a2a_report(floats), "1")["result"] == "fail", (
        "no profile, float failures passed"
    )
    inside = floats | {"A2-001"}
    assert summarize(work, _a2a_report(inside), "1", PROFILE="integer-only")["result"] == "fail", (
        "an in-profile failure was excused"
    )


def case_no_vectors_and_missing_cases(work: Path) -> None:
    empty = _a2a_report(set())
    empty["vectors"], empty["totals"]["vectors"] = [], 0
    assert summarize(work, empty, "0")["result"] == "fail"
    assert summarize(work, empty, "0", FAIL_ON_NO_VECTORS="false")["result"] == "no-verdict"
    short = _a2a_report(set())
    short["vectors"] = short["vectors"][1:]
    short["totals"]["vectors"] -= 1
    short["verifier"]["vectorsExecuted"] -= 1
    got = summarize(work, short, "0")
    assert got["result"] == "fail" and got["missing-cases"] == "1", got
    assert summarize(work, short, "0", FAIL_ON_MISSING_CASE="false")["result"] == "pass"


def case_controls_are_scored_and_judged(work: Path) -> None:
    accept = run(
        [sys.executable, "-S", str(SCRIPTS / "action-control-verifier.py"), "accept", "x.json"]
    )
    reject = run(
        [sys.executable, "-S", str(SCRIPTS / "action-control-verifier.py"), "reject", "x.json"]
    )
    assert (accept.returncode, reject.returncode) == (0, 1)
    assert action_checks.controls(["accept", "reject"], 1, 1)["discriminates"] is True
    lax = action_checks.controls(["accept", "reject"], 2, 1)
    assert lax["discriminates"] is False and "always-accept passes 2 of 2" in lax["findings"][0]
    controls = work / "controls"
    controls.mkdir()
    for mode, passed in (("accept", 46), ("reject", 0)):
        (controls / f"always-{mode}.json").write_text(json.dumps({"totals": {"pass": passed}}))
    got = summarize(work, _a2a_report(set()), "0", CONTROLS_DIR=str(controls))
    assert got["control-always-accept"] == "46" and got["discriminates"] == "true", got
    assert "Null controls" in (work / "summary.md").read_text()


# ---------------------------------------------------------------- conformance mode and -S


def conformance(
    work: Path, expected: str, verifier: str, *extra: str
) -> tuple[int, dict[str, Any]]:
    fixture = FIXTURES / "conformance"
    report = work / "conf.json"
    done = run(
        [
            sys.executable,
            "-S",
            str(SCRIPTS / "action-conformance.py"),
            "--expected",
            str(fixture / expected),
            "--cases",
            str(fixture / "cases"),
            "--verifier",
            f"{sys.executable} -S {fixture / verifier}",
            "--report",
            str(report),
            *extra,
        ]
    )
    return done.returncode, json.loads(report.read_text()) if report.is_file() else {}


def case_conformance_mode_holds_each_case(work: Path) -> None:
    code, report = conformance(work, "verify-expected.txt", "verifier.py")
    assert code == 0 and report["totals"]["pass"] == 4, report.get("totals")
    code, report = conformance(work, "verify-expected.txt", "lenient-verifier.py")
    assert code == 1 and {r["id"] for r in report["vectors"] if r["status"] == "FAIL"} == {
        "invalid/flag-false.json",
        "invalid/not-json.json",
    }
    code, report = conformance(work, "verify-expected-missing.txt", "verifier.py")
    assert code == 1 and report["missing"] == ["invalid/removed-case.json"]
    code, _ = conformance(
        work, "verify-expected-missing.txt", "verifier.py", "--fail-on-missing-case", "false"
    )
    assert code == 0


def case_conformance_mode_found_nothing(work: Path) -> None:
    expected = work / "expected.txt"
    expected.write_text("")
    empty = work / "empty"
    empty.mkdir()
    base = [
        sys.executable,
        "-S",
        str(SCRIPTS / "action-conformance.py"),
        "--expected",
        str(expected),
        "--cases",
        str(empty),
        "--verifier",
        "true",
        "--report",
        str(work / "r.json"),
    ]
    assert run(base).returncode == 1
    assert run([*base, "--fail-on-no-vectors", "false"]).returncode == 2


def case_reference_stage_runs_under_dash_s(work: Path) -> None:
    report = work / "r.json"
    report.write_text(json.dumps({"totals": {"vectors": 4}}))
    out = work / "out"
    out.write_text("")
    done = run(
        [sys.executable, "-S", str(SCRIPTS / "action-reference-stage.py")],
        {
            "PATH": os.environ.get("PATH", ""),
            "REPORT": str(report),
            "CORPUS_DIR": str(FIXTURES / "conformance" / "cases"),
            "GITHUB_STEP_SUMMARY": str(work / "s.md"),
            "GITHUB_OUTPUT": str(out),
        },
    )
    assert done.returncode == 0, done.stderr
    got = outputs(out)
    assert got["reference-checked"] == "0" and got["reference-total"] == "4", got
    assert got["reference-verifier-id"] == "unavailable"
    assert "reference-checked conformance 0 of 4" in done.stdout


# ---------------------------------------------------------------- producer: evaluation-claim


def produced(work: Path, record: str, pins: bool = True) -> tuple[int, dict[str, Any]]:
    receipt = work / "receipt.json"
    argv = [
        sys.executable,
        "-m",
        "agent_evidence_vectors.producer",
        "evaluation-claim",
        str(FIXTURES / "claim" / record),
        "--receipt",
        str(receipt),
    ]
    if pins:
        argv += ["--pins", str(FIXTURES / "claim" / "pins.json")]
    done = run(argv, {**os.environ, "PYTHONPATH": str(ROOT / "packaging")})
    return done.returncode, json.loads(receipt.read_text()) if receipt.is_file() else {}


def case_evaluation_claim_is_judged_under_the_pinned_rule(work: Path) -> None:
    code, receipt = produced(work, "record-pass.json")
    assert code == 0 and receipt["result"] == "pass", receipt
    assert receipt["reference"]["verifier"]["id"].endswith("#reader/evaluation-claim")
    assert receipt["acceptance"]["rule"]["sha256"]
    code, receipt = produced(work, "record-refused.json")
    assert code == 1 and "CASE_SET_NOT_ACCEPTED" in receipt["records"][0]["findings"][0]
    code, receipt = produced(work, "record-fail.json")
    assert code == 1 and "verdict fail" in receipt["records"][0]["findings"][0]
    code, receipt = produced(work, "record-pass.json", pins=False)
    assert code == 2 and receipt["result"] == "no-verdict", "a claim with no rule was judged"


# ---------------------------------------------------------------- mutation stage


def mutate(
    work: Path, corpus: str, candidate: str, mode: str, limit: str = "40", stage: Path | None = None
) -> dict[str, str]:
    report = work / "r.json"
    report.write_text(json.dumps({"totals": {"vectors": 1}}))
    out = work / "out"
    out.write_text("")
    done = run(
        [sys.executable, str(stage or SCRIPTS / "action-mutate-stage.py")],
        {
            **os.environ,
            "MUTATE": mode,
            "MUTATE_LIMIT": limit,
            "VERIFIER": candidate,
            "REPORT": str(report),
            "CORPUS_DIR": str(FIXTURES / "mutate" / corpus),
            "GITHUB_STEP_SUMMARY": str(work / "s.md"),
            "GITHUB_OUTPUT": str(out),
        },
    )
    assert done.returncode == 0, done.stderr
    return outputs(out)


def candidate(name: str, *args: str) -> str:
    return " ".join([sys.executable, str(FIXTURES / "mutate" / name), *args])


def case_mutants_both_reject_and_agree(work: Path) -> None:
    got = mutate(work, "aee", candidate("reference_candidate.py"), "bytes")
    assert got["mutation-result"] == "pass", (got, (work / "s.md").read_text())
    assert got["mutation-checked"] == got["mutation-total"] != "0", got
    # Structural mutants are re-signed, so some may change only a field no rule
    # binds: both verifiers then accept it and it is a named survivor. What the
    # stage must show is that the two verifiers never disagree.
    got = mutate(work, "aee", candidate("reference_candidate.py"), "structural")
    assert got["mutation-agreement"] == got["mutation-total"] != "0", got
    survivors = int(got["mutation-survivors"])
    assert got["mutation-result"] == ("pass" if survivors == 0 else "fail"), got
    assert int(got["mutation-checked"]) + survivors == int(got["mutation-total"]), got


def case_bytes_mode_skips_a_member_with_nothing_signed(work: Path) -> None:
    got = mutate(work, "plain", candidate("lenient_candidate.py"), "bytes")
    assert got["mutation-total"] == "0" and got["mutation-result"] == "fail", got
    assert "no DSSE envelope" in (work / "s.md").read_text()


def case_a_lenient_candidate_fails_and_names_survivors(work: Path) -> None:
    got = mutate(work, "aee", candidate("lenient_candidate.py"), "bytes")
    assert got["mutation-result"] == "fail" and got["mutation-checked"] == "0", got
    assert "disagreement" in (work / "s.md").read_text()


def case_one_disagreement_fails(work: Path) -> None:
    got = mutate(work, "aee", candidate("reference_candidate.py", "--flip-one", "0"), "bytes")
    assert got["mutation-result"] == "fail", got
    assert int(got["mutation-agreement"]) == int(got["mutation-total"]) - 1, got


def case_no_reference_route_reads_zero_of_m(work: Path) -> None:
    got = mutate(work, "plain", candidate("lenient_candidate.py"), "structural")
    assert got["mutation-checked"] == "0" and got["mutation-total"] != "0", got
    assert got["mutation-result"] == "fail"
    report = json.loads((work / "r.json").read_text())
    assert (
        report["mutation"]["checked"] == 0
        and "no reference route" in report["mutation"]["notes"][0]
    )


# ---------------------------------------------------------------- the guards go red


def _copy_with(work: Path, script: str, anchor: str, replacement: str) -> Path:
    source = (SCRIPTS / script).read_text(encoding="utf-8")
    assert anchor in source, f"{script}: the guard {anchor!r} moved; update this test"
    mutant = work / "scripts" / script
    mutant.parent.mkdir(parents=True, exist_ok=True)
    mutant.write_text(source.replace(anchor, replacement), encoding="utf-8")
    shutil.copy(SCRIPTS / "action_checks.py", mutant.parent / "action_checks.py")
    shutil.copy(SCRIPTS / "action-reference-stage.py", mutant.parent / "action-reference-stage.py")
    return mutant


def case_a_survivor_tolerant_stage_goes_red(work: Path) -> None:
    mutant = _copy_with(
        work,
        "action-mutate-stage.py",
        '"pass": bool(judged) and tally["checked"] == judged and not refusals,',
        '"pass": True,',
    )
    got = mutate(work, "aee", candidate("lenient_candidate.py"), "bytes", stage=mutant)
    assert got["mutation-result"] == "pass", "the copy without the guard still failed"


def case_a_profile_that_excuses_everything_goes_red(work: Path) -> None:
    mutant = _copy_with(
        work,
        "action-summary.py",
        'gates.profile_excuses = clean and inside["fail"] == 0',
        "gates.profile_excuses = True",
    )
    report = work / "report.json"
    report.write_text(json.dumps(_a2a_report({"A2-001"})))
    out = work / "out"
    out.write_text("")
    run(
        [sys.executable, str(mutant)],
        {
            **os.environ,
            "REPORT": str(report),
            "STATUS": "1",
            "CORPUS_DIR": str(A2A),
            "PROFILE": "integer-only",
            "GITHUB_STEP_SUMMARY": str(work / "s.md"),
            "GITHUB_OUTPUT": str(out),
        },
    )
    assert outputs(out).get("result") == "pass", (
        "the copy that excuses in-profile failures still failed"
    )


def case_a_missing_case_tolerant_count_goes_red(work: Path) -> None:
    mutant = _copy_with(
        work, "action-conformance.py", "bool(missing) and fail_on_missing", "False"
    )
    fixture = FIXTURES / "conformance"
    done = run(
        [
            sys.executable,
            "-S",
            str(mutant),
            "--expected",
            str(fixture / "verify-expected-missing.txt"),
            "--cases",
            str(fixture / "cases"),
            "--verifier",
            f"{sys.executable} -S {fixture / 'verifier.py'}",
            "--report",
            str(work / "r.json"),
        ]
    )
    assert done.returncode == 0, "the copy without the missing-case guard still failed"


CASES: list[Case] = [
    case_inputs_exist_with_strict_defaults,
    case_conformance_mode_installs_nothing,
    case_the_summary_decides_the_replay_job,
    case_a2a_float_inputs_are_out_of_integer_only,
    case_a_profile_file_names_features_and_ids,
    case_counts_name_a_missing_case,
    case_profile_excuses_only_out_of_profile_failures,
    case_no_vectors_and_missing_cases,
    case_controls_are_scored_and_judged,
    case_conformance_mode_holds_each_case,
    case_conformance_mode_found_nothing,
    case_reference_stage_runs_under_dash_s,
    case_evaluation_claim_is_judged_under_the_pinned_rule,
    case_mutants_both_reject_and_agree,
    case_bytes_mode_skips_a_member_with_nothing_signed,
    case_a_lenient_candidate_fails_and_names_survivors,
    case_one_disagreement_fails,
    case_no_reference_route_reads_zero_of_m,
    case_a_survivor_tolerant_stage_goes_red,
    case_a_profile_that_excuses_everything_goes_red,
    case_a_missing_case_tolerant_count_goes_red,
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
    raise SystemExit(main())
