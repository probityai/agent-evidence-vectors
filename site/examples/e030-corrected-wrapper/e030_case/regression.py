"""Run distinct injected cases against an unchanged, separately pinned wrapper."""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

from .faults import report_fixture, utc_now
from .report import assess, operator_identity, read_report

SOURCES = {
    "review": "cf7389097fe3a404b3557da2e72fdd8cbe962b81",
    "aps": "948f99b85343bef2c6fa677c8543965caacfc087",
    "priorseal": "d749d2691c3e6be139de4020e7b27cdafca2c428",
}
WRAPPER = "capsules/aps-priorseal-v0.1/run-pinned.sh"
WRAPPER_SHA256 = "4b289714de31174a917b9c0f856e1d8900828e1bcbf637cdc8e97bc2deec2e34"
CASES = (
    ("failed-install", "absent", 23, 0, 0, 23, "PROCESS_NONZERO"),
    ("failed-selftest", "absent", 0, 19, 0, 19, "PROCESS_NONZERO"),
    ("failed-node", "absent", 0, 0, 17, 17, "PROCESS_NONZERO"),
    ("absent-report", "absent", 0, 0, 0, 0, "REPORT_ABSENT"),
    ("malformed-report", "malformed", 0, 0, 0, 0, "REPORT_MALFORMED"),
    ("wrong-profile", "wrong-profile", 0, 0, 0, 0, "REPORT_PROFILE_MISMATCH"),
    ("wrong-input", "wrong-input", 0, 0, 0, 0, "REPORT_INPUT_MISMATCH"),
    ("wrong-claim", "wrong-claim", 0, 0, 0, 0, "REPORT_CLAIMS_MISMATCH"),
    ("wrong-summary", "wrong-summary", 0, 0, 0, 0, "REPORT_SUMMARY_MISMATCH"),
    ("stale-generation", "stale-generation", 0, 0, 0, 0, "REPORT_TIME_OUTSIDE_INTERVAL"),
    ("future-generation", "future-generation", 0, 0, 0, 0, "REPORT_TIME_OUTSIDE_INTERVAL"),
    ("symlink-report", "symlink", 0, 0, 0, 0, "REPORT_UNREADABLE"),
    ("matching-projection", "matching", 0, 0, 0, 0, None),
    ("preexisting-attempt", "matching", 0, 0, 0, 2, "PROCESS_NONZERO"),
)


def digest(path: Path) -> str:
    """Hash the delivered bytes without treating a hash as historical proof."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_environment() -> dict:
    """Refuse inherited Git routing and shell startup injection at this boundary."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    for key in ("BASH_ENV", "ENV", "PYTHONPATH"):
        env.pop(key, None)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


def _git(root: Path, *args) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        env=clean_environment(),
        check=False,
    )
    if result.returncode:
        raise ValueError("source Git read failed: " + result.stderr)
    return result.stdout.removesuffix("\n")


def _capture_process(argv, *, cwd: Path, env: dict, timeout: float = 30):
    """Retain raw outcomes and terminate only this invocation's process group."""
    started = utc_now()
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        return (
            b"",
            b"",
            {
                "started": started,
                "ended": utc_now(),
                "returncode": None,
                "actual_exit": None,
                "signal": None,
                "capture_complete": False,
                "termination": "spawn_failure",
                "error": str(error),
            },
        )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    code = process.returncode
    termination = "timeout" if timed_out else "signal" if code < 0 else "exit"
    return (
        stdout,
        stderr,
        {
            "started": started,
            "ended": utc_now(),
            "returncode": code,
            "actual_exit": code if code >= 0 else None,
            "signal": -code if code < 0 else None,
            "capture_complete": not timed_out,
            "termination": termination,
            "error": "observed invocation exceeded its timeout" if timed_out else None,
        },
    )


def validate_sources(roots: dict) -> None:
    """Require exact source checkouts and exact wrapper bytes before child execution."""
    for name, revision in SOURCES.items():
        root = roots[name]
        if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("source root selects another repository")
        if _git(root, "rev-parse", "HEAD") != revision:
            raise ValueError("wrong source revision: " + name)
        if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise ValueError("source checkout is dirty: " + name)
    if digest(roots["review"] / WRAPPER) != WRAPPER_SHA256:
        raise ValueError("wrapper bytes differ from the pinned source")


def validate_output(output: Path, roots: dict) -> None:
    """Keep new output outside every producer tree, including parent symlinks."""
    if os.path.lexists(output):
        raise ValueError("output directory must not exist")
    actual = output.resolve()
    if any(actual.is_relative_to(root) for root in roots.values()):
        raise ValueError("output directory must be outside producer checkouts")
    if not output.parent.is_dir():
        raise ValueError("output parent must exist")


def _stubs(bin_dir: Path) -> None:
    bin_dir.mkdir()
    npm = bin_dir / "npm"
    npm.write_text(
        '#!/bin/sh\nprintf "npm:%s\\n" "$1" >> "$VECTOR_LOG"\n'
        'if [ "$1" = "ci" ]; then exit "$NPM_CI_EXIT"; fi\n'
        'if [ "$1" = "run" ]; then exit "$NPM_SELFTEST_EXIT"; fi\nexit 2\n'
    )
    node = bin_dir / "node"
    node.write_text('#!/bin/sh\nexec "$E030_PYTHON" -m e030_case.faults "$@"\n')
    npm.chmod(0o700)
    node.chmod(0o700)


def one_case(case, roots: dict, output: Path) -> dict:
    """Preserve the actual child result before checking expected adverse behavior."""
    name, fault, npm_exit, selftest_exit, node_exit, expected_exit, expected_reason = case
    directory = output / name
    directory.mkdir()
    attempt = directory / "attempt"
    report = attempt / "frequency-run-report.json"
    if name == "preexisting-attempt":
        attempt.mkdir()
        report.write_text(json.dumps(report_fixture("2000-01-01T00:00:00.000Z")) + "\n")
    report_before = os.path.lexists(report)
    argv = [
        "bash",
        str(roots["review"] / WRAPPER),
        "--repo",
        str(roots["review"]),
        "--adapter-commit",
        SOURCES["review"],
        "--aps-repo",
        str(roots["aps"]),
        "--priorseal-repo",
        str(roots["priorseal"]),
        "--attempt-dir",
        str(attempt),
    ]
    env = clean_environment()
    overrides = {
        "PATH": str(output / "bin") + os.pathsep + env["PATH"],
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "E030_PYTHON": sys.executable,
        "VECTOR_LOG": str(directory / "injected-commands.txt"),
        "E030_FAULT": fault,
        "NPM_CI_EXIT": str(npm_exit),
        "NPM_SELFTEST_EXIT": str(selftest_exit),
        "NODE_EXIT": str(node_exit),
    }
    env.update(overrides)
    stdout, stderr, result = _capture_process(argv, cwd=output, env=env)
    code, complete = result["actual_exit"], result["capture_complete"]
    started, ended = result["started"], result["ended"]
    (directory / "wrapper.stdout").write_bytes(stdout)
    (directory / "wrapper.stderr").write_bytes(stderr)
    metadata = {
        "argv": argv,
        "cwd": str(output),
        "environment_overrides": overrides,
        **result,
    }
    (directory / "process.json").write_text(json.dumps(metadata, indent=2) + "\n")
    raw_status, status_error = read_report(attempt / "exit-status.txt")
    recorded_exit = (
        int(raw_status)
        if status_error is None and re.fullmatch(rb"[0-9]{1,3}\n", raw_status)
        else None
    )
    comparison = assess(
        process_exit=code,
        capture_complete=complete,
        recorded_exit=recorded_exit,
        report_before=report_before,
        report_path=report,
        started=started,
        ended=ended,
    )
    trace_path = directory / "injected-commands.txt"
    commands = trace_path.read_text().splitlines() if trace_path.exists() else []
    expected_commands = [] if report_before else ["npm:ci"]
    if not report_before and npm_exit == 0:
        expected_commands.append("npm:run")
        if selftest_exit == 0:
            expected_commands.append("node:verify.mjs")
    pass_printed = b"PASS: " in stdout
    row = {
        "name": name,
        "injection_origin": "author-created fault/report projection",
        "actual_exit": code,
        "signal": result["signal"],
        "termination": result["termination"],
        "recorded_exit": recorded_exit,
        "pass_printed": pass_printed,
        "report_sha256": digest(report) if report.is_file() and not report.is_symlink() else None,
        "injected_commands": commands,
        "comparison": comparison,
        "expected": {"exit": expected_exit, "reason": expected_reason},
        "matched": complete
        and code == expected_exit
        and comparison["reason"] == expected_reason
        and commands == expected_commands,
        "producer_verifier_executed": False,
    }
    (directory / "comparison.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def run(operator: str, roots: dict, output: Path) -> dict:
    """Run the finite experiment and leave source checkouts unchanged."""
    identity = operator_identity(operator)
    roots = {key: Path(value).resolve() for key, value in roots.items()}
    output = Path(output).absolute()
    validate_output(output, roots)
    validate_sources(roots)
    output.mkdir(mode=0o700)
    _stubs(output / "bin")
    cases = [one_case(case, roots, output) for case in CASES]
    validate_sources(roots)
    source_files = sorted(Path(__file__).parent.glob("*.py")) + [
        Path(__file__).parent / "expected.json"
    ]
    receipt = {
        "profile": "probity.e030-corrected-wrapper-regression/v1",
        "operator": identity,
        "vector": {
            "maintainer": "Probity",
            "finding_credit": "imokokok",
            "files": [
                {"path": str(p.relative_to(p.parent.parent)), "sha256": digest(p)}
                for p in source_files
            ],
        },
        "historical_baseline": (
            "probityai/agent-evidence-atlas@89250120e9cafe14eafb87eaa9c1454bab64683c"
        ),
        "source_commits": SOURCES,
        "wrapper_sha256": WRAPPER_SHA256,
        "cases": cases,
        "all_expected_controls_matched": all(row["matched"] for row in cases),
        "wrapper_report_content_guard": (
            "not established; zero-exit injected bad reports print PASS"
        ),
        "scope": {
            "method": (
                "unchanged pinned wrapper; injected npm/node commands and author-created reports"
            ),
            "producer_verifier_executed": False,
            "signatures_exercised": False,
            "formal_pilot": False,
            "operator_authentication": False,
            "run_correlation": "native report has no invocation token; no authenticity inferred",
        },
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main(argv=None) -> int:
    """Expose one explicit operator input, with no compatibility aliases."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator", required=True)
    for name in ("review", "aps", "priorseal", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args(argv)
    roots = {name: getattr(args, name) for name in SOURCES}
    receipt = run(args.operator, roots, args.output)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "operator": receipt["operator"],
                "all_expected_controls_matched": receipt["all_expected_controls_matched"],
            }
        )
    )
    return 0 if receipt["all_expected_controls_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
