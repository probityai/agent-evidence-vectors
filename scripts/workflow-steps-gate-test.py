#!/usr/bin/env python3
"""Tests for scripts/workflow-steps-gate.py.

The gate exists to run every workflow shell step locally so a push does not go
out against a red remote. It had a hole of exactly the kind it was written to
close, and the hole is the subject of this file.

GitHub Actions runs each `run:` block under `bash -e {0}` and prints that line
above the step in its own logs. The gate ran the block under a plain `bash`. In
a step with one command the two agree, so the divergence is invisible on most of
the workflow; in a step with several, the shell without `-e` keeps going after a
failure and the block reports the LAST command's status. On 2026-08-07 the
four-command forcing step failed its first command, passed the other three,
reported 0, and the gate passed a push whose CI went red four minutes later.

That is worse than an absent check. An absent check is known to be absent; this
one printed "workflow steps passed" over a step it had watched fail, which is
the same shape as the incident recorded at the top of the gate itself, one level
up. So the cases below assert the failing halves first: a multi-command step
whose FIRST command fails must be caught, and it must be caught by the shell
rather than by anything the gate parses out of the block, because the gate does
not read the block's contents and must not start.

The last case is the balance: a block whose commands all succeed still passes,
and a mirror that failed everything would be deleted rather than trusted.

Usage: .venv/bin/python -B scripts/workflow-steps-gate-test.py
Exit 0 when every case holds; 1 on a summary of failures.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
from collections.abc import Callable, Iterator
from typing import Any

from _workflow_test_fixture import fixture_authority, fixture_git

HERE = pathlib.Path(__file__).resolve().parent


def load_gate() -> object:
    """Import the gate by path, since its filename is not an identifier."""
    path = HERE / "workflow-steps-gate.py"
    spec = importlib.util.spec_from_file_location("workflow_steps_gate", path)
    if spec is None or spec.loader is None:
        sys.exit(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load_gate()
FAILURES: list[str] = []
RAN: list[str] = []


@contextlib.contextmanager
def installed(version: str) -> Iterator[None]:
    """Answer the version probe with `version` for the duration of the block.

    The three golangci-lint branches are decided by what is on PATH, and PATH is
    not the same on a runner as on a workstation: CI runs this file in a job that
    installs no Go linter, so a case that read the real binary would assert one
    thing here and the opposite there. Substituting the probe tests the branch
    the gate actually takes, in both places, and an empty string is the honest
    spelling of "no binary".
    """
    original = GATE.installed_golangci_version  # type: ignore[attr-defined]
    GATE.installed_golangci_version = lambda: version  # type: ignore[attr-defined]
    try:
        yield
    finally:
        GATE.installed_golangci_version = original  # type: ignore[attr-defined]


def check(name: str, fn: Callable[[], None]) -> None:
    RAN.append(name)
    try:
        fn()
    except AssertionError as exc:
        FAILURES.append(f"{name}: {exc}")


def _step(run: str, env: dict[str, str] | None = None, ident: str = "") -> Any:
    """One synthetic step, so the env plumbing can be tested without a workflow."""
    return GATE.Step(  # type: ignore[attr-defined]
        job="t", position=0, name="t", run=run, uses="", inputs={}, ident=ident, env=env or {}
    )


@contextlib.contextmanager
def _scratch() -> Iterator[str]:
    with tempfile.TemporaryDirectory(prefix="aee-gate-test-") as directory:
        yield directory


def run(block: str) -> int:
    code: int = GATE.run_step(block, {"PATH": "/usr/bin:/bin"}).returncode  # type: ignore[attr-defined]
    return code


def first_command_failing_is_caught() -> None:
    """The regression. Without `-e` this block exits 0 and the push goes out."""
    rc = run("false\ntrue\n")
    assert rc != 0, (
        "a block whose first command fails and whose last succeeds reported "
        f"exit {rc}. The shell is not running with -e, so this gate mirrors a "
        "workflow GitHub Actions would fail."
    )


def middle_command_failing_is_caught() -> None:
    """The four-command shape the incident actually had."""
    rc = run("true\nfalse\ntrue\ntrue\n")
    assert rc != 0, f"a failure in the middle of a four-command block reported exit {rc}"


def failure_stops_the_block() -> None:
    """`-e` aborts rather than running on, which is what Actions does.

    Asserted through an observable side effect rather than the exit status,
    because a block that ran every command and returned the first failure would
    satisfy the two cases above while still diverging from the remote on any
    step whose later commands are not safe to run after an earlier one failed.
    """
    proc = GATE.run_step("false\necho REACHED\n", {"PATH": "/usr/bin:/bin"})  # type: ignore[attr-defined]
    assert "REACHED" not in proc.stdout, (
        "the block continued past a failed command; Actions would have stopped, "
        f"so a later command ran here that never runs on the remote: {proc.stdout!r}"
    )


def a_passing_block_still_passes() -> None:
    """The mirror must not be stricter than the thing it mirrors."""
    rc = run("true\ntrue\ntrue\n")
    assert rc == 0, f"an all-succeeding block reported exit {rc}"


def pipefail_is_not_set() -> None:
    """Deliberately absent: Actions does not set it, and matching is the job.

    A mirror stricter than the remote fails pushes the remote would accept, and
    the cost lands on whoever cannot tell the two apart.
    """
    rc = run("false | true\n")
    assert rc == 0, (
        "a failing left-hand side of a pipe was reported as a step failure, so "
        "pipefail is set. Actions does not set it; this gate would now refuse "
        f"pushes the remote accepts (exit {rc})"
    )


def an_unclassified_action_is_a_fault() -> None:
    """An action nobody has classified must not drop out of coverage quietly.

    This is the second hole, found the same way as the first: a marketplace step
    was printed SKIP and passed over, so `golangci-lint (core module)` was never
    run here and the remote failed it on three pushes in a row. Silence about a
    step is now reserved for steps somebody wrote down a reason for.
    """
    local = GATE.local_equivalent("some/brand-new-action@v1", {})  # type: ignore[attr-defined]
    assert local.run is None, "an unknown action must not resolve to something runnable"
    assert local.fault, (
        "an unclassified action was reported as an ordinary NOT RUN. Adding an "
        "action to a workflow would then remove it from local coverage without "
        "anyone being told, which is the defect this gate exists to prevent."
    )


def a_runner_only_action_names_its_reason() -> None:
    """NOT RUN is only honest when it says what the runner does that we cannot."""
    local = GATE.local_equivalent("actions/checkout@v4", {})  # type: ignore[attr-defined]
    assert local.run is None, "checkout must not be mirrored; this gate runs inside a checkout"
    assert not local.fault, "checkout is classified, so it is not a fault"
    assert "actions/checkout" in local.reason and len(local.reason) > 30, (
        f"the reason does not describe the step: {local.reason!r}"
    )


def the_pinned_linter_is_mirrored() -> None:
    """The step the remote caught and this gate used to skip."""
    with installed("2.11.4"):
        local = GATE.local_equivalent(  # type: ignore[attr-defined]
            "golangci/golangci-lint-action@v7",
            {"version": "v2.11.4", "working-directory": "witnessattestor"},
        )
    assert local.run is not None, f"the pinned linter did not resolve to a command: {local.reason}"
    assert "golangci-lint run" in local.run, local.run
    assert "witnessattestor" in local.run, (
        f"working-directory was dropped, so the wrong module would be linted: {local.run!r}"
    )


def a_version_mismatch_is_not_run_rather_than_a_pass() -> None:
    """A different version is a different set of linters, so its silence is worthless."""
    with installed("2.10.0"):
        local = GATE.local_equivalent(  # type: ignore[attr-defined]
            "golangci/golangci-lint-action@v7", {"version": "v2.11.4"}
        )
    assert local.run is None, (
        "a version this workstation does not have resolved to a command anyway. "
        "The mirror would then report on a different tool than the remote runs."
    )
    assert "2.11.4" in local.reason and "2.10.0" in local.reason, (
        f"the refusal must name both versions so the reader can fix it: {local.reason!r}"
    )


def an_absent_linter_is_not_run_rather_than_a_pass() -> None:
    """No binary is NOT RUN. It must never read as a clean lint."""
    with installed(""):
        local = GATE.local_equivalent(  # type: ignore[attr-defined]
            "golangci/golangci-lint-action@v7", {"version": "v2.11.4"}
        )
    assert local.run is None, "a missing golangci-lint resolved to a command anyway"
    assert "not on PATH" in local.reason, (
        f"the reason does not say the binary is missing: {local.reason!r}"
    )


def a_literal_step_env_reaches_the_block() -> None:
    """A step's `env:` block used to be dropped on the floor, silently.

    Nothing read it: the gate built one environment for the whole run and never
    looked at the per-step mapping. A step whose assertions read a variable set
    there therefore ran with it unset, and `test "$X" = y` against an unset X is
    a check reporting a verdict on an input it never received.
    """
    step = _step(run='test "$GREETING" = hello\n', env={"GREETING": "hello"})
    with _scratch() as scratch:
        env, missing = GATE.step_environment(step, {}, scratch)  # type: ignore[attr-defined]
        assert not missing, missing
        rc = GATE.run_step(step.run, {"PATH": "/usr/bin:/bin", **env}).returncode  # type: ignore[attr-defined]
    assert rc == 0, f"the env block did not reach the step (exit {rc})"


def a_recorded_step_output_is_supplied() -> None:
    """The value a previous step wrote to $GITHUB_OUTPUT, as the runner gives it."""
    recorded = {"replay": {"result": "pass"}}
    value, missing = GATE.expand("${{ steps.replay.outputs.result }}", recorded)  # type: ignore[attr-defined]
    assert not missing, missing
    assert value == "pass", f"the recorded output was not substituted: {value!r}"


def an_output_of_a_step_that_did_not_run_is_not_run() -> None:
    """The regression this file's newest case exists for.

    `ci.yml` asserts on the composite action's outputs. The action was mirrored
    locally by replaying the corpus and nothing else, so the outputs were never
    produced, the env values came out empty, and the assertion failed a push the
    remote accepts. An empty string must never stand in for a value this gate
    does not have -- the step is declared NOT RUN and the reason names the step.
    """
    value, missing = GATE.expand("${{ steps.replay.outputs.result }}", {})  # type: ignore[attr-defined]
    assert value == "", value
    assert missing, (
        "an output of a step that was not run here resolved to the empty string "
        "with no complaint. The consuming step would then compare against it and "
        "fail a push the remote would accept, which is how a gate gets bypassed."
    )
    assert "replay" in missing, f"the reason does not name the step: {missing!r}"


def an_output_the_mirror_never_wrote_is_not_run() -> None:
    """A mirror that stops producing a declared output must say so, not fail."""
    # The step wrote one output and the reference asks for another. The value
    # is any string; what is being tested is that `result` is reported missing.
    _, missing = GATE.expand(  # type: ignore[attr-defined]
        "${{ steps.replay.outputs.result }}", {"replay": {"vectors": "3"}}
    )
    assert missing and "result" in missing, (
        f"a declared output the mirror did not write was not reported: {missing!r}"
    )


def an_unsupplied_context_is_empty_as_it_is_on_a_runner() -> None:
    """`github.*` resolves to the empty string, which is what Actions yields.

    The two steps here that read one are written for it: the commit-message lint
    falls back to `HEAD~1..HEAD` when `github.event.before` is empty, and the
    crosswalk filer prints its body and exits where `$GITHUB_ACTIONS` is not
    true. Declaring those NOT RUN instead would remove two checks that do real
    work locally, and a mirror blinder than it needs to be is its own defect.
    """
    value, missing = GATE.expand("${{ github.event.before }}", {})  # type: ignore[attr-defined]
    assert value == "" and not missing, (
        f"expected a silent empty string, got {value!r} / {missing!r}"
    )


def the_action_mirror_produces_the_declared_outputs() -> None:
    """The mirror runs the action's own summary script, not a copy of its sums."""
    local = GATE.local_equivalent("./", {"verifier": "./aee-verify -json"})  # type: ignore[attr-defined]
    assert local.run is not None, local.reason
    assert "scripts/action-summary.py" in local.run, (
        "the mirror does not run the action's summary script, so its outputs "
        f"are a second implementation that will drift: {local.run!r}"
    )
    assert "GITHUB_OUTPUT" in local.run, (
        f"the mirror writes no outputs, so a step reading them cannot run: {local.run!r}"
    )


def a_recorded_step_outcome_is_supplied() -> None:
    """steps.<id>.outcome resolves to what this gate recorded when it ran the step."""
    statuses = {"neg": {"outcome": "failure", "conclusion": "success"}}
    value, missing = GATE.expand("${{ steps.neg.outcome }}", {}, statuses)  # type: ignore[attr-defined]
    assert not missing and value == "failure", f"{value!r} / {missing!r}"
    value, missing = GATE.expand("${{ steps.neg.conclusion }}", {}, statuses)  # type: ignore[attr-defined]
    assert not missing and value == "success", f"{value!r} / {missing!r}"


def an_outcome_of_an_unrun_step_is_not_run() -> None:
    """An outcome this gate never recorded is not guessed, same as an output."""
    value, missing = GATE.expand("${{ steps.neg.outcome }}", {}, {})  # type: ignore[attr-defined]
    assert value == "" and missing and "neg" in missing, f"{value!r} / {missing!r}"


def continue_on_error_is_honoured_end_to_end() -> None:
    """A failing step marked continue-on-error does not fail the run, and a later
    step reads its outcome as failure. Without this, every negative step in a
    workflow -- the one that asserts something MUST fail -- was a red local run
    for a push the remote accepts."""
    workflow = (
        "jobs:\n"
        "  neg:\n"
        "    steps:\n"
        "      - name: this must fail\n"
        "        id: must_fail\n"
        "        continue-on-error: true\n"
        "        run: exit 3\n"
        "      - name: and it did\n"
        "        env:\n"
        "          OUTCOME: ${{ steps.must_fail.outcome }}\n"
        '        run: test "$OUTCOME" = failure\n'
    )
    rc, log = _execute(workflow)
    assert rc == 0, f"a continue-on-error failure failed the run (exit {rc}):\n{log}"
    # The balance: the same failure WITHOUT the key still fails the run.
    rc, _ = _execute(workflow.replace("        continue-on-error: true\n", ""))
    assert rc != 0, "a failing step without continue-on-error passed the run"


def the_action_mirror_fails_on_a_non_pass_verdict() -> None:
    """The action fails a job on the exit status OR on the summary verdict; so must its mirror."""
    local = GATE.local_equivalent("./", {"verifier": "./aee-verify -json"})  # type: ignore[attr-defined]
    assert local.run is not None, local.reason
    assert "result=pass" in local.run, (
        "the mirror exits on the harness status alone, so a report that does not "
        f"show the verifier running every vector would pass it: {local.run!r}"
    )


def _fixture(workflow: str, root: pathlib.Path) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / ".github" / "workflows" / "wf.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(workflow, encoding="utf-8")
    fixture_git(root, "init", "-q")
    fixture_git(root, "add", ".")
    fixture_git(
        root,
        "-c",
        "user.name=Fixture operator",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "--no-gpg-sign",
        "-qm",
        "test: record fixture source",
    )
    fixture_git(
        root,
        "-c",
        "user.name=Fixture operator",
        "-c",
        "user.email=fixture@example.test",
        "tag",
        "--no-sign",
        "-a",
        "fixture-tag",
        "-m",
        "fixture source annotation",
    )
    return path


@contextlib.contextmanager
def _local_input(root: pathlib.Path) -> Iterator[None]:
    original = GATE.REPO  # type: ignore[attr-defined]
    ambient = {
        key: os.environ.pop(key, None)
        for key in (
            "GITHUB_SHA",
            "GITHUB_HEAD_SHA",
            "GITHUB_EVENT_NAME",
        )
    }
    GATE.REPO = root  # type: ignore[attr-defined]
    try:
        yield
    finally:
        GATE.REPO = original  # type: ignore[attr-defined]
        for key, value in ambient.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)


def _execute(workflow: str, root: pathlib.Path | None = None) -> tuple[int, str]:
    """Run one synthetic workflow through the gate; return (exit, printed log)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = root or pathlib.Path(tmp) / "source"
        path = _fixture(workflow, root)
        out = pathlib.Path(tmp) / "out.txt"
        with _local_input(root), open(out, "w") as handle, contextlib.redirect_stdout(handle):
            rc = GATE.execute([path], branch_authority=fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        return rc, out.read_text()


def a_default_working_directory_is_honoured() -> None:
    """A job's defaults.run.working-directory is where its run blocks start.

    The 2026-10-01 regression: e2-reproduction.yml declares a default directory
    and runs `pytest test_reproduction.py` from it; the gate ran it from the
    root and failed a step the remote passes. A step's own key wins over it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "sub" / "deeper").mkdir(parents=True)
        (root / "sub" / "marker").write_text("x")
        (root / "sub" / "deeper" / "other").write_text("x")
        workflow = (
            "defaults:\n  run:\n    working-directory: nowhere\n"
            "jobs:\n  j:\n    defaults:\n      run:\n        working-directory: sub\n"
            "    steps:\n"
            "      - run: test -f marker\n"
            "      - working-directory: sub/deeper\n        run: test -f other\n"
        )
        rc, log = _execute(workflow, root)
    assert rc == 0, f"a run block did not start in its declared directory:\n{log}"


def github_env_and_runner_temp_carry_within_a_job() -> None:
    """$RUNNER_TEMP exists, and $GITHUB_ENV and $GITHUB_PATH reach later steps.

    gemara-method-link.yml writes a binary to $RUNNER_TEMP and names it in
    $GITHUB_ENV; the next step reads the variable. Before, the first step died
    on KeyError: 'RUNNER_TEMP' and the rest failed after it.
    """
    workflow = (
        "jobs:\n  j:\n    steps:\n"
        "      - run: |\n"
        '          test -d "$RUNNER_TEMP"\n'
        '          test -n "$GITHUB_WORKSPACE"\n'
        '          mkdir -p "$RUNNER_TEMP/bin"\n'
        "          printf '#!/bin/sh\\necho hi\\n' > \"$RUNNER_TEMP/bin/tool-xyz\"\n"
        '          chmod +x "$RUNNER_TEMP/bin/tool-xyz"\n'
        '          echo "TOOL=$RUNNER_TEMP/bin/tool-xyz" >> "$GITHUB_ENV"\n'
        "          printf 'MULTI<<EOF\\na\\nb\\nEOF\\n' >> \"$GITHUB_ENV\"\n"
        '          echo "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"\n'
        "      - run: |\n"
        '          test -x "$TOOL"\n'
        '          test "$MULTI" = "$(printf \'a\\nb\')"\n'
        '          test "$(tool-xyz)" = hi\n'
        "  k:\n    steps:\n"
        '      - run: test -z "${TOOL:-}"\n'
    )
    rc, log = _execute(workflow)
    assert rc == 0, f"runner variables did not carry within a job, or leaked across jobs:\n{log}"


def _corpus_harness_block() -> str:
    """Read the production block; the test must exercise its actual paths."""
    path = HERE.parent / ".github" / "workflows" / "ci.yml"
    doc = GATE.load_yaml(path)  # type: ignore[attr-defined]
    for step in GATE.steps_of(doc, path):  # type: ignore[attr-defined]
        if step.name == "one harness judges every corpus":
            assert step.run is not None
            return str(step.run)
    raise AssertionError("the corpus harness step is missing")


def corpus_harness_outputs_are_owned_by_the_job() -> None:
    """Two jobs with spaces in their paths must not share a verifier binary."""
    with tempfile.TemporaryDirectory(prefix="aee paths ") as tmp:
        root = pathlib.Path(tmp)
        tools = root / "tools"
        tools.mkdir()
        go = tools / "go"
        # Refuse a global output before writing it, even against the old block.
        go.write_text(
            '#!/bin/sh\n[ "$1" = build ] && [ "$2" = -o ] || exit 22\n'
            '[ "$3" = "$RUNNER_TEMP/aee-verify" ] || exit 23\n'
            'printf "#!/bin/sh\\nexit 0\\n" > "$3"\nchmod +x "$3"\n'
        )
        go.chmod(0o755)
        (root / "vectors").mkdir()
        (root / "vectors" / "MANIFEST.json").write_text("{}")
        original = GATE.REPO  # type: ignore[attr-defined]
        GATE.REPO = root  # type: ignore[attr-defined]
        try:
            for label in ("job one", "job two"):
                directory = root / label
                directory.mkdir()
                env = {"PATH": f"{tools}:/usr/bin:/bin", "RUNNER_TEMP": str(directory)}
                proc = GATE.run_step(_corpus_harness_block(), env)  # type: ignore[attr-defined]
                assert proc.returncode == 0, proc.stdout + proc.stderr
                assert (directory / "aee-verify").is_file()
            assert (root / "job one" / "aee-verify").read_bytes() == (
                root / "job two" / "aee-verify"
            ).read_bytes()
        finally:
            GATE.REPO = original  # type: ignore[attr-defined]


def job_owned_outputs_require_runner_context() -> None:
    """Both producers refuse unset or empty context before running a tool."""
    action = GATE.own_action({"verifier": "unused"})  # type: ignore[attr-defined]
    assert action.run is not None
    for block in (_corpus_harness_block(), action.run):
        for extra in ({}, {"RUNNER_TEMP": ""}):
            proc = GATE.run_step(block, {"PATH": "/usr/bin:/bin", **extra})  # type: ignore[attr-defined]
            assert proc.returncode != 0, "missing runner context passed"
            assert "RUNNER_TEMP is required" in proc.stderr, proc.stderr


def action_report_path_reaches_the_summary_and_outputs() -> None:
    """The real summary reads the report produced under the job's quoted path."""
    local = GATE.own_action(  # type: ignore[attr-defined]
        {"verifier": "fixture-only", "report-path": "report with spaces.json"}
    )
    assert local.run is not None
    with tempfile.TemporaryDirectory(prefix="aee action paths ") as tmp:
        root = pathlib.Path(tmp)
        (root / "packaging").mkdir()
        (root / "scripts").mkdir()
        (root / "scripts" / "action-summary.py").write_bytes(
            (HERE / "action-summary.py").read_bytes()
        )
        # This fixture exercises file transport, not conformance arithmetic.
        (root / "packaging" / "run_vectors.py").write_text(
            "import json,pathlib,sys\n"
            "p=pathlib.Path(sys.argv[sys.argv.index('--report')+1])\n"
            "p.write_text(json.dumps({'rail':'external','totals':{'vectors':1,"
            "'conform':1,'pass':1,'fail':0,'reasonParityMismatch':0,'suiteRefusals':0},"
            "'verifier':{'vectorsExecuted':1},'rows':[]}))\n"
        )
        runner = root / "job temp"
        runner.mkdir()
        output = root / "outputs"
        summary = root / "summary"
        env = {
            "PATH": f"{pathlib.Path(sys.executable).parent}:/usr/bin:/bin",
            "RUNNER_TEMP": str(runner),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
        }
        original = GATE.REPO  # type: ignore[attr-defined]
        GATE.REPO = root  # type: ignore[attr-defined]
        try:
            proc = GATE.run_step(local.run, env)  # type: ignore[attr-defined]
        finally:
            GATE.REPO = original  # type: ignore[attr-defined]
        assert proc.returncode == 0, proc.stdout + proc.stderr
        report = runner / "report with spaces.json"
        assert report.is_file()
        assert f"report={report}\n" in output.read_text()
        assert "result=pass\n" in output.read_text()
        assert "agent-evidence-vectors: pass" in summary.read_text()


@contextlib.contextmanager
def uv_provides(available: bool) -> Iterator[None]:
    """Answer the uv availability probe, so the case does not depend on the host."""
    original = GATE.uv_python_available  # type: ignore[attr-defined]
    GATE.uv_python_available = lambda version: available  # type: ignore[attr-defined]
    try:
        yield
    finally:
        GATE.uv_python_available = original  # type: ignore[attr-defined]


def action_verifier_imports_resolve_to_the_checkout() -> None:
    """A verifier the action names as `python -m agent_evidence_vectors.X` runs this revision.

    The action pip-installs its own checkout before replaying, so a verifier
    that imports the package gets the revision under test. The mirror skipped
    the install, and an older copy installed in whatever interpreter was first
    on PATH answered instead: the a2a-jcs replay failed every vector locally
    while the remote run passed.
    """
    local = GATE.own_action(  # type: ignore[attr-defined]
        {"verifier": "python3 -m agent_evidence_vectors.probe", "report-path": "r.json"}
    )
    assert local.run is not None
    with tempfile.TemporaryDirectory(prefix="aee action imports ") as tmp:
        root = pathlib.Path(tmp)
        (root / "scripts").mkdir()
        (root / "scripts" / "action-summary.py").write_bytes(
            (HERE / "action-summary.py").read_bytes()
        )
        checkout_pkg = root / "packaging" / "agent_evidence_vectors"
        checkout_pkg.mkdir(parents=True)
        (checkout_pkg / "__init__.py").write_text("")
        (checkout_pkg / "probe.py").write_text("print('checkout')\n")
        # An older installed copy that lacks the module, ahead of everything else.
        stale = root / "stale-site" / "agent_evidence_vectors"
        stale.mkdir(parents=True)
        (stale / "__init__.py").write_text("")
        # The fixture harness runs the verifier and passes only on the checkout's answer.
        (root / "packaging" / "run_vectors.py").write_text(
            "import json,pathlib,shlex,subprocess,sys\n"
            "cmd=shlex.split(sys.argv[sys.argv.index('--verifier')+1])\n"
            "out=subprocess.run(cmd,capture_output=True,text=True).stdout.strip()\n"
            "ok=1 if out=='checkout' else 0\n"
            "p=pathlib.Path(sys.argv[sys.argv.index('--report')+1])\n"
            "p.write_text(json.dumps({'rail':'external','totals':{'vectors':1,"
            "'conform':ok,'pass':ok,'fail':1-ok,'reasonParityMismatch':0,'suiteRefusals':0},"
            "'verifier':{'vectorsExecuted':1},'rows':[]}))\n"
            "sys.exit(0 if ok else 1)\n"
        )
        runner = root / "job temp"
        runner.mkdir()
        env = {
            "PATH": f"{pathlib.Path(sys.executable).parent}:/usr/bin:/bin",
            "PYTHONPATH": str(root / "stale-site"),
            "RUNNER_TEMP": str(runner),
            "GITHUB_OUTPUT": str(root / "outputs"),
            "GITHUB_STEP_SUMMARY": str(root / "summary"),
        }
        original = GATE.REPO  # type: ignore[attr-defined]
        GATE.REPO = root  # type: ignore[attr-defined]
        try:
            proc = GATE.run_step(local.run, env)  # type: ignore[attr-defined]
        finally:
            GATE.REPO = original  # type: ignore[attr-defined]
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "result=pass\n" in (root / "outputs").read_text()


def setup_python_is_mirrored_with_pip() -> None:
    """setup-python is mirrored by a pip-seeded interpreter put on $GITHUB_PATH.

    Leaving it NOT RUN ran `python -m pip install` against the hook's uv venv,
    which has no pip.
    """
    with uv_provides(True):
        local = GATE.local_equivalent("actions/setup-python@abc", {"python-version": "3.13.15"})  # type: ignore[attr-defined]
    assert local.run is not None, f"setup-python is not mirrored: {local.reason}"
    assert "--seed" in local.run, "the mirrored interpreter is not seeded with pip"
    assert "3.13.15" in local.run and "GITHUB_PATH" in local.run, local.run


def an_unprovidable_python_stops_its_job() -> None:
    """A pinned Python uv cannot provide is NOT RUN, and so is the rest of the job.

    A nearby release is not a mirror: the WIMSE reproduction refuses any
    interpreter but its pin, so running on 3.12.13 for a 3.12.14 pin failed a
    push the remote accepts. Another job in the same workflow still runs.
    """
    workflow = (
        "jobs:\n  j:\n    steps:\n"
        "      - uses: actions/setup-python@abc\n        with:\n          python-version: '9.9.9'\n"
        "      - run: exit 1\n"
        "  k:\n    steps:\n      - run: exit 7\n"
    )
    with uv_provides(False):
        rc, log = _execute(workflow)
    assert "NOT RUN  j[1]" in log, f"a step ran on an interpreter the job never got:\n{log}"
    assert rc != 0 and "FAIL  k[0]" in log, f"the block leaked into another job:\n{log}"


def a_step_guarded_to_another_event_is_not_run() -> None:
    """A step whose `if:` names another event does not run for a push.

    The merge-subject lint is guarded to pull_request and reads the PR title;
    run for a push it failed on an empty title the remote never gives it. A
    step guarded to push, or with an expression this gate cannot decide, runs.
    """
    workflow = (
        "jobs:\n  j:\n    steps:\n"
        "      - if: github.event_name == 'pull_request'\n        run: exit 3\n"
        "      - if: github.event_name != 'push'\n        run: exit 4\n"
        "      - if: github.event_name == 'push'\n        run: exit 5\n"
        "      - if: always()\n        run: exit 6\n"
    )
    rc, log = _execute(workflow)
    assert "NOT RUN  j[0]" in log and "NOT RUN  j[1]" in log, f"a guarded step ran:\n{log}"
    assert "FAIL  j[2]" in log and "FAIL  j[3]" in log, (
        f"a step that runs on a push was skipped:\n{log}"
    )
    assert rc != 0


def an_ambient_virtual_env_does_not_reach_the_steps() -> None:
    """`uv pip install` in a step must land in the project environment.

    The hook's `uv run --with` exported a throwaway VIRTUAL_ENV, so the
    workflow's package install went there and later `uv run` steps could not
    import the package. A runner has no VIRTUAL_ENV.
    """
    base = GATE.step_base_environment(  # type: ignore[attr-defined]
        {"VIRTUAL_ENV": "/tmp/throwaway", "UV_PROJECT_ENVIRONMENT": "/repo/.venv", "PATH": "/bin"}
    )
    assert base.get("VIRTUAL_ENV") == "/repo/.venv", base.get("VIRTUAL_ENV")
    bare = GATE.step_base_environment({"VIRTUAL_ENV": "/tmp/throwaway", "PATH": "/bin"})  # type: ignore[attr-defined]
    assert "VIRTUAL_ENV" not in bare, bare.get("VIRTUAL_ENV")


def a_mutating_job_does_not_change_the_next_jobs_source() -> None:
    """An OTS-like producer keeps its changed proof; the next job reads the original."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "input"
        root.mkdir()
        (root / "proof.ots").write_bytes(b"original-proof\x00\xff")
        workflow = (
            "jobs:\n  upgrade:\n    steps:\n"
            "      - run: printf upgraded > proof.ots\n"
            '      - run: test "$(cat proof.ots)" = upgraded\n'
            "  verify:\n    steps:\n"
            '      - run: python3 -c "from pathlib import Path; '
            "assert Path('proof.ots').read_bytes() == b'original-proof\\x00\\xff'\"\n"
        )
        rc, log = _execute(workflow, root)
        assert rc == 0, f"one job's mutated proof contaminated another:\n{log}"
        assert (root / "proof.ots").read_bytes() == b"original-proof\x00\xff"


def reader_revision_is_the_actual_full_source_sha() -> None:
    workflow = (
        "jobs:\n  reader:\n    steps:\n"
        "      - run: |\n"
        '          selected="${{ github.event.pull_request.head.sha || github.sha }}"\n'
        '          test "$selected" = "$(git rev-parse HEAD)"\n'
        '          test "${#selected}" = 40\n'
        "      - env:\n          REVISION: ${{ github.sha }}\n"
        '        run: test "$REVISION" = "$(git rev-parse HEAD)"\n'
    )
    rc, log = _execute(workflow)
    assert rc == 0, f"the reader revision did not bind to the actual source:\n{log}"


def mutations_and_native_report_bytes_survive_job_cleanup() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        root = directory / "input"
        root.mkdir()
        (root / "proof.ots").write_bytes(b"original proof")
        workflow = (
            "jobs:\n  upgrade:\n    steps:\n"
            "      - run: |\n"
            "          printf 'new proof' > proof.ots\n"
            "          mkdir -p .build/remora-e7-result\n"
            "          printf '{\"fixture_only\":true}\\r\\n' "
            "> .build/remora-e7-result/report.json\n"
            "          printf 'raw stdout\\r\\n'\n"
            "          printf 'raw stderr\\r\\n' >&2\n"
            "  verify:\n    steps:\n"
            "      - run: test \"$(cat proof.ots)\" = 'original proof'\n"
        )
        path = _fixture(workflow, root)
        evidence = directory / "evidence"
        with (
            _local_input(root),
            open(directory / "log", "w") as out,
            contextlib.redirect_stdout(out),
        ):
            rc = GATE.execute([path], evidence, fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        assert rc == 0, (directory / "log").read_text()
        producer = evidence / "001-wf-upgrade"
        consumer = evidence / "002-wf-verify"
        assert (producer / "changed-tracked/proof.ots").read_bytes() == b"new proof"
        assert b"original proof" in (producer / "tracked.diff").read_bytes()
        assert (producer / "reports/workspace/remora-e7-result/report.json").read_bytes() == (
            b'{"fixture_only":true}\r\n'
        )
        assert (producer / "steps/0/stdout").read_bytes() == b"raw stdout\r\n"
        assert (producer / "steps/0/stderr").read_bytes() == b"raw stderr\r\n"
        assert (producer / "original-tracked/proof.ots").read_bytes() == b"original proof"
        before = json.loads((producer / "source-initial.json").read_text())
        after = json.loads((producer / "source-final.json").read_text())
        independent = json.loads((consumer / "source-initial.json").read_text())
        assert before["files"] == independent["files"]
        scope = {
            "event_name": "push",
            "event_origin": "declared_local_push_simulation",
            "hosted_event_verified": False,
        }
        assert before["event_scope"] == after["event_scope"] == independent["event_scope"] == scope
        assert before["files"]["proof.ots"] != after["files"]["proof.ots"]
        assert before["tags"] == after["tags"] == independent["tags"]
        assert not (consumer / "changed-tracked").exists()


def unknown_context_refuses_execution_before_bash() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        marker = pathlib.Path(tmp) / "executed"
        workflow = (
            "jobs:\n  unknown:\n    steps:\n"
            "      - run: |\n"
            f"          echo executed > '{marker}'\n"
            '          echo "${{ secrets.UNKNOWN }}"\n'
        )
        rc, log = _execute(workflow)
        assert rc == 1 and "unsupported expression" in log, log
        assert not marker.exists(), "the unresolved expression reached a shell"
        value, missing = GATE.expand("${{ inputs.unrecognised }}", {})  # type: ignore[attr-defined]
        assert missing and value == "", (value, missing)


def multiline_expressions_have_the_same_bounded_context() -> None:
    rc, log = _execute(
        "jobs:\n  j:\n    steps:\n      - run: |\n"
        '          selected="${{ github.event.pull_request.head.sha ||\n'
        '          github.sha }}"\n'
        '          test "$selected" = "$(git rev-parse HEAD)"\n'
    )
    assert rc == 0, log
    with tempfile.TemporaryDirectory() as tmp:
        marker = pathlib.Path(tmp) / "executed"
        for expression in ("${{ secrets.\n          UNKNOWN }}", "${{ secrets.UNKNOWN"):
            rc, log = _execute(
                "jobs:\n  j:\n    steps:\n      - run: |\n"
                f"          echo executed > '{marker}'\n"
                f'          echo "{expression}"\n'
            )
            assert rc == 1 and not marker.exists(), log


def workflow_job_and_step_environment_use_actual_context() -> None:
    rc, log = _execute(
        "env:\n  REVISION: ${{ github.sha }}\n  PRIORITY: workflow\n"
        "jobs:\n  j:\n    env:\n      PRIORITY: job\n    steps:\n"
        '      - run: test "$REVISION" = "$(git rev-parse HEAD)" && test "$PRIORITY" = job\n'
        "      - env:\n          PRIORITY: step\n"
        '        run: test "$PRIORITY" = step\n'
    )
    assert rc == 0, log


def sparse_inputs_produce_complete_jobs_and_hidden_drift_is_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "source"
        (root / "hidden").mkdir(parents=True)
        (root / "hidden" / "proof").write_text("original")
        path = _fixture(
            'jobs:\n  j:\n    steps:\n      - run: test "$(cat hidden/proof)" = original\n',
            root,
        )
        fixture_git(root, "sparse-checkout", "init", "--cone")
        fixture_git(root, "sparse-checkout", "set", ".github")
        assert not (root / "hidden/proof").exists()
        with _local_input(root):
            assert GATE.execute([path], branch_authority=fixture_authority(path.parents[2])) == 0  # type: ignore[attr-defined]
        assert not (root / "hidden/proof").exists(), "the mirror changed its sparse donor"
        fixture_git(root, "sparse-checkout", "disable")
        fixture_git(root, "update-index", "--assume-unchanged", "hidden/proof")
        (root / "hidden/proof").write_text("hidden drift")
        assert not fixture_git(root, "status", "--porcelain", "--untracked-files=no")
        with _local_input(root):
            assert GATE.execute([path], branch_authority=fixture_authority(path.parents[2])) == 1  # type: ignore[attr-defined]


def step_outputs_and_status_do_not_leak_between_jobs() -> None:
    for expression in ("steps.producer.outputs.result", "steps.producer.outcome"):
        workflow = (
            "jobs:\n  first:\n    steps:\n"
            "      - id: producer\n"
            '        run: echo result=pass >> "$GITHUB_OUTPUT"\n'
            "      - env:\n          RESULT: ${{ steps.producer.outputs.result }}\n"
            '        run: test "$RESULT" = pass\n'
            "  second:\n    steps:\n"
            f"      - env:\n          RESULT: ${{{{ {expression} }}}}\n"
            "        run: exit 0\n"
        )
        rc, log = _execute(workflow)
        reason = "no value" if "outputs" in expression else "no outcome"
        assert rc == 1 and reason in log, log


def selected_source_cannot_be_faked_or_dirty() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "source"
        path = _fixture("jobs:\n  j:\n    steps:\n      - run: exit 0\n", root)
        with _local_input(root):
            for key in ("GITHUB_SHA", "GITHUB_HEAD_SHA"):
                os.environ[key] = "1" * 40
                rc = GATE.execute([path], branch_authority=fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
                assert rc == 1, f"a fake {key} was trusted"
                os.environ.pop(key)
            path.write_text(path.read_text() + "# changed tracked source\n")
            assert GATE.execute([path], branch_authority=fixture_authority(path.parents[2])) == 1  # type: ignore[attr-defined]


def job_tag_ref_changes_are_retained_and_cannot_change_the_donor() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        root = directory / "source"
        path = _fixture(
            "jobs:\n  j:\n    steps:\n      - run: git tag -d fixture-tag\n"
            "  next:\n    steps:\n"
            '      - run: test "$(git cat-file -t fixture-tag)" = tag\n',
            root,
        )
        annotation = fixture_git(root, "rev-parse", "refs/tags/fixture-tag")
        evidence = directory / "evidence"
        with _local_input(root):
            rc = GATE.execute([path], evidence, fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        assert rc == 1, "a job silently changed its frozen tag binding"
        assert fixture_git(root, "rev-parse", "refs/tags/fixture-tag") == annotation
        assert fixture_git(root, "cat-file", "-t", annotation) == "tag"
        final = json.loads((evidence / "001-wf-j/source-final.json").read_text())
        assert "refs/tags/fixture-tag" not in final["tags"]
        next_result = json.loads((evidence / "002-wf-next/steps/0/result.json").read_text())
        assert next_result["status"] == "EXECUTED" and next_result["returncode"] == 0


def checkout_and_working_directory_bind_to_the_selected_source() -> None:
    for declaration in (
        "      - uses: actions/checkout@v4\n        with:\n          ref: does-not-exist\n",
        "      - uses: actions/checkout@v4\n        with:\n          path: elsewhere\n",
        "      - working-directory: ..\n        run: exit 0\n",
    ):
        rc, log = _execute("jobs:\n  j:\n    steps:\n" + declaration)
        assert rc == 1, f"an unsupported checkout/directory was executed:\n{log}"
    rc, log = _execute(
        "jobs:\n  j:\n    steps:\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.sha }}\n"
        '      - run: test "$(git cat-file -t refs/tags/fixture-tag)" = tag\n'
    )
    assert rc == 0, log


def a_step_may_start_in_the_jobs_runner_temp() -> None:
    """`working-directory: ${{ runner.temp }}` starts the step in the job's own temp.

    A runner owns RUNNER_TEMP for the job, and the held-out workflow starts
    there on purpose so the installed wheel, not the checkout, answers. The
    mirror refused every directory outside the checkout and failed that step
    on every replay; a directory outside both the checkout and the job's temp
    is still refused.
    """
    rc, log = _execute(
        "jobs:\n  j:\n    steps:\n"
        "      - working-directory: ${{ runner.temp }}\n"
        '        run: test "$(pwd -P)" = "$(cd "$RUNNER_TEMP" && pwd -P)"\n'
    )
    assert rc == 0, log
    rc, log = _execute(
        "jobs:\n  j:\n    steps:\n      - working-directory: /\n        run: exit 0\n"
    )
    assert rc == 1, f"a directory outside the checkout and the job temp was executed:\n{log}"


def baseline_python_and_uv_environment_belong_to_each_job() -> None:
    workflow = (
        "jobs:\n  first:\n    steps:\n      - run: |\n"
        '          test "$VIRTUAL_ENV" = "$GITHUB_WORKSPACE/.venv"\n'
        '          test "$UV_PROJECT_ENVIRONMENT" = "$GITHUB_WORKSPACE/.venv"\n'
        '          test "$UV_PYTHON" = "$GITHUB_WORKSPACE/.venv/bin/python"\n'
        '          python3 -B -c "import os,sys; '
        "assert sys.prefix == os.environ['GITHUB_WORKSPACE']+'/.venv'\"\n"
        "  second:\n    steps:\n      - run: |\n"
        '          test "$VIRTUAL_ENV" = "$GITHUB_WORKSPACE/.venv"\n'
        '          test "$UV_PROJECT_ENVIRONMENT" = "$GITHUB_WORKSPACE/.venv"\n'
    )
    rc, log = _execute(workflow)
    assert rc == 0, log


def current_default_metadata_selects_the_actual_commit_lint_range() -> None:
    """Published bad legacy messages are outside the actual non-main default range."""
    doc = GATE.load_yaml(HERE.parent / ".github/workflows/commit-message-lint.yml")  # type: ignore[attr-defined]
    block = next(
        step.run
        for step in GATE.steps_of(doc, pathlib.Path("lint.yml"))  # type: ignore[attr-defined]
        if step.name == "Lint the commit messages this event introduces"
    )
    workflow = json.dumps(
        {
            "jobs": {
                "lint": {
                    "steps": [
                        {
                            "env": {
                                "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
                                "PUSH_REF": "${{ github.ref }}",
                                "PR_BASE": "",
                                "PUSH_BEFORE": "",
                            },
                            "run": block,
                        }
                    ]
                }
            }
        }
    )
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        root = directory / "source"
        path = _fixture(workflow, root)
        initial = fixture_git(root, "rev-parse", "HEAD")
        hooks = root / ".githooks"
        hooks.mkdir()
        for name in ("commit-msg", "commit-msg.permitted-paths", "commit-msg.forbidden-words"):
            target = hooks / name
            target.write_bytes((HERE.parent / ".githooks" / name).read_bytes())
            target.chmod((HERE.parent / ".githooks" / name).stat().st_mode & 0o777)
        fixture_git(root, "add", ".")
        fixture_git(
            root,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "test: " + "published legacy subject " * 4,
        )
        published = fixture_git(root, "rev-parse", "HEAD")
        fixture_git(root, "update-ref", "refs/remotes/origin/trunk", published)
        fixture_git(root, "update-ref", "refs/remotes/origin/stale", initial)
        fixture_git(root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/stale")
        (root / "new-change").write_text("selected feature change\n")
        fixture_git(root, "add", ".")
        fixture_git(
            root,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "test: add selected feature change",
        )
        evidence = directory / "evidence"
        with _local_input(root):
            rc = GATE.execute([path], evidence, fixture_authority(root))  # type: ignore[attr-defined]
        assert rc == 0, (evidence / "result.json").read_text()
        output = next(evidence.glob("*/steps/0/stdout")).read_text()
        assert "linting refs/remotes/origin/trunk..HEAD" in output, output
        assert "published legacy subject" not in output, output
        assert fixture_git(root, "symbolic-ref", "refs/remotes/origin/HEAD").endswith("/stale")


def changing_a_job_default_ref_stops_later_history_consumers() -> None:
    """A job may not silently change the history another step will lint."""
    workflow = (
        "jobs:\n  j:\n    steps:\n"
        "      - run: git update-ref -d refs/remotes/origin/trunk\n"
        "      - run: echo WRONG-HISTORY-CONSUMER\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        root = directory / "source"
        path = _fixture(workflow, root)
        packet = fixture_authority(root)
        evidence = directory / "evidence"
        with _local_input(root):
            rc = GATE.execute([path], evidence, packet)  # type: ignore[attr-defined]
        result = json.loads((evidence / "result.json").read_bytes())
        assert rc == 1 and result["ran"] == 1 and result["failed"] >= 1, result
        assert not list(evidence.glob("*/steps/1/stdout")), (
            "consumer ran after its base disappeared"
        )
        assert (
            fixture_git(root, "rev-parse", "refs/remotes/origin/trunk")
            == packet["authority"]["frozen_published_tip"]
        )


def envelope_failure_keeps_executed_counts_and_later_jobs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        root = directory / "source"
        path = _fixture(
            "jobs:\n  broken:\n    steps:\n"
            "      - run: exit 7\n"
            "      - run: printf '\\377' > \"$GITHUB_ENV\"\n"
            "      - name: unreachable consumer\n        run: echo unreachable\n"
            "  next:\n    steps:\n      - run: printf next-job\n",
            root,
        )
        evidence = directory / "evidence"
        with _local_input(root):
            rc = GATE.execute([path], evidence, fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        assert rc == 1
        result = json.loads((evidence / "result.json").read_text())
        assert result["ran"] == 3 and result["failed"] == 2, result
        assert len(result["not_run"]) == 1 and "unreachable" in result["not_run"][0], result
        first = json.loads((evidence / "001-wf-broken/steps/0/result.json").read_text())
        assert first["status"] == "EXECUTED" and first["returncode"] == 7
        assert (evidence / "001-wf-broken/steps/1/GITHUB_ENV").read_bytes() == b"\xff"
        next_step = json.loads((evidence / "002-wf-next/steps/0/result.json").read_text())
        assert next_step["status"] == "EXECUTED" and next_step["returncode"] == 0
        assert (evidence / "002-wf-next/steps/0/stdout").read_bytes() == b"next-job"


def alternate_backed_input_produces_independent_job_objects() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        original = directory / "original"
        _fixture(
            "jobs:\n  first:\n    steps:\n"
            "      - run: test ! -s .git/objects/info/alternates\n"
            "  second:\n    steps:\n"
            "      - run: test ! -s .git/objects/info/alternates\n",
            original,
        )
        borrowed = directory / "borrowed"
        fixture_git(directory, "clone", "--quiet", "--shared", str(original), str(borrowed))
        alternate = borrowed / ".git/objects/info/alternates"
        assert alternate.read_text().strip(), "fixture did not borrow an object store"
        before = alternate.read_bytes()
        annotation = fixture_git(borrowed, "rev-parse", "refs/tags/fixture-tag")
        path = borrowed / ".github/workflows/wf.yml"
        with _local_input(borrowed):
            rc = GATE.execute([path], branch_authority=fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        assert rc == 0, "a job retained the managed input's alternate-object dependency"
        assert alternate.read_bytes() == before
        assert fixture_git(borrowed, "rev-parse", "refs/tags/fixture-tag") == annotation
        assert fixture_git(original, "rev-parse", "refs/tags/fixture-tag") == annotation


def _origin(tmp: pathlib.Path) -> tuple[str, str]:
    """A local repository standing in for github.com/owner/other; (base, sha)."""
    import subprocess  # noqa: PLC0415 -- only this fixture shells out to git

    origin = tmp / "remote" / "owner" / "other.git"
    work = tmp / "seed"
    work.mkdir(parents=True)
    (work / "marker").write_text("fetched\n")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    for command in (
        [*git, "-C", str(work), "init", "-q"],
        [*git, "-C", str(work), "add", "marker"],
        [*git, "-C", str(work), "commit", "--no-gpg-sign", "-q", "-m", "test: seed foreign source"],
        ["git", "clone", "-q", "--bare", str(work), str(origin)],
        ["git", "-C", str(origin), "config", "uploadpack.allowAnySHA1InWant", "true"],
    ):
        subprocess.run(command, check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "-C", str(work), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return f"file://{tmp / 'remote'}", sha


@contextlib.contextmanager
def _checkout_base(base: str) -> Iterator[None]:
    original = GATE.CHECKOUT_BASE  # type: ignore[attr-defined]
    GATE.CHECKOUT_BASE = base  # type: ignore[attr-defined]
    try:
        yield
    finally:
        GATE.CHECKOUT_BASE = original  # type: ignore[attr-defined]


def a_foreign_checkout_is_fetched_and_removed() -> None:
    """A job that checks out another repository reads it here as on the runner.

    The APS comparison checks a third-party repository out at source/aps and
    its next steps run there. The first version of this gate fetched nothing
    and crashed on the missing directory; the second declared the whole job NOT
    RUN, so the comparison never ran before a push. Now the pinned commit is
    fetched into the workspace, the steps read it, and the job's end removes it
    the way a runner discards its workspace.
    """
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = pathlib.Path(tmp_name)
        base, sha = _origin(tmp)
        root = tmp / "workspace"
        root.mkdir()
        workflow = (
            "jobs:\n  j:\n    steps:\n"
            "      - uses: actions/checkout@abc\n"
            f"        with:\n          repository: owner/other\n          ref: {sha}\n"
            "          path: source/other\n"
            "      - run: grep -q fetched marker\n        working-directory: source/other\n"
        )
        with _checkout_base(base):
            rc, log = _execute(workflow, root)
        assert rc == 0 and "RUN   j[1]" in log, f"the fetched checkout was not readable:\n{log}"
        assert not (root / "source").exists(), "the fetched checkout outlived its job"


def a_failed_fetch_stops_its_job() -> None:
    """A checkout that cannot be fetched is NOT RUN with the reason, and so is the
    rest of its job; another job still runs."""
    with tempfile.TemporaryDirectory() as tmp_name:
        root = pathlib.Path(tmp_name)
        workflow = (
            "jobs:\n  j:\n    steps:\n"
            "      - uses: actions/checkout@abc\n"
            "        with:\n          repository: example/other\n          path: source/other\n"
            "      - run: exit 1\n        working-directory: source/other\n"
            "  k:\n    steps:\n      - run: exit 7\n"
        )
        with _checkout_base(f"file://{root / 'nowhere'}"):
            rc, log = _execute(workflow, root)
    assert "NOT RUN  j[0]" in log and "NOT RUN  j[1]" in log and "example/other" in log, (
        f"a step read bytes never fetched:\n{log}"
    )
    assert rc != 0 and "FAIL  k[0]" in log, f"the block leaked into another job:\n{log}"


def a_missing_working_directory_fails_the_step_not_the_gate() -> None:
    """A run block whose directory is absent fails that step; the gate goes on."""
    workflow = (
        "jobs:\n  j:\n    steps:\n"
        "      - run: true\n        working-directory: not/there\n"
        "      - run: exit 5\n"
    )
    rc, log = _execute(workflow)
    assert "NOT RUN  j[0]" in log and "not/there" in log, log
    assert "FAIL  j[1]" in log, f"the gate stopped at the missing directory:\n{log}"
    assert rc != 0


def a_matrix_runs_once_per_combination() -> None:
    """Each combination is its own job, and `matrix.*` reads its value."""
    workflow = (
        "jobs:\n  j:\n    strategy:\n      matrix:\n        python: ['a', 'b']\n"
        "    steps:\n"
        '      - run: test "${{ matrix.python }}" = a\n'
    )
    rc, log = _execute(workflow)
    assert "RUN   j (python=a)[0]" in log and "FAIL  j (python=a)" not in log, log
    assert "FAIL  j (python=b)[0]" in log and rc != 0, log


def each_job_starts_from_a_clean_workspace() -> None:
    """What one job writes into the workspace is gone before the next starts.

    The second REMORA combination refused to overwrite the qualification the
    first had written. A file that was there before the run is left alone.
    """
    with tempfile.TemporaryDirectory() as tmp_name:
        root = pathlib.Path(tmp_name)
        (root / "kept.txt").write_text("before\n")
        workflow = (
            "jobs:\n  j:\n    strategy:\n      matrix:\n        n: [1, 2]\n"
            "    steps:\n"
            "      - run: |\n"
            "          test ! -e out/result\n"
            "          mkdir -p out && echo done > out/result\n"
            "          echo changed > kept.txt.new\n"
        )
        rc, log = _execute(workflow, root)
        assert rc == 0, f"a combination saw what the one before it wrote:\n{log}"
        assert not (root / "out").exists() and not (root / "kept.txt.new").exists(), (
            "the job's output outlived it"
        )
        assert (root / "kept.txt").read_text() == "before\n", "a pre-existing file was touched"


def matrix_include_and_exclude_follow_the_documented_rules() -> None:
    """include extends matching combinations or adds its own; exclude removes."""
    combos, reason = GATE.matrix_combinations(  # type: ignore[attr-defined]
        {
            "strategy": {
                "matrix": {
                    "os": ["x", "y"],
                    "v": [1, 2],
                    "exclude": [{"os": "y", "v": 2}],
                    "include": [{"os": "x", "extra": True}, {"os": "z", "v": 9}],
                }
            }
        }
    )
    assert not reason, reason
    assert combos == [
        {"os": "x", "v": "1", "extra": "true"},
        {"os": "x", "v": "2", "extra": "true"},
        {"os": "y", "v": "1"},
        {"os": "z", "v": "9"},
    ], combos
    combos, reason = GATE.matrix_combinations(  # type: ignore[attr-defined]
        {"strategy": {"matrix": "${{ fromJSON(needs.a.outputs.m) }}"}}
    )
    assert combos == [] and "expression" in reason, (combos, reason)


def inputs_are_null_on_an_event_that_carries_none() -> None:
    """`inputs.x || default` reads the default on push and pull_request, as on a runner.

    GitHub fills the inputs context only for workflow_dispatch and workflow_call;
    on every other event it is empty, so `inputs.ref || github.sha` is the
    commit. The mirror called `inputs.ref` unknown and faulted the MCP SDK job.
    A matrix axis written as fromJSON of such an expression expands too, and a
    fromJSON over another job's output is still refused.
    """
    value, missing = GATE.evaluate(  # type: ignore[attr-defined]
        "inputs.ref || github.sha", {}, None, {"github.event_name": "push", "github.sha": "c0ffee"}
    )
    assert (value, missing) == ("c0ffee", ""), (value, missing)
    value, missing = GATE.evaluate(  # type: ignore[attr-defined]
        "inputs.ref || github.sha",
        {},
        None,
        {"github.event_name": "workflow_dispatch", "github.sha": "c0ffee"},
    )
    assert missing, "a dispatch input was invented instead of refused"
    combos, reason = GATE.matrix_combinations(  # type: ignore[attr-defined]
        {"strategy": {"matrix": {"sdk": "${{ fromJSON(inputs.sdks || '[\"go\",\"rust\"]') }}"}}}
    )
    assert not reason, reason
    assert combos == [{"sdk": "go"}, {"sdk": "rust"}], combos
    combos, reason = GATE.matrix_combinations(  # type: ignore[attr-defined]
        {"strategy": {"matrix": {"sdk": "${{ fromJSON(needs.a.outputs.m) }}"}}}
    )
    assert combos == [] and reason, (combos, reason)


def a_run_block_expression_is_substituted() -> None:
    """`${{ }}` in a run block reaches bash as its value, as on the runner.

    The JEP and REMORA readers pass `--reader-revision "${{
    github.event.pull_request.head.sha || github.sha }}"`; left in place, bash
    read `${{` as a bad substitution and failed a step the remote passes.
    """
    value, missing = GATE.expand(  # type: ignore[attr-defined]
        '--rev "${{ github.event.pull_request.head.sha || github.sha }}"',
        {},
        {},
        {"github.sha": "abc123"},
    )
    assert not missing and value == '--rev "abc123"', (value, missing)
    value, missing = GATE.expand(  # type: ignore[attr-defined]
        "${{ github.event_name == 'push' && 'yes' || 'no' }}", {}, {}, {"github.event_name": "push"}
    )
    assert not missing and value == "yes", (value, missing)
    workflow = 'jobs:\n  j:\n    steps:\n      - run: test -n "${{ runner.temp }}"\n'
    rc, log = _execute(workflow)
    assert rc == 0, f"runner.temp did not reach the run block:\n{log}"


def an_unevaluable_expression_is_not_run() -> None:
    """A function call is refused by name, never approximated."""
    workflow = "jobs:\n  j:\n    steps:\n      - run: echo \"${{ format('{0}', 'x') }}\"\n"
    rc, log = _execute(workflow)
    assert "NOT RUN  j[0]" in log and "format(" in log, log
    assert rc != 0, log


@contextlib.contextmanager
def _provides(action: str, tool: str) -> Iterator[None]:
    original = dict(GATE.PROVIDES)  # type: ignore[attr-defined]
    GATE.PROVIDES[action] = (tool,)  # type: ignore[attr-defined]
    try:
        yield
    finally:
        GATE.PROVIDES.clear()  # type: ignore[attr-defined]
        GATE.PROVIDES.update(original)  # type: ignore[attr-defined]


def a_tool_a_runner_step_provides_is_not_run_when_absent() -> None:
    """An absent declared tool is detected before the dependent shell is attempted."""
    tool = "aee-gate-test-absent-tool"
    workflow = (
        "jobs:\n  j:\n    steps:\n"
        "      - uses: sigstore/cosign-installer@v3\n"
        f"      - run: {tool} sign-blob x\n"
        "      - run: exit 9\n"
    )
    with _provides("sigstore/cosign-installer", tool):
        rc, log = _execute(workflow)
    assert "NOT RUN  j[1]" in log and f"{tool}" in log and "no dependent shell ran" in log, log
    assert "NOT RUN  j[2]" in log and rc != 0, f"missing required setup passed:\n{log}"
    assert "ran 0 steps" in log, f"a step that could not run was counted as run:\n{log}"


def a_script_that_cannot_spawn_the_tool_is_not_run() -> None:
    """release-gate.py runs cosign through subprocess, so a missing cosign is a
    FileNotFoundError traceback rather than the shell's exit 127."""
    tool = "aee-gate-test-absent-tool"
    spawn = f"import subprocess; subprocess.run(['{tool}', 'version'])"
    workflow = (
        "jobs:\n  j:\n    steps:\n"
        "      - uses: sigstore/cosign-installer@v3\n"
        f'      - run: python3 -c "{spawn}"\n'
    )
    with _provides("sigstore/cosign-installer", tool):
        rc, log = _execute(workflow)
    assert "NOT RUN  j[1]" in log and tool in log and "no dependent shell ran" in log, log
    assert rc != 0, log


def a_missing_command_nothing_provides_still_fails() -> None:
    """The balance: a command no step of the job provides is a real failure."""
    workflow = "jobs:\n  j:\n    steps:\n      - run: aee-gate-test-typo-tool --version\n"
    rc, log = _execute(workflow)
    assert "FAIL  j[0]" in log and rc != 0, log


def _fake_python(directory: pathlib.Path, pip_imports: bool) -> pathlib.Path:
    script = directory / "fakepython"
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = -m ]; then echo "$0: No module named pip" >&2; exit 1; fi\n'
        f"exit {0 if pip_imports else 1}\n"
    )
    script.chmod(0o755)
    return script


def an_interpreter_without_pip_is_not_run() -> None:
    """An attempted failing pip command remains native FAIL, with no relabeling."""
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = pathlib.Path(tmp_name)
        for name, imports, expected in (("a", False, "FAIL  j[0]"), ("b", True, "FAIL  j[0]")):
            (tmp / name).mkdir()
            python = _fake_python(tmp / name, imports)
            workflow = (
                f'jobs:\n  j:\n    steps:\n      - run: |\n          "{python}" -m pip install x\n'
            )
            rc, log = _execute(workflow)
            assert expected in log and "No module named pip" in log, log
            assert rc != 0, f"an actually attempted pip command failed but was relabeled: {log}"


def a_tag_only_workflow_runs_only_on_its_tag() -> None:
    """release.yml runs on a push of v* tags and nowhere else, so an untagged
    commit does not run it here either; a commit carrying a matching tag does,
    and any other trigger shape still runs."""
    excludes = GATE.trigger_excludes  # type: ignore[attr-defined]
    release = {"on": {"push": {"tags": ["v*"]}, "workflow_dispatch": None}}
    reason = excludes(release, [])
    assert reason and "v*" in reason, reason
    assert excludes(release, ["v0.17.0"]) == "", "a tagged release was skipped"
    assert excludes(release, ["cited/abc"]) != "", "a non-matching tag ran it"
    for other in (
        {"on": {"push": {"branches": ["main"]}}},
        {"on": {"push": {"tags": ["v*"], "branches": ["main"]}}},
        {"on": {"push": {"tags": ["v*"]}, "pull_request": None}},
        {"on": {"schedule": [{"cron": "0 0 * * *"}]}},
        {True: {"push": None}},
        {"on": "push"},
    ):
        assert excludes(other, []) == "", f"skipped a workflow the remote runs: {other}"


def matrix_include_keeps_original_rows_and_can_restore_excludes() -> None:
    """The documented fruit example has six jobs; later includes do not edit added rows."""
    combinations = GATE.matrix_combinations  # type: ignore[attr-defined]
    combos, reason = combinations(
        {
            "strategy": {
                "matrix": {
                    "fruit": ["apple", "pear"],
                    "animal": ["cat", "dog"],
                    "include": [
                        {"color": "green"},
                        {"color": "pink", "animal": "cat"},
                        {"fruit": "apple", "shape": "circle"},
                        {"fruit": "banana"},
                        {"fruit": "banana", "animal": "cat"},
                    ],
                }
            }
        }
    )
    assert not reason, reason
    assert combos == [
        {"fruit": "apple", "animal": "cat", "color": "pink", "shape": "circle"},
        {"fruit": "apple", "animal": "dog", "color": "green", "shape": "circle"},
        {"fruit": "pear", "animal": "cat", "color": "pink"},
        {"fruit": "pear", "animal": "dog", "color": "green"},
        {"fruit": "banana"},
        {"fruit": "banana", "animal": "cat"},
    ], combos
    combinations = GATE.matrix_combinations  # type: ignore[attr-defined]
    combos, reason = combinations(
        {
            "strategy": {
                "matrix": {
                    "os": ["a", "b"],
                    "exclude": [{"os": "b"}],
                    "include": [{"os": "b"}],
                }
            }
        }
    )
    assert not reason and combos == [{"os": "a"}, {"os": "b"}], (combos, reason)


def matrix_mutations_and_envelopes_are_owned_by_each_combination() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        root = directory / "input"
        root.mkdir()
        (root / "proof.ots").write_bytes(b"original")
        workflow = (
            "env:\n  EXPECTED: '${{ github.sha }}'\njobs:\n  upgrade:\n"
            "    strategy:\n      matrix:\n        n: [1, 2]\n"
            "    steps:\n      - id: producer\n        run: |\n"
            '          test "$(cat proof.ots)" = original\n'
            '          test "$EXPECTED" = "$(git rev-parse HEAD)"\n'
            '          echo "${{ matrix.n }}" > proof.ots\n'
            '          echo "value=${{ matrix.n }}" >> "$GITHUB_OUTPUT"\n'
            '          echo "CARRIED=${{ matrix.n }}" >> "$GITHUB_ENV"\n'
            '      - run: test "$CARRIED" = "${{ steps.producer.outputs.value }}"\n'
            "  verify:\n    steps:\n"
            '      - run: test "$(cat proof.ots)" = original && test -z "${CARRIED:-}"\n'
        )
        path = _fixture(workflow, root)
        evidence = directory / "evidence"
        with (
            _local_input(root),
            open(directory / "log", "w") as out,
            contextlib.redirect_stdout(out),
        ):
            rc = GATE.execute([path], evidence, fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        assert rc == 0, (directory / "log").read_text()
        jobs = sorted(evidence.glob("*-wf-*"))
        assert len(jobs) == 3, jobs
        assert [(job / "changed-tracked/proof.ots").read_bytes() for job in jobs[:2]] == [
            b"1\n",
            b"2\n",
        ]
        identities = [json.loads((job / "source-initial.json").read_text()) for job in jobs]
        assert all(
            row["files"] == identities[0]["files"] and row["tags"] == identities[0]["tags"]
            for row in identities
        )
        assert (root / "proof.ots").read_bytes() == b"original"
        assert json.loads((evidence / "result.json").read_text())["ran"] == 5


def foreign_identity_and_mutations_survive_owned_cleanup() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        base, sha = _origin(directory)
        root = directory / "input"
        workflow = (
            "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@abc\n"
            f"        with:\n          repository: owner/other\n          ref: {sha}\n"
            "          path: source/other\n"
            "      - run: |\n          printf 'changed\\r\\n' > marker\n"
            "          printf added > added.txt\n          ln -s marker link\n"
            "          git add added.txt link\n"
            "        working-directory: source/other\n"
            "  next:\n    steps:\n      - run: test ! -e source/other\n"
        )
        path = _fixture(workflow, root)
        evidence = directory / "evidence"
        with (
            _checkout_base(base),
            _local_input(root),
            open(directory / "log", "w") as out,
            contextlib.redirect_stdout(out),
        ):
            rc = GATE.execute([path], evidence, fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        assert rc == 0, (directory / "log").read_text()
        foreign = evidence / "001-wf-j/foreign/source/other"
        identity = json.loads((foreign / "identity.json").read_text())
        assert identity["selected"]["head"] == sha == identity["final_head"]
        assert (foreign / "selected/marker").read_bytes() == b"fetched\n"
        assert (foreign / "final/marker").read_bytes() == b"changed\r\n"
        assert b"changed" in (foreign / "tracked.diff").read_bytes()
        assert (foreign / "final/added.txt").read_bytes() == b"added"
        assert (foreign / "final/link").read_bytes() == b"marker"
        assert identity["final_files"]["link"]["mode"] == "120000"
        assert not (root / "source").exists()
        fetches = sorted((evidence / "001-wf-j/reports/runner-temp/foreign-fetch/0").glob("*.json"))
        assert len(fetches) == 3 and all(
            json.loads(p.read_text())["returncode"] == 0 for p in fetches
        )


def foreign_escape_and_wrong_sha_are_refused_without_running_consumers() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        base, sha = _origin(directory)
        for selected, path in (
            (sha, "../escape"),
            ("0" * 40, "source/other"),
            ("0", "source/other"),
        ):
            marker = directory / "consumer-ran"
            workflow = (
                "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@abc\n"
                f"        with:\n          repository: owner/other\n          ref: {selected}\n"
                f"          path: {path}\n"
                f"      - run: touch '{marker}'\n"
                "  next:\n    steps:\n      - run: exit 7\n"
            )
            with _checkout_base(base):
                rc, log = _execute(workflow)
            assert rc != 0 and not marker.exists() and "FAIL  next[0]" in log, log
            assert "NOT RUN  j[1]" in log, log


def attempted_missing_tool_and_pip_failures_keep_native_status() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = pathlib.Path(tmp)
        root = directory / "input"
        workflow = (
            "jobs:\n  j:\n    steps:\n"
            "      - run: |\n          printf 'attempted\\r\\n'\n"
            "          aee-absent-after-attempt --version\n"
            '      - run: python3 -c "import subprocess; '
            "subprocess.run(['aee-absent-after-attempt'])\"\n"
        )
        path = _fixture(workflow, root)
        evidence = directory / "evidence"
        with (
            _local_input(root),
            open(directory / "log", "w") as out,
            contextlib.redirect_stdout(out),
        ):
            rc = GATE.execute([path], evidence, fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
        result = json.loads((evidence / "result.json").read_text())
        assert rc == 1 and result["ran"] == result["failed"] == 2, result
        steps = evidence / "001-wf-j/steps"
        assert (steps / "0/stdout").read_bytes() == b"attempted\r\n"
        assert json.loads((steps / "0/result.json").read_text())["returncode"] == 127
        assert b"FileNotFoundError" in (steps / "1/stderr").read_bytes()
        assert json.loads((steps / "1/result.json").read_text())["status"] == "EXECUTED"


def unsupported_matrix_and_with_context_refuse_before_bash() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        marker = pathlib.Path(tmp) / "ran"
        for prefix in (
            "    strategy:\n      matrix: '${{ fromJSON(needs.x.outputs.m) }}'\n",
            "    strategy:\n      matrix:\n        os: [{nested: true}]\n",
        ):
            workflow = "jobs:\n  j:\n" + prefix + f"    steps:\n      - run: touch '{marker}'\n"
            rc, log = _execute(workflow)
            assert rc == 1 and not marker.exists() and "NOT RUN" in log, log
        workflow = (
            "jobs:\n  j:\n    steps:\n      - uses: actions/checkout@abc\n"
            "        with:\n          ref: '${{ unknown.sha }}'\n"
            f"      - run: touch '{marker}'\n"
        )
        rc, log = _execute(workflow)
        assert rc == 1 and "unknown.sha" in log, log
        # The refused checkout must also block consumers; it did not select any source.
        assert not marker.exists(), log


def duplicate_matrix_values_still_get_independent_jobs() -> None:
    workflow = (
        "jobs:\n  j:\n    strategy:\n      matrix:\n        n: ['same', 'same']\n"
        "    steps:\n      - run: |\n"
        "          test ! -e output\n          printf done > output\n"
        '          test "${{ matrix.n }}" = same\n'
    )
    rc, log = _execute(workflow)
    assert rc == 0 and "ran 2 steps" in log, log
    assert "[combination 1]" in log, "equal-valued combinations silently became one job"


def bounded_expression_literals_and_comparisons_match_actions() -> None:
    cases = (
        ("1 == true", "true"),
        ("0 == null", "true"),
        ("2 == true", "false"),
        ("'CASE' == 'case'", "true"),
        ("'2' == 2", "true"),
        ("'not-a-number' == 0", "false"),
        ("'(' == '('", "true"),
        ("'a||b'", "a||b"),
        ("'it''s quoted'", "it's quoted"),
        ("false && 'bad' || 'good'", "good"),
        ("!false", "true"),
    )
    for expression, expected in cases:
        value, problem = GATE.expand("${{ " + expression + " }}", {})  # type: ignore[attr-defined]
        assert not problem and value == expected, (expression, value, problem)
    for expression in ("'unclosed", "'a' 'b'", "unknown.value", "format('a', 'b')"):
        value, problem = GATE.expand("${{ " + expression + " }}", {})  # type: ignore[attr-defined]
        assert problem and value == "", (expression, value, problem)


def setup_python_owns_uv_selection_despite_ambient_pin() -> None:
    """A real seeded setup interpreter must govern uv, even with a conflicting ambient pin."""
    workflow = (
        "jobs:\n  j:\n    steps:\n      - uses: actions/setup-python@abc\n"
        "        with:\n          python-version: '3.13'\n"
        '      - run: uv run --no-project --offline python -c "import sys; '
        'assert sys.version_info[:2] == (3, 13)"\n'
    )
    original = os.environ.get("UV_PYTHON")
    os.environ["UV_PYTHON"] = "9.9.9"
    try:
        with uv_provides(True):
            rc, log = _execute(workflow)
    finally:
        if original is None:
            os.environ.pop("UV_PYTHON", None)
        else:
            os.environ["UV_PYTHON"] = original
    assert rc == 0 and "RUN   j[1]" in log, log


def remote_only_inputs_keep_their_reason_and_raw_evidence() -> None:
    """An unavailable remote dependency is irrelevant to a remote-only action."""
    expression = "${{ needs.visibility.outputs.public == 'true' }}"
    for action in (
        "ossf/scorecard-action",
        "pypa/gh-action-pypi-publish",
        "actions/upload-artifact",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "source"
            evidence = pathlib.Path(tmp) / "evidence"
            workflow = (
                "jobs:\n  j:\n    steps:\n"
                f"      - uses: {action}@pinned\n"
                f'        with:\n          publish_results: "{expression}"\n'
                "      - run: true\n"
            )
            path = _fixture(workflow, root)
            out = pathlib.Path(tmp) / "out.txt"
            with _local_input(root), open(out, "w") as handle, contextlib.redirect_stdout(handle):
                rc = GATE.execute([path], evidence, fixture_authority(path.parents[2]))  # type: ignore[attr-defined]
            result = json.loads(next(evidence.glob("*/steps/0/result.json")).read_text())
            assert rc == 0 and result["status"] == "NOT_RUN" and not result["fault"], result
            reason = action + " " + GATE.CANNOT_RUN[action]  # type: ignore[attr-defined]
            assert result["reason"] == reason, result
            original = json.loads(next(evidence.glob("*/steps/0/input.json")).read_text())
            assert original == {
                "uses": action + "@pinned",
                "with": {"publish_results": expression},
                "if": "",
            }, original
            assert "ran 1 steps, 0 failed" in out.read_text(), out.read_text()


def unknown_action_inputs_still_fault() -> None:
    rc, log = _execute(
        "jobs:\n  j:\n    steps:\n      - uses: unknown/action@pinned\n"
        "        with:\n          value: '${{ needs.remote.outputs.value }}'\n"
        "      - run: true\n"
    )
    assert rc == 1 and "needs.remote.outputs.value" in log and "1 failed" in log, log


def local_action_and_provider_inputs_still_fault() -> None:
    for action, key in (
        ("actions/setup-python", "python-version"),
        ("actions/setup-go", "go-version"),
    ):
        rc, log = _execute(
            f"jobs:\n  j:\n    steps:\n      - uses: {action}@pinned\n"
            f"        with:\n          {key}: '${{{{ needs.remote.outputs.version }}}}'\n"
        )
        assert rc == 1 and "needs.remote.outputs.version" in log and "1 failed" in log, log


def main() -> int:
    check(
        "remote-only inputs retain classification and raw custody",
        remote_only_inputs_keep_their_reason_and_raw_evidence,
    )
    check("unknown action inputs remain a fault", unknown_action_inputs_still_fault)
    check(
        "local action and provider inputs remain a fault",
        local_action_and_provider_inputs_still_fault,
    )
    check("a failing first command is caught", first_command_failing_is_caught)
    check("a failing middle command is caught", middle_command_failing_is_caught)
    check("a failure stops the block", failure_stops_the_block)
    check("an all-succeeding block passes", a_passing_block_still_passes)
    check("pipefail is not set", pipefail_is_not_set)
    check("an unclassified action is a fault", an_unclassified_action_is_a_fault)
    check("a runner-only action names its reason", a_runner_only_action_names_its_reason)
    check("the pinned linter is mirrored", the_pinned_linter_is_mirrored)
    check("a version mismatch is not run", a_version_mismatch_is_not_run_rather_than_a_pass)
    check("an absent linter is not run", an_absent_linter_is_not_run_rather_than_a_pass)
    check("a literal step env reaches the block", a_literal_step_env_reaches_the_block)
    check("a recorded step output is supplied", a_recorded_step_output_is_supplied)
    check("an output of an unrun step is not run", an_output_of_a_step_that_did_not_run_is_not_run)
    check(
        "an output the mirror never wrote is not run",
        an_output_the_mirror_never_wrote_is_not_run,
    )
    check("an unsupplied context is empty", an_unsupplied_context_is_empty_as_it_is_on_a_runner)
    check("the action mirror produces its outputs", the_action_mirror_produces_the_declared_outputs)
    check("a recorded step outcome is supplied", a_recorded_step_outcome_is_supplied)
    check("an outcome of an unrun step is not run", an_outcome_of_an_unrun_step_is_not_run)
    check("continue-on-error is honoured end to end", continue_on_error_is_honoured_end_to_end)
    check(
        "the action mirror fails on a non-pass verdict",
        the_action_mirror_fails_on_a_non_pass_verdict,
    )

    check("a default working directory is honoured", a_default_working_directory_is_honoured)
    check(
        "captured default metadata selects the real lint range",
        current_default_metadata_selects_the_actual_commit_lint_range,
    )
    check(
        "changed job default refs stop later history consumers",
        changing_a_job_default_ref_stops_later_history_consumers,
    )
    check("runner variables carry within a job", github_env_and_runner_temp_carry_within_a_job)
    check("corpus binaries belong to their job", corpus_harness_outputs_are_owned_by_the_job)
    check("job outputs require runner context", job_owned_outputs_require_runner_context)
    check(
        "the action report reaches its consumers",
        action_report_path_reaches_the_summary_and_outputs,
    )
    check(
        "the action's verifier imports this revision",
        action_verifier_imports_resolve_to_the_checkout,
    )
    check("setup-python is mirrored with pip", setup_python_is_mirrored_with_pip)
    check("an unprovidable Python stops its job", an_unprovidable_python_stops_its_job)
    check("a failed foreign fetch stops only its job", a_failed_fetch_stops_its_job)
    check("a step guarded to another event is not run", a_step_guarded_to_another_event_is_not_run)
    check(
        "an ambient VIRTUAL_ENV does not reach the steps",
        an_ambient_virtual_env_does_not_reach_the_steps,
    )
    check(
        "mutating jobs do not contaminate source",
        a_mutating_job_does_not_change_the_next_jobs_source,
    )
    check("reader revision binds actual source SHA", reader_revision_is_the_actual_full_source_sha)
    check(
        "mutation and original process bytes survive cleanup",
        mutations_and_native_report_bytes_survive_job_cleanup,
    )
    check("unknown context refuses before Bash", unknown_context_refuses_execution_before_bash)
    check(
        "multiline expressions have bounded context",
        multiline_expressions_have_the_same_bounded_context,
    )
    check(
        "workflow/job/step environment respects context",
        workflow_job_and_step_environment_use_actual_context,
    )
    check(
        "sparse source and hidden drift have exact identity",
        sparse_inputs_produce_complete_jobs_and_hidden_drift_is_refused,
    )
    check(
        "step outputs and status belong to a job", step_outputs_and_status_do_not_leak_between_jobs
    )
    check("fake or dirty source is refused", selected_source_cannot_be_faked_or_dirty)
    check(
        "job refs do not alter the donor",
        job_tag_ref_changes_are_retained_and_cannot_change_the_donor,
    )
    check(
        "checkout and directory binding is enforced",
        checkout_and_working_directory_bind_to_the_selected_source,
    )
    check("a step may start in the job's runner temp", a_step_may_start_in_the_jobs_runner_temp)
    check(
        "baseline Python and uv environment belong to a job",
        baseline_python_and_uv_environment_belong_to_each_job,
    )
    check(
        "envelope failure retains execution and later jobs",
        envelope_failure_keeps_executed_counts_and_later_jobs,
    )
    check(
        "borrowed input yields independent job objects",
        alternate_backed_input_produces_independent_job_objects,
    )

    check("a foreign checkout is fetched and removed", a_foreign_checkout_is_fetched_and_removed)
    check(
        "a missing working directory fails the step not the gate",
        a_missing_working_directory_fails_the_step_not_the_gate,
    )
    check("a matrix runs once per combination", a_matrix_runs_once_per_combination)
    check("each job starts from a clean workspace", each_job_starts_from_a_clean_workspace)
    check(
        "matrix include and exclude follow the documented rules",
        matrix_include_and_exclude_follow_the_documented_rules,
    )
    check(
        "inputs are null on an event that carries none",
        inputs_are_null_on_an_event_that_carries_none,
    )
    check("a run block expression is substituted", a_run_block_expression_is_substituted)
    check("an unevaluable expression is not run", an_unevaluable_expression_is_not_run)
    check(
        "a tool a runner step provides is not run when absent",
        a_tool_a_runner_step_provides_is_not_run_when_absent,
    )
    check(
        "a script that cannot spawn the tool is not run",
        a_script_that_cannot_spawn_the_tool_is_not_run,
    )
    check(
        "a missing command nothing provides still fails",
        a_missing_command_nothing_provides_still_fails,
    )
    check("an interpreter without pip is not run", an_interpreter_without_pip_is_not_run)
    check("a tag only workflow runs only on its tag", a_tag_only_workflow_runs_only_on_its_tag)

    check(
        "matrix include keeps original rows and can restore excludes",
        matrix_include_keeps_original_rows_and_can_restore_excludes,
    )
    check(
        "matrix mutations and envelopes are owned by each combination",
        matrix_mutations_and_envelopes_are_owned_by_each_combination,
    )
    check(
        "foreign identity and mutations survive owned cleanup",
        foreign_identity_and_mutations_survive_owned_cleanup,
    )
    check(
        "foreign escape and wrong sha are refused without running consumers",
        foreign_escape_and_wrong_sha_are_refused_without_running_consumers,
    )
    check(
        "attempted missing tool and pip failures keep native status",
        attempted_missing_tool_and_pip_failures_keep_native_status,
    )
    check(
        "unsupported matrix and with context refuse before bash",
        unsupported_matrix_and_with_context_refuse_before_bash,
    )

    check(
        "duplicate matrix values retain independent jobs",
        duplicate_matrix_values_still_get_independent_jobs,
    )
    check(
        "bounded expression literals follow Actions",
        bounded_expression_literals_and_comparisons_match_actions,
    )

    check(
        "setup-python owns uv interpreter selection",
        setup_python_owns_uv_selection_despite_ambient_pin,
    )

    if FAILURES:
        print(f"FAIL: {len(FAILURES)} case(s) do not hold:")
        for line in FAILURES:
            print(f"  {line}")
        return 1
    print(f"OK: {len(RAN)} case(s); the local mirror runs steps the way GitHub Actions does.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
