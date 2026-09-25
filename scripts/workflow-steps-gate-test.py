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

Usage: python3 scripts/workflow-steps-gate-test.py
Exit 0 when every case holds; 1 on a summary of failures.
"""

from __future__ import annotations

import contextlib
import importlib.util
import pathlib
import sys
import tempfile
from collections.abc import Callable
from typing import Any

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


@contextlib.contextmanager
def installed(version: str):
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
def _scratch():
    with tempfile.TemporaryDirectory(prefix="aee-gate-test-") as directory:
        yield directory


def run(block: str) -> int:
    return GATE.run_step(block, {"PATH": "/usr/bin:/bin"}).returncode  # type: ignore[attr-defined]


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
        "        run: test \"$OUTCOME\" = failure\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "neg.yml"
        path.write_text(workflow, encoding="utf-8")
        with contextlib.redirect_stdout(open(pathlib.Path(tmp) / "out.txt", "w")):
            rc = GATE.execute([path])  # type: ignore[attr-defined]
    assert rc == 0, f"a continue-on-error failure failed the run (exit {rc})"
    # The balance: the same failure WITHOUT the key still fails the run.
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "pos.yml"
        path.write_text(workflow.replace("        continue-on-error: true\n", ""), encoding="utf-8")
        with contextlib.redirect_stdout(open(pathlib.Path(tmp) / "out.txt", "w")):
            rc = GATE.execute([path])  # type: ignore[attr-defined]
    assert rc != 0, "a failing step without continue-on-error passed the run"


def the_action_mirror_fails_on_a_non_pass_verdict() -> None:
    """The action fails a job on the exit status OR on the summary verdict; so must its mirror."""
    local = GATE.local_equivalent("./", {"verifier": "./aee-verify -json"})  # type: ignore[attr-defined]
    assert local.run is not None, local.reason
    assert "result=pass" in local.run, (
        "the mirror exits on the harness status alone, so a report that does not "
        f"show the verifier running every vector would pass it: {local.run!r}"
    )


def main() -> int:
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

    if FAILURES:
        print(f"FAIL: {len(FAILURES)} case(s) do not hold:")
        for line in FAILURES:
            print(f"  {line}")
        return 1
    print("OK: 20 case(s); the local mirror runs steps the way GitHub Actions does.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
