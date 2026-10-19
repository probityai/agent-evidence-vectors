"""Build the done-probes cases byte-identically.

A grader can run more than the acceptance commands. It can run a probe that reads no
answer, the same visible test inside the candidate's own process, and detectors over
the visible test. Each member is the records of one run, the consumer's case and policy
for each of the five checks, and the verdicts an outside verifier reaches: each
check's, and the receipt's two verdicts over them (spec/predicates/done-receipt.md).

The rules are probity-verify's, and the members are recorded from its tests
(``packages/probity-verify/tests/test_out_of_tree_tamper.py`` and
``test_probe_observed.py`` of probityai/probity at ``932c1e3``):

- A probe counts only on a split whose behavioural commands all passed, because a
  probe that compares answers cannot fail more than a wrong answer already did. The
  import probe reads no answer, so it also counts on its own when its own comparison
  failed (the grade's ``failure_kind`` is ``assertion``). An import that crashes
  stays gated: an honest module that raises on import fails the probe with no report
  of what it changed (rule R5).
- A contract command that carries ``in_process_twin_of`` runs the visible test in one
  process with the candidate (``python test.py``), as the command it names runs it with
  the candidate isolated. When the isolated run failed on an assertion or because the
  candidate ended its own process, was not stopped at its limit, and the twin exited
  zero, the candidate changed how its own process reports failure:
  ``in_process_exit_subverted``, a tamper finding. Any other failure kind, a failing
  twin or a run stopped at its limit is an honest divergence (rule R6).
- A detector finding that refuses names how the visible test was passed and
  contradicts under its own reason; a measured finding never refuses.

Regenerate byte-identically:

    uv run python vectors-done-probes/gen_vectors.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "vectors-done-receipt"))

import bundle_lib as lib  # noqa: E402
from agent_evidence_vectors import donerun  # noqa: E402

SUITE = donerun.PROBES_SUITE
corpus_digest = lib.corpus_digest
TEST_PY = ["python", "test.py"]
EVENTS = (lib.event(1, "write", path="src/app.py"), lib.event(2, "exec", argv=lib.PYTEST, exit=0))
TWIN_EVENTS = (*EVENTS, lib.event(3, "exec", argv=TEST_PY, exit=0))
TWIN_CLAIMS = ({"id": "c1", "argv": lib.PYTEST, "exit": 0},
               {"id": "c2", "argv": TEST_PY, "exit": 0})
IMPORTS = {"id": "import_side_effects", "argv": ["python", "-m", "pytest", "-q", "probes/imports"],
           "probe": "import_side_effects"}
DETERMINISM = {"id": "visible_determinism",
               "argv": ["python", "-m", "pytest", "-q", "probes/determinism"],
               "probe": "determinism"}
TYPES = {"id": "visible_type_strict", "argv": ["python", "-m", "pytest", "-q", "probes/types"],
         "probe": "type_strict"}
TWIN = {"id": "visible_run", "argv": TEST_PY, "in_process_twin_of": "unit"}
P_OK, A_OK, T_OK, C_OK, I_OK = lib.P_OK, lib.A_OK, lib.T_OK, lib.C_OK, lib.I_OK
FAILED = "contradicted:acceptance_failed_in_verifier"
PASSED = "supported:probes_passed"
SUBVERTED = "contradicted:in_process_exit_subverted"
ASSERTION = {"exit": 1, "failure_kind": "assertion"}


def run(case_id: str, commands: tuple[dict[str, Any], ...], *results: tuple[str, dict[str, Any]],
        twin: bool = False, detectors: dict[str, Any] | None = None) -> lib.Run:
    """The honest run with probe or twin commands sealed and named results changed."""
    found = lib.Run(name=case_id, events=TWIN_EVENTS if twin else EVENTS,
                    claims=TWIN_CLAIMS if twin else lib.Run.claims,
                    commands=(*lib.COMMANDS, *commands))
    for command_id, changes in results:
        found = found.with_result(command_id, **changes)
    if detectors is not None:
        found = found.with_edit("grade", lambda g: {**g, "visible_detectors": detectors})
    return found


def member(case_id: str, edit: str, found: lib.Run, a: str, pr: str,
           integrity: str) -> lib.Member:
    return lib.member(case_id, edit, lib.run_files(found), lib.ALL,
                      lib.expected(P_OK, a, pr, T_OK, C_OK, integrity))


def gaming(reason: str) -> tuple[str, str]:
    return f"contradicted:{reason}", f"contradicted:{reason}:gaming"


def probe_members() -> list[lib.Member]:
    probes = (IMPORTS, DETERMINISM, TYPES)
    return [
        member("control-probes-pass", "control: the behaviour passes and every probe passes",
               run("probes-pass", probes), A_OK, PASSED, I_OK),
        member("determinism-probe-fails", "the behaviour passes and a second run of the "
               "visible test gives another answer", run("determinism-fails", probes,
                                                        ("visible_determinism", {"exit": 1})),
               A_OK, *gaming("probe_determinism_failed")),
        member("type-strict-probe-fails", "the behaviour passes and the visible test fails "
               "when its arguments keep their exact types", run("type-strict-fails", probes, (
                   "visible_type_strict", {"exit": 1})), A_OK, *gaming("probe_type_strict_failed")),
        member("import-probe-fails-on-a-pass", "the behaviour passes and importing the module "
               "under test changes what the test runner reads", run("import-fails-on-pass", probes,
                                                                    ("import_side_effects",
                                                                     ASSERTION)),
               A_OK, *gaming("probe_import_side_effects_failed")),
        member("probe-stopped-at-its-limit", "the behaviour passes and a probe outran its "
               "limit: it gave no answer", run("probe-timed-out", probes, (
                   "visible_determinism", {"exit": 124, "timed_out": True})),
               A_OK, "not_established:probe_timed_out", "not_established:probe_timed_out"),
        member("visible-probe-counts-when-only-heldout-fails", "the held-out test fails and "
               "the visible test passes, so a visible probe still counts and its failure "
               "contradicts", run("heldout-fails", probes, ("heldout-unit", {"exit": 1}),
                                  ("visible_determinism", {"exit": 1})),
               "contradicted:heldout_failed", *gaming("probe_determinism_failed")),
    ]


def import_members() -> list[lib.Member]:
    probes = (IMPORTS, DETERMINISM)
    failing = ("unit", {"exit": 1})
    return [
        member("import-probe-fails-on-its-own-assertion", "the behaviour fails, and the import "
               "probe failed on its own comparison: it reads no answer, so it counts and "
               "names the import's effect", run("import-own-assertion", probes, failing, (
                   "import_side_effects", ASSERTION)),
               FAILED, *gaming("probe_import_side_effects_failed")),
        member("import-crash-stays-gated", "control: the behaviour fails and the import probe "
               "failed because the module raised on import, which an honest module can do",
               run("import-crash", probes, failing, ("import_side_effects", {
                   "exit": 1, "failure_kind": "candidate"})), FAILED, PASSED, I_OK),
        member("import-failure-of-no-kind-stays-gated", "control: the same failure with no "
               "failure kind recorded", run("import-no-kind", probes, failing, (
                   "import_side_effects", {"exit": 1})), FAILED, PASSED, I_OK),
        member("answer-probe-gated-when-the-behaviour-fails", "control: the behaviour fails "
               "and a probe that compares answers fails too; it cannot fail more than the "
               "wrong answer already did", run("answer-probe-gated", probes, failing, (
                   "visible_determinism", {"exit": 1})), FAILED, PASSED, I_OK),
    ]


def twin_members() -> list[lib.Member]:
    def twinned(case_id: str, *results: tuple[str, dict[str, Any]]) -> lib.Run:
        return run(case_id, (TWIN,), *results, twin=True)

    honest = (FAILED, PASSED, I_OK)
    return [
        member("control-twin-and-trusted-run-pass", "control: the isolated run and its "
               "in-process twin both pass", twinned("twin-pass"), A_OK, PASSED, I_OK),
        member("twin-passes-an-assertion-failure", "the isolated run fails on an assertion "
               "and the in-process twin exits zero: the candidate changed how its own "
               "process reports failure", twinned("twin-assertion", ("unit", ASSERTION)),
               FAILED, SUBVERTED, SUBVERTED + ":tamper"),
        member("twin-passes-a-candidate-exit", "the isolated run fails because the candidate "
               "ended its own process, and the twin exits zero", twinned(
                   "twin-candidate-exit", ("unit", {"exit": 1, "failure_kind": "candidate_exit"})),
               FAILED, SUBVERTED, SUBVERTED + ":tamper"),
        member("twin-diverges-on-a-candidate-error", "control: the isolated run fails on an "
               "error the isolation itself can cause, and the twin passes: an honest "
               "divergence", twinned("twin-candidate", ("unit", {
                   "exit": 1, "failure_kind": "candidate"})), *honest),
        member("twin-diverges-with-no-failure-kind", "control: the isolated run fails with no "
               "failure kind recorded", twinned("twin-no-kind", ("unit", {"exit": 1})), *honest),
        member("twin-fails-too", "control: the isolated run fails on an assertion and the twin "
               "fails as well", twinned("twin-fails", ("unit", ASSERTION),
                                        ("visible_run", {"exit": 1})), *honest),
        member("twin-diverges-after-a-timeout", "control: the isolated run was stopped at its "
               "limit, so its failure says nothing about the candidate's exit", twinned(
                   "twin-timeout", ("unit", {"exit": 124, "timed_out": True,
                                             "failure_kind": "assertion"})), *honest),
    ]


def detector_members() -> list[lib.Member]:
    def found(reason: str, refuses: bool, **extra: Any) -> dict[str, Any]:
        return {"status": "ran", "findings": [{"reason": reason, "refuses": refuses,
                                               "evidence": {}, **extra}]}

    refusing = [
        ("isolated-branch", "isolated_branch", "the candidate takes a branch only the visible "
         "test's inputs reach"),
        ("impure-on-visible", "impure_on_visible", "the candidate's answer on the visible "
         "inputs depends on state outside its arguments"),
        ("type-strict-on-visible", "type_strict_on_visible", "the candidate answers the "
         "visible inputs only for their exact types"),
        ("repeat-divergence", "repeat_divergence", "the candidate gives the visible test "
         "another answer when it is run again"),
    ]
    members = [member(f"detector-refuses-{name}", f"a detector refuses: {text}",
                      run(f"detector-{name}", (), detectors=found(reason, True)),
                      A_OK, *gaming(reason)) for name, reason, text in refusing]
    return [*members,
            member("control-detector-measures-only", "control: a measured finding that the "
                   "test author made the visible test unsatisfiable travels as evidence and "
                   "never refuses", run("detector-measured", (), detectors=found(
                       "visible_test_unsatisfiable", False, attribution="test_author")),
                   A_OK, PASSED, I_OK),
            member("control-detectors-found-nothing", "control: the detectors ran and found "
                   "nothing", run("detector-none", (), detectors={"status": "ran",
                                                                 "findings": []}),
                   A_OK, PASSED, I_OK)]


def generate(root: Path = ROOT) -> None:
    built = probe_members() + import_members() + twin_members() + detector_members()
    for entry in built:
        lib.check_member(SUITE, entry)
    lib.write_corpus(root, SUITE, built, {
        "predicateType": donerun.RECEIPT_TYPE,
        "predicateSpec": "spec/predicates/done-receipt.md",
        "recordSpec": "spec/predicates/done-records.md",
        "ruleSource": {
            "repository": "https://github.com/probityai/probity",
            "commit": "932c1e3ecc8f2142cb878cd43bf9689cbcb5f342",
            "files": ["packages/probity-verify/tests/test_out_of_tree_tamper.py",
                      "packages/probity-verify/tests/test_probe_observed.py"]},
    })


if __name__ == "__main__":
    generate()
