"""Generate the verifier isolation vectors the rego module is held to.

    python3 rego/gen_verifier_isolation_vectors.py           # write the file
    python3 rego/gen_verifier_isolation_vectors.py --check   # exit 1 on drift

Every vector is a function of this file. The baseline is a done receipt statement whose
isolation report closes all nine vectors of terminal-bench issue 2086; every other case is the
baseline with one fact opened, removed or mistyped, and carries the exact refusal set the
module must return. A case names the obligation it opens (`opens`), which is what the
conformance harness counts to decide an obligation is measured: an obligation needs at least
one case that opens it and a baseline that admits.

The outputs are `rego/verifier_isolation_vectors.json`, which `opa test rego/` loads as data
under `verifier_isolation_vectors`, and `rego/verifier_isolation_test.rego`, which holds one
test per case so a failure names it. The test file is written here too, so a case can neither
lack a test nor keep one after it is removed.
Nothing here needs a signing library: the module reads a statement after the engine has
verified its envelope.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
OUT = HERE / "verifier_isolation_vectors.json"
TEST_OUT = HERE / "verifier_isolation_test.rego"

PREDICATE_URI = "https://probityai.github.io/probity/predicate/v1/done-receipt"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PINS = {"signature_verified_upstream": True}


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


CONTRACT = _hex("done contract")
TREE = _hex("final tree")
TRUSTED = _hex("trusted tests and runner")


def baseline_report() -> dict[str, Any]:
    """An isolation report that closes V1 to V9."""
    return {
        "contract_sha256": CONTRACT,
        "trusted_tree": {"expected_sha256": TRUSTED, "measured_sha256": TRUSTED, "excluded_names_reset": True},
        "worker": {
            "uid": 65534,
            "supplementary_groups": [],
            "env_scrubbed": True,
            "scratch_copy": True,
        },
        "verifier": {
            "uid": 0,
            "assertions_in_parent": True,
            "python_isolated": True,
            "replay_parent": {"runtime": "docker", "uid": 65534, "env": ["HOME", "LANG", "PATH", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "PYTHONNOUSERSITE"]},
        },
        "result": {"dir_mode": "0700", "precleared": True, "written_by": "verifier", "files_read": ["reward.txt"]},
        "tests": {"expected": 12, "collected": 12, "skipped": 0, "exit_status_alone_accepted": False},
        "processes": {"worker_killed": True, "remaining": 0, "killed_step": 41, "result_read_step": 44},
        "staging": {"nofollow": True, "destination_removed_first": True, "special_files_rejected": True},
        "evidence_from_worker": [],
        "reference": {"dir_mode": "0700", "inside_artifact_dir": False},
        "loaders": [{"name": "json", "safe": True}, {"name": "torch.load weights_only", "safe": True}],
    }


def statement(report: Any = "baseline") -> dict[str, Any]:
    body = baseline_report() if report == "baseline" else report
    predicate: dict[str, Any] = {"contract_sha256": CONTRACT}
    if body is not None:
        predicate["verifier_isolation"] = body
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "final-tree", "digest": {"sha256": TREE}}],
        "predicateType": PREDICATE_URI,
        "predicate": predicate,
    }


def case(name: str, description: str, reasons: list[str], opens: str | None, *, report: Any = "baseline",
         consumer: dict[str, Any] | None = None, mutate: Any = None, raw: dict[str, Any] | None = None) -> dict[str, Any]:
    if raw is not None:
        stmt = raw
    else:
        rep = baseline_report() if report == "baseline" else report
        if mutate is not None and rep is not None:
            rep = copy.deepcopy(rep)
            mutate(rep)
        stmt = statement(rep)
    return {
        "name": name,
        "description": description,
        "input": stmt,
        "consumer": PINS if consumer is None else consumer,
        "reasons": sorted(reasons),
        "opens": opens,
    }


def _set(path: str, value: Any):
    keys = path.split(".")

    def go(rep: dict[str, Any]) -> None:
        cur = rep
        for k in keys[:-1]:
            cur = cur[k]
        cur[keys[-1]] = value

    return go


def _drop(path: str):
    keys = path.split(".")

    def go(rep: dict[str, Any]) -> None:
        cur = rep
        for k in keys[:-1]:
            cur = cur[k]
        del cur[keys[-1]]

    return go


def cases() -> list[dict[str, Any]]:
    c = case
    out = [
        c("baseline-admitted", "the isolation report closes all nine vectors", [], None),
        # -- the statement as a whole
        c("signature-undeclared", "the consumer never declared an upstream signature check", ["signature_verification_undeclared"], None, consumer={}),
        c("statement-type-wrong", "not an in-toto Statement v1", ["unsupported_statement_type"], None,
          raw={**statement(), "_type": "https://example.invalid/Statement/v9"}),
        c("predicate-type-wrong", "another predicate type", ["unsupported_predicate"], None,
          raw={**statement(), "predicateType": "https://example.invalid/predicate/other"}),
        c("report-missing", "a receipt that carries no isolation report opens every vector",
          ["isolation_report_missing", "contract_digest_invalid", "vi-1:trusted_tree_not_reset_to_contract", "vi-1:excluded_names_not_reset",
           "vi-2:worker_not_unprivileged", "vi-2:worker_supplementary_groups_kept", "vi-2:assertions_not_in_parent", "vi-2:trusted_python_not_isolated",
           "vi-2:replay_parent_not_contained", "vi-2:replay_parent_shares_verifier_uid", "vi-2:replay_parent_environment_not_scrubbed",
           "vi-3:result_dir_open_to_worker", "vi-3:result_not_precleared", "vi-3:result_not_written_by_verifier", "vi-3:result_source_ambiguous",
           "vi-4:no_tests_expected", "vi-4:test_count_mismatch", "vi-4:tests_skipped", "vi-4:verdict_from_exit_status_alone",
           "vi-5:worker_processes_not_killed", "vi-5:worker_processes_remain", "vi-5:result_read_before_kill",
           "vi-6:links_followed", "vi-6:destination_not_removed_first", "vi-6:special_files_admitted",
           "vi-7:evidence_taken_from_worker", "vi-7:environment_not_scrubbed", "vi-7:no_scratch_copy",
           "vi-8:reference_readable_by_worker", "vi-8:reference_inside_artifact", "vi-9:loaders_undeclared"],
          "all", report=None),
        c("contract-pin-matches", "the consumer pins the contract the report names", [], None,
          consumer={**PINS, "expected_contract_sha256": CONTRACT}),
        c("contract-pin-mismatch", "the report names another contract than the one pinned", ["contract_digest_mismatch"], None,
          consumer={**PINS, "expected_contract_sha256": _hex("another contract")}),
        c("contract-digest-invalid", "the contract digest is not 64 lowercase hex", ["contract_digest_invalid"], None,
          mutate=_set("contract_sha256", "ABC")),
        # -- vi-1 V1 Overwrite
        c("vi1-trusted-tree-differs", "the trusted files measured before grading are not the contract's", ["vi-1:trusted_tree_not_reset_to_contract"], "vi-1",
          mutate=_set("trusted_tree.measured_sha256", _hex("a test file the agent replaced"))),
        c("vi1-trusted-tree-undeclared", "no expected digest, so nothing was compared", ["vi-1:trusted_tree_not_reset_to_contract"], "vi-1",
          mutate=_drop("trusted_tree.expected_sha256")),
        c("vi1-excluded-names-kept", "a poisoned bytecode cache survives because excluded names were not reset", ["vi-1:excluded_names_not_reset"], "vi-1",
          mutate=_set("trusted_tree.excluded_names_reset", False)),
        # -- vi-2 V2 Patch
        c("vi2-worker-is-root", "submitted code ran as uid 0", ["vi-2:worker_not_unprivileged"], "vi-2", mutate=_set("worker.uid", 0)),
        c("vi2-worker-is-verifier", "submitted code ran as the verifier's own uid", ["vi-2:worker_not_unprivileged"], "vi-2",
          mutate=lambda r: (r["verifier"].__setitem__("uid", 1000), r["worker"].__setitem__("uid", 1000))),
        c("vi2-worker-uid-string", "the uid is a string, not a number", ["vi-2:worker_not_unprivileged"], "vi-2", mutate=_set("worker.uid", "65534")),
        c("vi2-groups-kept", "supplementary groups were not cleared", ["vi-2:worker_supplementary_groups_kept"], "vi-2",
          mutate=_set("worker.supplementary_groups", [27])),
        c("vi2-groups-undeclared", "no statement about supplementary groups", ["vi-2:worker_supplementary_groups_kept"], "vi-2",
          mutate=_drop("worker.supplementary_groups")),
        c("vi2-assertions-with-submission", "assertions ran in the process that imported the submission", ["vi-2:assertions_not_in_parent"], "vi-2",
          mutate=_set("verifier.assertions_in_parent", False)),
        c("vi2-python-not-isolated", "trusted Python saw the artifact directory on its path", ["vi-2:trusted_python_not_isolated"], "vi-2",
          mutate=_set("verifier.python_isolated", False)),
        c("vi2-flag-is-string", "the flag is the string true, which closes nothing", ["vi-2:assertions_not_in_parent"], "vi-2",
          mutate=_set("verifier.assertions_in_parent", "true")),
        c("vi2-replay-parent-on-host", "the parent that ran the sealed tests ran on the verifier host, as the verifier's uid",
          ["vi-2:replay_parent_not_contained", "vi-2:replay_parent_shares_verifier_uid"], "vi-2",
          mutate=lambda r: r["verifier"].__setitem__("replay_parent", {**r["verifier"]["replay_parent"], "runtime": "host", "uid": 0})),
        c("vi2-replay-parent-claims-container-as-verifier", "the record names a container, but the parent measured the verifier's own uid",
          ["vi-2:replay_parent_shares_verifier_uid"], "vi-2", mutate=_set("verifier.replay_parent.uid", 0)),
        c("vi2-replay-parent-unverified", "the parent never reported the host name of the container it was launched in",
          ["vi-2:replay_parent_not_contained"], "vi-2", mutate=_set("verifier.replay_parent.runtime", "unverified")),
        c("vi2-replay-parent-unrecorded", "no statement about where the parent ran",
          ["vi-2:replay_parent_not_contained", "vi-2:replay_parent_shares_verifier_uid", "vi-2:replay_parent_environment_not_scrubbed"], "vi-2",
          mutate=_drop("verifier.replay_parent")),
        c("vi2-replay-parent-root", "the parent ran as uid 0", ["vi-2:replay_parent_shares_verifier_uid"], "vi-2",
          mutate=lambda r: (r["verifier"].__setitem__("uid", 1000), r["verifier"]["replay_parent"].__setitem__("uid", 0))),
        c("vi2-replay-parent-runtime-socket", "the parent's environment names the container runtime",
          ["vi-2:replay_parent_environment_not_scrubbed"], "vi-2",
          mutate=lambda r: r["verifier"]["replay_parent"]["env"].append("DOCKER_HOST")),
        c("vi2-replay-parent-env-undeclared", "no statement about the parent's environment",
          ["vi-2:replay_parent_environment_not_scrubbed"], "vi-2", mutate=_drop("verifier.replay_parent.env")),
        # -- vi-3 V3 Reward
        c("vi3-result-dir-777", "the result directory is world-writable, as Harbor leaves it", ["vi-3:result_dir_open_to_worker"], "vi-3",
          mutate=_set("result.dir_mode", "0777")),
        c("vi3-result-dir-group", "the result directory is open to its group", ["vi-3:result_dir_open_to_worker"], "vi-3",
          mutate=_set("result.dir_mode", "770")),
        c("vi3-result-dir-undeclared", "no mode recorded", ["vi-3:result_dir_open_to_worker"], "vi-3", mutate=_drop("result.dir_mode")),
        c("vi3-not-precleared", "a reward file from before the run was not removed", ["vi-3:result_not_precleared"], "vi-3",
          mutate=_set("result.precleared", False)),
        c("vi3-written-by-worker", "the result was written by the worker", ["vi-3:result_not_written_by_verifier"], "vi-3",
          mutate=_set("result.written_by", "worker")),
        c("vi3-two-sources", "two reward files were candidates, so which one counted depends on read order", ["vi-3:result_source_ambiguous"], "vi-3",
          mutate=_set("result.files_read", ["reward.json", "reward.txt"])),
        c("vi3-no-source", "no reward file was read", ["vi-3:result_source_ambiguous"], "vi-3", mutate=_set("result.files_read", [])),
        # -- vi-4 V4 Fail-open
        c("vi4-no-tests", "the suite is empty", ["vi-4:no_tests_expected"], "vi-4",
          mutate=lambda r: r["tests"].update({"expected": 0, "collected": 0})),
        c("vi4-fewer-collected", "fewer tests ran than the contract expects", ["vi-4:test_count_mismatch"], "vi-4",
          mutate=_set("tests.collected", 7)),
        c("vi4-skipped", "tests were skipped and counted as passes", ["vi-4:tests_skipped"], "vi-4", mutate=_set("tests.skipped", 3)),
        c("vi4-skipped-undeclared", "no skip count at all", ["vi-4:tests_skipped"], "vi-4", mutate=_drop("tests.skipped")),
        c("vi4-exit-status-alone", "exit status zero was taken as the verdict", ["vi-4:verdict_from_exit_status_alone"], "vi-4",
          mutate=_set("tests.exit_status_alone_accepted", True)),
        # -- vi-5 V5 Sleeper
        c("vi5-not-killed", "the worker's processes were not killed", ["vi-5:worker_processes_not_killed"], "vi-5",
          mutate=_set("processes.worker_killed", False)),
        c("vi5-remaining", "a worker process was still alive after the kill", ["vi-5:worker_processes_remain"], "vi-5",
          mutate=_set("processes.remaining", 1)),
        c("vi5-read-before-kill", "the result was read before the kill", ["vi-5:result_read_before_kill"], "vi-5",
          mutate=lambda r: r["processes"].update({"killed_step": 50, "result_read_step": 44})),
        c("vi5-steps-equal", "the kill and the read share one step, so their order is unknown", ["vi-5:result_read_before_kill"], "vi-5",
          mutate=lambda r: r["processes"].update({"killed_step": 44, "result_read_step": 44})),
        # -- vi-6 V6 Staging
        c("vi6-links-followed", "a symlink in the submission was followed", ["vi-6:links_followed"], "vi-6", mutate=_set("staging.nofollow", False)),
        c("vi6-destination-kept", "the copy destination was not removed first", ["vi-6:destination_not_removed_first"], "vi-6",
          mutate=_set("staging.destination_removed_first", False)),
        c("vi6-special-files", "device nodes and sockets in the submission were admitted", ["vi-6:special_files_admitted"], "vi-6",
          mutate=_set("staging.special_files_rejected", False)),
        # -- vi-7 V7 Forgery
        c("vi7-worker-evidence", "a timer reading came from the worker's own output", ["vi-7:evidence_taken_from_worker"], "vi-7",
          mutate=_set("evidence_from_worker", ["elapsed_ms"])),
        c("vi7-worker-evidence-undeclared", "the list was not recorded", ["vi-7:evidence_taken_from_worker"], "vi-7", mutate=lambda r: r.pop("evidence_from_worker")),
        c("vi7-env-not-scrubbed", "verifier secrets stayed in the worker's environment", ["vi-7:environment_not_scrubbed"], "vi-7",
          mutate=_set("worker.env_scrubbed", False)),
        c("vi7-no-scratch-copy", "the worker ran on the verifier's own tree", ["vi-7:no_scratch_copy"], "vi-7", mutate=_set("worker.scratch_copy", False)),
        # -- vi-8 V8 Disclosure
        c("vi8-reference-readable", "reference outputs are readable by the worker", ["vi-8:reference_readable_by_worker"], "vi-8",
          mutate=_set("reference.dir_mode", "0755")),
        c("vi8-reference-undeclared", "no mode recorded for the reference outputs", ["vi-8:reference_readable_by_worker"], "vi-8",
          mutate=_drop("reference.dir_mode")),
        c("vi8-reference-in-artifact", "reference outputs sit inside the artifact directory", ["vi-8:reference_inside_artifact"], "vi-8",
          mutate=_set("reference.inside_artifact_dir", True)),
        # -- vi-9 V9 Exploit
        c("vi9-unsafe-loader", "a pickle loader read submitted data in a privileged process", ["vi-9:unsafe_loader:torch.load"], "vi-9",
          mutate=_set("loaders", [{"name": "json", "safe": True}, {"name": "torch.load", "safe": False}])),
        c("vi9-unnamed-unsafe-loader", "an unsafe loader with no name", ["vi-9:unsafe_loader:unnamed"], "vi-9",
          mutate=_set("loaders", [{"safe": False}])),
        c("vi9-loader-safe-undeclared", "a loader that does not say it is safe is not safe", ["vi-9:unsafe_loader:yaml.load"], "vi-9",
          mutate=_set("loaders", [{"name": "yaml.load"}])),
        c("vi9-no-loaders", "the report lists no loaders, so nothing was accounted for", ["vi-9:loaders_undeclared"], "vi-9", mutate=_set("loaders", [])),
    ]
    return out


def render() -> str:
    cs = cases()
    names = [x["name"] for x in cs]
    if len(set(names)) != len(names):
        raise SystemExit("verifier isolation vectors: duplicate case name")
    doc = {
        "verifier_isolation_vectors": {
            "predicate_type": PREDICATE_URI,
            "contract_sha256": CONTRACT,
            "cases": {x["name"]: x for x in cs},
        }
    }
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


TEST_HEAD = """# Tests for verifier_isolation.rego, one per vector in verifier_isolation_vectors.json.
#
# Written by gen_verifier_isolation_vectors.py; never edit it by hand. A failure names the
# case, and a case the generator drops loses its test in the same write.

package verifier_isolation_test

import data.verifier_isolation
import rego.v1

vectors := data.verifier_isolation_vectors.cases

reasons_for(name) := r if {
	c := vectors[name]
	r := verifier_isolation.reasons with input as c.input
		with data.verifier_isolation_consumer as c.consumer
}

compliant_for(name) := v if {
	c := vectors[name]
	v := verifier_isolation.isCompliant with input as c.input
		with data.verifier_isolation_consumer as c.consumer
}

holds(name) if {
	want := sort(vectors[name].reasons)
	reasons_for(name) == want
	count(want) == 0
	compliant_for(name) == true
}

holds(name) if {
	want := sort(vectors[name].reasons)
	reasons_for(name) == want
	count(want) > 0
	compliant_for(name) == false
}
"""


def render_tests() -> str:
    names = sorted(x["name"] for x in cases())
    out = [TEST_HEAD]
    for n in names:
        ident = "test_" + n.replace("-", "_")
        out.append(f'{ident} if holds("{n}")\n')
    listed = ",\n".join(f'\t"{n}"' for n in names)
    out.append(
        "tested := {\n" + listed + ",\n}\n\n"
        "# A vector with no test above would pass unseen.\n"
        "test_every_vector_has_a_test if {\n\tcount(vectors) == count(tested)\n\tevery name in tested {\n\t\tvectors[name]\n\t}\n}\n"
    )
    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the committed file differs")
    args = parser.parse_args(argv[1:])
    rendered = render()
    count = len(json.loads(rendered)["verifier_isolation_vectors"]["cases"])
    tests = render_tests()
    if args.check:
        for path, want in ((OUT, rendered), (TEST_OUT, tests)):
            if not path.is_file() or path.read_text(encoding="utf-8") != want:
                print(f"{path.name} is not what this generator renders; regenerate it and commit", file=sys.stderr)
                return 1
        print(f"check: {OUT.name} and {TEST_OUT.name} regenerate byte for byte ({count} cases)")
        return 0
    OUT.write_text(rendered, encoding="utf-8")
    TEST_OUT.write_text(tests, encoding="utf-8")
    print(f"wrote {OUT} ({count} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
