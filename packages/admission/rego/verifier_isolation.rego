# Verifier isolation: admit a done verdict only when the verifier that produced it was isolated
# from the code it graded.
#
# WHAT THIS DECIDES. A coding agent says it is done, and a verifier decides whether that is
# true by running the contract's acceptance commands on the agent's final tree. The verdict is
# only worth what the verifier's isolation is worth: terminal-bench issue 2086 lists nine ways
# submitted code reaches into a verifier (V1 to V9) and a minimum seven-step hardening that
# closes most of them. This module turns each of the nine into one obligation, vi-1 to vi-9,
# and refuses a done receipt whose own isolation report shows one open.
#
# THE INPUT. An in-toto Statement v1 after the engine's key authority verified its envelope, as
# for the other rule sets here. Its predicate type is the done receipt's, and the isolation
# facts sit in `predicate.verifier_isolation`, written by the verifier harness at the end of the
# grading run. The shape is in docs/VERIFIER-ISOLATION.md.
#
# FAIL CLOSED. A fact that is absent, or of the wrong type, is an open obligation: every rule
# below asks for the closing fact to be present and true, never for the opening fact to be
# absent. A report that says nothing about the result directory fails vi-3.
#
# WHAT THIS CANNOT KNOW. The report is the verifier's account of itself. This module checks
# that the account closes each vector, not that the account is true. Whether the verifier
# really ran as it says is the observer's job (the done receipt's observation record carries
# the vantage), and a consumer that needs more than the verifier's word pins an independent
# observation as well. Rego has no signature check; the engine verifies the envelope first.
#
# CONSUMER PINS, read from data.verifier_isolation_consumer:
#   signature_verified_upstream  true when a verifier checked the envelope signature before
#                                this rule. Required.
#   expected_contract_sha256     the contract digest this deployment grades against. Optional;
#                                compared whenever present.
#
# Every refusal is a string in `errors`, spelled `vi-N:<reason>` for an obligation or a plain
# word for the statement as a whole. `isCompliant` holds when there is none.

package verifier_isolation

import rego.v1

predicate_uri := "https://probityai.github.io/probity/predicate/v1/done-receipt"

statement_type := "https://in-toto.io/Statement/v1"

hex64 := `^[0-9a-f]{64}$`

# A file mode written as octal digits: three or four, optionally with a leading zero.
mode_pattern := `^0?[0-7]{3}$`

default consumer := {}

consumer := data.verifier_isolation_consumer if is_object(data.verifier_isolation_consumer)

# ---------------------------------------------------------------------------
# The statement
# ---------------------------------------------------------------------------

errors contains "signature_verification_undeclared" if {
	object.get(consumer, "signature_verified_upstream", false) != true
}

errors contains "unsupported_statement_type" if {
	object.get(input, "_type", null) != statement_type
}

errors contains "unsupported_predicate" if {
	object.get(input, "predicateType", null) != predicate_uri
}

errors contains "isolation_report_missing" if {
	not report_present
}

report_present if is_object(object.get(object.get(input, "predicate", {}), "verifier_isolation", null))

# From here on a missing report is read as an empty object, so every obligation below refuses
# it too. A statement with no report has opened all nine, and says so nine times.
report := object.get(object.get(input, "predicate", {}), "verifier_isolation", {}) if report_present

default report := {}

section(name) := s if {
	s := object.get(report, name, {})
	is_object(s)
} else := {}

# True only for the boolean true. A string "true", a number 1 or an absent key is not true.
closed(obj, key) if object.get(obj, key, null) == true

is_hex(v) if {
	is_string(v)
	regex.match(hex64, v)
}

# A mode with group and other bits all clear: the owner may hold any permission, nobody else
# holds any. `700`, `0700` and `600` pass; `770`, `755` and `777` do not.
private_mode(v) if {
	is_string(v)
	regex.match(mode_pattern, v)
	d := split(v, "")
	d[count(d) - 1] == "0"
	d[count(d) - 2] == "0"
}

errors contains "contract_digest_mismatch" if {
	pin := object.get(consumer, "expected_contract_sha256", null)
	pin != null
	object.get(report, "contract_sha256", null) != pin
}

errors contains "contract_digest_invalid" if {
	not is_hex(object.get(report, "contract_sha256", null))
}

# ---------------------------------------------------------------------------
# vi-1  V1 Overwrite: trusted tests, runner and dependencies are restored from the contract.
# ---------------------------------------------------------------------------

trusted := section("trusted_tree")

errors contains "vi-1:trusted_tree_not_reset_to_contract" if {
	not trusted_tree_matches
}

trusted_tree_matches if {
	is_hex(object.get(trusted, "expected_sha256", null))
	object.get(trusted, "measured_sha256", null) == object.get(trusted, "expected_sha256", null)
}

errors contains "vi-1:excluded_names_not_reset" if {
	not closed(trusted, "excluded_names_reset")
}

# ---------------------------------------------------------------------------
# vi-2  V2 Patch: submitted code never shares a process with the assertions.
# ---------------------------------------------------------------------------

worker := section("worker")

verifier := section("verifier")

errors contains "vi-2:worker_not_unprivileged" if {
	not worker_unprivileged
}

worker_unprivileged if {
	w := object.get(worker, "uid", null)
	v := object.get(verifier, "uid", null)
	is_number(w)
	is_number(v)
	w != 0
	w != v
}

errors contains "vi-2:worker_supplementary_groups_kept" if {
	not worker_groups_cleared
}

worker_groups_cleared if {
	groups := object.get(worker, "supplementary_groups", null)
	is_array(groups)
	count(groups) == 0
}

errors contains "vi-2:assertions_not_in_parent" if {
	not closed(verifier, "assertions_in_parent")
}

errors contains "vi-2:trusted_python_not_isolated" if {
	not closed(verifier, "python_isolated")
}

# The parent that holds the assertions runs the task's own test code (its test files and
# conftests), so it is held to the worker's isolation from the verifier as well: it runs in a
# container of its own, as a uid that is neither root nor the verifier's, with an environment
# of neutral names only. `verifier.replay_parent` is the parent's own measurement of where it
# ran; a parent left on the verifier host reads `host`, or the verifier's uid, and is refused.
replay_parent := p if {
	p := object.get(verifier, "replay_parent", null)
	is_object(p)
} else := {}

replay_parent_runtimes := {"docker", "podman"}

replay_parent_env_names := {"HOME", "LANG", "LC_ALL", "PATH", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "PYTHONNOUSERSITE", "TMPDIR", "TZ"}

errors contains "vi-2:replay_parent_not_contained" if {
	not replay_parent_runtimes[object.get(replay_parent, "runtime", null)]
}

errors contains "vi-2:replay_parent_shares_verifier_uid" if {
	not replay_parent_own_uid
}

replay_parent_own_uid if {
	p := object.get(replay_parent, "uid", null)
	v := object.get(verifier, "uid", null)
	is_number(p)
	is_number(v)
	p != 0
	p != v
}

errors contains "vi-2:replay_parent_environment_not_scrubbed" if {
	not replay_parent_env_scrubbed
}

replay_parent_env_scrubbed if {
	names := object.get(replay_parent, "env", null)
	is_array(names)
	every name in names {
		replay_parent_env_names[name]
	}
}

# ---------------------------------------------------------------------------
# vi-3  V3 Reward: the worker can neither write the result nor choose which file is read.
# ---------------------------------------------------------------------------

result := section("result")

errors contains "vi-3:result_dir_open_to_worker" if {
	not private_mode(object.get(result, "dir_mode", null))
}

errors contains "vi-3:result_not_precleared" if {
	not closed(result, "precleared")
}

errors contains "vi-3:result_not_written_by_verifier" if {
	object.get(result, "written_by", null) != "verifier"
}

errors contains "vi-3:result_source_ambiguous" if {
	not one_result_source
}

one_result_source if {
	files := object.get(result, "files_read", null)
	is_array(files)
	count(files) == 1
}

# ---------------------------------------------------------------------------
# vi-4  V4 Fail-open: an empty, skipped or exit-zero run is not a pass.
# ---------------------------------------------------------------------------

tests := section("tests")

errors contains "vi-4:no_tests_expected" if {
	not positive(object.get(tests, "expected", null))
}

positive(v) if {
	is_number(v)
	v > 0
}

errors contains "vi-4:test_count_mismatch" if {
	not counts_agree
}

counts_agree if {
	is_number(object.get(tests, "expected", null))
	object.get(tests, "collected", null) == object.get(tests, "expected", null)
}

errors contains "vi-4:tests_skipped" if {
	object.get(tests, "skipped", null) != 0
}

errors contains "vi-4:verdict_from_exit_status_alone" if {
	object.get(tests, "exit_status_alone_accepted", null) != false
}

# ---------------------------------------------------------------------------
# vi-5  V5 Sleeper: nothing the worker started survives into the reading of the result.
# ---------------------------------------------------------------------------

procs := section("processes")

errors contains "vi-5:worker_processes_not_killed" if {
	not closed(procs, "worker_killed")
}

errors contains "vi-5:worker_processes_remain" if {
	object.get(procs, "remaining", null) != 0
}

errors contains "vi-5:result_read_before_kill" if {
	not kill_precedes_read
}

kill_precedes_read if {
	k := object.get(procs, "killed_step", null)
	r := object.get(procs, "result_read_step", null)
	is_number(k)
	is_number(r)
	k < r
}

# ---------------------------------------------------------------------------
# vi-6  V6 Staging: submitted files are copied in without following links or special files.
# ---------------------------------------------------------------------------

staging := section("staging")

errors contains "vi-6:links_followed" if {
	not closed(staging, "nofollow")
}

errors contains "vi-6:destination_not_removed_first" if {
	not closed(staging, "destination_removed_first")
}

errors contains "vi-6:special_files_admitted" if {
	not closed(staging, "special_files_rejected")
}

# ---------------------------------------------------------------------------
# vi-7  V7 Forgery: measurements and secrets stay on the trusted side.
# ---------------------------------------------------------------------------

errors contains "vi-7:evidence_taken_from_worker" if {
	not no_worker_evidence
}

no_worker_evidence if {
	taken := object.get(report, "evidence_from_worker", null)
	is_array(taken)
	count(taken) == 0
}

errors contains "vi-7:environment_not_scrubbed" if {
	not closed(worker, "env_scrubbed")
}

errors contains "vi-7:no_scratch_copy" if {
	not closed(worker, "scratch_copy")
}

# ---------------------------------------------------------------------------
# vi-8  V8 Disclosure: reference outputs and hidden inputs are unreadable to the worker.
# ---------------------------------------------------------------------------

reference := section("reference")

errors contains "vi-8:reference_readable_by_worker" if {
	not private_mode(object.get(reference, "dir_mode", null))
}

errors contains "vi-8:reference_inside_artifact" if {
	object.get(reference, "inside_artifact_dir", null) != false
}

# ---------------------------------------------------------------------------
# vi-9  V9 Exploit: untrusted data meets only loaders that cannot run code.
# ---------------------------------------------------------------------------

errors contains "vi-9:loaders_undeclared" if {
	not loaders_declared
}

loaders_declared if {
	l := object.get(report, "loaders", null)
	is_array(l)
	count(l) > 0
}

errors contains sprintf("vi-9:unsafe_loader:%s", [name]) if {
	loaders_declared
	some l in report.loaders
	not closed(l, "safe")
	name := loader_name(l)
}

loader_name(l) := n if {
	n := object.get(l, "name", null)
	is_string(n)
} else := "unnamed"

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

default isCompliant := false

isCompliant if count(errors) == 0

reasons := sort([e | some e in errors])

# The obligations a report leaves open, for the conformance harness.
open_obligations := {id |
	some e in errors
	startswith(e, "vi-")
	id := split(e, ":")[0]
}
