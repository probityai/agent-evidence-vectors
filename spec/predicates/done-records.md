# Done run records

Version: 0.2.0

> Status: DRAFT. These are the records a verifier reads to decide whether a coding agent
> finished its task and whether it gamed the process. The two predicates that carry them
> are [done-contract](done-contract.md) and [done-receipt](done-receipt.md). The record
> shapes are defined by the `probity-verify` done-receipt adapters
> (`packages/probity-verify/docs/done-receipt.md` of probityai/probity, at commit
> `932c1e3`); this document restates them as the rules a reader enforces, with a code for
> each. Version 0.2.0 replaces `probity-observation/v2`, `probity-tree/v1` and
> `probity-tool-claims/v1` with the versions below and drops the launch records, which no
> verdict reads.

## Purpose

An agent that says it is done makes claims: it changed the right files, it left the tests
alone, it ran the tests and they passed, it is done. The transcript that carries those
claims is the agent's own. These records are made from outside the agent, so that each
claim can be checked against something the agent could not write.

Every record is a JSON object with a `schema_version`, a closed set of members and no
duplicate member at any depth. A reader refuses a record that breaks a rule, and names the
first rule it breaks, in the order given below. It does not repair the record and read what
is left.

## Common rules

1. **Strict JSON.** The bytes are UTF-8. A duplicate member name at any depth is refused
   (`<record>_json_duplicate_key`). `NaN`, `Infinity` and `-Infinity` are refused
   (`<record>_json_number`). Bytes that do not parse are refused (`<record>_json_invalid`).
2. **Closed members.** A record has exactly its required members and any optional ones the
   record names (`<record>_fields`); so does each object inside it that the rules below
   name, under the code given there.
3. **Workspace paths** in protected entries, `files`, events, `run_writes` and
   `module_under_test` are workspace-relative, normalized, `/`-separated, without a leading
   or trailing `/`, a `.` or `..` segment, or an empty segment.
4. **Container paths** (`workspace_root`, `exe`, `cwd`, outside mutations, the execution
   surface) are absolute and normalized, and do not start with `//`.
5. **Digests** are 64 lowercase hexadecimal characters of SHA-256.
6. **Instants** are UTC RFC 3339 to the second and end in `Z`.
7. **Origin members.** The tree, observation and grade records each carry `claim_id`,
   `invocation_id`, `producer`, `vantage` (`independent` or `self_reported`) and
   `witness_scope` (`PEER` or `EXTERNAL`). A record cannot raise its own pin: a consumer
   pins the producer, vantage and scope of each record it relies on, and the record counts
   as independent only when the record and the pin say `independent`, the producers are
   equal, and the producer is not the observed party.

## Done contract: `probity-done-contract/v1`

Sealed before the agent's first turn. The record is refused at the first of these rules it
breaks, in this order: `strength` (`gated`, `reference_free` or `synthesized_spec`,
`contract_strength`); `native_loaded`, a list of `{path, sha256}` naming native code the
commands loaded (`contract_native_loaded`); `schema_version` (`contract_schema_unsupported`);
then the members below.

| member | rule |
| --- | --- |
| `contract_id` | nonempty string (`contract_id`) |
| `task` | optional nonempty string (`contract_task`) |
| `heldout_split_sha256`, `mutant_set_sha256`, `authority_sha256` | optional digests the contract compiler bound (`contract_digest_malformed`) |
| `protected_paths` | a list (`contract_protected_paths_type`) of `{path, kind, sha256}` with optional `exclude` and `equivalence` (`contract_protected_path_fields`), distinct paths (`contract_protected_duplicate`). `kind` is `file` or `directory` (`contract_protected_kind`). A `file` digest is the SHA-256 of the file; a `directory` digest is the tree digest of the regular files under it. `exclude`, on a directory only, is a nonempty list of distinct path segment names (no `/`, left out at any depth) and workspace paths under the entry (with `/`, left out with everything below them) (`contract_exclude_invalid`). `equivalence`, on a file only, is `python_ast` (`contract_equivalence`) |
| `acceptance` | a nonempty list (`contract_acceptance_empty`) of commands with distinct ids (`contract_acceptance_duplicate_id`); see below |
| `execution_surface` | optional sorted distinct container paths sealed from the agent image (`contract_execution_surface`), none of them `/`, `/tmp` or `/var/tmp` (`contract_execution_surface_shared_root`) |
| `surface_aliases` | optional, beside `execution_surface` only: an object mapping each image link that leads into the surface to what it resolves to, both container paths (`contract_surface_aliases`) |
| `adequacy` | `{mutants, killed}` with optional `by_class`, `kill_vector_sha256` and `gates` (`contract_adequacy_fields`). Each gate is an object with a boolean `pass` (`contract_adequacy_gates`); the counts are nonnegative integers (`contract_adequacy_count`) with `killed <= mutants` (`contract_adequacy_overcount`); the kill vector is a digest; `by_class` maps names to `{mutants, killed}` that sum to the totals (`contract_adequacy_by_class`) |
| `module_under_test` | optional nonempty list of distinct workspace paths the task asks the agent to write (`contract_module_under_test`) |

An acceptance command is `{id, argv}` with optional `ids`, `run_writes`, `cwd`, `exe`,
`interpreter`, `tier`, `probe` and `in_process_twin_of` (`contract_acceptance_fields`):

- `tier` is `trusted` or `synthesized` (`contract_acceptance_tier`); `probe` is
  `determinism`, `type_strict` or `import_side_effects` (`contract_acceptance_probe`) and
  marks an oracle-free probe rather than a behavioural test;
- `id` is a nonempty string (`contract_acceptance_id`), and an id that starts with
  `heldout` names a held-out command the agent never saw; `argv` is a nonempty list of
  strings whose first is nonempty (`contract_acceptance_argv`);
- `cwd` and `exe` are sealed together: `cwd` a container path, `exe` one container path or a
  sorted list of distinct ones that name the same executable file
  (`contract_acceptance_seal`); `interpreter`, beside `exe` only, is a sorted list of distinct
  container paths of the Python that runs the command's entry point as `-m <module>`
  (`contract_acceptance_interpreter`);
- `in_process_twin_of` is a nonempty string (checked here) naming another command that is
  not a probe (checked once every id is known) (`contract_acceptance_twin`);
- `ids` is a nonempty list of distinct nonempty test ids (`contract_acceptance_ids`);
  `run_writes` is a list of distinct workspace paths (`contract_acceptance_run_writes`).

After the members, a reader that holds the observation also checks the surface against the
run: an entry that is the workspace, lies inside it or above it is refused
(`contract_execution_surface_covers_workspace`), and so is an alias chain that has not ended
after 40 hops (`contract_surface_aliases_cycle`).

**Tree digest.** The SHA-256 of the lines `"<sha256>  <path>\n"`, one per file, sorted by the
UTF-8 bytes of the path. That is what `sha256sum` prints for the files.

## Tree: `probity-tree/v2`

Every non-directory entry of the final workspace, with the origin members. In order: the
schema version (`tree_schema_unsupported`); the origin members; `files`, `symlinks` and
`special`, each an object (`tree_entries_type`) keyed by workspace path
(`tree_path_not_normalized`), `files` mapping to a digest (`tree_digest_malformed`),
`symlinks` to a nonempty raw link target (`tree_symlink_target`), `special` to `fifo`,
`socket`, `char` or `block` (`tree_special_kind`); no path under two kinds
(`tree_path_duplicate`); no entry under another (`tree_path_nested`); `executable`, the
sorted distinct listed files with an execute bit (`tree_executable`); and `tree_sha256`, the
SHA-256 of one sorted line per entry: `<sha256>  <path>` for a plain file, `x:<sha256>
<path>` for an executable one, `l:<sha256 of the target>  <path>` for a link and
`s:<kind>  <path>` for a special file. A tree whose digest is not its entries' is refused
(`tree_digest_mismatch`).

## Observation: `probity-observation/v3`

The observer's events for one invocation and interval, with the origin members.

| member | rule |
| --- | --- |
| `scope` | `{id, start, end}` with `end` not before `start` (`observation_scope_fields`, `_id`, `_instant`, `_order`) |
| `workspace_root` | the container path of the workspace (`observation_workspace_root`) |
| `coverage` | `complete`, `incomplete` or `unknown` (`observation_coverage`) |
| `gaps` | present for `incomplete` (`observation_gaps_required`) and only then (`observation_gaps_unexpected`): a nonempty list of `{start, end, gap_cause}` (`observation_gap_fields`), `gap_cause` one of `agent`, `host`, `sensor`, `unknown` (`observation_gap_cause`), each inside the scope and nonempty (`observation_gap_instant`, `observation_gap_outside_scope`) |
| `events`, `external_mutations` | two lists (`observation_events_type`) |

Every entry of both lists has an integer `step` (`observation_step`), and the two lists share
one step sequence: steps are unique across both and increase within each
(`observation_steps_not_increasing`). Ids are distinct across both and every time lies in the
scope (`observation_event_duplicate_or_outside`, `observation_event_instant`). Entries are
checked in step order, so an `origin`, in either list, names an `exec` event with a smaller
step (`observation_origin_unknown`).

An **event** inside the workspace has `id`, `type`, `time` and `step`
(`observation_event_fields`, `_id`, `_type`, `observation_step`):

- an `exec` carries `argv` (`observation_exec_argv`), the absolute path the kernel executed
  as `exe` (`observation_exec_exe`), the working directory as `cwd` (`observation_exec_cwd`),
  the loader variables present among `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
  `PYTHONPATH`, `PYTHONHOME`, `PYTHONSAFEPATH`, `PYTHONSTARTUP`, `PYTHONUSERBASE`,
  `PYTHONNOUSERSITE`, `PYTHONPYCACHEPREFIX`, `PYTHONWARNINGS`, `PYTEST_ADDOPTS`,
  `PYTEST_PLUGINS`, `NODE_OPTIONS` and `NODE_PATH` as string `env` (`observation_exec_env`),
  and, when the observer saw the process end, `exit` (`observation_exec_exit`); it carries no
  path, target or address (`observation_exec_path`);
- any other event carries none of the exec members (`observation_argv_on_file_event`); a
  `connect` carries an `address` and no path (`observation_connect_address`), and no other
  event carries an address (`observation_address_unexpected`);
- a mutation (`write`, `create`, `rename`, `link`, `unlink`, `truncate`, `chmod`) carries a
  workspace `path` (`observation_path_required`, `observation_path_not_normalized`), and only
  `rename` and `link` may carry a `target` (`observation_target_unexpected`). A shared
  writable `mmap` is reported as `write`.

An **outside mutation** has `id`, `step`, `time`, a mutation `type`, nonempty container
`paths` outside the workspace and a `location` (`grader_path` or `outside_workspace`), and
may carry `origin` (`observation_external_fields`, `_id`, `_type`, `_paths`, `_location`,
`observation_external_in_workspace`).

**Origin rule.** An event's `origin` is the first exec of the command whose process tree
produced it; events of the agent's own root process carry none. `sh -c "edit; test"` is one
command, so without a contract that seals `run_writes` its edit is not an edit after the test
run. That is a stated limit of `tool_claim_match/v1`.

**Exit status.** An exit caused by a signal is recorded as 128 plus the signal number.

**Time.** Instants are whole seconds, so order between events comes from `step` alone.

## Capabilities: `probity-capabilities/v1`

`claim_id`, `invocation_id`, `producer` and `visible_event_types`, a list of distinct
nonempty strings (`capability_types`, `capability_types_duplicate`): the event types the
observer can see. An absence is evidence only for a type listed here.

## Acceptance grade: `probity-acceptance-grade/v1`

Written by a verifier that rebuilt the agent's final tree in a fresh sandbox, reset the
protected paths from the contract and ran the acceptance commands. It carries the origin
members, the `contract_sha256` and `tree_sha256` it ran on (`grade_digest_malformed`),
`results`, and optional `hunks` and `visible_detectors`.

- `results` is a list (`grade_results_type`) of `{id, argv, exit}` with optional
  `collected`, `replay`, `timed_out` and `failure_kind` (`grade_result_fields`, `_id`,
  `_argv`, `_exit`) and distinct ids (`grade_result_duplicate_id`). `timed_out` is present
  only as `true`, on a failed run (`grade_result_timed_out`); `failure_kind` (`assertion`,
  `candidate_exit` or `candidate`) only on a failed run (`grade_result_failure_kind`);
  `collected` is a count (`grade_result_collected`); `replay` is `{calls_intercepted,
  distinct_calls}` with no more distinct calls than calls (`grade_result_replay`).
- `hunks` is a list (`grade_hunks_type`) of `{path, lines, mutants, killed}` with `lines` a
  pair of line numbers in order and no more killed than mutants (`grade_hunk`).
- `visible_detectors` is `{status, findings}`, each finding `{reason, refuses, evidence}`
  with optional `attribution`; a refusing finding names `impure_on_visible`,
  `type_strict_on_visible`, `repeat_divergence` or `isolated_branch`, and only a
  `visible_test_unsatisfiable` finding names an attribution (`agent` or `test_author`)
  (`grade_detectors`).

## Tool claims: `probity-tool-claims/v2`

The runs the agent says it made and whether it asserted the task done, parsed from its
transcript by the harness. `completion` is `{asserted, basis}` (`claims_completion_fields`):
`asserted` a boolean (`claims_completion_asserted`), and `basis` where the harness read it,
one of `final_text`, `tool_claim` or `both` when asserted and `none` exactly when not
(`claims_completion_basis`). Then `claim_id`, `invocation_id`, `producer`, and `claims`, a
list (`claims_type`) of `{id, argv}` with an optional claimed `exit` (`claims_entry_fields`,
`_id`, `_argv`, `_exit`) and distinct ids (`claims_duplicate_id`). Claims are the agent's
statements and have no vantage pin.

## Consumer case and policy

The consumer pins every record it reads. A **case** (`probity-case/v1`) names a `case_id`,
equal to the records' `claim_id`, and binds each artifact by path, length and SHA-256. A
**policy** (`probity-policy/v1`) holds the witnesses, each with the artifact, the digest the
consumer expects and an authority statement, and for observed roles the pinned `producer`,
`vantage` and `witness_scope`, and one assessment per case naming the claim type, the
invocation, the observed party and, where the check needs it, the interval. An acceptance
assessment may set `allow_no_heldout` (a boolean, `policy_allow_no_heldout`); a receipt
assessment may set `verifier_ids` (a nonempty list of URIs, `policy_verifier_ids`).

A case whose bytes differ from the length or digest it binds is refused
(`case_artifact_binding_mismatch`): the consumer's own files disagree. A case whose bytes
match its binding but differ from the digest the policy pins leaves that witness unbound, and
the check is `not_established`.

**Witness scope.** A record earns `EXTERNAL` only from a verified witness co-signature by a
second operator, which an `EXTERNAL` pin names in a `witnessed` block, and never from its own
`witness_scope`. probity-verify checks that co-signature. The readers of this repository do
not: an `EXTERNAL` pin with no `witnessed` block is malformed (`policy_witness_unwitnessed`),
one with a block is refused rather than downgraded (`policy_witness_witnessed_unverified`),
and a block beside a `PEER` pin is malformed (`policy_witness_witnessed_unexpected`). Every
verdict these readers reach is therefore `PEER`, and a record that says `EXTERNAL` without a
verified co-signature is named in the verdict's `unwitnessed_scope_claims`, with the witness,
`claimed: EXTERNAL`, `earned: PEER` and the reason `no witness bundle is pinned for this
record`.

**Syntax-tree equivalence.** A protected file with `equivalence: python_ast` is unchanged for
probity-verify when its final source parses to the sealed source's Python syntax tree, given
both sources as case artifacts named `source:<sha256>`. These readers do not parse Python:
when both sources are bound and the digests differ, the check is refused
(`contract_equivalence_unjudged`) rather than judged on the digest alone. Without both
sources the digest decides, as it does for probity-verify.

## Refusal codes

A reader that refuses a record names the code below for the first rule the record breaks.
Every code here is forced by at least one member of the conformance corpora, and a reader that
names another code for the same member does not conform. Besides the codes listed, every
record has four generic ones: `<record>_fields`, `<record>_json_invalid`,
`<record>_json_duplicate_key` and `<record>_json_number`. In a member, the refusal is
declared on each check that reads the record.

- **contract**: `contract_acceptance_argv`, `contract_acceptance_duplicate_id`, `contract_acceptance_empty`, `contract_acceptance_fields`, `contract_acceptance_id`, `contract_acceptance_ids`, `contract_acceptance_interpreter`, `contract_acceptance_probe`, `contract_acceptance_run_writes`, `contract_acceptance_seal`, `contract_acceptance_tier`, `contract_acceptance_twin`, `contract_adequacy_by_class`, `contract_adequacy_count`, `contract_adequacy_fields`, `contract_adequacy_gates`, `contract_adequacy_overcount`, `contract_digest_malformed`, `contract_equivalence`, `contract_equivalence_unjudged`, `contract_exclude_invalid`, `contract_execution_surface`, `contract_execution_surface_covers_workspace`, `contract_execution_surface_shared_root`, `contract_id`, `contract_module_under_test`, `contract_native_loaded`, `contract_protected_duplicate`, `contract_protected_kind`, `contract_protected_path_not_normalized`, `contract_protected_paths_type`, `contract_schema_unsupported`, `contract_strength`, `contract_surface_aliases`, `contract_surface_aliases_cycle`, `contract_task`
- **tree**: `tree_claim_id`, `tree_digest_malformed`, `tree_digest_mismatch`, `tree_entries_type`, `tree_executable`, `tree_invocation_id`, `tree_path_duplicate`, `tree_path_nested`, `tree_path_not_normalized`, `tree_producer`, `tree_schema_unsupported`, `tree_special_kind`, `tree_symlink_target`, `tree_vantage`, `tree_witness_scope`
- **observation**: `observation_address_unexpected`, `observation_argv_on_file_event`, `observation_claim_id`, `observation_connect_address`, `observation_coverage`, `observation_event_duplicate_or_outside`, `observation_event_fields`, `observation_event_id`, `observation_event_instant`, `observation_event_type`, `observation_events_type`, `observation_exec_argv`, `observation_exec_cwd`, `observation_exec_env`, `observation_exec_exe`, `observation_exec_exit`, `observation_exec_path`, `observation_external_fields`, `observation_external_id`, `observation_external_in_workspace`, `observation_external_location`, `observation_external_paths`, `observation_external_type`, `observation_gap_cause`, `observation_gap_fields`, `observation_gap_instant`, `observation_gap_outside_scope`, `observation_gaps_required`, `observation_gaps_unexpected`, `observation_invocation_id`, `observation_origin_unknown`, `observation_path_not_normalized`, `observation_path_required`, `observation_producer`, `observation_schema_unsupported`, `observation_scope_fields`, `observation_scope_id`, `observation_scope_instant`, `observation_scope_order`, `observation_step`, `observation_steps_not_increasing`, `observation_target_unexpected`, `observation_vantage`, `observation_witness_scope`, `observation_workspace_root`
- **capability**: `capability_claim_id`, `capability_invocation_id`, `capability_producer`, `capability_schema_unsupported`, `capability_types`, `capability_types_duplicate`
- **grade**: `grade_claim_id`, `grade_detectors`, `grade_digest_malformed`, `grade_hunk`, `grade_hunks_type`, `grade_invocation_id`, `grade_producer`, `grade_result_argv`, `grade_result_collected`, `grade_result_duplicate_id`, `grade_result_exit`, `grade_result_failure_kind`, `grade_result_fields`, `grade_result_id`, `grade_result_replay`, `grade_result_timed_out`, `grade_results_type`, `grade_schema_unsupported`, `grade_vantage`, `grade_witness_scope`
- **claims**: `claims_claim_id`, `claims_completion_asserted`, `claims_completion_basis`, `claims_completion_fields`, `claims_duplicate_id`, `claims_entry_argv`, `claims_entry_exit`, `claims_entry_fields`, `claims_entry_id`, `claims_invocation_id`, `claims_producer`, `claims_schema_unsupported`, `claims_type`
- **case**: `case_artifact_binding_mismatch`, `case_artifact_digest_malformed`, `case_artifact_fields`, `case_artifact_length`, `case_artifact_path`, `case_artifact_path_not_normalized`, `case_artifact_unknown`, `case_id`, `case_missing`, `case_objects`, `case_schema_unsupported`
- **policy**: `policy_allow_no_heldout`, `policy_artifact_shared`, `policy_assessment_fields`, `policy_assessment_missing`, `policy_claim_type_unsupported`, `policy_invocation_id`, `policy_observed_party`, `policy_scope_instant`, `policy_verifier_ids`, `policy_witness_artifact`, `policy_witness_authority`, `policy_witness_digest_malformed`, `policy_witness_fields`, `policy_witness_producer`, `policy_witness_scope`, `policy_witness_shared`, `policy_witness_unknown`, `policy_witness_unwitnessed`, `policy_witness_vantage`, `policy_witness_witnessed_unexpected`, `policy_witness_witnessed_unverified`
- **file conditions**: `case_unreadable`, `policy_unreadable`, `member_unreadable`, `case_artifact_unsafe` and `member_incomplete` name a file that cannot be read as a regular file, or is absent; a corpus of regular files does not carry them.

The receipt's own codes are in [done-receipt](done-receipt.md) and the contract statement's in
[done-contract](done-contract.md).

## What these records do not establish

- Producer, vantage and witness scope are consumer pins, not authenticated identities.
  Verify any DSSE envelope that carries a record before reading it.
- Paths are compared as recorded. The observer must resolve symbolic links, `..` and case
  folding before it writes a path.
- A write through an already-open descriptor is covered by the open that created it, and a
  descriptor received from outside the container is not seen.
- Reads outside the workspace are not recorded.
- The grade reports exit statuses. Whether the acceptance commands test the task is the
  contract's job, which `adequacy` measures.
