# Done run records

Version: 0.1.0

> Status: DRAFT. These are the records a verifier reads to decide whether a coding agent
> finished its task. The two predicates that carry them are
> [done-contract](done-contract.md) and [done-receipt](done-receipt.md). The record
> shapes were defined first by the `probity-verify` done-receipt adapters
> (`docs/done-receipt.md` in that repository); this document restates them as
> the rules a reader enforces and adds the two records the observer launcher writes.

## Purpose

An agent that says it is done makes claims: it changed the right files, it left the tests
alone, it ran the tests and they passed. The transcript that carries those claims is the
agent's own. These records are made from outside the agent, so that each claim can be
checked against something the agent could not write.

Every record is a JSON object with a `schema_version`, a closed set of members and no
duplicate member at any depth. A reader refuses a record that breaks a rule, and names the
first rule it breaks, in the order given below. It does not repair the record and read what
is left.

## Common rules

1. **Strict JSON.** The bytes are UTF-8. A duplicate member name at any depth is refused
   (`<record>_json_duplicate_key`). `NaN`, `Infinity` and `-Infinity` are refused
   (`<record>_json_number`). Bytes that do not parse are refused (`<record>_json_invalid`).
2. **Closed members.** A record has exactly its required members and any optional ones the
   record names (`<record>_fields`).
3. **Paths** in `files`, protected entries and events are workspace-relative, normalized,
   `/`-separated, without a leading or trailing `/`, a `.` or `..` segment, or an empty
   segment. A path that is not so is refused (`<record>_path_not_normalized`).
4. **Digests** are 64 lowercase hexadecimal characters of SHA-256.
5. **Instants** are UTC RFC 3339 to the second and end in `Z`.
6. **Origin members.** The tree, observation and grade records each carry `claim_id`,
   `invocation_id`, `producer`, `vantage` (`independent` or `self_reported`) and
   `witness_scope` (`PEER` or `EXTERNAL`). `PEER` means the witness key runs under the same
   operator as the observer. `EXTERNAL` means a different operator holds it. A record
   cannot raise its own pin: a consumer pins the producer, vantage and scope of each record
   it relies on, and the record counts as independent only when the record and the pin say
   `independent`, the producers are equal, and the producer is not the observed party.

## Done contract: `probity-done-contract/v1`

Sealed before the agent's first turn.

| member | rule |
| --- | --- |
| `contract_id` | nonempty string |
| `task` | optional nonempty string |
| `protected_paths` | list of `{path, kind, sha256}` and optionally `exclude`. `kind` is `file` or `directory`. A `file` digest is the SHA-256 of the file. A `directory` digest is the tree digest of the files under it (below). `exclude` lists path segment names, such as `__pycache__`, left out of both the digest and the event match; it is allowed on a directory only, nonempty, without duplicates, `/`, `.`, `..` or the empty name. Paths are distinct |
| `acceptance` | nonempty list of `{id, argv}` with distinct ids and nonempty `argv` of strings |
| `adequacy` | `{mutants, killed}`, nonnegative integers with `killed <= mutants`: how many generated mutants the acceptance commands killed |
| `heldout_split_sha256`, `mutant_set_sha256`, `authority_sha256` | optional digests the contract compiler bound |


**Tree digest.** The SHA-256 of the lines `"<sha256>  <path>\n"`, one per file, sorted by the
UTF-8 bytes of the path. That is what `sha256sum` prints for the files.

## Tree: `probity-tree/v1`

The final workspace: `files`, a map from path to the SHA-256 of the file, and `tree_sha256`,
the tree digest of `files`. A reader recomputes it and refuses a tree whose digest does not
match its files (`tree_digest_mismatch`).

## Observation: `probity-observation/v2`

The observer's events for one invocation and interval.

| member | rule |
| --- | --- |
| `scope` | `{id, start, end}` with `end` not before `start` |
| `coverage` | `complete`, `incomplete` or `unknown` |
| `gaps` | present for `incomplete` and only then: a nonempty list of `{start, end}` inside the scope, each nonempty |
| `events` | optional list, in record order, with distinct ids, times inside the scope, and `step` increasing |

An event has `id`, `type`, `time` and `step`. Mutation events (`write`, `create`, `rename`,
`link`, `unlink`, `truncate`, `chmod`) carry a `path`; `rename` and `link` may carry a
`target`. A shared writable `mmap` is reported as `write`. An `exec` event carries `argv` and,
when the observer saw the process end, `exit`; it carries no path. Any event may carry
`origin`, the id of an earlier `exec` event.

**Origin rule.** A command is a process the agent's root process started, or a process an
interactive shell (a shell run without `-c`) started. An event's `origin` is the first exec
of the command whose process tree produced it. Events of the agent's own root process carry
none. A persistent tool shell therefore gives each command its own origin, while
`sh -c "edit; test"` is one command: its edit is not counted as an edit after the test run.
That is a stated limit of `tool_claim_match/v1`, not a defect to be repaired by a reader.

**Exit status.** An exit caused by a signal is recorded as 128 plus the signal number. An exec
that a later exec in the same process replaces has no `exit`.

**Time.** Instants are whole seconds, so order between events comes from `step` alone.


## Capabilities: `probity-capabilities/v1`

`claim_id`, `invocation_id`, `producer` and `visible_event_types`, a list of distinct strings:
the event types the observer can see. An absence is evidence only for a type listed here.

## Acceptance grade: `probity-acceptance-grade/v1`

Written by a verifier that rebuilt the agent's final tree in a fresh sandbox, reset the
protected paths from the contract and ran the acceptance commands. It names the
`contract_sha256` and `tree_sha256` it ran on and lists `results` as `{id, argv, exit}` with
distinct ids.

## Tool claims: `probity-tool-claims/v1`

The commands the agent says it ran, parsed from its transcript by the harness: `claim_id`,
`invocation_id`, `producer` and `claims`, a list of `{id, argv}` with an optional claimed
`exit`. Claims are the agent's statements and have no vantage pin.

## Launch: `probity-launch/v1`

What the launcher ran. Its SHA-256 is the launch digest. Members: `backend` (`docker` or
`apptainer`), `image`, `image_id`, `runtime_version`, `strace_version`, `container_argv`,
`trace_expression`, `tracer_flags`, `tracer_uid_separated` (boolean), `agent_argv`,
`agent_uid`, `env`, `network` (boolean), `container_workspace`, `start_tarball_sha256`,
`observer_source_sha256` and `timeout_seconds`. Under apptainer the tracer and the agent share
a uid, so `tracer_uid_separated` is false and a forged trace line is not detected; a consumer
that needs that guarantee pins the docker backend.

## Launch receipt: `probity-launch-receipt/v1`

What the sensors found. Members: `claim_id`, `invocation_id`, `producer`, `witnessScope`
(the observer's own camelCase member, which the verify records carry as `witness_scope`),
`launch_sha256`, `trace_expression`, `watch_list`, `start_tarball_sha256`, `coverage`,
`container_exit`, `agent_exit` (an integer or null), `timed_out`, `transcript_sha256`,
`trace_sha256`, `observation_sha256`, `capability_sha256`, `doesNotAssert`, `sensors` and
`tree_sha256`.

`tree_sha256` here is the SHA-256 of the bytes of `tree.json`, not the tree digest. The tree
digest is `sensors.s3_tree.tree_sha256`. (Two members of the observer's receipt share that
name; the names are the observer's, and a reader uses the paths given here.)

`sensors` has five members:

- `s1_inotify`: the change count, `overflow`, `watch_failures`, `watch_list` and `mask`;
- `s2_strace`: `tracer` (`complete` or `lost`), the call count, `unparsed_lines`,
  `unresolved` calls, `escapes` (`io_uring_setup`, `ptrace`, `process_vm_writev`) and the
  `origin_rule`;
- `s3_tree`: the tree digest and counts of files, symbolic links and special files;
- `join.unattributed`: changes the host saw that the trace did not;
- `external_effects`: mutations outside the workspace, each `{type, paths, time}`, and
  network connections, each `{type: "connect", address, time}`. Observation records hold
  workspace paths only, so these live here. Paths under `/dev`, `/proc` and `/sys` are left
  out.


## Consumer case and policy

The consumer pins every record it reads. A **case** (`probity-case/v1`) names a `case_id`,
equal to the records' `claim_id`, and binds each artifact by path, length and SHA-256. A
**policy** (`probity-policy/v1`) holds the witnesses, each with the artifact, the digest the
consumer expects and an authority statement, and for observed roles the pinned `producer`,
`vantage` and `witness_scope`, and one assessment per case naming the claim type, the
invocation, the observed party and, where the check needs it, the interval.

A case whose bytes differ from the length or digest it binds is refused
(`case_artifact_binding_mismatch`): the consumer's own files disagree. A case whose bytes
match its binding but differ from the digest the policy pins leaves that witness unbound, and
the check is `not_established`.


## Refusal codes

A reader that refuses a record names the code below for the first rule the record breaks. Every code
here is forced by at least one member of the conformance corpora, and a reader that names
another code for the same member does not conform. Besides the codes listed, every record
has four generic ones: `<record>_fields` (a missing or unexpected member),
`<record>_json_invalid`, `<record>_json_duplicate_key` and `<record>_json_number`.

- **contract**: `contract_acceptance_argv`, `contract_acceptance_duplicate_id`, `contract_acceptance_empty`, `contract_acceptance_id`, `contract_adequacy_count`, `contract_adequacy_fields`, `contract_adequacy_overcount`, `contract_digest_malformed`, `contract_exclude_invalid`, `contract_fields`, `contract_id`, `contract_json_duplicate_key`, `contract_json_invalid`, `contract_json_number`, `contract_protected_duplicate`, `contract_protected_kind`, `contract_protected_path_not_normalized`, `contract_protected_paths_type`, `contract_schema_unsupported`, `contract_task`
- **tree**: `tree_claim_id`, `tree_digest_malformed`, `tree_digest_mismatch`, `tree_fields`, `tree_files_type`, `tree_invocation_id`, `tree_json_duplicate_key`, `tree_json_invalid`, `tree_json_number`, `tree_path_not_normalized`, `tree_producer`, `tree_schema_unsupported`, `tree_vantage`, `tree_witness_scope`
- **observation**: `observation_argv_on_file_event`, `observation_claim_id`, `observation_coverage`, `observation_event_duplicate_or_outside`, `observation_event_fields`, `observation_event_id`, `observation_event_instant`, `observation_event_type`, `observation_events_type`, `observation_exec_argv`, `observation_exec_exit`, `observation_exec_path`, `observation_fields`, `observation_gap_instant`, `observation_gap_outside_scope`, `observation_gaps_required`, `observation_gaps_unexpected`, `observation_invocation_id`, `observation_json_duplicate_key`, `observation_json_invalid`, `observation_json_number`, `observation_origin_unknown`, `observation_path_not_normalized`, `observation_path_required`, `observation_producer`, `observation_schema_unsupported`, `observation_scope_fields`, `observation_scope_id`, `observation_scope_instant`, `observation_scope_order`, `observation_step`, `observation_steps_not_increasing`, `observation_target_unexpected`, `observation_vantage`, `observation_witness_scope`
- **capability**: `capability_claim_id`, `capability_fields`, `capability_json_duplicate_key`, `capability_json_invalid`, `capability_json_number`, `capability_schema_unsupported`, `capability_types`, `capability_types_duplicate`
- **grade**: `grade_claim_id`, `grade_digest_malformed`, `grade_fields`, `grade_invocation_id`, `grade_json_duplicate_key`, `grade_json_invalid`, `grade_json_number`, `grade_producer`, `grade_result_argv`, `grade_result_duplicate_id`, `grade_result_exit`, `grade_result_fields`, `grade_result_id`, `grade_results_type`, `grade_schema_unsupported`, `grade_vantage`, `grade_witness_scope`
- **claims**: `claims_claim_id`, `claims_duplicate_id`, `claims_entry_argv`, `claims_entry_exit`, `claims_entry_fields`, `claims_entry_id`, `claims_fields`, `claims_json_duplicate_key`, `claims_json_invalid`, `claims_json_number`, `claims_schema_unsupported`, `claims_type`
- **launch**: `launch_backend`, `launch_digest_malformed`, `launch_schema_unsupported`, `launch_types`
- **launch receipt**: `launch_receipt_coverage`, `launch_receipt_digest_malformed`, `launch_receipt_effect`, `launch_receipt_schema_unsupported`, `launch_receipt_sensors`, `launch_receipt_types`, `launch_receipt_witness_scope`
- **case**: `case_artifact_binding_mismatch`, `case_artifact_digest_malformed`, `case_artifact_fields`, `case_artifact_length`, `case_artifact_path`, `case_artifact_path_not_normalized`, `case_artifact_unknown`, `case_fields`, `case_id`, `case_json_duplicate_key`, `case_json_invalid`, `case_json_number`, `case_missing`, `case_objects`, `case_schema_unsupported`
- **policy**: `policy_artifact_shared`, `policy_assessment_fields`, `policy_assessment_missing`, `policy_claim_type_unsupported`, `policy_fields`, `policy_invocation_id`, `policy_json_duplicate_key`, `policy_json_invalid`, `policy_json_number`, `policy_observed_party`, `policy_scope_instant`, `policy_witness_artifact`, `policy_witness_authority`, `policy_witness_digest_malformed`, `policy_witness_fields`, `policy_witness_producer`, `policy_witness_scope`, `policy_witness_shared`, `policy_witness_unknown`, `policy_witness_vantage`
- **file conditions**: `case_unreadable`, `policy_unreadable`, `member_unreadable`, `case_artifact_unsafe` and `member_incomplete` name a file that cannot be read as a regular file, or is absent; a corpus of regular files does not carry them.

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
