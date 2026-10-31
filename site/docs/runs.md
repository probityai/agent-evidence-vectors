# Find a retained run

Choose a run to inspect its original [report, provenance and contract](lab/register.json). Each record keeps its own claim results, roles and limits. A passed claim does not establish that every claim passed or that someone independently operated the workload.

Search by a project, claim, role or limit. The result filter shows records that contain the selected per-claim token. It does not give a run an overall grade. Without JavaScript, every record remains below and in the [Markdown page](runs.md).

Use the [Open Evidence Lab](lab.md) for the submission protocol and review process. Use [Experiments](experiments.md) for procedures and [the claim ledger](claims.md#retained-run-navigation) for sources.

<form id="run-filters" class="run-filters" hidden>

<label for="run-search">Search records, claims, roles or limits</label> <input id="run-search" type="search" autocomplete="off" aria-controls="run-records" /> <label for="run-result">Contains a per-claim result</label> <select id="run-result" aria-controls="run-records"><option value="">All result tokens</option><option value="fail">fail</option><option value="not-exercised">not-exercised</option><option value="out-of-scope">out-of-scope</option><option value="pass">pass</option></select> <button type="reset">Clear filters</button>
<p id="run-count" role="status" aria-live="polite">

</p>

</form>

<p id="run-empty" hidden>

No retained record matches these filters. Clear filters or use another search term.
</p>

<div id="run-records">

<div>

<a id="record-E6-observer-admission"></a>

## E6-observer-admission

Claim scope: verifier-behavior-on-author-fixture

Review state: retained-measured-record

Open [Report](experiments/observer-admission/recorded.json), [Provenance](experiments/observer-admission/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/blob/8562c25fb7ec97596ea9d0297c495340298914b6/docs/CONSUMER-ADMISSION.md).

[Recorded procedure](experiments.md#observer-consumer-admission)

<a id="per-claim-results"></a>

### Per-claim results

| Claim                       | Recorded result |
|-----------------------------|-----------------|
| consumer-authority-binding  | pass            |
| durable-consumer-admission  | pass            |
| persisted-replay-refusal    | pass            |
| signed-claim-tamper-refusal | pass            |
| independent-custody         | not-exercised   |
| external-host-ci-adoption   | not-exercised   |
| unmediated-effect-capture   | not-exercised   |

<a id="roles"></a>

### Roles

| Role                 | Declaration           |
|----------------------|-----------------------|
| atlasReplay          | author-produced       |
| evidenceVantage      | artifact              |
| fixtureOperator      | same-operator-fixture |
| independentOperation | not-established       |
| witnessScope         | PEER                  |

<a id="limits"></a>

### Limits

- One declared broker file write and one local consumer admission
- No live-agent or production-isolation measurement
- No independently operated witness or consumer
- Consumer-state rollback can erase replay protection
- No exactly-once downstream-effect claim

answerExposure: Implementation, demo and retained expected outcomes were available to the atlas runner; not an answer-blind replication

comparisonOrder: Retrospective retained-fixture comparison; not a result frozen before expected-answer comparison

</div>

<div>

<a id="record-jep-core07-2026-10-02"></a>

## jep-core07-2026-10-02

Claim scope: verifier-behavior-on-public-producer-fixtures

Review state: submitted-awaiting-producer-response

Open [Report](experiments/jep-core07-2026-10-02/report.json), [Provenance](experiments/jep-core07-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-vectors/blob/4f344209c8ea65f60bab0f51747ae4f80346181d/interop/jep-core07-reader/PROTOCOL.md).

<a id="per-claim-results-1"></a>

### Per-claim results

| Claim                                           | Recorded result |
|-------------------------------------------------|-----------------|
| validation-assertions-match-pinned-expectations | pass            |
| producer-assertions-match-pinned-expectations   | pass            |
| acceptance-assertions-match-pinned-expectations | pass            |
| external-host-ci-adoption                       | not-exercised   |
| independent-effect-custody                      | not-exercised   |

<a id="roles-1"></a>

### Roles

| Role                     | Declaration                  |
|--------------------------|------------------------------|
| readerAuthor             | Probity                      |
| runner                   | Probity-owned GitHub Actions |
| producer                 | JEP                          |
| independentEffectCustody | not-established              |

<a id="limits-1"></a>

### Limits

- Pinned manifest coverage only, not complete JEP Core coverage.
- Acceptance effects are synthetic local SQLite rows.
- No power-loss or distributed failover experiment.

answerExposure: Published expected outcomes were available before implementation; not answer-blind.

comparisonOrder: Actual per-case outputs retained before comparison in memory; raw output and comparison published together, not separate revisions.

</div>

<div>

<a id="record-remora-e7-2026-10-02"></a>

## remora-e7-2026-10-02

Claim scope: verifier-behavior-on-public-producer-fixtures

Review state: producer-review-open

Open [Report](experiments/remora-e7-2026-10-02/report.json), [Provenance](experiments/remora-e7-2026-10-02/provenance.json) and [Contract](https://github.com/darklordVirtual/REMORA-research/tree/e4fe474f488c3047b346abb01cbfd77ab447ad69/artifacts/interop/runtime-surface-e7-v0.1).

<a id="per-claim-results-2"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| valid_reference_surface-matches-native-fixture-outcome | pass |
| undeclared_tool_invocation_surface-matches-native-fixture-outcome | pass |
| runtime_identity_changed-matches-native-fixture-outcome | pass |
| observation_coverage_incomplete-matches-native-fixture-outcome | pass |
| alternative_effect_path_observed-matches-native-fixture-outcome | pass |
| global-runtime-capability-surface-completeness | not-exercised |
| external-host-ci-adoption | not-exercised |
| independent-effect-custody | not-exercised |

<a id="roles-2"></a>

### Roles

| Role                     | Declaration                  |
|--------------------------|------------------------------|
| readerAuthor             | Probity                      |
| runner                   | Probity-owned GitHub Actions |
| producer                 | REMORA                       |
| independentEffectCustody | not-established              |

<a id="limits-2"></a>

### Limits

- Native INDEPENDENT means the external operator and separate implementation satisfy REMORA package criteria; it establishes no independent effect custody.
- Global runtime_capability_surface_completeness remains NOT_ESTABLISHED.
- Producer review is open; it does not establish producer acceptance, final verification or CI adoption.

answerExposure: Published expected outcomes were available before implementation; not answer-blind. REMORA reference-verifier text was also exposed during lint diagnostics after implementation.

comparisonOrder: Actual per-case outputs retained before comparison in memory; raw output and comparison published together, not separate revisions.

</div>

<div>

<a id="record-langgraph-durable-2026-10-02"></a>

## langgraph-durable-2026-10-02

Claim scope: author-operated-native-framework-control

Review state: author-retained-measured-record

Open [Report](experiments/langgraph-durable-2026-10-02/report.json), [Provenance](experiments/langgraph-durable-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/90cd62c0ee926b456aa9aada3537f36ee5f17cd3/interop/langgraph-ticket-2026-10-02).

<a id="per-claim-results-3"></a>

### Per-claim results

| Claim                                       | Recorded result |
|---------------------------------------------|-----------------|
| bounded-six-case-population                 | pass            |
| reader-reconstructed-native-record          | pass            |
| crash-after-effect-recovers-at-revision-one | pass            |
| pending-intent-no-automatic-replay          | pass            |
| missing-checkpoint-refusal                  | pass            |
| wrong-thread-refusal                        | pass            |
| external-host-recurring-adoption            | not-exercised   |
| independent-effect-custody                  | not-exercised   |

<a id="roles-3"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-3"></a>

### Limits

- Graph-worker hard exits/reopened SQLite checkpoints only; target process remains alive.
- No target-process restart, host power loss, issuer authentication, general exactly-once guarantee or independent custody.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison published together; not separate raw-result-first revisions.

</div>

<div>

<a id="record-pydantic-failure-2026-10-02"></a>

## pydantic-failure-2026-10-02

Claim scope: author-operated-native-framework-control

Review state: author-retained-measured-record

Open [Report](experiments/pydantic-failure-2026-10-02/report.json), [Provenance](experiments/pydantic-failure-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/afda549c3f20f8e7b031275c06558a50bf20726e/interop/pydantic-ai-native-2026-10-02).

<a id="per-claim-results-4"></a>

### Per-claim results

| Claim                                       | Recorded result |
|---------------------------------------------|-----------------|
| bounded-seven-case-population               | pass            |
| reader-reconstructed-native-record          | pass            |
| retry-exhaustion-remains-error-no-effect    | pass            |
| committed-effect-error-retains-revision-one | pass            |
| external-host-recurring-adoption            | not-exercised   |
| independent-effect-custody                  | not-exercised   |

<a id="roles-4"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-4"></a>

### Limits

- Real Pydantic framework with scripted FunctionModel; no model-quality or real-provider inference measurement.
- Selected loopback ticket effects; no caller authentication, outside adoption or independent custody.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison published together; not separate raw-result-first revisions.

</div>

<div>

<a id="record-model-operational-2026-10-02"></a>

## model-operational-2026-10-02

Claim scope: author-operated-actual-weight-microtask-result

Review state: author-retained-measured-record

Open [Report](experiments/model-operational-2026-10-02/report.json), [Provenance](experiments/model-operational-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/ab84161d09bb7bd696bba57717a418a95dd1d976/interop/local-model-tasks-2026-10-02).

<a id="per-claim-results-5"></a>

### Per-claim results

| Claim                                          | Recorded result |
|------------------------------------------------|-----------------|
| complete-declared-population                   | pass            |
| evidence-complete                              | pass            |
| declared-run-budget                            | pass            |
| task-correctness-short24-structured-extraction | fail            |
| task-correctness-short24-arithmetic            | fail            |
| task-correctness-short24-policy-decision       | fail            |
| task-correctness-short24-grounded-abstention   | fail            |
| task-correctness-long96-structured-extraction  | fail            |
| task-correctness-long96-arithmetic             | fail            |
| task-correctness-long96-policy-decision        | fail            |
| task-correctness-long96-grounded-abstention    | fail            |
| external-host-recurring-adoption               | not-exercised   |
| independent-effect-custody                     | not-exercised   |

<a id="roles-5"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-5"></a>

### Limits

- Original 274795286-byte ZIP retained locally and available through expiring GitHub workflow artifact, not committed to Git or represented by the capsule.
- Capsule retains exact selected JSON/text members and excludes model weights/binaries; it cannot replay the full source/binary integrity check or rerun inference alone.
- Fixed configuration order confounds cache/warmup; author microtasks are not a benchmark estimate.
- CPU is whole-process delta; RSS process-lifetime peak; no task memory isolation, monetary cost or independent effects.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison published together; not separate raw-result-first revisions.

</div>

<div>

<a id="record-authority-recovery-2026-10-02"></a>

## authority-recovery-2026-10-02

Claim scope: author-operated-native-recovery-authority-control

Review state: author-retained-measured-record

Open [Report](experiments/authority-recovery-2026-10-02/report.json), [Provenance](experiments/authority-recovery-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/b02988a771bea3652660bec934c3c599c3ec4d27/interop/langgraph-recovery-authority-2026-10-02).

<a id="per-claim-results-6"></a>

### Per-claim results

| Claim                                        | Recorded result |
|----------------------------------------------|-----------------|
| complete-selected-population                 | pass            |
| exact-reader-reconstruction                  | pass            |
| valid-before-recovery-and-effect-separate    | pass            |
| valid-after-recovery-and-effect-separate     | pass            |
| revoked-before-recovery-and-effect-separate  | pass            |
| revoked-after-recovery-and-effect-separate   | pass            |
| expired-before-recovery-and-effect-separate  | pass            |
| expired-after-recovery-and-effect-separate   | pass            |
| rollback-before-recovery-and-effect-separate | pass            |
| rollback-after-recovery-and-effect-separate  | pass            |
| external-host-recurring-adoption             | not-exercised   |
| independent-effect-custody                   | not-exercised   |

<a id="roles-6"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-6"></a>

### Limits

- Host-selected deterministic integer recovery clock; signed target grant remains separate.
- Graph workers hard-exit/reopen; target process stays alive; no host power loss, distributed exactly-once or independent custody.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-target-process-recovery-2026-10-02"></a>

## target-process-recovery-2026-10-02

Claim scope: author-operated-native-target-process-control

Review state: author-retained-measured-record

Open [Report](experiments/target-process-recovery-2026-10-02/report.json), [Provenance](experiments/target-process-recovery-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/37d1dd42239fbe2ef55f625855e385d7337572c1/interop/target-recovery-2026-10-02).

<a id="per-claim-results-7"></a>

### Per-claim results

| Claim                                | Recorded result |
|--------------------------------------|-----------------|
| complete-selected-population         | pass            |
| exact-reader-reconstruction          | pass            |
| retained-completedEffects            | pass            |
| retained-incompleteRefusals          | pass            |
| retained-startupRefusals             | pass            |
| retained-targetProcesses             | pass            |
| restart-ready-retained-state         | pass            |
| crash-after-intent-retained-state    | pass            |
| crash-inside-effect-retained-state   | pass            |
| crash-after-effect-retained-state    | pass            |
| concurrent-intent-retained-state     | pass            |
| missing-store-retained-state         | pass            |
| changed-configuration-retained-state | pass            |
| external-host-recurring-adoption     | not-exercised   |
| independent-effect-custody           | not-exercised   |

<a id="roles-7"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-7"></a>

### Limits

- Selected target-process hard exits/reopen and local concurrency only; process IDs are unsigned runner testimony.
- Native SQLite/key/clock/HTTP remain same-operator; no power loss, production containment, general exactly-once or outside adoption.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-model-paired-cpu-2026-10-02"></a>

## model-paired-cpu-2026-10-02

Claim scope: author-operated-actual-weight-paired-microtask-result

Review state: author-retained-measured-record

Open [Report](experiments/model-paired-cpu-2026-10-02/report.json), [Provenance](experiments/model-paired-cpu-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/b7db63c319d53b0cb27638a229f966d477a2bbd5/interop/local-model-comparison-2026-10-02).

<a id="per-claim-results-8"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| complete-selected-population | pass |
| exact-reader-reconstruction | pass |
| within-declared-native-run-budget | pass |
| smol135-q4-short24-structured-extraction-all-six-strict-targets | fail |
| smol135-q4-short24-arithmetic-all-six-strict-targets | fail |
| smol135-q4-short24-policy-decision-all-six-strict-targets | fail |
| smol135-q4-short24-grounded-abstention-all-six-strict-targets | fail |
| smol135-q4-long96-structured-extraction-all-six-strict-targets | fail |
| smol135-q4-long96-arithmetic-all-six-strict-targets | fail |
| smol135-q4-long96-policy-decision-all-six-strict-targets | fail |
| smol135-q4-long96-grounded-abstention-all-six-strict-targets | fail |
| smol360-q4-short24-structured-extraction-all-six-strict-targets | fail |
| smol360-q4-short24-arithmetic-all-six-strict-targets | fail |
| smol360-q4-short24-policy-decision-all-six-strict-targets | fail |
| smol360-q4-short24-grounded-abstention-all-six-strict-targets | fail |
| smol360-q4-long96-structured-extraction-all-six-strict-targets | fail |
| smol360-q4-long96-arithmetic-all-six-strict-targets | fail |
| smol360-q4-long96-policy-decision-all-six-strict-targets | fail |
| smol360-q4-long96-grounded-abstention-all-six-strict-targets | fail |
| external-host-recurring-adoption | not-exercised |
| independent-effect-custody | not-exercised |

<a id="roles-8"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-8"></a>

### Limits

- Producer-selected compact original retains native source/library/call bytes; full preparation weights/source/dependency wheels remain privately archived and provider-expiring.
- Two separately declared preparation attempts, initial failure before inference and corrected preparation; cumulative transfer is not one 512MiB budget.
- Author tasks/answers exposed; blocked interleaving and cache reset do not make a representative benchmark or independent operation.
- Whole-process CPU and shared lifetime RSS are not per-task allocations; no live decision effects.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-openai-agents-ticket-2026-10-02"></a>

## openai-agents-ticket-2026-10-02

Claim scope: author-operated-scripted-native-sdk-control

Review state: author-retained-measured-record

Open [Report](experiments/openai-agents-ticket-2026-10-02/report.json), [Provenance](experiments/openai-agents-ticket-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/7a4b26058e54f0e6bbbaeab400dcd93c47607389/interop/openai-agents-ticket-2026-10-02).

<a id="per-claim-results-9"></a>

### Per-claim results

| Claim                                                | Recorded result |
|------------------------------------------------------|-----------------|
| complete-selected-population                         | pass            |
| exact-reader-reconstruction                          | pass            |
| typed-quality-not-evaluated                          | pass            |
| scripted-sdk-call-and-resource-accounting            | pass            |
| permit-task-effect-and-resource-axes                 | pass            |
| deny-task-effect-and-resource-axes                   | pass            |
| changed-arguments-task-effect-and-resource-axes      | pass            |
| producer-error-task-effect-and-resource-axes         | pass            |
| committed-effect-error-task-effect-and-resource-axes | pass            |
| turns-exhausted-task-effect-and-resource-axes        | pass            |
| external-host-recurring-adoption                     | not-exercised   |
| independent-effect-custody                           | not-exercised   |

<a id="roles-9"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-9"></a>

### Limits

- Actual OpenAI Agents SDK Runner/function_tool/TraceProcessor with scripted Model; nine model calls do not measure remote inference or model quality.
- Producer implementation, PR synthetic execution, final reader and separately pinned protected target revisions remain distinct.
- Same-operator synthetic HTTP ticket effect/key/clock; no independent custody, target restart or outside recurring adoption.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-execsurface-state-2026-10-02"></a>

## execsurface-state-2026-10-02

Claim scope: author-operated-native-metadata-and-endpoint-state-join

Review state: author-retained-measured-record

Open [Report](experiments/execsurface-state-2026-10-02/report.json), [Provenance](experiments/execsurface-state-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/88f475da4c4626b52ab78900e03ba9f73aa35640/interop/execsurface-state-2026-10-02).

<a id="per-claim-results-10"></a>

### Per-claim results

| Claim                                             | Recorded result |
|---------------------------------------------------|-----------------|
| selected-byte-predicate-valid                     | pass            |
| selected-evidence-valid                           | pass            |
| declared-carried-write-count                      | pass            |
| separate-endpoint-after-byte-count                | pass            |
| native-invocation-complete                        | pass            |
| import-origin-remains-disclosed                   | pass            |
| voluntary-tier-remains-disclosed                  | pass            |
| complete-observation-scope                        | fail            |
| unknown-typed-collection-health-remains-disclosed | pass            |
| native-write-count-not-invented                   | pass            |
| producer-calibration-pass                         | pass            |
| producer-comparison-outside-claimed-interval      | pass            |
| independent-effect-key-store-clock-custody        | not-exercised   |
| external-host-recurring-adoption                  | not-exercised   |
| typed-collection-health-envelope                  | not-exercised   |
| absence-of-intermediate-writes                    | not-exercised   |

<a id="roles-10"></a>

### Roles

| Role | Declaration |
|----|----|
| producer | Probity-owned workflow using pinned ExecSurface binary |
| companionAuthor | Probity |
| atlasOperator | Probity |
| retentionHolder | Probity |
| independentOperation | not-established |
| independentEffectCustody | not-established |
| outsideRecurringUse | not-established |

<a id="limits-10"></a>

### Limits

- Voluntary/peer/log-import/software-only predicate with incomplete scope and unknown typed collection health.
- Native schema-v2 metadata does not carry written bytes or write count; nine-byte content comes from separate snapshots and declared workload.
- Same operator controls generated fixture, key, store, clock and captures; no independent custody, principal authentication or outside adoption.
- Selected Linux x86_64 ptrace metadata only; no mmap/io_uring attribution or absence-of-intermediate-write claim.
- Native learn/check producer PASS is a separate outside-interval same-byte calibration, not authority, collection health or task quality.
- Release source/binary association is pinned but Rust build reproducibility is not established.

answerExposure: Author-written deterministic overwrite, companion and expected outcomes exposed; not blind.

comparisonOrder: Native companion output and verifier comparison emitted together; public raw retention before indexing does not establish a blind or native raw-result-first comparison.

</div>

<div>

<a id="record-model-format-cpu-2026-10-02"></a>

## model-format-cpu-2026-10-02

Claim scope: author-operated-actual-weight-paired-format-and-correctness-result

Review state: author-retained-measured-record

Open [Report](experiments/model-format-cpu-2026-10-02/report.json), [Provenance](experiments/model-format-cpu-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/75797cbb4fafc0669849357dd2275825b469c1f9/interop/local-model-format-control-2026-10-02).

<a id="per-claim-results-11"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| complete-selected-population | pass |
| exact-reader-reconstruction | pass |
| within-declared-native-run-budget | pass |
| smol135-q4-short24-unconstrained-structured-extraction-all-six-strict-targets | fail |
| smol135-q4-short24-unconstrained-arithmetic-all-six-strict-targets | fail |
| smol135-q4-short24-unconstrained-policy-decision-all-six-strict-targets | fail |
| smol135-q4-short24-unconstrained-grounded-abstention-all-six-strict-targets | fail |
| smol135-q4-short24-schema-structured-extraction-all-six-strict-targets | fail |
| smol135-q4-short24-schema-arithmetic-all-six-strict-targets | fail |
| smol135-q4-short24-schema-policy-decision-all-six-strict-targets | fail |
| smol135-q4-short24-schema-grounded-abstention-all-six-strict-targets | fail |
| smol135-q4-long96-unconstrained-structured-extraction-all-six-strict-targets | fail |
| smol135-q4-long96-unconstrained-arithmetic-all-six-strict-targets | fail |
| smol135-q4-long96-unconstrained-policy-decision-all-six-strict-targets | fail |
| smol135-q4-long96-unconstrained-grounded-abstention-all-six-strict-targets | fail |
| smol135-q4-long96-schema-structured-extraction-all-six-strict-targets | fail |
| smol135-q4-long96-schema-arithmetic-all-six-strict-targets | fail |
| smol135-q4-long96-schema-policy-decision-all-six-strict-targets | fail |
| smol135-q4-long96-schema-grounded-abstention-all-six-strict-targets | fail |
| smol360-q4-short24-unconstrained-structured-extraction-all-six-strict-targets | fail |
| smol360-q4-short24-unconstrained-arithmetic-all-six-strict-targets | fail |
| smol360-q4-short24-unconstrained-policy-decision-all-six-strict-targets | fail |
| smol360-q4-short24-unconstrained-grounded-abstention-all-six-strict-targets | fail |
| smol360-q4-short24-schema-structured-extraction-all-six-strict-targets | pass |
| smol360-q4-short24-schema-arithmetic-all-six-strict-targets | fail |
| smol360-q4-short24-schema-policy-decision-all-six-strict-targets | fail |
| smol360-q4-short24-schema-grounded-abstention-all-six-strict-targets | fail |
| smol360-q4-long96-unconstrained-structured-extraction-all-six-strict-targets | fail |
| smol360-q4-long96-unconstrained-arithmetic-all-six-strict-targets | fail |
| smol360-q4-long96-unconstrained-policy-decision-all-six-strict-targets | fail |
| smol360-q4-long96-unconstrained-grounded-abstention-all-six-strict-targets | fail |
| smol360-q4-long96-schema-structured-extraction-all-six-strict-targets | pass |
| smol360-q4-long96-schema-arithmetic-all-six-strict-targets | fail |
| smol360-q4-long96-schema-policy-decision-all-six-strict-targets | fail |
| smol360-q4-long96-schema-grounded-abstention-all-six-strict-targets | fail |
| independent-effect-key-store-clock-custody | not-exercised |
| external-host-recurring-adoption | not-exercised |
| protected-decision-effects | not-exercised |

<a id="roles-11"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-11"></a>

### Limits

- Format/schema correctness separate from typed-exact target correctness; each model/cap/decoder/family row retained independently.
- Protocol/compiler/grammars frozen before inference; selected integer-length, key-order and spacing restrictions limit generalization.
- Exposed author tasks and same-operator native execution; no representative benchmark, live protected decision effects or independent custody.
- Four separately declared preparation envelopes; cumulative transfer exceeds one512MiB envelope.
- Original compact native provider archive retains sources/grammars/outputs and resources; full preparation weights/source/wheels remain privately archived.
- CPU is whole-process delta and RSS shared lifetime peak; not per-model/task allocation.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-google-adk-ticket-2026-10-02"></a>

## google-adk-ticket-2026-10-02

Claim scope: author-operated-native-google-adk-scripted-reference-result

Review state: author-retained-measured-record

Open [Report](experiments/google-adk-ticket-2026-10-02/report.json), [Provenance](experiments/google-adk-ticket-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/a6cb0b0eb767e01ad2d0813c9483c39af08163cd/interop/adk-ticket-2026-10-02).

<a id="per-claim-results-12"></a>

### Per-claim results

| Claim                                      | Recorded result |
|--------------------------------------------|-----------------|
| bounded-reference-evidence-verified        | pass            |
| declared-reference-population              | pass            |
| scripted-SDK-resource-counts               | pass            |
| model-quality-not-measured                 | pass            |
| permit-task-completion                     | pass            |
| permit-native-revision-one                 | pass            |
| deny-task-completion                       | pass            |
| deny-native-revision-one                   | fail            |
| changed-arguments-task-completion          | pass            |
| changed-arguments-native-revision-one      | fail            |
| unhandled-before-task-completion           | fail            |
| unhandled-before-native-revision-one       | fail            |
| unhandled-after-task-completion            | fail            |
| unhandled-after-native-revision-one        | pass            |
| handled-first-task-completion              | pass            |
| handled-first-native-revision-one          | pass            |
| handled-last-task-completion               | pass            |
| handled-last-native-revision-one           | pass            |
| exhausted-first-task-completion            | fail            |
| exhausted-first-native-revision-one        | fail            |
| exhausted-last-task-completion             | fail            |
| exhausted-last-native-revision-one         | fail            |
| returned-error-first-task-completion       | pass            |
| returned-error-first-native-revision-one   | pass            |
| returned-error-last-task-completion        | pass            |
| returned-error-last-native-revision-one    | pass            |
| incomplete-close-task-completion           | fail            |
| incomplete-close-native-revision-one       | pass            |
| independent-effect-key-store-clock-custody | not-exercised   |
| external-host-recurring-adoption           | not-exercised   |

<a id="roles-12"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-12"></a>

### Limits

- Real Google ADK nativeRunner/plugin/retry paths with scriptedBaseLlm; no remote inference or model-quality evaluation.
- Typed MCPisError throughFunctionTool is not actual MCP transport.
- Task complete/error/incomplete separate from signednativeRevision; after-effect error and early close retain committed effects.
- Author-operated target/store/key/clock/capture and exposed expected outcomes; no independent custody/outside adoption.
- Original synthetic execution source, producer implementation, reviewed reader and protected target baseline separately pinned.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-installed-format-policy-2026-10-02"></a>

## installed-format-policy-2026-10-02

Claim scope: author-operated-installed-native-reader-upgrade-and-publication-policy-result

Review state: author-retained-measured-record

Open [Report](experiments/installed-format-policy-2026-10-02/report.json), [Provenance](experiments/installed-format-policy-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/efa0a2932e31dc69db60bb812b142e580fbf993c/interop/model-consumer-2026-10-02).

<a id="per-claim-results-13"></a>

### Per-claim results

| Claim                                           | Recorded result |
|-------------------------------------------------|-----------------|
| baseline-installed-version                      | pass            |
| baseline-framework-modules-absent               | pass            |
| baseline-original-evidence-state                | pass            |
| baseline-original-selected-publication-state    | pass            |
| baseline-comparison-evidence-state              | pass            |
| baseline-comparison-selected-publication-state  | pass            |
| baseline-format-evidence-state                  | pass            |
| baseline-format-selected-publication-state      | pass            |
| candidate-installed-version                     | pass            |
| candidate-framework-modules-absent              | pass            |
| candidate-original-evidence-state               | pass            |
| candidate-original-selected-publication-state   | pass            |
| candidate-comparison-evidence-state             | pass            |
| candidate-comparison-selected-publication-state | pass            |
| candidate-format-evidence-state                 | pass            |
| candidate-format-selected-publication-state     | pass            |
| prior-native-report-hashes-preserved            | pass            |
| old-reader-refuses-unsupported-format           | pass            |
| schema-policy-evidence-verified                 | pass            |
| schema-policy-selected-quality-hold             | pass            |
| two-low-policy-score-refusals                   | pass            |
| changed-source-evidence-refused                 | pass            |
| changed-source-publication-held                 | pass            |
| independent-effect-key-store-clock-custody      | not-exercised   |
| external-host-recurring-adoption                | not-exercised   |

<a id="roles-13"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-13"></a>

### Limits

- Actual framework-free installed0.0.2→0.0.3 upgrade and selectedhostpolicy run, not a new inference experiment.
- Verified scoped-report publication separate from held policy1/6 correctness, no dispatch or recovery authority.
- Full original2268member provider artifact retained including previous upgrade, wheels, immutable fixture packets and rawgate streams; no omissions.
- Same operator selects installation/reader/policy/expected outcomes; no registry release, outside recurring use or independent custody.
- Consumer source/reviewed commit and actualnative192 producer source/run remain separate.

answerExposure: Author-written tasks/controls and expected outcomes exposed; not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-model-boundary-cpu-2026-10-02"></a>

## model-boundary-cpu-2026-10-02

Claim scope: author-operated-finite-typed-policy-grounded-boundary-result

Review state: author-retained-measured-record

Open [Report](experiments/model-boundary-cpu-2026-10-02/report.json), [Provenance](experiments/model-boundary-cpu-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/6cfd28dc61aa0ae43be5da8382fe959c94235997/interop/local-model-boundary-tasks-2026-10-02).

<a id="per-claim-results-14"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| all384-original-attempts-scored | pass |
| evidence-complete-and-within-run-budget | pass |
| protected-effects-not-executed | pass |
| smol135-q4-short24-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-short24-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-short24-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-short24-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | pass |
| smol135-q4-short24-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-short24-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-long96-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-long96-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-long96-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-long96-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | pass |
| smol135-q4-long96-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol135-q4-long96-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-short24-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-short24-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-short24-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-short24-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-short24-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-short24-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-long96-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-long96-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-long96-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-long96-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-long96-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| smol360-q4-long96-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| independent-effect-custody | not-exercised |
| outside-recurring-host-use | not-exercised |
| representative-benchmark-performance | out-of-scope |

<a id="roles-14"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| atlasOperator            | Probity                |
| retentionHolder          | Probity                |
| independentOperation     | not-established        |
| independentEffectCustody | not-established        |
| outsideRecurringUse      | not-established        |

<a id="limits-14"></a>

### Limits

- All24 model/cap/decoder/family rows and384 original attempt scores retained unchanged; pair correctness separate from schema validity.
- 48 authored case identities include46 unique literal inputs and two repeated positive controls; exposed targets, not blind or representative.
- No protected model decision effects, independent operation/effect custody or outside recurring use.
- Five separate preparation envelopes; cumulative2167006362 response-body bytes cannot be presented as one512MiB acquisition.
- Complete original preparation privately archived; public871-member original compact maps to901 full members with30 explicit omissions.
- Total process CPU includes initialization; returned-call CPU and shared lifetime RSS keep their original scopes.
- Post hoc vocabulary diagnosis and cap comparisons do not alter the frozen rubric or published scores.

answerExposure: Author-written cases, public targets and previous public failures informed selection;48 identities include46 literal inputs and two repeated positive-control inputs. Not blind.

comparisonOrder: Native output and comparison emitted and published together; public Atlas retention before indexing does not establish a blind or raw-result-first comparison.

</div>

<div>

<a id="record-atomic-delegation-2026-10-02"></a>

## atomic-delegation-2026-10-02

Claim scope: native-local-certificate-selection-persistence

Review state: author-operated-upstream-review-pending

Open [Report](experiments/atomic-delegation-2026-10-02/report.json), [Provenance](experiments/atomic-delegation-2026-10-02/provenance.json) and [Contract](https://github.com/astrogilda/atomic/blob/80be8dae6feb8b9106181b78fba2c7c6a7c8f4d8/tools/native-evaluation/README.md).

<a id="per-claim-results-15"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| complete-declared-native-population | pass |
| exact_retry_and_process_restart_preserve_a_narrow_grant | pass |
| revocation_survives_restart_and_does_not_revoke_a_distinct_renewal | pass |
| expired_and_corrupt_grants_stay_inactive_after_restart | pass |
| local_selection_does_not_establish_external_issuer_authority | pass |
| upstream-maintainer-acceptance | not-exercised |
| outside-recurring-host-use | not-exercised |
| independent-effect-custody | not-exercised |
| server-permission-enforcement | not-exercised |
| remote-revocation | not-exercised |
| crash-mid-write | not-exercised |

<a id="roles-15"></a>

### Roles

| Role                        | Declaration             |
|-----------------------------|-------------------------|
| fixtureAuthor               | Probity                 |
| runner                      | Probity local workspace |
| keyClockFilesystemCustodian | Probity local workspace |
| independentOperation        | not-established         |
| independentEffectCustody    | not-established         |
| outsideRecurringUse         | not-established         |

<a id="limits-15"></a>

### Limits

- Normal fresh reader-process restart, not crash-mid-write consistency.
- Self-contained local grant selection does not establish external issuer authority or server permission enforcement.
- Local key, clock and filesystem remain under one operator; child PIDs are unsigned testimony.
- No remote revocation, independently operated effect custody, model task quality or recurring outside use is established.
- Full author-assembled ZIP packages byte-exact original retained-run files; it is not a CI provider archive.

answerExposure: Author-written native cases and expected outcomes exposed; not blind.

comparisonOrder: Original native observations and test assertions emitted together, not separate public raw-result-first revisions.

</div>

<div>

<a id="record-installed-boundary-policy-2026-10-02"></a>

## installed-boundary-policy-2026-10-02

Claim scope: author-operated-installed-reader-publication-and-quality-policy-result

Review state: author-retained-measured-record

Open [Report](experiments/installed-boundary-policy-2026-10-02/report.json), [Provenance](experiments/installed-boundary-policy-2026-10-02/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/72fc276003232e3b34aed057adc9a76db4f147e3/interop/model-consumer-2026-10-02).

<a id="per-claim-results-16"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| ordinary-installed-0.0.3-to0.0.4-upgrade | pass |
| baseline-boundary-refuses-before-reader-launch | pass |
| complete-evidence-publication | pass |
| selected-quality-policy-acceptance | fail |
| installed-smol135-q4-short24-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-short24-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-short24-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-short24-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | pass |
| installed-smol135-q4-short24-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-short24-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-long96-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-long96-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-long96-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-long96-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | pass |
| installed-smol135-q4-long96-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol135-q4-long96-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-short24-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-short24-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-short24-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-short24-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-short24-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-short24-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-long96-unconstrained-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-long96-unconstrained-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-long96-unconstrained-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-long96-schema-typed-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-long96-schema-policy-boundary-all-sixteen-targets-and-eight-pairs | fail |
| installed-smol360-q4-long96-schema-grounded-boundary-all-sixteen-targets-and-eight-pairs | fail |
| selected-quality-smol135-q4-short24-schema-policy-boundary-correct | fail |
| selected-quality-smol135-q4-short24-schema-policy-boundary-fullyCorrectPairs | fail |
| selected-quality-smol135-q4-short24-schema-grounded-boundary-correct | fail |
| selected-quality-smol135-q4-short24-schema-grounded-boundary-fullyCorrectPairs | fail |
| selected-quality-smol135-q4-long96-schema-policy-boundary-correct | fail |
| selected-quality-smol135-q4-long96-schema-policy-boundary-fullyCorrectPairs | fail |
| selected-quality-smol135-q4-long96-schema-grounded-boundary-correct | fail |
| selected-quality-smol135-q4-long96-schema-grounded-boundary-fullyCorrectPairs | fail |
| selected-quality-smol360-q4-short24-schema-policy-boundary-correct | fail |
| selected-quality-smol360-q4-short24-schema-policy-boundary-fullyCorrectPairs | fail |
| selected-quality-smol360-q4-short24-schema-grounded-boundary-correct | fail |
| selected-quality-smol360-q4-short24-schema-grounded-boundary-fullyCorrectPairs | fail |
| selected-quality-smol360-q4-long96-schema-policy-boundary-correct | fail |
| selected-quality-smol360-q4-long96-schema-policy-boundary-fullyCorrectPairs | fail |
| selected-quality-smol360-q4-long96-schema-grounded-boundary-correct | fail |
| selected-quality-smol360-q4-long96-schema-grounded-boundary-fullyCorrectPairs | fail |
| external-host-recurring-adoption | not-exercised |
| independent-effect-custody | not-exercised |
| model-action-acceptance | not-exercised |
| new-model-inference | not-exercised |
| general-benchmark-performance | not-exercised |

<a id="roles-16"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| atlasOperator            | Probity                |
| independentEffectCustody | not-established        |
| independentOperation     | not-established        |
| outsideRecurringUse      | not-established        |
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| retentionHolder          | Probity                |

<a id="limits-16"></a>

### Limits

- Author-operated installed0.0.3-to0.0.4 reader and host-selected publication/quality policy; no new inference.
- Public selected capsule omits native packet duplicates and unrelated earlier workflow results; hashes cannot recreate omitted bytes.
- The complete provider original is retained separately; native compact archive and preparation originals have their own retention records.
- Evidence verification and complete measurement are distinct from selected quality acceptance, action authority, recurring outside adoption and independent effect custody.

answerExposure: Author-written cases, targets and host quality thresholds exposed; not blind.

comparisonOrder: Original CI execution and comparison emitted together. Selected raw Atlas retention precedes indexing at dc54f604d90278fc41c730313ffa9310a18d7ebc; it does not establish blind or independent comparison.

</div>

<div>

<a id="record-model-vocabulary-cpu-2026-10-03"></a>

## model-vocabulary-cpu-2026-10-03

Claim scope: authored-native-action-vocabulary-and-installed-quality-hold

Review state: author-retained-measured-record

Open [Report](experiments/model-vocabulary-cpu-2026-10-03/report.json), [Provenance](experiments/model-vocabulary-cpu-2026-10-03/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/ff556045011010025cc95b7572bffb0dbe0dc0d6/interop/local-model-vocabulary-2026-10-02).

<a id="per-claim-results-17"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| complete-native-population | pass |
| complete-evidence-within-declared-budget | pass |
| control-complete-policy-correctness | fail |
| vocabulary-complete-policy-correctness | fail |
| default-quality--smol135-q4--short24--policy-control | fail |
| default-quality--smol135-q4--short24--policy-vocabulary | fail |
| default-quality--smol135-q4--long96--policy-control | fail |
| default-quality--smol135-q4--long96--policy-vocabulary | fail |
| default-quality--smol360-q4--short24--policy-control | fail |
| default-quality--smol360-q4--short24--policy-vocabulary | fail |
| default-quality--smol360-q4--long96--policy-control | fail |
| default-quality--smol360-q4--long96--policy-vocabulary | fail |
| native-resource--elapsed_ns | pass |
| native-resource--process_cpu_ns | pass |
| native-resource--nativeTokens | pass |
| native-resource--preparation | pass |
| installed-replay--evidenceDecision | pass |
| installed-replay--stdoutReplayExact | pass |
| installed-replay--structuredReplayExact | pass |
| installed-replay--evidenceOnlyStillQualityHold | pass |
| installed-replay--mutations | pass |
| installed-replay--cumulativeSixPreparationsResponseBodyBytes | pass |
| installed-default-quality | fail |
| outside-producer-acceptance | not-exercised |
| external-host-recurring-adoption | not-exercised |
| independent-effect-custody | not-exercised |
| model-action-acceptance | not-exercised |
| general-benchmark-performance | not-exercised |
| independent-transfer-or-inference-witness | not-exercised |

<a id="roles-17"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| atlasOperator            | Probity                |
| independentEffectCustody | not-established        |
| independentOperation     | not-established        |
| outsideRecurringUse      | not-established        |
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| retentionHolder          | Probity                |

<a id="limits-17"></a>

### Limits

- Finite authored CPU policy task; schema validity does not imply policy correctness.
- Installed review performs no model calls and grants no action authority.
- Same operator source-bound readback; outside producer acceptance, recurring adoption and independent effect custody remain unestablished.
- Public retention preserves all native packet members; full weights, dependency wheels, source archive and CI installed environment remain outside this capsule. Their hashes cannot reconstruct omitted bytes.
- Provider retention expiry is recorded; separate same-operator retention is not independent custody.

answerExposure: Authored policy inputs and targets exposed; vocabulary intervention informed by previous 384-call results; not blind.

comparisonOrder: Native inference follows frozen protocol, source-bound controls and protected merge; Atlas raw retention precedes indexing at e1122b6c08915207921ca575d98115cea4790062. Same-operator replay does not establish independent custody.

</div>

<div>

<a id="record-model-tool-arguments-cpu-2026-10-03"></a>

## model-tool-arguments-cpu-2026-10-03

Claim scope: authored-native-tool-arguments-with-strict-quality-hold

Review state: author-retained-measured-record

Open [Report](experiments/model-tool-arguments-cpu-2026-10-03/native-report.json), [Provenance](experiments/model-tool-arguments-cpu-2026-10-03/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/tree/884814fe8cbc2e3b21d267fbaf86726c37892b14/interop/local-model-tool-arguments-2026-10-03).

<a id="per-claim-results-18"></a>

### Per-claim results

| Claim                               | Recorded result |
|-------------------------------------|-----------------|
| complete-native-population          | pass            |
| complete-evidence-within-run-budget | pass            |
| scoped-evidence-publication         | pass            |
| strict-tool-quality                 | fail            |
| strict-quality-row--0               | fail            |
| strict-quality-row--1               | fail            |
| strict-quality-row--2               | fail            |
| strict-quality-row--3               | fail            |
| strict-quality-row--4               | fail            |
| strict-quality-row--5               | fail            |
| strict-quality-row--6               | fail            |
| strict-quality-row--7               | fail            |
| native--nativeTokens                | pass            |
| native--resources                   | pass            |
| native--preparationReuse            | pass            |
| native--effectsExecuted             | pass            |
| native--providerCalls               | pass            |
| native--providerDollars             | pass            |
| outside-producer-acceptance         | not-exercised   |
| external-host-recurring-adoption    | not-exercised   |
| independent-effect-custody          | not-exercised   |
| independent-inference-witness       | not-exercised   |
| model-action-acceptance             | not-exercised   |
| general-benchmark-performance       | not-exercised   |

<a id="roles-18"></a>

### Roles

| Role                     | Declaration            |
|--------------------------|------------------------|
| atlasOperator            | Probity                |
| independentEffectCustody | not-established        |
| independentOperation     | not-established        |
| outsideRecurringUse      | not-established        |
| producer                 | Probity-owned workflow |
| readerAuthor             | Probity                |
| retentionHolder          | Probity                |

<a id="limits-18"></a>

### Limits

- Finite exposed authored tool-argument and abstention cases; no representative benchmark or blind evaluation.
- Native inference, evidence publication and semantic quality are separate; all eight strict quality rows hold.
- No tools or protected publication/admission/dispatch/recovery effects execute from model answers.
- Atlas retains the entire compact native provider artifact, not the complete preparation artifact containing model weights, wheels, archive and installed environment; hashes cannot reconstruct omitted bytes.
- Provider artifact expiry is disclosed; durable author-held Git bytes do not establish independent effect custody, outside acceptance or recurring adoption.
- Atlas validation reads data only and performs no new inference or installation of packet code.

answerExposure: Authored inputs, targets and thresholds exposed; prospective new study follows earlier 384/128-call findings; not blind.

comparisonOrder: Prospective protocol and reviewed source precede the protected Observer main execution; exact native provider bytes are retained additively in Atlas afterward. Neither raw retention nor replay establishes independent execution.

</div>

<div>

<a id="record-aps-jcs-2026-10-04"></a>

## aps-jcs-2026-10-04

Claim scope: raw-admission-serializer-and-signed-receipt-comparison

Review state: author-retained-measured-record

Open [Report](experiments/aps-jcs-2026-10-04/report.json), [Provenance](experiments/aps-jcs-2026-10-04/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-vectors/blob/fa3e6705746e0131a7884591a86e5c05b6c050ab/interop/aps-jcs/README.md).

<a id="per-claim-results-19"></a>

### Per-claim results

| Claim                               | Recorded result |
|-------------------------------------|-----------------|
| native-admission-outcomes--v20.20.2 | pass            |
| signed-receipt-controls--v20.20.2   | pass            |
| native-admission-outcomes--v22.23.3 | pass            |
| signed-receipt-controls--v22.23.3   | pass            |
| cross-runtime-machine-agreement     | pass            |
| cross-runtime-receipt-agreement     | pass            |
| diagnostic-prose-differences        | pass            |
| outside-recurring-host-adoption     | not-exercised   |
| independently-operated-custody      | not-exercised   |
| formal-frozen-APS-study             | not-exercised   |

<a id="roles-19"></a>

### Roles

| Role | Declaration |
|----|----|
| producer | Pinned public native inputs and Probity-authored finite controls |
| readerAuthor | Probity |
| runner | Probity-owned GitHub Actions |
| atlasOperator | Probity |
| retentionHolder | Probity |
| independentOperation | not-established |
| independentEffectCustody | not-established |
| outsideRecurringUse | not-established |

<a id="limits-19"></a>

### Limits

- Two runtimes repeat the same 1,223 identities; populations remain separate.
- Parsed serialization, strict raw parsing and signed serialized receipt verification remain separate.
- The 42 parsed acceptances on raw-refusal rows include profile differences; they are not all duplicate losses.
- RFC 8785 and opt-in I-JSON numeric and Unicode policies differ; all 23 strict-parser policy rows remain retained.
- Selected licensed first-party source is retained separately from native output. Registry packages restore from integrity lockfiles; Node and Rust runtimes are not vendored.
- Author-operated conformance; separately proposed APS dependency and formal pre-run study confirmation remain separate.

answerExposure: Frozen public conformance expectations and authored receipt controls were exposed before implementation.

comparisonOrder: Native outputs and comparisons were emitted together; original archives and selected source were published before Atlas indexing.

</div>

<div>

<a id="record-google-adk-responses-2026-10-04"></a>

## google-adk-responses-2026-10-04

Claim scope: native-user-response-routing-callback-effect-and-separate-verify-comparison

Review state: author-retained-measured-record

Open [Report](experiments/google-adk-responses-2026-10-04/report.json), [Provenance](experiments/google-adk-responses-2026-10-04/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/blob/de522aa60966309599d03b06d02f50a52d7fb58f/interop/adk-user-responses-2026-10-04/README.md).

<a id="per-claim-results-20"></a>

### Per-claim results

| Claim                                            | Recorded result |
|--------------------------------------------------|-----------------|
| issuing-call-later-root-and-effects--37202968778 | pass            |
| installed-routing-reader-repeat--37202968778     | pass            |
| native-semantic-controls--37202968778            | pass            |
| actual-verify-six-repeated-cases--37202968778    | pass            |
| actual-verify-boundary-controls--37202968778     | pass            |
| issuing-call-later-root-and-effects--37204220648 | pass            |
| installed-routing-reader-repeat--37204220648     | pass            |
| native-semantic-controls--37204220648            | pass            |
| actual-verify-six-repeated-cases--37204220648    | pass            |
| actual-verify-boundary-controls--37204220648     | pass            |
| outside-recurring-host-adoption                  | not-exercised   |
| independently-operated-effect-custody            | not-exercised   |
| prospective-eight-task-study                     | not-exercised   |

<a id="roles-20"></a>

### Roles

| Role | Declaration |
|----|----|
| producer | Actual pinned Google ADK Runner with fixed public BaseLlm responses |
| readerAuthor | Probity |
| runner | Probity-owned GitHub Actions |
| atlasOperator | Probity |
| retentionHolder | Probity |
| independentOperation | not-established |
| independentEffectCustody | not-established; author-operated PEER |
| outsideRecurringUse | not-established |

<a id="limits-20"></a>

### Limits

- Three finite three-turn cases on each fully qualified execution; resumability disabled.
- Actual ADK framework with a fixed public BaseLlm script, no provider inference or model-quality measurement.
- The LRO write is a same-author host completion, separate from the native start-only tool body.
- Two distinct Observer/witness keys remain author-held PEER custody with author-operated storage and clock.
- Actual Verify event_absence/v1 covers the six plugin-delivered native turns; whole-second projections retain original fractional timestamps separately.
- First failed reader attempt and intermediate correction remain separate original archives.
- The older 16-row comparison remains pinned separately; the prospective eight-task implementation-owned study has not started.
- Restore the originally empty denied-workspace directory before installed-reader replay; no file bytes change.

answerExposure: Fixed public model responses, authored controls and expected outcomes were exposed before execution.

comparisonOrder: Native outputs and assertions were emitted together. Failed, corrected, PR and merged-main originals were retained before Atlas indexing.

</div>

<div>

<a id="record-go-jcs-2026-10-04"></a>

## go-jcs-2026-10-04

Claim scope: raw-input-admission-and-pinned-go-canonical-byte-comparison

Review state: author-retained-measured-record

Open [Report](experiments/go-jcs-2026-10-04/report.json), [Provenance](experiments/go-jcs-2026-10-04/provenance.json) and [Contract](https://github.com/probityai/jcs-admit/blob/7573937b882de4f32cbc4cd69dfaab8098729412/interop/go-jcs/README.md).

<a id="per-claim-results-21"></a>

### Per-claim results

| Claim                                                | Recorded result |
|------------------------------------------------------|-----------------|
| complete-conformance-outcomes--pull-request-go1.27.1 | pass            |
| bare-go-outcomes-retained--pull-request-go1.27.1     | pass            |
| clean-native-worktree--pull-request-go1.27.1         | pass            |
| complete-conformance-outcomes--pull-request-go1.25.5 | pass            |
| bare-go-outcomes-retained--pull-request-go1.25.5     | pass            |
| clean-native-worktree--pull-request-go1.25.5         | pass            |
| complete-conformance-outcomes--push-go1.25.5         | pass            |
| bare-go-outcomes-retained--push-go1.25.5             | pass            |
| clean-native-worktree--push-go1.25.5                 | pass            |
| complete-conformance-outcomes--push-go1.27.1         | pass            |
| bare-go-outcomes-retained--push-go1.27.1             | pass            |
| clean-native-worktree--push-go1.27.1                 | pass            |
| outside-recurring-host-adoption                      | not-exercised   |
| independently-operated-custody                       | not-exercised   |
| task-or-workload-execution                           | not-exercised   |
| complete-conformance-outcomes--main-go1.25.5         | pass            |
| bare-go-outcomes-retained--main-go1.25.5             | pass            |
| clean-native-worktree--main-go1.25.5                 | pass            |
| complete-conformance-outcomes--main-go1.27.1         | pass            |
| bare-go-outcomes-retained--main-go1.27.1             | pass            |
| clean-native-worktree--main-go1.27.1                 | pass            |

<a id="roles-21"></a>

### Roles

| Role | Declaration |
|----|----|
| producer | Public RFC, Go-rail, attack and Node number fixtures; Probity-authored finite controls |
| readerAuthor | Probity |
| runner | Probity-owned GitHub Actions |
| atlasOperator | Probity |
| retentionHolder | Probity |
| independentOperation | not-established |
| independentEffectCustody | not-exercised |
| outsideRecurringUse | not-established |

<a id="limits-21"></a>

### Limits

- Finite conformance inputs and exposed expected answers; no task or workload experiment.
- Six executions on two Go runtimes repeat the same 1,263 case identities: two final-PR, two branch-push and two merged-main runs; each stays separate.
- Go accepts objects or arrays; number samples use declared array wrappers, admitted scalar roots refuse separately.
- RFC 8785 and I-JSON policies differ; bare Go outcomes remain separate from admission policy.
- The original native archives retain source and reports. Installed executable hashes are recorded, but executables and the full installed runtime are outside those provider archives.
- The upstream multi-gigabyte number benchmark was not selected.

answerExposure: Public fixture expectations and finite controls were available before implementation.

comparisonOrder: Native outputs and comparisons were emitted together; all four originals were byte-retained before Atlas indexing.

</div>

<div>

<a id="record-ag2-push-authority-2026-10-04"></a>

## ag2-push-authority-2026-10-04

Claim scope: native-task-and-push-url-admission-dispatch-target-and-observed-effect-comparison

Review state: author-retained-measured-record

Open [Report](experiments/ag2-push-authority-2026-10-04/report.json), [Provenance](experiments/ag2-push-authority-2026-10-04/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-observer/blob/4b5ca47854c9be2814eeb5fe6f72b79b0182d2c7/interop/ag2-push-authority-2026-10-04/README.md).

<a id="per-claim-results-22"></a>

### Per-claim results

| Claim                                              | Recorded result |
|----------------------------------------------------|-----------------|
| native-task-population--pull-request               | pass            |
| target-callbacks--pull-request                     | pass            |
| observed-writes--pull-request                      | pass            |
| semantic-controls--pull-request                    | pass            |
| installed-reader-repeat--pull-request              | pass            |
| native-task-population--main                       | pass            |
| target-callbacks--main                             | pass            |
| observed-writes--main                              | pass            |
| semantic-controls--main                            | pass            |
| installed-reader-repeat--main                      | pass            |
| outside-effect-custody                             | not-exercised   |
| automatic-task-dispatch                            | not-exercised   |
| callback-network-service                           | not-exercised   |
| recurring-consumer-adoption                        | not-exercised   |
| provider-or-model-quality                          | not-exercised   |
| configuration-callback-effect-matrix--pull-request | pass            |
| configuration-callback-effect-matrix--main         | pass            |

<a id="roles-22"></a>

### Roles

| Role | Declaration |
|----|----|
| producer | Pinned native AG2 TestConfig and A2A Python, with Probity-authored finite controls |
| readerAuthor | Probity |
| runner | Probity-owned GitHub Actions |
| atlasOperator | Probity |
| retentionHolder | Probity |
| independentOperation | not-established |
| independentEffectCustody | not-established |
| outsideRecurringUse | not-established |

<a id="limits-22"></a>

### Limits

- 18 finite actual native tasks per qualified run; fixed answers and no provider inference.
- Explicit same-author post-completion sender call; no automatic task callback dispatch.
- Controlled ASGI target and native plaintext gRPC loopback; no external callback target.
- PEER keys, target and custody; no outside operator or host adoption.
- Original native JSON and wire bytes retained; the reader checks JSON semantics without decoding protobuf wire.
- Older 16 rows unchanged; prospective eight-task study not started.

answerExposure: Public fixed responses and finite expected outcomes were exposed before execution.

comparisonOrder: Original failures and passing native archives were retained before Lab indexing.

</div>

<div>

<a id="record-remora-boundary-2026-10-04"></a>

## remora-boundary-2026-10-04

Claim scope: verifier-behavior-on-public-producer-fixtures

Review state: producer-review-pending-submission

Open [Report](experiments/remora-boundary-2026-10-04/report.json), [Provenance](experiments/remora-boundary-2026-10-04/provenance.json) and [Contract](https://github.com/darklordVirtual/REMORA-research/blob/fe324dd734734d9227aa894330ac52c2bb916b94/artifacts/interop/index.json).

<a id="per-claim-results-23"></a>

### Per-claim results

| Claim                                     | Recorded result |
|-------------------------------------------|-----------------|
| exact-call-binding-v1-cases-match-fixture | pass            |
| fresh-authority-v1-cases-match-fixture    | pass            |
| effect-evidence-v1-cases-match-fixture    | pass            |
| exact_call_binding-status                 | pass            |
| single_use_authorization-status           | pass            |
| fresh_authority_at_dispatch-status        | pass            |
| effect_state_distinction-status           | pass            |
| interpreters-agree-on-every-case          | pass            |
| source-mutations-caught                   | pass            |
| run-record-independence                   | pass            |
| effect-hash-rule                          | not-exercised   |
| independent-effect-custody                | not-exercised   |
| production-safety                         | out-of-scope    |
| producer-acceptance                       | not-exercised   |

<a id="roles-23"></a>

### Roles

| Role                     | Declaration                  |
|--------------------------|------------------------------|
| readerAuthor             | Probity                      |
| runner                   | Probity-owned GitHub Actions |
| producer                 | REMORA                       |
| independentOperation     | not-established              |
| independentEffectCustody | not-established              |

<a id="limits-23"></a>

### Limits

- Run records state SECOND_IMPLEMENTATION, EXTERNAL operator and NOT_INDEPENDENT; under REMORA's rule they support REPRODUCED, not EXTERNALLY_VERIFIED.
- Authorization signatures use a public test-only HMAC key created and checked by the reader; no REMORA-issued authorization is authenticated.
- The effect hash rule is unsupported until the contract defines its preimage; no frozen case uses it.
- Fixture premises such as revocation visibility at presentation and the observed field values are taken as supplied.
- No production safety, authority, independent effect custody or lifecycle change follows from these records.

answerExposure: Expected outcomes are inside the frozen fixtures and the reader compares against them; not answer-blind. Whether reference-verifier text was read while the reader was written is not recorded.

comparisonOrder: Native outputs and comparisons were emitted together in one run.

</div>

<div>

<a id="record-aeoess-receipt-signature-2026-10-05"></a>

## aeoess-receipt-signature-2026-10-05

Claim scope: source-reported-outside-verifier-and-primitive-checks-on-public-fixtures

Review state: upstream-merged-retained-run

Open [Report](experiments/aeoess-receipt-signature-2026-10-05/report.json), [Provenance](experiments/aeoess-receipt-signature-2026-10-05/provenance.json) and [Contract](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/f8d6eb4461759ce7dbb4c33ab03a688ba2bb541f/CONTRIBUTING.md).

<a id="per-claim-results-24"></a>

### Per-claim results

| Claim                                     | Recorded result |
|-------------------------------------------|-----------------|
| outside-verifier-fixture-comparisons      | pass            |
| outside-context-free-identifiers          | pass            |
| always-valid-negative-control-failures    | pass            |
| signature-mutation-affected-members       | pass            |
| outside-context-bearing-identifier-checks | not-exercised   |
| independent-semantic-grading              | not-exercised   |
| independent-effect-custody                | not-exercised   |
| maintained-host-ci-adoption               | not-exercised   |

<a id="roles-24"></a>

### Roles

| Role | Declaration |
|----|----|
| runner | Claude under Tymofii Pidlisnyi (@aeoess)’s revocable mandate, as declared in RUN.md |
| humanReviewer | Tymofii Pidlisnyi (@aeoess), source-reported |
| verifierAuthor | tomjwxf |
| identifierPrimitive | GNU coreutils sha256sum, invoked by runner-authored digests21.py |
| atlasRetentionAndIntegrityChecks | Probity |
| independentEffectCustody | not-established |
| corpusMemberAuthors | giskard09, tomjwxf and astrogilda, as declared by original RUN.md and corpus README |
| adapterAndHarnessAuthor | astrogilda (Probity) |

<a id="limits-24"></a>

### Limits

- Operator identity, human review and container custody are declared by the original source, not independently authenticated.
- Four context-bearing identifier checks remain outside the runner primitive coverage.
- Author harness interpretation and grading remain a separate layer.
- Repeated runs use the same 25 fixtures; no agent, production effect or independent custody measurement.
- Merged run record does not establish full-family admission or maintained host CI adoption.

answerExposure: Published expected outcomes and the author harness were available before the run; not answer-blind.

comparisonOrder: The original harness emitted verifier answers and comparison results together. No separate raw-result revision preceded comparison.

</div>

<div>

<a id="record-w3c-report-replay-2026-10-06"></a>

## w3c-report-replay-2026-10-06

Claim scope: historical-report-accounting-and-separate-diagnostic-control-dependencies

Review state: author-retained-measured-record

Open [Report](experiments/w3c-report-replay-2026-10-06/report.json), [Provenance](experiments/w3c-report-replay-2026-10-06/provenance.json) and [Contract](https://github.com/probityai/agent-evidence-vectors/tree/2f3aee40a454df6de0f571d119f057d7dbb8dd67).

<a id="per-claim-results-25"></a>

### Per-claim results

| Claim                                      | Recorded result |
|--------------------------------------------|-----------------|
| historical-harness-comparisons             | pass            |
| historical-report-state-accounting         | pass            |
| historical-report-crosswalk                | pass            |
| negative-witness-state-recorded-control    | pass            |
| checker-and-configuration-recorded-control | pass            |
| real-workload-action-completion            | not-exercised   |
| independent-operation                      | not-exercised   |
| outside-maintained-host-adoption           | not-exercised   |
| current-vectors-reader-replay              | not-exercised   |

<a id="roles-25"></a>

### Roles

| Role                   | Declaration              |
|------------------------|--------------------------|
| verifierAuthor         | Probity                  |
| historicalRunner       | Probity, author-operated |
| diagnosticRunner       | Probity, author-operated |
| retentionAndAccounting | Probity                  |
| independentOperator    | not-established          |

<a id="limits-25"></a>

### Limits

- Synthetic conformance artifacts; the customer refund story is hypothetical.
- Retained-output accounting executes no captured reader or mutant code and performs no new model inference.
- Historical 272-case report and separate 232-fixture diagnostic population are not combined.
- Report validity, evidence conclusion and actual action completion are distinct.
- Reader binding check is a historical proposed rule; its draft normative status is not promoted.
- No independent operation, effect custody, production workload, customer payment or outside maintained job is established.

answerExposure: Published expected answers and author-selected predicates were exposed; not answer-blind.

comparisonOrder: Historical harness outcomes and comparison grades emitted together. Diagnostic copies remove one predicate each; outputs are retained separately from the historical report.

</div>

<div>

<a id="record-aps-corrected20-2026-10-10"></a>

## aps-corrected20-2026-10-10

Claim scope: independently-written-and-operated-reader-on-producer-authored-finite-synthetic-corpus

Review state: author-retained-measured-record

Open [Report](experiments/aps-corrected20-2026-10-10/report.json), [Provenance](experiments/aps-corrected20-2026-10-10/provenance.json) and [Contract](https://github.com/agent-passport-system/agent-passport-system/blob/407ca2d5ad10c846860ad1b6faafc971ae9690e5/fixtures/agent-passport-v2/README.md).

<a id="per-claim-results-26"></a>

### Per-claim results

| Claim                                         | Recorded result |
|-----------------------------------------------|-----------------|
| corrected-corpus-source-SHA256                | pass            |
| finite-diagnostic-comparison                  | pass            |
| upstream-SDK-observation-population           | pass            |
| separate-reader-outcome-population            | pass            |
| five-separate-upstream-draft-annotations      | pass            |
| reader-does-not-import-APS-SDK                | pass            |
| selected-SDK-corpus-characterization          | not-exercised   |
| historical-ambiguous-key-SDK-characterization | not-exercised   |
| authenticated-historical-key-authority        | not-exercised   |
| principal-binding                             | not-exercised   |
| general-JCS-conformance                       | out-of-scope    |
| independent-cryptographic-backend             | out-of-scope    |
| outside-recurring-host-adoption               | not-exercised   |
| independent-effect-custody                    | not-exercised   |

<a id="roles-26"></a>

### Roles

| Role | Declaration |
|----|----|
| producer | APS/AEOESS |
| readerAuthor | Probity |
| runner | Probity, normal canonical one-CPU job |
| atlasOperator | Probity |
| retentionHolder | Probity |
| independentOperation | Probity operated the reader separately from APS/AEOESS fixture authors; not independent of Probity |
| independentEffectCustody | not-established |
| outsideRecurringUse | not-established |

<a id="limits-26"></a>

### Limits

- Finite printable-ASCII corpus reader; not general JCS conformance.
- Signature verification uses cryptography/OpenSSL; no independent cryptographic-backend claim.
- Diagnostic agreement does not force the five normatively undetermined SDK outcomes.
- Resolver answers are supplied synthetic data, without historical validity windows or authenticated lookup.
- No APS package qualification, principal binding, live DID lookup, host adoption, federation enrollment or commercial agreement.
- Twenty public synthetic cases, not a representative deployment population.
- Three declared full-outcome differences remain visible; PASS means the bounded diagnostic comparison, not uniform verdict agreement.
- The five upstream draft annotations are separate from the two indeterminate source outcomes.
- No new package release, maintainer acceptance of this reader, host adoption, federation enrollment or commercial agreement.
- Both selected SDK invocations stopped at IPC creation; their corpus/ambiguity checks remain not exercised.
- Original dependency audit remains adverse; the finite reader result is a separate evidence layer.

answerExposure: The corrected public fixture, all upstream expected outcomes and README annotations were available before the reader and run.

comparisonOrder: The independently written reader emitted raw checks, its outcomes and comparisons in one report; not answer-blind or separately graded.

</div>

<div>

<a id="record-aps-corrected20-r2-2026-10-27"></a>

## aps-corrected20-r2-2026-10-27

Claim scope: independently-written-and-operated-reader-on-producer-authored-finite-synthetic-corpus

Review state: author-retained-measured-record

Open [Report](experiments/aps-corrected20-r2-2026-10-27/report.json), [Provenance](experiments/aps-corrected20-r2-2026-10-27/provenance.json) and [Contract](https://github.com/agent-passport-system/agent-passport-system/blob/e061462cea95b029203374496bbd14488d8d2993/fixtures/agent-passport-v2/README.md).

<a id="per-claim-results-27"></a>

### Per-claim results

| Claim                                    | Recorded result |
|------------------------------------------|-----------------|
| revision-2-corpus-source-SHA256          | pass            |
| superseded-revision-1-source-SHA256      | pass            |
| finite-diagnostic-comparison             | pass            |
| upstream-source-outcome-population       | pass            |
| separate-reader-outcome-population       | pass            |
| five-separate-upstream-draft-annotations | pass            |
| reader-does-not-import-APS-SDK           | pass            |
| selected-SDK-corpus-characterization     | not-exercised   |
| authenticated-historical-key-authority   | not-exercised   |
| principal-binding                        | not-exercised   |
| general-JCS-conformance                  | out-of-scope    |
| independent-cryptographic-backend        | out-of-scope    |
| outside-recurring-host-adoption          | not-exercised   |
| independent-effect-custody               | not-exercised   |

<a id="roles-27"></a>

### Roles

| Role | Declaration |
|----|----|
| producer | APS/AEOESS |
| readerAuthor | Probity |
| runner | Probity, operator workstation; not the one-CPU lab job of revision 1 |
| atlasOperator | Probity |
| retentionHolder | Probity |
| independentOperation | Probity operated the reader separately from APS/AEOESS fixture authors; not independent of Probity |
| independentEffectCustody | not-established |
| outsideRecurringUse | not-established |

<a id="limits-27"></a>

### Limits

- Finite printable-ASCII corpus reader; not general JCS conformance.
- Signature verification uses cryptography/OpenSSL; no independent cryptographic-backend claim.
- Resolver answers are supplied synthetic data, without historical validity windows or authenticated lookup.
- No APS package qualification, principal binding, live DID lookup, host adoption, federation enrollment or commercial agreement.
- Twenty public synthetic cases, not a representative deployment population.
- Run on an operator workstation with a hash-enforced install; wall-clock authentication of the run time is not established.
- Agreement with the revision 2 file follows the producer moving three outcomes to the revision 1 report values; it is not a new blind test.
- No SDK invocation, dependency audit or one-CPU lab job was rerun for revision 2; the adverse revision 1 SDK and audit records stand as published.
- No new package release, maintainer acceptance of this reader, host adoption, federation enrollment or commercial agreement.

answerExposure: The revision 2 public fixture, all upstream expected outcomes and README annotations were available before the reader and run; the reader had already been written and run over revision 1.

comparisonOrder: The revision 1 reader, with a small retained diff, emitted raw checks, its outcomes and comparisons in one report. The producer moved three expected outcomes to the values the revision 1 report returned, so agreement confirms the revision; it is not a new blind test.

</div>

<div>

<a id="record-trace-m1-consumer-2026-10-11"></a>

## trace-m1-consumer-2026-10-11

Claim scope: signature-report-binding-and-native-claim-ceiling-on-public-synthetic-inputs

Review state: retained-independent-consumer-result

Open [Report](interop/trace-m1/retained/public-report.json), [Provenance](interop/trace-m1/retained/QUALIFICATION.json) and [Contract](https://github.com/darklordVirtual/REMORA-research/pull/822).

[Recorded procedure](trace-m1-consumer.md)

<a id="per-claim-results-28"></a>

### Per-claim results

| Claim                                | Recorded result |
|--------------------------------------|-----------------|
| frozen-case-population               | pass            |
| declared-comparison-agreement        | pass            |
| native-contradiction-preserved       | pass            |
| absent-selected-report-refused       | pass            |
| trace-trust-record-ceiling-preserved | pass            |
| native-result-truth                  | not-exercised   |
| outside-host-adoption                | not-exercised   |
| trace-conformance                    | out-of-scope    |

<a id="roles-28"></a>

### Roles

| Role | Declaration |
|----|----|
| readerAuthorship | Probity; second implementation maintained outside REMORA |
| fixtureOperator | Probity |
| evidenceVantage | artifact |
| producerIndependence | external implementation and operator; no REMORA runtime or reference-verifier imports |
| independentWitness | not-established |

<a id="limits-28"></a>

### Limits

- Bounded ASCII JSON, explicit report digest, P1Y retention and frozen synthetic inputs
- Native reason codes are preserved; independent refusal codes are not equated
- Signature and binding checks do not establish truth, workload identity, authority or effects
- Unsigned external-evidence mapping is not a TRACE Trust Record or conformance level
- No REMORA or AgenTrust host adoption, deployment or commercial agreement is established

answerExposure: Author read producer source and expected cases before implementation; not an answer-blind study

comparisonOrder: Synthetic known-answer replay; retained native output compared to published fixture expectations

</div>

<div>

<a id="record-packslip-dsse-host-ci-2026-10-11"></a>

## packslip-dsse-host-ci-2026-10-11

Claim scope: host-project-ci-dependency

Review state: retained-source-bound-observation

Open [Report](experiments/packslip-dsse-host-ci-2026-10-11/report.json), [Provenance](experiments/packslip-dsse-host-ci-2026-10-11/provenance.json) and [Contract](lab.md#choose-the-claim-you-are-submitting).

[Recorded procedure](experiments/packslip-dsse-host-ci-2026-10-11/README.md)

<a id="per-claim-results-29"></a>

### Per-claim results

| Claim                                   | Recorded result |
|-----------------------------------------|-----------------|
| host-ci-cargo-test-all-features-success | pass            |
| published-development-dependency        | pass            |
| independently-authored-regression       | not-exercised   |
| production-runtime-adoption             | not-exercised   |
| independently-observed-effect           | not-exercised   |
| paid-use                                | not-exercised   |

<a id="roles-29"></a>

### Roles

| Role | Declaration |
|----|----|
| fixtureOperator | Packslip host CI at jdx/packslip |
| regressionAuthor | astrogilda (author-contributed regression) |
| hostMaintainer | jdx |
| atlasReplay | Probity retained metadata reader; no test execution repeated |
| independentOperation | not-established |
| sourceOfObservation | GitHub host job metadata and crates.io publisher metadata |

<a id="limits-29"></a>

### Limits

- Historical exact-head job and source; no current or recurring success claim
- Author-contributed regression maintained by the host; not independently authored
- Published development dependency, not a production runtime dependency
- No numeric native exit, raw process output, independent witness custody, effect or payment established

answerExposure: Published regression source and results available to the Atlas reader; no answer-blind replication

comparisonOrder: Retrospective source-bound metadata reading; no new host execution or model/effect run

</div>

<div>

<a id="record-horizon-signed-target-reader-2026-10-09"></a>

## horizon-signed-target-reader-2026-10-09

Claim scope: outside-hosted-signed-record-reader

Review state: retained-source-bound-observation

Open [Report](experiments/horizon-signed-target-reader-2026-10-09/report.json), [Provenance](experiments/horizon-signed-target-reader-2026-10-09/provenance.json) and [Contract](lab.md#choose-the-claim-you-are-submitting).

[Recorded procedure](experiments/horizon-signed-target-reader-2026-10-09/README.md)

<a id="per-claim-results-30"></a>

### Per-claim results

| Claim                                     | Recorded result |
|-------------------------------------------|-----------------|
| recorded-command-exits-match-expectations | pass            |
| pair-a-signed-record-matches-exact-target | pass            |
| pair-b-wrong-target-refused               | pass            |
| all-eight-pair-a-assertions-reported-true | fail            |
| fresh-network-effect-reproduction         | not-exercised   |
| independent-witness-custody               | not-exercised   |

<a id="roles-30"></a>

### Roles

| Role | Declaration |
|----|----|
| fixtureOperator | GitHub Actions in ogasurfproject-jpg/horizon-shield (actor ogasurfproject-jpg) |
| atlasReplay | Probity retained-output reader; no original workload repeated |
| independentOperation | not-established |
| signedRecordProducers | pipavlo82 and kuangmi-bit; producer-declared vantages retained |
| readerMaintainer | Probity |
| reportOperator | Caller-declared unauthenticated Probity Codex / ordinary shared BoxPool author-run; not GitHub actor identity |

<a id="limits-30"></a>

### Limits

- Host CI actor is separately established by GitHub metadata; the output operator string is caller-declared and unauthenticated
- The original signed-record assertions remain producer-declared: pair A has seven true assertions and one unevaluated assertion.
- Both ledger fetches returned HTTP 403. A successful job does not establish successful ledger acquisition.
- No new walk, response correctness, historical key control, independent custody, production effect or paid use established

answerExposure: Public original results and expected controls available before Atlas reading; no answer-blind replication

comparisonOrder: Retrospective reading of retained exact-head source/output; no new native workload or effect execution

</div>

<div>

<a id="record-ten-sdk-json-bytes-2026-10-09"></a>

## ten-sdk-json-bytes-2026-10-09

Claim scope: author-hosted-serializer-byte-comparison

Review state: retained-source-bound-observation

Open [Report](experiments/ten-sdk-json-bytes-2026-10-09/report.json), [Provenance](experiments/ten-sdk-json-bytes-2026-10-09/provenance.json) and [Contract](lab.md#choose-the-claim-you-are-submitting).

[Recorded procedure](experiments/ten-sdk-json-bytes-2026-10-09/README.md)

<a id="per-claim-results-31"></a>

### Per-claim results

| Claim                                              | Recorded result |
|----------------------------------------------------|-----------------|
| all-ten-sdk-original-reports-retained              | pass            |
| complete-27-row-populations-and-raw-verdicts       | pass            |
| historical-workflow-reports-differences-by-default | pass            |
| sdk-jcs-conformance                                | not-exercised   |
| independent-operation                              | not-exercised   |
| production-or-commercial-effect                    | not-exercised   |

<a id="roles-31"></a>

### Roles

| Role | Declaration |
|----|----|
| fixtureOperator | Probity public repository GitHub Actions |
| atlasReplay | Probity retained-output reader; no original workload repeated |
| independentOperation | not-established |

<a id="limits-31"></a>

### Limits

- The 27 recorded rows include the row for the bounded profile. Earlier summaries with 26 rows do not cover the full artifact population.
- The raw canonical, differs and refused values are byte-comparison outcomes. They do not grade whether an SDK met its contract.
- The workflow reports differences by default; its green jobs do not establish canonicalization conformance
- The same retained JCS oracle report appears in each ZIP; it is not ten independent oracle runs
- No current SDK behavior, deployment, incident or paid use inferred

answerExposure: Public original results and expected controls available before Atlas reading; no answer-blind replication

comparisonOrder: Retrospective reading of retained exact-head source/output; no new native workload or effect execution

</div>

<div>

<a id="record-nist-ai300-1-checker-2026-10-13"></a>

## nist-ai300-1-checker-2026-10-13

Claim scope: author-hosted-structural-rule-check

Review state: retained-source-bound-observation

Open [Report](experiments/nist-ai300-1-checker-2026-10-13/report.json), [Provenance](experiments/nist-ai300-1-checker-2026-10-13/provenance.json) and [Contract](lab.md#choose-the-claim-you-are-submitting).

[Recorded procedure](experiments/nist-ai300-1-checker-2026-10-13/README.md)

<a id="per-claim-results-32"></a>

### Per-claim results

| Claim                                         | Recorded result |
|-----------------------------------------------|-----------------|
| original-thirteen-native-tests-succeeded      | pass            |
| complete-structural-and-mutation-check-output | pass            |
| recorded-regeneration-kept-source-clean       | pass            |
| nist-certification                            | not-exercised   |
| semantic-sufficiency-of-all-requirements      | not-exercised   |
| production-compliance                         | not-exercised   |

<a id="roles-32"></a>

### Roles

| Role | Declaration |
|----|----|
| fixtureOperator | Probity public repository GitHub Actions |
| atlasReplay | Probity retained-output reader; no original workload repeated |
| independentOperation | not-established |

<a id="limits-32"></a>

### Limits

- The original Python 3.13.15 host output is retained. This packet does not repeat the checker workload.
- Structural extraction and mutation sensitivity do not establish semantic completeness, NIST certification or compliance
- The population of 235 members over 139 rules comes from the actual checker output. Another current corpus count cannot replace it.
- Reviewer ambiguities and requirements beyond structural checks stay open

answerExposure: Public original results and expected controls available before Atlas reading; no answer-blind replication

comparisonOrder: Retrospective reading of retained exact-head source/output; no new native workload or effect execution

</div>

<div>

<a id="record-signed-history-boundaries-2026-10-13"></a>

## signed-history-boundaries-2026-10-13

Claim scope: author-hosted-signed-history-controls

Review state: retained-source-bound-observation

Open [Report](experiments/signed-history-boundaries-2026-10-13/report.json), [Provenance](experiments/signed-history-boundaries-2026-10-13/provenance.json) and [Contract](lab.md#choose-the-claim-you-are-submitting).

[Recorded procedure](experiments/signed-history-boundaries-2026-10-13/README.md)

<a id="per-claim-results-33"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| original-fifteen-case-specific-tests-passed | pass |
| executed-tests-force-genuine-signature-order-anchor-controls | pass |
| default-285-report-not-substituted-as-anchored-evidence | pass |
| independent-anchor-publication | not-exercised |
| independent-key-custody | not-exercised |
| production-history-completeness | not-exercised |

<a id="roles-33"></a>

### Roles

| Role | Declaration |
|----|----|
| fixtureOperator | Probity public repository GitHub Actions |
| atlasReplay | Probity retained-output reader; no original workload repeated |
| independentOperation | not-established |

<a id="limits-33"></a>

### Limits

- Public deterministic test keys and author-generated synthetic histories; independently controlled anchors and custody remain unestablished
- The original output for the case-specific job and the exact executed tests bind the control claims. The default artifact of 285 cases does not.
- Fourteen is the fixture population declared by the source. Fifteen is the actual pytest result, not fifteen independent reproductions.
- No continuous operation, real-world rollback prevention or commercial effect inferred

answerExposure: Public original results and expected controls available before Atlas reading; no answer-blind replication

comparisonOrder: Retrospective reading of retained exact-head source/output; no new native workload or effect execution

</div>

<div>

<a id="record-ratchet-benign-heredoc-2026-10-15"></a>

## ratchet-benign-heredoc-2026-10-15

Claim scope: author-reported-history-with-hosted-public-regression

Review state: retained-source-bound-observation

Open [Report](experiments/ratchet-benign-heredoc-2026-10-15/report.json), [Provenance](experiments/ratchet-benign-heredoc-2026-10-15/provenance.json) and [Contract](lab.md#choose-the-claim-you-are-submitting).

[Recorded procedure](experiments/ratchet-benign-heredoc-2026-10-15/README.md)

<a id="per-claim-results-34"></a>

### Per-claim results

| Claim | Recorded result |
|----|----|
| original-public-regression-job-succeeded | pass |
| benign-document-and-destructive-push-controls-remain-distinct | pass |
| dated-author-replay-counts-retained-as-author-report | pass |
| independent-replay-of-private-transcripts | not-exercised |
| zero-false-alarms-outside-selected-history | not-exercised |
| prevented-production-incident | not-exercised |

<a id="roles-34"></a>

### Roles

| Role | Declaration |
|----|----|
| fixtureOperator | Probity public repository GitHub Actions |
| atlasReplay | Probity retained-output reader; no original workload repeated |
| independentOperation | not-established |

<a id="limits-34"></a>

### Limits

- The 13,739 sessions and 632,126 tool calls are the author's pinned report. They are not an independent measured Atlas run.
- The first reported run had one false alarm: a Python heredoc wrote documentation naming a force push; no push occurred
- The corrected source treats heredoc data separately, handles --mirror and ignores a dry run. The public test source and the default pytest selection bind the regression.
- The hosted suite reports 1,431 tests passed, one skipped and nine deselected. It is not a fresh replay of private historical transcripts.
- This packet copies no private transcript or private source. It does not establish production prevention or revenue.

answerExposure: Public original results and expected controls available before Atlas reading; no answer-blind replication

comparisonOrder: Retrospective reading of retained exact-head source/output; no new native workload or effect execution

</div>

</div>

[HTML view](runs.html) | [Agent guide](llms.txt)
