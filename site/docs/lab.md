# Probity Open Evidence Lab

What was an agent allowed to do, and what actually happened?

The protocol is a draft. Each result names the question it answers and the evidence it still needs.

An agent says it completed a task. What would let you check that claim?

Imagine an agent approved to refund an order. A signed approval can show who authorized the request. It takes a separate observation to show that the refund happened. If the acknowledgement was lost, the outcome may still be unknown. These are different questions, and the evidence should keep them separate.

The Open Evidence Lab helps teams test a specific question like this. A useful run leaves an example you can reproduce and a result you can inspect, and it says what it does not show. A failed check or missing observation can be useful too.

<a id="find-an-example"></a>

## Find an example

| Your question | Start here |
|----|----|
| How can tests pass while the evidence says a claim failed? | [Read the worked report](evidence-test-meaning.md). Its refund story is hypothetical. |
| Does a signed witness record cover this exact endpoint? | [Run the signed-pair reader](nenrin-witness-pair.md), keep the assertion values, or bring another pair. |
| Does a wrapper's PASS match its command result and report? | [Run the corrected-wrapper cases](e030-corrected-wrapper.md) or keep the reader in CI. |
| What has someone actually run? | [Browse retained runs](runs.md). Each entry links its original report and stated limits. |
| Does a published host package keep a test dependency? | [Read Packslip's historical host observation](runs.md#record-packslip-dsse-host-ci-2026-10-11). |
| What did the outside host CI establish about signed records and the exact endpoint? | [Read the retained case](runs.md#record-horizon-signed-target-reader-2026-10-09). |
| Where did the ten SDK serializers match, differ or refuse the selected bytes? | [Read the retained case](runs.md#record-ten-sdk-json-bytes-2026-10-09). |
| Which NIST AI 300-1 structural and mutation checks actually ran? | [Read the retained case](runs.md#record-nist-ai300-1-checker-2026-10-13). |
| Can genuine signatures survive a broken or rolled-back stored history? | [Read the retained case](runs.md#record-signed-history-boundaries-2026-10-13). |
| Did the guard distinguish a benign document from an actual force push? | [Read the retained case](runs.md#record-ratchet-benign-heredoc-2026-10-15). |
| How do I check approval, retries, and a missing acknowledgement? | [Read the refund example](https://github.com/probityai/probity/blob/main/packages/observer/docs/APS-REFUND-RETRIES.md). |
| Did a database write match its approval, even if the state changed later? | [Try the SQL example](approved-sql.md) and bring a native audit pair. |
| Did the agent change the call after approval, or did the resource change later? | [Compare the request/effect cases](request-effect-join.md) and bring a reader or retained run. |
| Did an agent purchase that was approved get charged, ordered and delivered as approved? | [Read the checkout assessment](agent-checkout-assessment.md) and run the public refund-handoff cases. |
| Does an approved target, completion report or later observation establish the same thing? | [Try the authority and effect controls](authority-effect-cases.md) and compare the separate conclusions. |
| Does a signed native result identify the selected report without enlarging its claim? | [Replay the independent M1 consumer](trace-m1-consumer.md) and inspect its retained decisions. |
| How do I replay an existing result? | [Open the retained replay procedure](#start-with-a-run-that-exists) in the technical notes below. |

<a id="bring-one-question"></a>

## Bring one question

Start with one decision your system needs to make. For example: should this changed request be refused, does this record identify the right tenant, or did the observed effect match the approved action?

Probity offers working examples, verification tools, a shared result page, and help with the integration it contributes. You bring the real question and the part of the system you can exercise. Together we agree what success would mean, add cases that should fail, and keep the original output. The aim is a check your own project can keep running.

You keep control of your implementation, policy, and original result. The first contribution is a concrete experiment with a named owner. A run in the Lab does not appoint your project to a coalition role or establish its endorsement.

Have a tool, a check, or a problem to work on? [Join the collaboration thread](https://github.com/probityai/agent-evidence/issues/24) and tell us about it.

[Propose a run](https://github.com/probityai/agent-evidence/issues/new?template=evidence-run.yml). Describe the question and the evidence you can supply. The form and technical protocol list the inputs needed for review.

<a id="read-a-result-with-its-limits"></a>

## Read a result with its limits

A signature check, an authorization decision, and an observed effect answer different questions. A result should say which it checked. Missing evidence must remain visible. A run by the author can be useful without establishing that another operator independently controlled its keys or observations.

Keep the original report separate from later comparisons or corrections. [Report a correction](https://github.com/probityai/agent-evidence/issues/new?template=evidence-correction.yml) when the retained evidence does not support a claim.

<a id="technical-protocol-and-retained-run-notes"></a>

## Technical protocol and retained-run notes

<details>

<summary>

Open the protocol, replay commands, and detailed evidence limits
</summary>

Protocol draft 0.1.9. Register updated 11 October 2026. The register retains native framework, admission, receipt and bounded actual-weight comparisons. Host adoption and independently operated custody have separate evidence.

Maintainers can use this protocol to submit a verifier run, a host-project CI integration, or an observer/witness experiment. Each record names its contract, retained inputs, implementation and operators, and reports what passed, failed or remained untested. Probity maintains this register. A listed result makes no membership, endorsement or adoption commitment on behalf of another project.

[Submit a run](https://github.com/probityai/agent-evidence/issues/new?template=evidence-run.yml) or [report a correction](https://github.com/probityai/agent-evidence/issues/new?template=evidence-correction.yml). The forms request the evidence needed for review. The [machine-readable register](lab/register.json), [experiments](experiments.md) and [claim ledger](claims.md) retain the supporting records.

[Find a retained run](runs.md) by a claim, declared role, limit or per-claim result. Each entry links its original report, provenance and contract. The browser keeps the recorded result tokens and does not assign a grade to the whole run.

The [earlier APS and PriorSeal pilot proposal](pilot.md) retains its proposed run, owner confirmations and open decisions. It is separate from this measured register and from current invitations.

The [task-grouped rates example](task-grouped-rates.md) shows how to retain a matched benign control, repeated episodes, unresolved labels and two weighting targets when reporting uncertainty. Its invented labels make the calculation reproducible; they add no empirical record to the register.

The [published robot controls companion](provael-task-controls.md) reads Provael's original simulator reports and the author's correction. It retains the matched controls, unknown runtime provenance and complete task-resampling weights. This is a publisher-report-derived reading alongside the register.

<a id="test-outcomes-and-evidence-conclusions"></a>

## Test outcomes and evidence conclusions

The [worked report example](evidence-test-meaning.md) explains why all conformance tests can pass while a report retains negative conclusions. The historical record covers synthetic artifacts. Its hypothetical refund story explains the customer problem; it adds no customer or live action result.

[Inspect the retained record](runs.md#record-w3c-report-replay-2026-10-06) or [check the original-output accounting](experiments/w3c-report-replay-2026-10-06/README.md). The maintained consumer checks file bindings and complete per-case accounting. It does not execute the captured reader copies. The record keeps the original report separate from two later diagnostic controls and retains unexercised action, independent-operation and outside-host claims.

<a id="corrected-agent-passport-corpus-independent-reader"></a>

## Corrected Agent Passport corpus: independent reader

Probity wrote and operated a separate Python reader for APS/AEOESS's 20 frozen synthetic Agent Passport cases, using the corrected source at `407ca2d5ad10c846860ad1b6faafc971ae9690e5`. The [unchanged native report](experiments/aps-corrected20-2026-10-10/report.json) and [source and runtime record](experiments/aps-corrected20-2026-10-10/README.md) retain the inputs and comparisons.

The source records four valid, fourteen invalid and two indeterminate SDK observations. The reader returns four valid, eleven invalid, three indeterminate and two unsupported outcomes. Its diagnostic and exposed-preimage checks agree. Three declared full-outcome differences remain visible; the report's `PASS` does not make the verdicts identical.

Five upstream draft annotations remain separate from those outcome counts: `did-web-resolver-not-found`, `expired`, `not-yet-valid`, `record-type-changed` and `version-changed`. The reader uses supplied resolver answers and evaluation times. It does not establish historical key authority, principal binding or live identity acceptance. Ed25519 checks use cryptography/OpenSSL; the reader does not import the APS SDK or claim an independent cryptographic backend.

The original overall run remains adverse. Both selected SDK invocations stopped at IPC creation before corpus evaluation, and their original locked dependency audit retains three high entries and two advisories. The useful reader result stays separate from those failures, whole-SDK qualification, federation enrollment and host adoption. All earlier register objects and evidence bytes are unchanged.

<a id="revision-2-of-the-corrected-corpus"></a>

### Revision 2 of the corrected corpus

APS/AEOESS then published revision 2 of the file, at `e061462cea95b029203374496bbd14488d8d2993`, SHA-256 `9bd1f1849910c85f0555baf8efaa529aa9d057dce13c24606285b8643a003b89`. Probity ran the same reader over it with a small [retained diff](experiments/aps-corrected20-r2-2026-10-27/reader-diff-from-r1.diff). The [report](experiments/aps-corrected20-r2-2026-10-27/report.json) shows source and reader both at four valid, eleven invalid, three indeterminate and two unsupported outcomes, with all 20 outcomes, layer maps and resolver requests in agreement and no declared difference. Its raw byte checks match the revision 1 report on all 20 cases. The producer moved three expected outcomes to the values the revision 1 report returned, so this confirms the revision and is not a new blind test. The [source and run record](experiments/aps-corrected20-r2-2026-10-27/README.md) holds the hash-pinned requirements and the replay command. The revision 1 record above stays as published, and no SDK invocation or dependency audit was repeated.

<a id="outside-receipt-verifier-and-primitive-identifier-checks"></a>

## Outside receipt verifier and primitive identifier checks

The 25th record retains the run merged in [APS conformance PR 154](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/154). All 24 earlier register objects and their evidence bytes are unchanged. The original [operator declaration](experiments/aeoess-receipt-signature-2026-10-05/RUN.md) names Claude under Tymofii Pidlisnyi (@aeoess)'s revocable mandate, with human review. Atlas retains that declaration without independently authenticating the actor, model, review or container custody.

The run covers 25 receipt fixtures with `@veritasacta/verify` 0.10.21. Both key-window profiles match the public expected answers. The repeated reports and stdout are byte-identical. A runner-authored thin wrapper invokes GNU `sha256sum` for 21 context-free identifiers; all match. Four context-bearing identifiers remain explicitly uncovered. Harness interpretation and grading remain author implementation. Expected answers were exposed, and answers and grades were emitted together.

The always-valid control produces eight failures and three SHOULD refusals. A signature mutation affects five members that share one receipt; all five fail with `signature_invalid` under both profiles. The explicitly selected unmodified corpus passes all 25 members. The [derived report](experiments/aeoess-receipt-signature-2026-10-05/report.json), [complete original source and controls](experiments/aeoess-receipt-signature-2026-10-05/README.md) and [provenance](experiments/aeoess-receipt-signature-2026-10-05/provenance.json) retain these layers. The data-only checker executes no captured code.

This fixture record establishes no independent effect custody, maintained host job, full-family admission or production workload result. [Claims P-75 and P-76](claims.md) bind the retained results and their limits.

<a id="new-raw-admission-and-response-routing-comparisons"></a>

## New raw-admission and response-routing comparisons

Three additional records bring the register to 22. The 19 earlier objects and their original evidence bytes are preserved. Each new record keeps the native archives, selected source, operators and outcome fields together.

| Route | Recorded result | Evidence |
|----|----|----|
| APS receipt and JCS admission | Node 20.20.2 and 22.23.3 each ran 1,223 pinned cases: 1,048 exact admitted byte matches and 175 refusals. Parsed serialization accepted 42 raw-refusal rows; strict parsing differed on 23 policy rows. Both duplicate-issuer receipt controls stopped before signatures. | [Report](experiments/aps-jcs-2026-10-04/report.json), [originals and source](experiments/aps-jcs-2026-10-04/README.md), [provenance](experiments/aps-jcs-2026-10-04/provenance.json). Numeric and Unicode profiles stay distinct; machine outcomes agree across runtimes, with 88 diagnostic prose differences. |
| ADK user responses, Observer and Verify | Each qualified PR/main run covers grant, denial and long-running completion. Responses reach the issuing agent and call; later plain text returns to root. Signed observed writes are 1/0/1. Both routing-reader outputs repeat exactly; six actual Verify cases repeat with three boundary controls. | [Report](experiments/google-adk-responses-2026-10-04/report.json), [all four attempts and replay](experiments/google-adk-responses-2026-10-04/README.md), [provenance](experiments/google-adk-responses-2026-10-04/provenance.json). Real ADK with scripted model responses. The long-running write belongs to the same host operator, separately from its native start-only tool body. |
| Go JCS consumer | Go 1.25.5 and 1.27.1 each ran the same 1,263 cases: 1,077 exact byte matches, 181 raw refusals and five scalar-root refusals. Every bare Go outcome is retained separately, including 1,129 accepts. Six distinct PR/push/main archives retain the repeated population. | [Report](experiments/go-jcs-2026-10-04/report.json), [originals and replay](experiments/go-jcs-2026-10-04/README.md), [provenance](experiments/go-jcs-2026-10-04/provenance.json). Admission runs on original bytes before the pinned Go writer. |

These are author-operated comparisons. APS receipt verification, raw admission, native task routing, effects and publication remain separate axes. Observer and Verify custody remains PEER; the older 16-row comparison and its separately pinned prospective eight-task study keep their original status. Outside host adoption and independently operated custody need their own executed evidence.

The ADK record retains its initial reader failure and label-boundary correction alongside both fully qualified runs. New source-derived checks authenticate every original member and re-derive the displayed fields from native output. Source retention preceded indexing; expected outcomes were exposed and native comparisons were emitted together.

<a id="ag2-tasks-callbacks-and-target-authority"></a>

## AG2 tasks, callbacks and target authority

The 23rd [register record](lab/register.json) keeps two qualified runs of the same 18 native AG2 tasks: six variants over JSON-RPC, REST and gRPC. Each run retains 12 stored configurations, six target callbacks and three signed Observer writes. The 22 earlier record objects and their original bytes stay unchanged.

Each transport keeps these outcomes separate:

| Variant | Stored configuration | Target callbacks | Observed writes |
|----|----|----|----|
| Accepted | 1 | 1 | 1 |
| Registration denied | 0 | 0 | 0 |
| Sender admission denied | 1 | 0 | 0 |
| Target denied | 1 | 1 | 0 |
| Legacy configuration only | 1 | 0 | 0 |
| SDK policy denied | 0 | 0 | 0 |

The host calls the unchanged SDK sender after task completion. The target is a controlled ASGI app; task and configuration gRPC use native plaintext loopback. The target's refusal remains visible after a callback arrives. The legacy route stores an unsafe URL without sending it. Fixed model responses are exposed; no provider inference runs here.

The [report](experiments/ag2-push-authority-2026-10-04/report.json), [originals and replay](experiments/ag2-push-authority-2026-10-04/README.md) and [provenance](experiments/ag2-push-authority-2026-10-04/provenance.json) retain all 453 selected AG2 and 127 A2A Python source files and their licenses. Each passing native run retains two byte-identical installed-reader decisions and 16 semantic controls. The Lab checker authenticates every original member and reconstructs the native task, configuration, callback and effect fields.

The first local reader failure stays separate from the first Actions setup failure, which ran no native cases and produced no artifact. Both qualified PR and main archives remain intact. Restore the 15 empty refused-case workspace directories before an installed replay; no file bytes change.

Sender, target, keys and storage share the author operator (PEER). Automatic task callbacks, an outside callback service, independent custody and recurring host adoption remain untested. Original protobuf wire bytes are retained; the reader checks captured JSON semantics. The older 16-row comparison stays pinned, and the prospective eight-task implementation-owned study has not started. [Claims P-71 and P-72](claims.md) bind these results to the retained originals.

<a id="remora-execution-boundary-run-records"></a>

## REMORA execution-boundary run records

The 24th [register record](lab/register.json) holds the run records for REMORA's three frozen execution-boundary contracts at `fe324dd734734d9227aa894330ac52c2bb916b94`. The separate reader ran at `308c5b4401b18d42ed73dea80459375932e6b8e8`, whose reader files equal the reviewed head `bf294ec7`. The 23 earlier record objects and their bytes are unchanged.

| Contract | Claim | Cases | Result per case |
|----|----|----|----|
| `exact-call-binding-v1` | `exact_call_binding` | 13 | 11 `ESTABLISHED`, 2 `NOT_ESTABLISHED` |
|  | `single_use_authorization` | 2 | 2 `ESTABLISHED` |
| `fresh-authority-v1` | `fresh_authority_at_dispatch` | 14 | 13 `ESTABLISHED`, 1 `NOT_ESTABLISHED` |
| `effect-evidence-v1` | `effect_state_distinction` | 12 | 12 `ESTABLISHED` |

All 41 results equal the fixture expectations on CPython 3.13.15 and 3.14.7. The same run passed 13 additional cases, eight malformed-input refusals, nine source mutations and 20 Verify decisions. The [report](experiments/remora-boundary-2026-10-04/report.json), [records and originals](experiments/remora-boundary-2026-10-04/README.md) and [provenance](experiments/remora-boundary-2026-10-04/provenance.json) keep both Actions archives; the Lab checker recomputes each package digest from retained manifests and input hashes and derives every displayed count. The missing reference verifier contributes its declared digest; its source was not retained.

Each `external-run-record-v1` states `SECOND_IMPLEMENTATION`, an external operator and `NOT_INDEPENDENT`, exactly as the reader emits it, so under REMORA's rule it supports `REPRODUCED`. Authorization signatures use a public test-only key; the effect `hash` rule stays unsupported; fixture premises are taken as supplied. Expected outcomes were exposed. The [scope correction](experiments/remora-boundary-2026-10-04/README.md) preserves the original presentation and native results. Producer review of these run records starts when they are shared with REMORA. [Claims P-73 and P-74](claims.md) bind these results.

<a id="submitted-producer-fixture-runs"></a>

## Submitted producer-fixture runs

The separate Probity readers have executed the accepted pinned fixture populations. These submissions retain the original CI archives, raw exchanges, environment, reader hashes and source pins. REMORA producer review is open. [JEP's maintainer confirmed the host-operated reproduction and merged the reader](https://github.com/hjs-spec/jep-core/pull/48#issuecomment-5975088744): 25 validation, four producer and eight acceptance assertions pass. These original Probity-run records remain separate from the later host PR and main runs.

| Submission | Recorded result | Evidence and limits |
|----|----|----|
| REMORA E7 | All five native cases match the frozen package; global capability completeness remains `NOT_ESTABLISHED` | [Native external run record](experiments/remora-e7-2026-10-02/external-run-record-v1.json), [full report](experiments/remora-e7-2026-10-02/report.json), [provenance](experiments/remora-e7-2026-10-02/provenance.json), [original archive](experiments/remora-e7-2026-10-02/original-artifact.zip) |
| JEP Core 0.7 | Validation 25 of 25, producer four of four, acceptance eight of eight | [Complete exchanges and results](experiments/jep-core07-2026-10-02/report.json), [provenance](experiments/jep-core07-2026-10-02/provenance.json), [original archive including SQLite state](experiments/jep-core07-2026-10-02/original-artifact.zip) |

REMORA's native `INDEPENDENT` classification uses its package's external-operator and implementation criteria. Probity controls its reader and run; independent effect custody remains unestablished. Its [seven-day producer review](https://github.com/darklordVirtual/REMORA-research/issues/707#issuecomment-5957358281) runs from October 2, 2026 at 17:04:37 UTC through October 9 at 17:04:37 UTC. Any unresolved disagreement will remain attached to the result. The [JEP maintainer supports a separate required candidate check after reviewing regression and suite-update handling](https://github.com/hjs-spec/jep-core/pull/48#issuecomment-5976676141). That recurring candidate integration remains pending. JEP's acceptance effects are synthetic local SQLite rows; they establish no external act, power-loss recovery or distributed failover. Both studies used exposed expected answers. The reports retain actual outputs before comparison but publish them together; this deviates from the lab's separate raw-result-publication step and is recorded in both provenance files.

<a id="retained-recovery-and-actual-weight-runs"></a>

## Retained recovery and actual-weight runs

These are Probity-operated runs and Probity-selected reader reproductions. They add runnable capability and retained measurement. They do not show outside workflow adoption or independent effect custody. [The register](lab/register.json) binds measured claims to exact report fields and retains separate outcome axes.

| Run | Measured result | Retained bytes and limit |
|----|----|----|
| LangGraph durable restart | Six selected cases reconstruct. Crash after effect recovers at native revision one; pending intent remains incomplete; missing checkpoint and wrong thread refuse. | [Report](experiments/langgraph-durable-2026-10-02/report.json), [original CI ZIP](experiments/langgraph-durable-2026-10-02/original-artifact.zip), [source/member provenance](experiments/langgraph-durable-2026-10-02/provenance.json). Distinct graph worker processes reopen SQLite checkpoints; the target remains alive. No power-loss, target restart or general exactly-once claim. |
| Pydantic failure controls | Seven selected attempts reconstruct. Retry exhaustion retains error/no effect; an error after committed effect retains error and local ticket revision one. | [Report](experiments/pydantic-failure-2026-10-02/report.json), [original CI ZIP](experiments/pydantic-failure-2026-10-02/original-artifact.zip), [source/member provenance](experiments/pydantic-failure-2026-10-02/provenance.json). Real framework, scripted FunctionModel; no real-provider or task-quality result. |
| Actual-weight operational microtasks | All 48 declared attempts were scored: zero correct under the strict rubric; two format-valid. Evidence completeness and run budget hold separately from failed task quality. | [Unmodified native reader report](experiments/model-operational-2026-10-02/report.json), [selected derivative capsule](experiments/model-operational-2026-10-02/selected-capsule.zip), [full original-member selection/digests](experiments/model-operational-2026-10-02/provenance.json). Author-written tasks and expected outcomes exposed; no representative benchmark estimate. |

The model result covers structured extraction, arithmetic, policy decisions and grounded abstention under two declared output limits. Native tokens, elapsed time, whole-process CPU deltas and process-lifetime peak RSS stay labelled by their actual scope. Fixed configuration order confounds cache/warmup with the output-limit comparison. No publication, admission, dispatch or recovery effect was executed by the model run.

The model capsule copies selected original JSON/text bytes; its provenance lists every original ZIP member, digest and inclusion decision. Model weights, compiled libraries and omitted build files are outside this capsule. The full original 274,795,286-byte provider ZIP is retained locally and referenced by digest and [workflow run](https://github.com/probityai/agent-evidence-observer/actions/runs/37044646302); it is not committed here and the provider archive can expire. The capsule alone cannot reproduce excluded model/source hash checks or rerun inference. The two framework ZIPs are complete byte-exact original archives.

<a id="continued-recovery-sdk-and-paired-cpu-runs"></a>

## Continued recovery, SDK and paired CPU runs

Four further author-operated records retain original native archives and separate outcome axes. Their original bytes were published in the Atlas feature branch before these register entries. Native outputs and expected-result comparisons were emitted together; this publication order does not make them blind studies or satisfy a separate native raw-result-first comparison.

| Run | Measured result | Retention and boundary |
|----|----|----|
| Recovery authority | Eight selected cases, sixteen native graph workers. Revocation, exact-boundary expiry and clock rollback each refuse before recovery dispatch, both before an effect and after a revision-one commit. Earlier commits remain separately retained. | [Report](experiments/authority-recovery-2026-10-02/report.json), [original exact-main archive](experiments/authority-recovery-2026-10-02/original-artifact.zip), [source/member provenance](experiments/authority-recovery-2026-10-02/provenance.json). Recovery policy uses a host-selected deterministic integer clock; signed target grants remain separate and the target stays alive. |
| Target process recovery | Seven cases use fourteen actual target processes: three completed effects, two incomplete refusals and two startup refusals. The selected eight-request overlap yields one completion and seven refusals. | [Report](experiments/target-process-recovery-2026-10-02/report.json), [original exact-main archive](experiments/target-process-recovery-2026-10-02/original-artifact.zip), [source/member provenance](experiments/target-process-recovery-2026-10-02/provenance.json). Process IDs are unsigned runner testimony; native SQLite, key and clock remain author controlled. |
| Paired actual-weight CPU tasks | All ninety-six attempts score under sixteen separate model/cap/family rows. The selected 135M model has zero strict targets and two format-valid answers across forty-eight attempts; the 360M model has eight strict targets and forty-two format-valid answers across forty-eight. Each cap's 360M rows retain extraction two of six, arithmetic one of six, policy one of six and abstention zero of six. | [Unmodified report](experiments/model-paired-cpu-2026-10-02/report.json), [original producer-selected compact archive](experiments/model-paired-cpu-2026-10-02/original-artifact.zip), [complete member/omission provenance](experiments/model-paired-cpu-2026-10-02/provenance.json). Authored tasks, SHA-ranked blocked order and disabled/reset cache; a bounded comparison rather than a representative benchmark estimate. |
| OpenAI Agents SDK | Six native SDK cases retain nine scripted model calls, six tool calls and three signed ticket effects. Three tasks complete, two error and one remains incomplete; an error after effect and exhausted turns retain revision one separately from task status. | [Report](experiments/openai-agents-ticket-2026-10-02/report.json), [original SDK archive](experiments/openai-agents-ticket-2026-10-02/original-artifact.zip), [source/member provenance](experiments/openai-agents-ticket-2026-10-02/provenance.json). Actual SDK Runner, function tool and trace processor with scripted Model; no remote-provider inference or model-quality result. |

The paired CPU native compact archive is an original producer artifact, retained byte for byte. Its 246 members match the corresponding `run/` members of the 276-member full preparation archive. The provenance identifies all thirty omitted preparation members, including model weights and source/dependency wheels. The full 465,338,754-byte preparation archive stays in the private program archive and provider retention; it is not committed here. The compact archive retains native source/library hashes and every started/returned call, but cannot rerun inference without the omitted weights or reconstruct every acquisition byte independently.

The first preparation failed before inference after 472,190,754 response-body bytes; a separately declared corrected preparation used 472,221,945 bytes. Their cumulative 944,412,699 bytes span two declared 512 MiB envelopes, rather than one acquisition budget. No model inference was retried. Native token, whole-process CPU, serial elapsed time and shared process-lifetime peak RSS stay labelled by their actual scope. Author-written expectations were exposed.

The four continuation additions bring the register to ten retained records, with each measured claim bound to literal report fields. All four continuation records remain Probity-operated; none establishes producer acceptance, an outside maintained workflow, independent effect/key/store/clock custody, host power-loss recovery or a general exactly-once guarantee. SDK behavior and actual-weight quality remain separate measurements.

<a id="native-metadata-and-separate-endpoint-state"></a>

## Native metadata and separate endpoint state

An additional [ExecSurface state-join record](experiments/execsurface-state-2026-10-02/report.json) retains one declared generated-file overwrite and its separate before/after captures. Actual native metadata carries one successful file-descriptor write; the companion carries the declared nine-byte endpoint state and authenticates a source-selected byte predicate. Native schema-v2 metadata contains neither the written bytes nor the write count. Endpoint snapshots do not prove that no intermediate writes occurred.

The record remains voluntary/peer/log-import/software-only. Its predicate is valid, native invocation reports complete and the selected byte join verifies, while `scopeComplete` is false and typed collection health remains `unknown-no-typed-envelope`. Each of these is reported on its own. The producer's native learn/check PASS is a same-byte calibration outside the claimed signed interval; it does not establish authority, collection health or task quality. Same-team software signing does not establish independent key, store or clock custody.

[The original exact-main archive](experiments/execsurface-state-2026-10-02/original-artifact.zip) and [source/member provenance](experiments/execsurface-state-2026-10-02/provenance.json) retain all twenty-nine provider members, including native trace, snapshots, commitment/envelope, selected publication policy and calibration. The signed interval retains eighteen selected files. The register now contains eleven records; this additional record preserves all ten earlier entries and their archive bytes. Linux x86_64 ptrace scope and backend limitations remain explicit; no outside adoption or independent effect custody is established.

<a id="atomic-native-local-delegation-evaluation"></a>

## Atomic native local-delegation evaluation

An author-operated Atomic run passes all four declared cases using twelve distinct reader processes. The cases preserve a narrow grant across exact retries and fresh process starts, retain local revocation while allowing a distinct renewal, refuse expired/altered/ambiguous grants with a valid recovery control, and keep local self-contained selection separate from externally keyed issuer verification and other-subject grants.

[The original native report](experiments/atomic-delegation-2026-10-02/report.json), [complete capsule](experiments/atomic-delegation-2026-10-02/native-run-capsule.zip) and [provenance](experiments/atomic-delegation-2026-10-02/provenance.json) retain the exact executable, source snapshots, lockfile, fixed test population and original build/case output. The capsule packages unmodified local run files; it is an author-assembled archive, not a CI provider ZIP.

The [immutable Atomic fork source](https://github.com/astrogilda/atomic/tree/80be8dae6feb8b9106181b78fba2c7c6a7c8f4d8) contains the [rerun command and boundary](https://github.com/astrogilda/atomic/blob/80be8dae6feb8b9106181b78fba2c7c6a7c8f4d8/tools/native-evaluation/README.md). Normal reader-process restarts establish local certificate-selection persistence; they do not establish crash-mid-write recovery, server permission enforcement, remote revocation or external effect custody. Child process identifiers are unsigned runner testimony. Expected outcomes were exposed in the tests, and observations and assertions were emitted together.

This record adds to the register and preserves all fifteen earlier register objects and artifact bytes. Upstream maintainer acceptance, completed host CI, recurring outside use and independently operated custody remain unestablished for this contribution.

<a id="start-with-a-run-that-exists"></a>

## Start with a run that exists

The first register entry is [E6: observer declaration, admission and replay](experiments.md#observer-consumer-admission). It joins one prior declaration, one brokered durable file effect, signed history and a persisted consumer admission. Replaying the interval, changing consumer authority and altering a signed claim all refuse with exact reasons and unchanged consumer state.

| item | retained evidence |
|----|----|
| Observer implementation | [Exact revision 8562c25fb7ec97596ea9d0297c495340298914b6](https://github.com/probityai/agent-evidence-observer/tree/8562c25fb7ec97596ea9d0297c495340298914b6) |
| Checked source bytes | [Git blob pins](experiments/observer-admission/source-pins.json) and per-source SHA-256 values in the [result](experiments/observer-admission/recorded.json) |
| Original CI artifact | [Provenance and file manifest](experiments/observer-admission/provenance.json); original archive SHA-256 `bcc22cd27b1f9404e961f7329770620994a76348d085b7b711ab586986493892` |
| Actual runs | [Original PR-tree run](https://github.com/probityai/agent-evidence-observer/actions/runs/36808961399) and [exact-main run](https://github.com/probityai/agent-evidence-observer/actions/runs/36825509807) |
| Execution and comparison | [Atlas runner](experiments/observer-admission/run.py), [complete recorded outcomes](experiments/observer-admission/recorded.json), and the E6 procedure |
| Claim ceiling | Author-produced same-operator fixture; `PEER`; `evidence_vantage: artifact`; unmediated effects and independent custody remain unestablished |

On Linux, use the actual checked-in runner and retained bytes:

``` sh
git clone https://github.com/probityai/agent-evidence/tree/main/site atlas
cd atlas
git checkout --detach 91a0759e459acee8355e2f9aba34f8e80d19e038
git clone https://github.com/probityai/probity/tree/main/packages/observer .observer-source
git -C .observer-source checkout --detach 8562c25fb7ec97596ea9d0297c495340298914b6
uv venv --python 3.12.14 .venv
UV_LINK_MODE=copy uv pip install --python .venv/bin/python cryptography==46.0.7
.venv/bin/python experiments/observer-admission/run.py --observer-root .observer-source \
  --bundle experiments/observer-admission/retained \
  --manifest experiments/observer-admission/provenance.json \
  --expect experiments/observer-admission/recorded.json
.venv/bin/python experiments/observer-admission/run.py --observer-root .observer-source \
  --output /tmp/observer-admission-new \
  --expect experiments/observer-admission/recorded.json
```

The output directory must be empty. Source blobs are checked before private-copy import. The first command checks the original artifact's exact retained bytes; the second generates new keys and signatures and requires the same complete semantic outcomes. Running this fixture in another CI system supplies a new execution record. An independently operated witness still needs a separately justified operator and trust boundary.

The E6 implementation, demo and retained expected outcomes were available to the atlas runner. This is a retrospective fixture comparison; it does not establish an answer-blind replication or a result frozen before expected-answer comparison.

<a id="choose-the-claim-you-are-submitting"></a>

## Choose the claim you are submitting

These are separate claims. A submission may establish more than one, with separate evidence for each.

| claim | evidence needed | ceiling |
|----|----|----|
| Retained-byte integrity | Raw input bytes, retrieval record, algorithm, digest, byte size and verification outcome | Identifies a representation; does not establish execution, authority or an effect |
| Verifier behavior on a fixture | Pinned contract and reader, explicit mapping, complete input/result manifests and hostile controls | Applies to the selected inputs; implementation independence and operator independence are separate |
| Host-project CI dependency | A host-owned workflow at an exact commit imports or invokes the pinned package/adapter, a completed host run, retained outputs, and a maintainer-owned merge or dependency decision | A fixture rerun, development-only byte library and production runtime dependency are different uses; record the actual use |
| Observed bounded effect | Prior authority, actual effect bytes or service observations, observer reachability boundary, coverage denominator, gaps and failure behavior | Covers only the declared channel and interval |
| Independent witness or consumer operation | Named producer, runner, policy owner and key custodians; how the consumer acquired keys/head outside the candidate bundle; retained history and evidence of separate operational control | Separate signing keys, repositories, containers or directories alone do not establish custody independence |

Use claim-level results: `pass`, `fail`, `unknown`, `not-exercised` or `out-of-scope`. State the rule producing each result. Unsupported checks and unavailable observations remain visible. A signature verdict, service correlation, policy admission and observed effect must have separate fields even when their outcomes agree.

Use `unknown` when an observation cannot settle the claim. Use `not-exercised` when the check was not exercised, and `out-of-scope` when the claim falls outside the declared scope. Preserve the source report's words and explain the result.

<a id="submit-a-reproducible-evidence-packet"></a>

## Submit a reproducible evidence packet

1.  **Fix the question before scoring.** Name the exact specification/profile revision, claim and expected scope. Pin the producer, reader/adapter, configuration, policy and input manifests. Identify any local interpretation of an unresolved contract. Record who chose the keys and witness head, and when.
2.  **Preserve the delivered evidence.** Retain the original byte stream, its SHA-256, length, media type and immutable source. Record retrieval failures. Keep any normalized or redacted derivative separately, with its own digest and an explanation of what changed. Never substitute a reserialized document for a raw-byte integrity check.
3.  **Record the roles and exposure.** Name the implementation author, runner, policy owner, signer and custodian for each claim. State whether they share operational control. Record which producer code, expected files, README outcomes or earlier answers the reader author and runner knew. Expected-file-blind is narrower than answer-blind.
4.  **Execute the positive and hostile cases.** Retain commands, runtime/dependency pins, stdout, stderr, exit status, every attempted case and its denominator. Report missing, partial, failed and unscored checks. Do not infer a zero effect count from missing records.
5.  **Freeze results before comparison.** Commit or publish the complete raw report and manifest, then publish the expected-answer comparison in a separate revision. Supply both immutable links and their order. If answers were already known, say so; freezing a report does not undo that exposure. A report signature binds the report bytes and signer, without upgrading the observations' custody.
6.  **Submit the packet.** Use the run form and link the retained files. A maintainer review records the supported claims, ceilings and unresolved gaps. A register addition is proposed by pull request with its reviewed evidence links; the intake issue remains the public discussion and decision trail.

The register checker requires both the report and provenance in each record's hashed artifact manifest. Roles need nonempty names and declarations. This checks the submitted metadata; it does not establish separate operational control. The append helper returns bytes without writing files. Validate the candidate register before saving those bytes.

For a live capture, classify each gap as unsupported behavior, instrumentation gap, interpretation/guidance gap, missing convention, or unavailable evidence. Keep the raw capture and mapping with the gap. A proposed fix needs a later run showing what changed.

<a id="controls-a-reviewed-result-must-survive"></a>

## Controls a reviewed result must survive

Select controls for the submitted claim and explain any that do not apply. Keep the positive control and all refused, failed or unknown controls in the record.

| claim under test | required discriminating control |
|----|----|
| Fixture reader | An accept-all or naive adapter must fail at least one declared negative; missing and out-of-scope cases cannot silently pass |
| Representation integrity | Change an octet; reserialize unchanged JSON; omit the digest; supply an unsupported algorithm or unavailable retrieval. Report each according to the pinned raw-byte contract |
| Authority or signature | Change the declared scope/operation, substitute an untrusted key, or alter signed bytes. Supply the exact refusal and unchanged prior consumer state where that state is part of the contract |
| Admission/history | Replay after persistence, truncate or fork history, omit a committed interval, or reset/roll back the consumer store. Report which trust assumptions make rollback detectable |
| Bounded effects | Exercise a bypass and missing observation relative to the declared channel. Retain the effect or attempted effect, record liveness and coverage gaps, and refuse an absence claim when coverage is unknown |
| Claimed independent operation | Attempt candidate-supplied trust replacement and publish who can address or replace the observer, keys, journal and retained head |

Passing these selected controls is a result for that contract and run. The register records their count and scope; it does not treat a test score as a production guarantee.

<a id="review-rejection-and-correction"></a>

## Review, rejection and correction

A submission starts as **submitted**. Review can classify individual claims as **supported with stated limits**, **needs evidence**, **unsupported** or **out-of-scope**. These review states are separate from the measured pass/fail outcomes. Only a reviewed pull request changes the register. There is no automatic certification or promotion to independent custody.

Review returns an explicit missing field, unresolved rule, counterexample or evidence mismatch. Changed source bytes without a new revision, missing raw outputs, answer-key exposure described as blind, an accept-all control that succeeds, bundled keys described as independently pinned, and missing observations counted as success block the affected claim. A useful failed or partial run can still be retained as a gap record.

Use the [correction form](https://github.com/probityai/agent-evidence/issues/new?template=evidence-correction.yml) with the record ID, challenged claim, immutable counterevidence and proposed correction. A corrective pull request marks the affected claim disputed or superseded, links the replacement record and preserves the original result and review trail. Do not rewrite an old run to look like the corrected experiment. Scope or contract disagreements remain named until the relevant specification owner resolves them.

<a id="connections-to-current-upstream-work"></a>

## Connections to current upstream work

The [AAIF execution-plan proposal at 99d72c8](https://github.com/aaif/wg-observability-and-traceability/blob/99d72c8484ac82f2c7128f2cb3b09e2971f8f234/working-documents/AGENT-BEHAVIOR-TRACE-MODEL-EXECUTION-PLAN.md) puts agree, evidence, interpret and contribute in sequence, with actual captures and an observed-gap register guiding later work. This lab uses that evidence-first sequence for its own submissions. [PR \#60](https://github.com/aaif/wg-observability-and-traceability/pull/60) is a proposed direction; it does not commit AAIF or any agent to this lab.

The [Gemara evidence proposal at a3016f4](https://github.com/gemaraproj/gemara/blob/a3016f4ddadda4e2d4a68ab353ce430fdb62b6bf/evidence.cue) defines a citation digest over the full octet stream delivered, including a required SHA-256 support floor. Coordinates and entry IDs are lookup hints, rather than digest inputs. Its citation-integrity outcomes are `verified`, `integrity-failure` and `unverifiable`; absence of a digest makes no integrity claim. These are byte-integrity results, separate from the claim-level outcomes above. [PR \#507](https://github.com/gemaraproj/gemara/pull/507) remains a pinned proposal here. A raw-octet adapter run is an open contribution route, with no completed lab result or Gemara commitment claimed.

The initial E6 record exercises the existing observer contract. Future records can connect these proposed upstream contracts only after their exact rules, inputs and measured limits are supplied. The register records adoption when a host project owns and retains the dependency run, and records independent operation only when its distinct trust requirements are demonstrated.

<a id="paired-schema-decoding-and-correctness"></a>

## Paired schema decoding and correctness

The [paired format-control report](experiments/model-format-cpu-2026-10-02/report.json) retains 192 actual-weight CPU attempts under thirty-two separate model/cap/decoder/family rows. Its protocol, compiler and grammar hashes were published before inference. It compares unconstrained decoding with a frozen JSON syntax/type grammar on the same exposed authored tasks, without target constants, enums or semantic patterns. Selected restrictions include at most sixteen integer digits, one optional ASCII space and fixed required-key order.

| Model | Output cap | Decoder | Extraction correct | Arithmetic correct | Policy correct | Abstention correct | JSON valid | Schema valid |
|----|----|----|----|----|----|----|----|----|
| 135M | 24 | unconstrained | 0/6 | 0/6 | 0/6 | 0/6 | 1/24 | 0/24 |
| 135M | 24 | schema | 4/6 | 0/6 | 0/6 | 1/6 | 24/24 | 24/24 |
| 135M | 96 | unconstrained | 0/6 | 0/6 | 0/6 | 0/6 | 1/24 | 0/24 |
| 135M | 96 | schema | 4/6 | 0/6 | 0/6 | 1/6 | 24/24 | 24/24 |
| 360M | 24 | unconstrained | 2/6 | 1/6 | 1/6 | 0/6 | 21/24 | 10/24 |
| 360M | 24 | schema | 6/6 | 3/6 | 1/6 | 3/6 | 24/24 | 24/24 |
| 360M | 96 | unconstrained | 2/6 | 1/6 | 1/6 | 0/6 | 21/24 | 10/24 |
| 360M | 96 | schema | 6/6 | 3/6 | 1/6 | 3/6 | 24/24 | 24/24 |

All constrained outputs are schema-valid, while the larger model's policy family remains correct in only one of six cases at each cap. Each register row separately binds format validity, schema validity and typed-exact target correctness. The runnable register checker refuses replacing an incomplete correctness result with schema success, pooling decoder rows or omitting a row. A complete published report is not approval to publish, admit or dispatch the model's decisions. No protected effects were executed.

The [original compact provider archive](experiments/model-format-cpu-2026-10-02/original-artifact.zip) retains 463 native members. The [provenance](experiments/model-format-cpu-2026-10-02/provenance.json) binds every member to the authenticated full preparation archive's 493 members, with thirty explicit omissions. Weights, source/dependency wheels and preparation records remain in the private original, required to rerun inference or reconstruct all acquisition bytes. The new format preparation transferred 472,221,945 response-body bytes. Including the original short run and failed and successful comparison preparations, cumulative acquisition was 1,694,784,417 bytes across four separately declared preparation envelopes. This exceeds a single envelope; no response retry or quality retuning followed observed outputs.

The twelve-record [register](lab/register.json) preserves all eleven earlier records and their retained artifacts. These measurements remain author-operated, with exposed expected answers and output/comparison emitted together. Raw Atlas publication before indexing does not make native inference blind. Shared process lifetime RSS and whole-process CPU are not per-model/task allocations. Independent custody, representative benchmark performance and outside recurring use remain unestablished.

<a id="scripted-adk-execution-and-installed-policy-decisions"></a>

## Scripted ADK execution and installed policy decisions

The [Google ADK reference report](experiments/google-adk-ticket-2026-10-02/report.json) retains twelve cases through the actual native Runner, capture plugins and ReflectAndRetryToolPlugin. A scripted BaseLlm emitted twenty-five model calls; eighteen tool calls made nine HTTP posts, with seven committed native effects and forty-three yielded native events. Seven tasks completed, four ended in error and one remained incomplete. Task completion and committed effects stay separate: the after-effect error and early-close cases retain their committed effect. These calls are not remote provider inference or model-quality results. The typed MCP error result passed through a FunctionTool; actual MCP transport was not exercised.

The [complete original ADK archive](experiments/google-adk-ticket-2026-10-02/original-artifact.zip) and [provenance](experiments/google-adk-ticket-2026-10-02/provenance.json) retain 838 members and distinguish original synthetic execution source, producer implementation, reviewed reader and separately selected target baseline. A later exact-main run also passed; its separate metrics do not replace this original report. Target, store, keys, clock and expected outcomes remain under the same operator. No process restart, power-loss recovery, outside recurring use or independent effect custody is established.

The [installed consumer report](experiments/installed-format-policy-2026-10-02/report.json) retains a framework-free installed reader upgrade from 0.0.2 to 0.0.3. The old reader refuses the unsupported format profile. The upgraded reader preserves the earlier native reports and verifies the format experiment's evidence for bounded report publication. A separate selected quality policy still holds both larger-model schema-decoded policy rows: each is correct in one of six cases against the example host's minimum of three. Verifying the evidence does not approve the model's decisions, and publishing a scoped report does not either. A changed-source mutant is also held.

The [complete installed upgrade archive](experiments/installed-format-policy-2026-10-02/original-artifact.zip) and [provenance](experiments/installed-format-policy-2026-10-02/provenance.json) retain all 2,268 original members, including the earlier upgrade, immutable producer fixtures, installation receipts, three wheels and raw reader/gate streams. This run performs no new model inference and supplies no dispatch or recovery authority. It does not establish a registry release, outside acceptance or recurring adoption. The selected register gate refuses promoting a committed ADK error into task completion or a verified-but-held quality result into publication, including reselected receipt controls.

These additions bring the [register](lab/register.json) to fourteen records, while preserving all twelve earlier record objects and artifact bytes. Raw archives were published before this index; native outputs and comparison still emitted together under exposed author-selected tasks and policies.

<a id="retained-typed-policy-and-grounded-boundaries"></a>

## Retained typed, policy and grounded boundaries

The fifteenth author-operated [register record](lab/register.json) retains the completed 384-call original with all twenty-four separate semantic rows and 192 pair records. Its 192 schema-constrained outputs are schema-valid, while no policy or grounded pair has both cases strictly correct. The [finite comparative finding](boundary-findings.md) preserves every original score and distinguishes policy vocabulary failures from wrong decisions using valid labels; it introduces no new inference, general benchmark estimate, outside acceptance, recurring adoption or independent custody.

The [unmodified report](experiments/model-boundary-cpu-2026-10-02/report.json), [original compact provider ZIP](experiments/model-boundary-cpu-2026-10-02/original-artifact.zip) and [source/member provenance](experiments/model-boundary-cpu-2026-10-02/provenance.json) preserve all 871 compact members and an explicit mapping to the complete 901-member preparation original, including all thirty omissions. The complete original remains privately archived. All fourteen earlier register objects and retained artifact bytes remain unchanged. The selected source, the installed consumer's acceptance and actual outside operation are recorded separately.

<a id="installed-boundary-evidence-and-semantic-quality-policy"></a>

## Installed boundary evidence and semantic quality policy

The seventeenth [register record](lab/register.json) retains the actual framework-free reader upgrade from 0.0.3 to 0.0.4, separately from the native boundary experiment. The [installed report](experiments/installed-boundary-policy-2026-10-02/report.json) contains the original CI upgrade values and all twenty-four unchanged native rows, attempts, pairs and resource scopes. The old reader refuses the boundary profile before launch. The upgraded reader verifies complete evidence and permits a scoped report; it performs no new model inference.

The selected host quality policy requires eight correct cases and four fully correct pairs per constrained family row, together with all sixteen outputs format-valid and schema-valid. It still holds all eight constrained policy and grounded rows through sixteen separate correctness/pair failures. The typed rows pass those example thresholds; the larger model's thirteen correct cases and five pairs remain below the original all-sixteen/all-eight strict claim. Neither evidence publication nor these example thresholds authorize actions.

The [selected capsule](experiments/installed-boundary-policy-2026-10-02/selected-capsule.zip) retains 101 byte-exact CI members: installed wheels/build records, original reader and gate streams, installation results and CI test output. The [provenance](experiments/installed-boundary-policy-2026-10-02/provenance.json) accounts for every member of the complete 4,964-member provider original, including all 4,863 explicit omissions. The complete original is separately retained; the capsule does not contain duplicate native packets or unrelated older workflow results. The native boundary archive remains in its fifteenth record. The [source contract](experiments/installed-boundary-policy-2026-10-02/source-contract.json) independently pins the actual wheel's reader and gate sources.

All sixteen earlier record objects and artifact bytes are preserved. This is author-operated offline installation and selected report/quality gating, with exposed cases, answers and thresholds. A package registry release, recurring outside adoption, dispatch/recovery authority and independent custody remain unestablished.

<a id="native-policy-vocabulary-and-an-installed-quality-hold"></a>

## Native policy vocabulary and an installed quality hold

The eighteenth [register record](lab/register.json) retains the original 128-call CPU vocabulary intervention from 2026-10-03. A fixed global action vocabulary scores 18/64 correct decisions and 2/32 complete pairs. The broad string control scores 4/64 and 0/32. All 128 outputs satisfy their selected schema. All eight rows still fail the default semantic quality gate.

The [full finding and runnable offline consumer](vocabulary-findings.md) show all row scores, unchanged resource budgets, exact original packet bytes, selected wheel sources and explicit full-original omissions. The installed reader accepts scoped evidence and returns `hold-quality`; repeated stdout is byte-identical. Evidence-only exit success preserves the quality hold.

The contribution preserves all seventeen earlier literal objects and artifact bytes. The earlier unexecuted vocabulary diagnosis is a historical checkpoint. This record supplies a new frozen intervention and measured result. Authored inputs, answers and thresholds remain exposed. Outside producer acceptance, recurring adoption, model-action authority and independent effect custody remain unestablished.

<a id="native-tool-arguments-and-explicit-abstention-failures"></a>

## Native tool arguments and explicit abstention failures

The nineteenth [register record](lab/register.json) retains the complete original 128-call tool-argument CPU study. All short-cap outputs fail JSON parsing; all long-cap outputs satisfy their selected schema. At the long cap, the smaller model scores 0/16 and the larger model 7/16 in each mode. No quality row has a correct abstention or fully correct pair. All eight strict quality rows hold.

The [complete finding and offline retention gate](tool-argument-findings.md) preserve every raw response, source commitment, denominator and external whole-child resource observation. The exact native provider ZIP retains all 331 members. The separate complete preparation archive remains outside Atlas; its digest cannot reconstruct omitted model, dependency or environment bytes.

All eighteen earlier literal records and artifact bytes remain unchanged. Native evidence publication, semantic quality, model-action authority, outside acceptance, recurring adoption and independent effect custody remain separate. [Claims P-51–P-56](claims.md) record the new sources, read times and limits.

</details>

[HTML view](lab.html) | [Agent guide](llms.txt)
