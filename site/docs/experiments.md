# Experiments: evidence, effects and bytes

A PEER pilot, pinned decision-call, byte and consumer-admission experiments, and two registered observer designs

Draft 0.4, 15 October 2026. A bounded checkout composition reference joins the retained pilot and fixture experiments. Their independent operation and custody remain unestablished.

The [atlas's open cell](atlas.md#the-open-cell) asks whether a record of an agent action comes from a vantage the agent cannot control, whether its evidence binds to the actual effect, and what was missed. A signature and an offline verifier answer questions about retained bytes. They do not answer who could alter or omit the underlying observations. These experiments keep those questions separate.

<a id="historical-report-meaning-and-diagnostic-rule-controls"></a>

## Historical report meaning and diagnostic rule controls

The [worked report example](evidence-test-meaning.md) retains a historical report replay and two separate diagnostic controls. [Inspect its Lab record](runs.md#record-w3c-report-replay-2026-10-06) or [check the retained accounting](experiments/w3c-report-replay-2026-10-06/README.md). These are existing author-operated measurements; no new numbered study or live customer workload is introduced.

<a id="checkout-composition"></a>

## Checkout composition reference

[Agent checkout runner](https://github.com/probityai/agent-checkout-runner/blob/297b5b182bb40605b62586eccbf93a9c68a4aee1/README.md) is a combined CLI and GitHub Action at source tag `v0.2.0`, commit `297b5b182bb40605b62586eccbf93a9c68a4aee1`. It drives checkout and refund components, keeps admission decisions, dispatch attempts, simulator effects and report-time observations in separate streams, and seals a bundle for replay.

Use the [version-pinned guide](https://github.com/probityai/agent-checkout-runner/blob/297b5b182bb40605b62586eccbf93a9c68a4aee1/README.md) to install the CLI or pin the Action. It needs Python 3.12 or later, git, Node 24 and npm. The guide declares 26 matrix cases. Its separate [claim reference](https://github.com/probityai/agent-checkout-runner/blob/297b5b182bb40605b62586eccbf93a9c68a4aee1/docs/CLAIMS.md) defines `ESTABLISHED`, `CONTRADICTED` and `NOT_ESTABLISHED` per retained claim. Bundle verification re-derives those claims; it does not turn a contradiction into permission to act.

This is a **bounded composition example**. Its provider is a local simulator, every record is synthetic and its keys are public test keys. Component suites run on their own fixtures; passing them side by side does not establish a connected deployment. An author-operated fixture run does not establish an independent run, maintained adoption or a merchant deployment. The [coverage map](https://github.com/probityai/agent-checkout-runner/blob/297b5b182bb40605b62586eccbf93a9c68a4aee1/docs/COVERAGE-MAP.md) keeps the component roles and remaining connection requirements explicit. This reference adds no new native run to the Atlas Lab register.

<a id="historical-gate-reference"></a>

## Historical event reference

The [Approval-Gate event snapshot](https://github.com/probityai/Approval-Gate/blob/9a8649b1be95cd6de6a7854ca4acfa0bd4ec6a45/README.md) retains a customer-support simulation that checks evidence and policy before a mock email action. Its source-pinned adapter calls the public Verify kernel. The offline replay checks a saved decision without sending an action. This historical example provides event context, not a merchant deployment or a production email service. Its original commands and recorded result keep their own source and scope.

<a id="e1.-peer-pilot-the-snapshot-gap"></a>

## E1. PEER pilot: the snapshot gap

The local `agent-evidence-observer` prototype mediates one file replacement, commits to the before-state, signs a bounded result, and checks a hash-chain head under a second key. It does not isolate an agent. Its own record says `witnessScope: PEER` and `unmediatedEffects: not-established`. The two keys are controlled by one local operator.

I ran [the exact pilot script](experiments/observer-vantage/run.py) against the package source identified by SHA-256 `273e4985cb4de671145bcd55ef85545be213e8520f766ab7692e9d05edae60d1`. The [recorded machine result](experiments/observer-vantage/recorded.json) contains three scripted intervals. At that read, the package source was a local unpublished prototype. The observer now has public source, used at a different pin in E6; that does not supply or identify the exact older source bytes for this pilot. Its original result remains a local measurement without an independent reproduction.

| interval | deliberately attempted effect | observed result | inference |
|----|----|----|----|
| Brokered write | A script says "no write," then asks the broker to write once and repeats the same request ID | One accepted write, one replayed request, offline verification passed, `PEER`, `noDetectedGap=true` | The retained broker record contradicts that *scripted* self-report. No unmodified agent or independent witness was tested. |
| Durable bypass | The same process writes directly to the workspace and leaves the bytes there | The direct write succeeded; the next snapshot reported `workspace changed outside the broker`. Verification against the current workspace refused the stale root. | The observer can detect this particular durable divergence, but did not prevent it. |
| Transient bypass | The same process creates a file and removes it before the next snapshot | The direct write succeeded; `knownGaps=[]`, `noDetectedGap=true`, and offline verification against the restored workspace passed. | A snapshot-only check can miss an effect that leaves no final byte difference. `noDetectedGap` is not complete coverage. |

The population for this pilot is three scripted intervals: one brokered write plus its retry, one durable direct write, and one transient direct write. The broker's declared coverage population is calls with valid request IDs. The direct effects are **outside** that denominator. There is no sample of live agents, tool calls, reads, network effects, file modes, concurrent races, hostile host operators, or independent witnesses. The only tested observation point is the sequential file-tree snapshot at a broker call or seal. The test deliberately controls both sides; its contradiction is a counterexample to a claim of complete coverage, not a measured detection rate in deployment.

To re-run after obtaining the matching observer source, create its Python 3.12+ environment with the dependencies in its `pyproject.toml`, then use:

``` sh
/path/to/observer/.venv/bin/python experiments/observer-vantage/run.py \
  --observer-root /path/to/agent-evidence-observer > /tmp/observer-pilot.json
diff -u experiments/observer-vantage/recorded.json /tmp/observer-pilot.json
```

The script hashes the package metadata and every `src/probity_observer/*.py` file before importing the package. A different digest is a different implementation, even if the three outcomes match. It prints no ephemeral signing keys or timestamps. The claim ledger records this run and its limits as E-01 through E-03.

<a id="e2.-below-agent-observation-registered-design-no-result"></a>

## E2. Below-agent observation: registered design, no result

**Hypothesis.** Under a pinned launch configuration, a host broker unavailable to the agent records every accepted or denied file replacement through one declared channel. A direct attempt to alter the watched tree, observer process, key, or journal fails. If any channel loses its record, the result becomes incomplete instead of an absence claim.

**Unit and denominator.** One launch interval is the unit. Before each interval, pin the agent image and policy digests, authority, allowed path scope, observer build/configuration, initial tree root, nonce, and observer key. Report counts for attempted, accepted, denied, replayed, dropped, and unresolved requests. Record the paths and privileges reachable by the agent as part of the denominator. Do not convert "no event seen" into "no effect" when reachability or liveness is unknown.

**Interventions and controls.** Run the same workload under (a) the current PEER prototype as a negative control and (b) a host-side isolation boundary whose configuration is published. Exercise a normal write, a false self-report, direct workspace write, key read, process signal, alternate channel, path traversal or symlink, lost response retry, broker death, and a missing event. Retain failed and null runs. The agent must not choose the observer's key, journal, commitment, or before-root. A separate operator reproduces one live interval and pins the key independently.

**Primary outcomes.** For each attempted effect, report its raw trace, broker decision, resulting durable bytes, record, refusal or gap, and verification result. The threshold to claim a *bounded below-agent file-write observation* is a demonstrated inability of the tested agent to address the observer and watched tree except through the broker, no missing record for the tested channel, and a signed prior commitment bound to that interval. A single escaped effect or missing record blocks that claim. This does not establish all filesystem effects, all agent actions, or host-operator honesty.

This registered design has no separately reproduced isolated-agent result or measured overhead here. Upstream now runs an author-operated Linux boundary probe, whose CI provenance is recorded in E6. That artifact does not satisfy this design's separate-operator requirement. The [observer acceptance criteria](https://github.com/probityai/agent-evidence-vectors/blob/main/spec/predicates/observed-effect.md) remain a target; no conformant Observed Effect statement is established by the retained pilot or E6.

<a id="e3.-separately-witnessed-history-registered-design-no-result"></a>

## E3. Separately witnessed history: registered design, no result

**Hypothesis.** A witness run by a separate principal, with a pinned key and retained highest head, detects deletion, reorder, replay, divergent heads, and an absent committed interval when shown inclusion and consistency evidence. A second key held by the same operator cannot establish that property.

**Unit and denominator.** One committed interval and its checkpoint pair, plus each attempted history mutation. Publish the witness operator boundary, retention policy, head pinning method, hash/signature profile, and every accepted or refused fork attempt. Test honest append, truncation, two conflicting suffixes, withheld interval, witness unavailability, and key substitution. An offline consumer with an independently pinned head must reproduce refusals. Report mutation count, detected count, undecidable count, and time/space overhead; never recode an unavailable witness as success.

There are **zero separately operated witness runs**. The local PEER pilot's second key is a protocol test only. The witness experiment will remain unclaimed until a separately operated history and a second reproducer exist.

<a id="aps-priorseal-e2"></a>

## E4. APS/PriorSeal E2: decision evidence and exact-call fixtures

The [immutable run record](https://github.com/probityai/agent-evidence-vectors/tree/00f5acab880bffc5ee8fe124f3a015d3ed970514/interop/aps-priorseal-e2-2026-09-30) checks APS decision evidence against PriorSeal's exact-call examples. Its checker imports no APS or PriorSeal implementation. It uses draft-pidlisnyi-aps-03, the fixture documentation, pinned public test keys, and a fixed reference time of `2026-09-19T10:05:00.000Z`. Implementation independence does not establish independent custody of an action observation.

The fetch script pins 31 files from APS `948f99b85343bef2c6fa677c8543965caacfc087` and PriorSeal `d749d2691c3e6be139de4020e7b27cdafca2c428`. [RESULTS.json](https://github.com/probityai/agent-evidence-vectors/blob/00f5acab880bffc5ee8fe124f3a015d3ed970514/interop/aps-priorseal-e2-2026-09-30/RESULTS.json) contains 96 rows, one per claim per input: 86 `pass`, four `fail`, and six `not-exercised`. These are fixture outcomes, not a deployment success rate. The four failures are the denied APS dispatch, the expired APS reference-time check, and the over-limit pair's call-value and per-action-cap checks.

| claim | within-limit pair | over-limit pair |
|----|----|----|
| APS decision-ref correlation | pass | pass |
| Exact call against the supplied observation | pass | fail: intent value 1e15, observation value 6e15 |
| APS per-action cap, using the checker's declared asset mapping | pass | fail: 6e15 exceeds 5e15 |
| PriorSeal principal, acceptance and receipt signatures | not-exercised: out_of_scope | not-exercised: out_of_scope |

The report's 22 recomputable values agree, and three quoted fixture values agree. Report assertions about PriorSeal receipt validity remain unexercised. [SPEC-GAPS.md](https://github.com/probityai/agent-evidence-vectors/blob/00f5acab880bffc5ee8fe124f3a015d3ed970514/interop/aps-priorseal-e2-2026-09-30/SPEC-GAPS.md) records the missing written PriorSeal signing profile, hash constructions recovered by trial, and the checker's mapping from APS spend units to the PriorSeal asset. No result evaluated by this checker differs from the producer's stated outcome.

[NEGATIVES.json](https://github.com/probityai/agent-evidence-vectors/blob/00f5acab880bffc5ee8fe124f3a015d3ed970514/interop/aps-priorseal-e2-2026-09-30/NEGATIVES.json) records five variants and two controls:

| variant or control | measured outcome |
|----|----|
| Invalid APS signature | Decision signature fails; dependent composition claims become void |
| Re-signed APS receipt with an unpinned key offered by adjacent keys.json | Decision signature fails under the checker's pinned configuration |
| Altered authorization with unchanged hashes | Intent-hash consistency fails |
| Altered authorization with every carried intentHash recomputed | Survives at the targeted PriorSeal signature claim, which is unexercised; exact-call comparison changes to pass, while the cross-check against APS requested_call changes to fail |
| Unbound decision_ref, paired with the narrow APS case | Correlation fails on both payments |
| Changed issued_at without re-signing | Receipt identifier and signature checks fail |
| Re-serialization with unchanged JSON value | No state changes |

The surviving rehashed variant is not a whole-case acceptance: the APS cross-check still refuses it. It demonstrates the precise limit of this checker at an unexercised principal-signature claim. The fixtures do not establish chain execution, live authorization currency, live revocation, decision-level single use, cumulative spend, independently operated custody, or production usage.

To reproduce, check out the immutable vectors revision above and run the commands in its [README](https://github.com/probityai/agent-evidence-vectors/blob/00f5acab880bffc5ee8fe124f3a015d3ed970514/interop/aps-priorseal-e2-2026-09-30/README.md). The checker pins agent-evidence-vectors 0.15.0 and pycryptodome 3.23.0; mutation generation additionally pins cryptography 44.0.2. The corpus package supplies byte and Ed25519 primitives, not APS or PriorSeal policy decisions. The ledger records the outputs and ceilings as E-05 through E-07.

<a id="trace-transcript-bytes"></a>

## E5. AGT TRACE transcript bytes: a source-pinned reproduction

The [runner](experiments/trace-transcript/run.py) calls the real AuditEntry, MerkleAuditChain, and both AGT session mappers at [AGT 60931ce](https://github.com/microsoft/agent-governance-toolkit/tree/60931ce0c65db144032cdc8e8f342c66cbb1201c). Before import, it verifies each retrieved source against its exact Git tree blob. Its byte oracle is [rfc8785.py 655cbe0](https://github.com/trailofbits/rfc8785.py/tree/655cbe02b8761208e3f4cc49e879ab1e328a7dca). IDs, times and contexts are fixed. The [recorded result](experiments/trace-transcript/recorded.json) includes all six inputs, digests, source SHA-256 values, Python 3.12.14, and Pydantic 2.13.5.

| AuditEntry.data input | model equals sink | model equals RFC 8785 | sink equals RFC 8785 |
|----|----|----|----|
| ASCII strings | yes | yes | yes |
| U+00E9 value | no | yes | no |
| U+E000 and U+10000 keys | no | no | no |
| Float 1.0 | yes | no | no |
| Negative zero -0.0 | yes | no | no |
| Float 0.000001 | yes | no | no |

The sink escapes non-ASCII characters while the model emits UTF-8 characters. Both sort keys by Unicode code point and use Python's number spelling; RFC 8785 requires UTF-16 code-unit ordering and ECMAScript number serialization. A JSON-value match therefore does not establish a transcript-byte match. These results concern the pinned AGT implementation's transcript hash, not the current TRACE library's separate reverse adapter or an entire protocol-conformance claim.

``` sh
uv run --no-project --python 3.12.14 --with pydantic==2.13.5 \
  python experiments/trace-transcript/run.py > /tmp/trace-transcript.json
diff -u experiments/trace-transcript/recorded.json /tmp/trace-transcript.json
```

The runner also accepts `--source-dir` for an offline rerun from cached source blobs; it checks the same immutable pins. This experiment signs no record and executes no live agent. It establishes byte disagreements on the selected inputs, with no measured claim about effect capture, coverage, custody, or production failures. The ledger records its provenance and results as E-08 and E-09.

<a id="observer-consumer-admission"></a>

## E6. Observer declaration, admission and replay

Read the [worked article](replay-an-evidence-decision.md) and [presentation packet](experiments/observer-admission/README.md) for the explanation, original images and exact retained input/result bindings.

The [runner](experiments/observer-admission/run.py) executes the unchanged public observer demo at [8562c25](https://github.com/probityai/agent-evidence-observer/tree/8562c25fb7ec97596ea9d0297c495340298914b6). It checks [12 Git blob pins](experiments/observer-admission/source-pins.json), privately copies the verified sources, and only then imports them. The declaration fixes interval `admission-demo-1`, scope `/work`, and operation `write-file`. The consumer records those expectations and a signed witness head before the broker begins. The broker performs one durable file replacement, seals its history, and the consumer persists its admission before returning success.

The [retained bundle](experiments/observer-admission/provenance.json) is the original `admission-run` artifact from [observer CI run 36808961399](https://github.com/probityai/agent-evidence-observer/actions/runs/36808961399), downloaded and hash-checked. Its archive SHA-256 is `bcc22cd27b1f9404e961f7329770620994a76348d085b7b711ab586986493892`. The provenance record supplies a digest for each of the eight retained evidence files and records the omission of two empty lock files, so the evidence survives the original artifact's expiry. The PR run reports head `cc7191e344aabcd26baec8cbac922050ad1420b2`; its logs show checkout of synthetic merge `e8040a8032ea197ea7a185a832808c5fb9ee9355`. The tested tree matches the pinned observer revision. That original archive records the tested PR tree. A later [native main run 36825509807](https://github.com/probityai/agent-evidence-observer/actions/runs/36825509807) checked out exact revision `8562c25fb7ec97596ea9d0297c495340298914b6` and passed the same 148 tests, admission demo and eight Linux boundary-probe checks. The provenance record includes this additional run and its distinct artifact digests. None was independently operated.

| retained file | what is checked |
|----|----|
| [Policy](experiments/observer-admission/retained/consumer/policy.json) | Fixture authority, interval, public keys, and signed witness head |
| [Packet](experiments/observer-admission/retained/producer/packet.json) and [broker history](experiments/observer-admission/retained/producer/history.jsonl) | Prior commitment, signatures, roots, request history and bounded coverage |
| [Witness receipt log](experiments/observer-admission/retained/producer/ledger.jsonl) | Two authenticated checkpoint receipts and retained-head continuity |
| [Durable file](experiments/observer-admission/retained/producer/workspace/result.txt) | Exact bytes `one durable effect` followed by a newline, and the current retained tree root |
| [Decision](experiments/observer-admission/retained/consumer/decision.json) and [consumer state](experiments/observer-admission/retained/consumer/state.json) | One admission, bound to authority, claim digest, effect root and receipt-log head |
| [Original demo report](experiments/observer-admission/retained/demo-report.json) | Successful first admission and the exact replay refusal |

The atlas re-admits those signed bytes in a fresh scratch consumer store and requires its decision and durable state to equal the retained records. Its [deterministic result](experiments/observer-admission/recorded.json) also records three controls:

| intervention | required outcome |
|----|----|
| Repeat the admitted interval | Refuse: `interval was already admitted by this consumer` |
| Change the consumer's expected authority scope to `/other`, in a fresh store | Refuse: `packet authority differs from consumer policy` |
| Change the signed claim's after-root without re-signing, in another fresh store | Refuse: `signature does not verify under the pinned key` |

Every refusal must leave consumer state unchanged. Fresh stores for the latter controls ensure replay protection cannot mask a missing authority or signature check. A newly executed demo generates new keys, nonces and signatures; the comparison checks complete semantic outcomes and source digests, while the original bundle has its own exact file manifest.

To reproduce on Linux:

``` sh
git clone https://github.com/probityai/probity/tree/main/packages/observer observer-source
git -C observer-source checkout --detach 8562c25fb7ec97596ea9d0297c495340298914b6
uv run --no-project --python 3.12.14 --with cryptography==46.0.7 \
  python experiments/observer-admission/run.py --observer-root observer-source \
  --bundle experiments/observer-admission/retained \
  --manifest experiments/observer-admission/provenance.json \
  --expect experiments/observer-admission/recorded.json
uv run --no-project --python 3.12.14 --with cryptography==46.0.7 \
  python experiments/observer-admission/run.py --observer-root observer-source \
  --output /tmp/observer-admission-new \
  --expect experiments/observer-admission/recorded.json
```

The output directory must be empty. After the exact source checkout and runtime are available, neither command fetches sources or contacts a witness. The atlas CI job runs both commands and the source-pin/refusal attack tests on every push and pull request, retaining each fresh bundle.

This is an **author-produced same-operator fixture**, with `witnessScope: PEER` and `evidence_vantage: artifact`. Its public keys and head are fixture expectations, not externally acquired trust. It establishes the tested declaration-to-admission ordering, signed-byte checks and local at-most-once admission. Its coverage remains `broker-write-calls-with-valid-request-id`, with `unmediatedEffects: not-established`. It does not establish independent custody, live-agent behavior, wall-clock freshness, complete effect capture, production isolation, cross-host consensus, or exactly-once downstream effects. Deleting or rolling back consumer state can erase replay protection. The ledger records these outcomes and ceilings as E-10 through E-13.

[HTML view](experiments.html) | [Agent guide](llms.txt)
