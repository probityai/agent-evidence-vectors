# APS and PriorSeal: proposed Lab pilot

One pinned decision, one receipt, and a reader that shows exactly what the pair establishes

Proposed, 1 October 2026. Probity coordinates this work. APS, PriorSeal and Frequency have not confirmed this pilot or accepted its results.

Probity is preparing one [Open Evidence Lab](lab.md) pilot around the APS decision and PriorSeal receipt. The question is whether a reader can independently check the declared signatures and the association between a particular decision, authorized call and receipt from pinned owner bytes. The answer must show each established, contradicted and unestablished assertion. A valid envelope or a single `VERIFIED` label would leave too much of that question unanswered.

This page is Probity's work register. Its state is **proposed**. It records no agreement by APS, PriorSeal, Frequency or the [federation discussion](https://github.com/aeoess/agent-governance-vocabulary/issues/185), and it is not a reviewed Lab result. Probity will coordinate the question, maintain the public status, and implement and run the reader. Each producer can speak only for its own artifact; an independently operated reader or custodian needs a separately named operator and trust boundary.

<a id="starting-evidence"></a>

## Starting evidence

The [merged source-replay PR \#5](https://github.com/probityai/agent-evidence-atlas/pull/5) contains Probity's runnable check of the unmodified Frequency review adapter at revision [`4162622`](https://github.com/altrudev/Frequency-Federation-Review/tree/4162622af24c94efb843f53aa27940ffd1256ad6/capsules/aps-priorseal-v0.1). It reads the [APS owner fixture at `948f99b`](https://github.com/aeoess/agent-passport-system/tree/948f99b85343bef2c6fa677c8543965caacfc087/fixtures/priorseal-decision-binding) and the [PriorSeal copy and observations at `d749d26`](https://github.com/imokokok/PriorSeal/tree/d749d2691c3e6be139de4020e7b27cdafca2c428/examples/aps-priorseal-decision-binding-v1). The runner also pins the adapter, dependency lockfile, manifests and selected reports by SHA-256. Its [procedure](https://github.com/probityai/agent-evidence-atlas/blob/516bd0aa0f93e94ee6877f64dbd122c52545f388/experiments/aps-priorseal-source-replay/RUN.md) and [recorded outcomes](https://github.com/probityai/agent-evidence-atlas/blob/516bd0aa0f93e94ee6877f64dbd122c52545f388/experiments/aps-priorseal-source-replay/recorded.json) are pinned to the PR's October 1 head.

That technical replay compared all **17 declared owner/copy fixture files** byte for byte. The clean run reported **14 established, 3 contradicted and 5 not established** claims. A changed copy and a missing owner refused; omission of the owner flag refused; a failed rerun left an old output file, which the runner rejected as stale. The [source-replay CI run](https://github.com/probityai/agent-evidence-atlas/actions/runs/36910480718) passed on the exact PR head, and PR \#5 merged on 1 October. It retains Probity's receipt as an artifact; the full generated adapter report and third-party source checkouts remain in the job. These are technical results for public fixtures using the review adapter, whose expected outcomes were visible. They do not establish mutation adequacy, live payment execution, independent custody, production adoption or approval of a formal pilot.

There is a separate run-contract limit. In the [pinned review wrapper at `b12879d`](https://github.com/altrudev/Frequency-Federation-Review/blob/b12879d5878991d9c3ed260d06ee11716eb99d33/capsules/aps-priorseal-v0.1/run-pinned.sh), stubbed command failures and an absent output report still led to a zero exit, a recorded zero and `PASS`. Probity's [bounded control](https://github.com/probityai/agent-evidence-vectors/tree/main/site/experiments/aps-priorseal-source-replay) checks those cases without evaluating adapter claims. Our replay invokes the adapter directly and accepts a result only with a zero exit and a fresh report. A wrapper status on its own is not evidence of a completed check.

<a id="roles-and-acceptance"></a>

## Roles and acceptance

The [replay tools guide](replay-tools.md) describes the current tools, which require callers to declare their runner identity. They retain the entrypoint and helper source hashes separately from producer input pins. The [copied-file procedure](https://github.com/probityai/agent-evidence-vectors/blob/main/site/experiments/aps-priorseal-source-replay/RUN.md#use-copied-tools-outside-an-atlas-checkout) supports callers without an Atlas checkout. A declared identity does not prove who controlled the operator, keys or storage. Old receipts and pilot decisions keep the scope they were issued under.

| Work | Proposed owner | Decision needed |
|----|----|----|
| Scope, status and retained result | Probity coordinator and Lab reader | Publish an exact claim set, source pins, checked fields, raw run receipt and all refusals; record the reader revision, runner and exposure to expected results |
| APS decision bytes and meaning | APS artifact owner, **unconfirmed** | Confirm the selected owner fixture, decision reference, authorized call and what its signature is meant to assert |
| PriorSeal receipt bytes and meaning | PriorSeal artifact owner, **unconfirmed** | Confirm the selected receipt, key and observation semantics, including what the fixture does not prove about an actual payment |
| Frequency review adapter | Frequency maintainer, **unconfirmed** | Confirm only the adapter revision and allowed use under its notice; any formal or shared result needs a separate scope decision |
| Independent reading or custody | Operator **unassigned** | Name who holds policy, keys, witness head and results outside producer control; document how the reader obtains them |

The first gate is an owner-confirmed, immutable input manifest and field-level question. The second is a fresh run with zero exit status, retained command, dependency pins, stdout, stderr, full report, hashes and negative cases. An independent implementation must recompute the signature and decision-to-call-to-receipt binding rather than accept the adapter's label. Controls must distinguish a changed owner or copy byte, missing owner, wrong key, wrong decision reference, changed call or cap, and a stale output. Each control needs its exact refusal and unchanged claim ceiling. Probity will publish the result and review trail in the [Lab register](lab/register.json) only when actual retained files and measured claim bindings pass its [protocol](lab.md); this proposed page is not a register entry.

An actual action/effect pilot is a further gate. It requires a preselected consumer policy, an observed effect and coverage boundary, independently acquired trust anchors where independence is claimed, and a decision tied to the exact evidence bytes. A producer fixture or an adapter signature result cannot fill those fields. The result should keep `supported`, `contradicted`, `unestablished` and disputed claims visible rather than turn them into one pass mark.

<a id="open-decisions-and-next-review"></a>

## Open decisions and next review

- **Owner scope:** APS and PriorSeal have not confirmed a shared artifact description, selected pair or public formal pilot. Seek each owner's confirmation on its own side before reporting one.
- **Mutation adequacy:** Source binding controls passed the bounded technical replay. Wrong-key, wrong-decision, changed-call and adversarial composition cases still need discriminating fixtures and a separate adequacy review.
- **Reuse:** Frequency's [review-only notice](https://github.com/altrudev/Frequency-Federation-Review/blob/4162622af24c94efb843f53aa27940ffd1256ad6/REVIEW-ONLY-NOTICE.md) allows technical review and reproducibility assessment, but withholds commercial incorporation and redistribution of modified or derivative Frequency implementations. The PR invokes pinned sources without copying their implementation or fixtures into this repository. Reusing Frequency's schema or implementation in a shared deliverable needs a separate permission decision.
- **Result custody:** The October 1 CI retains a bounded Probity receipt; a formal Lab record needs the complete run inputs and outputs under clear reuse terms, plus a named runner and reviewer. Separate keys or repositories alone do not establish independent operation.

Probity's next status review is **6 October 2026**: recheck the exact PR head and CI, confirm whether the owners have answered their respective scope questions, freeze the intended controls, and record any unresolved objections here. If the answers are absent, the state stays **proposed**. Neither a map listing nor technical participation counts as joining a coalition or accepting a commercial role.

[HTML view](pilot.html) | [Agent guide](llms.txt)
