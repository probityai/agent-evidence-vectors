# Verdict precedence

When several policies answer the same proposed action, they can disagree. This page is the normative rule for which answer stands, so that two verifiers given the same answers reach the same verdict. The key words MUST, MUST NOT and MAY are used as in RFC 2119.

The rule is a design of this repository. Decision points in the field already return verdicts from a small closed set; none of them states the tie-break as a rule a third party can check, and a reader comparing two vendors' records otherwise reverses it out of code.

## The order

From least to most strict:

| rank | verdict | meaning |
|---|---|---|
| 1 | `allow` | the action may run as proposed |
| 2 | `constrain` | the action may run only after the decision point rewrites it as the record states; the bytes bound by the permit are the rewritten bytes |
| 3 | `require_approval` | the action waits for a named approver other than the proposer |
| 4 | `block` | this one action is refused; the run may continue with other actions |
| 5 | `halt` | the action is refused and the run ends |

The same list is the `values` of the `decision_verdict` term in the [vocabulary](https://github.com/probityai/agent-evidence-vectors/blob/main/packages/vocabulary/docs/decision-receipt.md), in this order, and a test holds the two together.

## The rules

1. **Strictest wins.** A verifier MUST resolve the answers to the verdict of highest rank among them.
2. **Order independence.** The resolution MUST NOT depend on the order in which the policies answered.
3. **Every deciding policy is named.** The resolution MUST list every policy that gave the winning verdict, sorted by identifier.
4. **No answers is no decision.** An empty set of answers MUST NOT resolve to `allow`. The verifier reports that no decision was made.
5. **An unknown verdict is refused.** A verdict that is not in the table, or is spelled differently (`ALLOW`, `Deny`), MUST be refused. It MUST NOT be read as `allow`, and it MUST NOT be skipped.
6. **A failed check is a block.** A check that failed without producing a verdict of its own, such as a content guardrail that errored or did not pass, counts as `block`. It MUST NOT be skipped and MUST NOT wait behind an approval.
7. **Two-valued decision points.** A decision point that answers `allow` or `deny` is read with `deny` as `block`. No other verdict is rewritten.
8. **One answer per policy.** A policy that answers twice is refused.
9. **Constrain carries its constraint.** A `constrain` answer MUST name its constraint. When `constrain` wins, the resolution carries every constraint of every policy that gave it, sorted and without repeats, and the permit binds the bytes after all of them are applied.

## The resolver and the vectors

`agent_evidence_admission.verdict_precedence.resolve(answers)` implements the rules, and `agent-evidence-admission resolve-verdicts <answers.json>` runs it; it exits 0 when a verdict was resolved and 2 when the input has no resolution. The [conflict vectors](../python/vectors/precedence/manifest.json) hold a positive and a negative case for each rule, and the tests also resolve every case in every order of its answers. A verifier in another language is conformant when it returns the same resolution, or the same refusal reason, for every case.
