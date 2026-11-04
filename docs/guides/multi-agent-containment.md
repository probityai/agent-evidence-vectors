# Prove a multi-agent containment claim

A defence for a system of cooperating agents says it contained a compromised agent: it cut the agent's channels, isolated it, fell back safely when its own detector failed, and let the agent back only on evidence. Each of those sentences is a claim about the run, and a party who trusts neither the orchestrator nor the agents should be able to recompute it from the run's own record. This guide shows a defence how to emit that record, how to state its claims so they can be checked, and how to hold its verifier to the [containment-journal corpus](../../corpora/vectors-containment-journal/README.md) in CI.

The record has three parts: the journal, the claims it carries, and an optional blast-radius receipt. The normative rules, in the order a reader applies them, are in the [predicate document](../../corpora/vectors-containment-journal/README.md); both type URIs are listed in the [predicate registry](../../spec/predicates/REGISTRY.md).

## Write the journal

The journal is one hash-chained list of typed entries, written as the run happens. A containment decision can be checked only against the deliveries that follow it, and a return to service only against the evidence that precedes it, so every event goes in the same chain:

| Entry | Write it when |
| --- | --- |
| `topology` | The run starts. It is the first entry and appears once. |
| `delivery` | A message passes from one agent to another, or the router drops it. Record whether the edge was in force. |
| `decision` | The defence changes the communication graph. Record the new edges, the edges removed and added, the agents left with no outgoing edge, the `basis` that steered the change and, for a detector, its per-agent risk estimates and the message fields it reads. |
| `fallback` | The defence failed and replaced the graph. Record the posture it declares, `fail_open` or `fail_closed`. |
| `restart` | An agent was restarted. Record whether its memory was cleared and the configuration digests before and after. |
| `assessment` | An agent's output was scored. Record the score, whether one was produced, and whether the witness was the agent itself or an external judge. |
| `restoration` | An agent is let back. Cite, by entry digest, the restart and assessment the decision rests on. |
| `response` | Someone acted, continued or escalated after an alert. Record the authority and the reason. |
| `tool_call` | An agent called a tool. From revision 1.1 it may say the call was refused and why, and name the grant chain it ran under; a call that ran for an isolated agent is refused by the reader. |
| `refusal` | Revision 1.1: the router refused a message over an edge in force for its budget or purpose scope, under a neutral reason code; it is not a drop. |
| `retrieval` | Revision 1.1: an agent asked for a document, whether it was admitted, and the inclusion path from the document's digest to the run's `snapshotRoot`; an admitted document outside the snapshot is refused. |

Each entry carries `seq`, `prev` (the digest of the entry before it) and `at`. Keep the record to integers and printable ASCII strings; an entry's digest is then the SHA-256 of its RFC 8785 bytes, which any language can recompute.

Write `enforcement` honestly. A topology enforced by an enforcing router, one that refuses a message over an absent edge, is `enforced`. A topology that is only stated to the agents in their prompts is `advisory`, and a reader refuses a claim that the channels were closed over it.

## State the claims

The journal's `claims` object is what the defence asserts about the run, and each member is recomputed from the entries:

- `channelsClosed`: cut edges carried no traffic. Refused over an advisory topology.
- `restorationGated`: every agent that came back had an admitted restoration citing a restart and an external assessment below its threshold.
- `defendedThroughout`: the defence never fell back open.
- `detectorDriven`: at least one detector decision had risk estimates that told the agents apart.
- `responseBoundSeconds`: the longest time from alert to action.

Leave a claim out rather than state one the run does not support. A journal with no claims that is internally consistent is still `allow`.

## Bound the damage with a receipt

A blast-radius receipt names one agent and the entry from which it is treated as compromised, and states the agents it reached through deliveries the router did not drop, with the deliveries and tool calls that reach involved. It names the journal by run, head digest and entry count. A reader recomputes the reach from the journal and refuses a receipt that leaves an agent out or adds one, so an incident report can quote the receipt instead of an estimate.

## Hold your verifier to the corpus in CI

A verifier takes `record.json --json`, judges `receipt.json` beside it when present, and prints `{"decision": ..., "reason": ...}`. Pin the Action to a release that carries the corpus (`agent-evidence-vectors --list-corpora` lists them):

```yaml
- uses: probityai/agent-evidence-vectors@<tag>
  with:
    verifier: ./my-containment-verifier
    corpus: vectors-containment-journal
```

Or pin the package and replay the corpus yourself:

```sh
pip install "agent-evidence-vectors==<version>"
agent-evidence-vectors --corpus vectors-containment-journal --verifier ./my-containment-verifier
```

Keep the pin exact and let a bot move it, so each release reaches you as a pull request your CI tests:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
```

A release that adds a case a conforming verifier fails is a minor release, never a patch ([RELEASING.md](../../RELEASING.md)), so the bump pull request is where a new refusal first reaches you.

## The reference verifier

[probity-verify](https://github.com/probityai/probity) is the reference verifier. After your verifier runs, the Action replays the corpus through a pinned probity-verify release and prints `reference-checked conformance N of M`, where N counts the members whose declared verdict the reference verifier reached; the [runner guide](runner.md#reference-stage) describes that stage. Run your own journals through the packaged reader the same way:

```sh
python3 corpora/vectors-containment-journal/check_vectors.py path/to/record.json --json
```

## What this does not prove

A consistent journal shows that the defence's claims follow from the events it recorded. It does not show that every event was recorded, that the detector is any good, or that the defence would stop the next attack. Pair the journal with a collector the defended agents cannot write to.
