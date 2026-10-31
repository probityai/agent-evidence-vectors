# Retained admission decision: article and presentation packet

[Read the article](../../replay-an-evidence-decision.html), inspect this
[packet manifest](presentation.json), or open the
[E6 Lab record](../../runs.html#record-E6-observer-admission).
The packet joins the existing explanation and images to their exact retained
inputs and result. It does not run the brokered file action again.

## Inspect the evidence

| Question | Retained source |
| --- | --- |
| Which article explains the replay? | [Article](../../replay-an-evidence-decision.html) and [immutable method before the added packet link](https://github.com/probityai/agent-evidence-atlas/blob/a592d539569c5754ea5eba70bdfd140db762fb1d/src/replay-an-evidence-decision.md) |
| Which source and files were checked? | [Source pins](source-pins.json) and [provenance](provenance.json) |
| What did the replay report? | [Complete recorded result](recorded.json) |
| Which images accompany that result? | [Decision diagram](../../assets/admission-replay.svg), [editable preview](../../assets/admission-social.svg) and [served PNG](../../assets/admission-social.png) |
| How is an image exported? | [Original source and export instructions](../../assets/README.md) |
| Where is the original experiment? | [Method and limits](../../experiments.html#observer-consumer-admission) and [E6 Lab record](../../runs.html#record-E6-observer-admission) |

The manifest pins the article source, input manifests, recorded result and all
three image files by SHA-256. Its six selected outcomes come from the complete
recorded result:

| Field | Recorded value |
| --- | --- |
| `admissionCount` | `1` |
| `admissionStatus` | `admitted` |
| `replayRefusal` | `interval was already admitted by this consumer` |
| `authorityRefusal` | `packet authority differs from consumer policy` |
| `tamperRefusal` | `signature does not verify under the pinned key` |
| `refusalsPreserveState` | `true` |

This is an author-produced, same-operator fixture with `PEER` witness scope and
an artifact vantage. The Atlas replay checks the retained evidence and local
admission decision. The original CI result and later main result remain
distinct in the [provenance](provenance.json). Expected refusal controls do not
contradict the admitted claim. This packet establishes no independent custody,
complete transient effect capture, downstream exactly-once result or paid use.
