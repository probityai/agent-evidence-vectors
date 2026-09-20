# AEE to AVE crosswalk

Mapping the Adversarial Execution Evidence predicate onto the Agentic Vulnerability Enumeration standard. Written 2026-07-28 against AVE's 59 published records.

This is offered as a basis for collaboration, not as a competing taxonomy. AVE answers which behavioural class was found. AEE answers what an outside party can re-check about the run that found it. Those are different questions, and a record answering the first is strictly more useful when it can also answer the second.

## Why this crosswalk has a different shape from the others

The existing inbound crosswalks in this project map a scanner's finding IDs onto AVE record IDs. AEE is not a scanner and emits no finding IDs, so a finding-to-record table would be inventing a correspondence that does not exist.

What AEE does have is a vocabulary for the provenance of an observation, and AVE already carries fields in that same territory: detection_stage, detection_layer, evidence_kind_default, evidence_basis_engines, and confidence_baseline. Every one of those is a string or a float attached to a record as a SARIF result.properties tag. They classify the evidence; nothing in them can be re-checked by someone who was not present when the scan ran.

So this crosswalk maps **AVE's evidence vocabulary onto AEE's evidence structure**: for each way AVE already describes how a finding was reached, what would the corresponding signed, offline-verifiable record look like.

## The vocabularies, with counts

All counts derived from the 59 records in the records directory on 2026-07-28.

| AVE detection_stage | Records | AEE method | Why |
|---|---|---|---|
| static_detection | 44 | examination | The component was read, not run. AEE's examination method covers exactly this: an assertion about an artifact derived without executing it. |
| runtime_observed | 15 | interception or arming | The component was executed and something watched. Which of the two depends on whether the observer sat in the data path or planted a tripwire. |

| AVE detection_layer | Records | AEE observationEnvironment implication |
|---|---|---|
| content | 37 | No execution environment exists to describe. substrate is undefined and honestly so. |
| runtime | 15 | A substrate exists and can be pinned: corpus digest, manifest, catch policy, network posture. |
| registry_metadata | 4 | The observation is about a registry response, so the fetch itself is the thing needing provenance. |
| server_card | 3 | Same, for a declared capability document. |

The stage and layer fields are near-perfectly correlated in the current corpus: 37 of 44 static records are content, and all 15 runtime records are runtime. In practice one field carries the signal and the other restates it.

| AVE evidence_basis_engines | Records citing it | Can AEE express it today |
|---|---|---|
| semgrep | 52 | Yes, as an examination-method observation over a named corpus. |
| pattern | 43 | Yes, same. |
| llm | 25 | Yes, and this is the one where a signed record helps most: a model's judgement is exactly the kind of claim a reader has no independent way to check. |
| yara | 13 | Yes. |
| sandbox | 2 | Yes, and only here is `basis: intercepted` available, because only here did the component actually run. The two records are AVE-2026-00054 and AVE-2026-00056. |
| magika | 1 | Yes. |

## The one field with no AEE counterpart, and it is the interesting one

confidence_baseline is a float between 0.5 and 0.9, assigned per record. Thirteen records sit at 0.83, twelve at 0.62, ten at 0.75.

AEE has no confidence field and will not be gaining one. The predicate expresses trust structurally instead, through three fields a verifier can act on. evidenceTier records who stands behind the observation, as declared, attested, or unattested. basis records whether the observer saw the event or inferred it afterwards. result carries pass, degraded, or fail, and degraded exists so that partial observation stays reportable as partial instead of being rounded to whichever confident outcome is closer.

The difference is not cosmetic. A reader who sees a confidence baseline of 0.83 learns what the record's author believed. A reader who sees an attested evidence tier with an intercepted basis learns something they can verify without trusting the author at all. Both are useful; only the second survives the author being wrong, or dishonest, or simply gone.

This is the crosswalk's actual proposal: keep confidence_baseline as the human-facing summary it already is, and let an optional AEE attachment carry the part a stranger can check.

## Worked example

AVE-2026-00054, code-execution sandbox escape, is one of the two records whose evidence_basis_engines includes sandbox. It is therefore the only class in the corpus where the full AEE structure is available rather than partially undefined:

```
AVE-2026-00054                          the behavioural class
  -> AEE conformance vector             the run that exercised it
  -> signed catch record                what the substrate observed, with the network posture pinned
  -> offline re-verification            a third party re-checks without re-running anything
```

For a content-layer record the same chain is shorter and should be, because nothing executed. That asymmetry is a feature: AEE is explicit about which claims rest on execution and which do not, and it refuses to dress an examination up as an observation.

## What this does not claim

AEE does not detect anything and does not compete with AVE's classification work. It cannot tell you a component is malicious. It can only tell you whether the account of how you found out is checkable.

The two conformance-relevant limits, stated plainly: AEE is presently exercised by a first-party implementation set, so cross-rail agreement is a drift check rather than independent corroboration; and the predicate is a draft under review at in-toto, not a ratified standard.

## Provenance

AVE records were read from the published corpus on 2026-07-28, 59 in total. That read names a date and no commit, and it cannot be pinned to one now: twelve upstream commits across seven days carried a 59-record tree, so the date does not identify which of them this document describes. The figures below are therefore left exactly as they were read and are not tracked forward. `aee-to-ave.json` beside this file is the anchored version: it names the upstream commit its counts were taken from, and `scripts/crosswalk-gen.py` regenerates it against a named checkout rather than being edited.

The AEE field vocabulary comes from spec/predicates/adversarial-execution-evidence.md in this repository. The conformance suite is at revision 30 with 281 vectors, 61 accept, 218 reject and 2 indeterminate, per vectors/MANIFEST.json. The predicate is under review as in-toto/attestation pull request 570.
