# When an interoperability claim is evidence

register: edelman

Status: proposal, and a checker. The rule below is implemented in `corpora/vectors-mcp-record-contract/check_run_record.py` and measured against corpora/vectors-mcp-record-contract/, so it is not a rule anyone has to take on trust.

## The rule

An interoperability claim is evidence only when its run record is re-checkable. A claim is re-checkable when a third party can get the same result from what is published and compare it byte for byte. That reduces to four inputs, per direction of the cross-run:

The inputs, at an immutable reference. A commit identifier or a digest. A repository name plus a version string names a thing that can change under the claim, and the projects in this area know it: one of them left a tag it had published "against the wrong commit" in place rather than moving it, "because re-pointing a published tag would break exactly the reproducibility this verifier exists to check". That was the right call, and it is also the demonstration that a tag can be moved.

The runner, at an immutable reference or a digest. Naming the library the runner was built on is not naming the runner. The driver that loaded the inputs and emitted the result is the part a third party has to have, and it is the part most often absent while both endpoints resolve cleanly.

The invocation, verbatim. I can hold the inputs and the runner, and without the invocation I still do not know what anyone asked of them. A cross-run whose two sides ran different subsets is not a cross-run.

The result, published, with a digest. A digest turns a re-run into a comparison. Give me the digest and no file and I hold a promise; give me the file and no digest and I hold an artifact nobody pinned.

## Two declarations that decide what the number means

These do not decide whether a reader can get the result. The counting rule and the independence declaration decide what a result says, so a checker reports each apart from the verdict and never folds them into it.

The counting rule. A figure states what its denominator counts, and how it counts a member the runner did not score. A figure written as N of N is read as N passes, and the author of one such figure wrote the honest form himself, one line down: "24 vectors, 0 hard failures". The same run is honestly describable as N members with no failures when some were deliberately not scored, and those are different claims. A record can enumerate its unscored members by name one line down and still publish a headline with a whole numerator, and the headline is likely the half a reader quotes. That case is a member of the corpus, and it is the one that separates a checker reading the record from a checker reading the summary; [What a checker answers](#what-a-checker-answers) gives the three columns it turns on.

Independence. One of three: independent, self-report, or undeclared. A run of somebody else's vectors by their author is worth publishing and is not independent evidence. Only the third value is a defect. A declared self-report tells a reader what it is; an undeclared record leaves the reader guessing; and a checker that failed self-reports would probably push records towards dropping the declaration.

The environment is noted and does not fail a record. A result that turns out not to depend on the runtime is a stronger result, and nobody can establish that from a record that never named one. The environment therefore appears in the report and never in the verdict.

## What a checker answers

Fold these three together and a self-report reads as a reproduction:

| answer | question |
|---|---|
| recheckable | can a third party get the same result from what is published |
| figureMeansWhatItSays | does the headline agree with its own counting rule |
| independence | independent, self-report, or undeclared |

A record can be fully re-checkable, carry a figure nobody should quote, and be a declared self-report. Folding those into one pass is how each of them disappears.

## Why this is not a documentation preference

An audit of 1 published cross-run claim in an open specification thread found both halves of a paired figure sharing 1 table cell. One half was re-checkable. Its inputs were pinned at a tag object that resolves to a 40-character commit id, its author had published the runner, its invocation sat in the repository's own instructions, and its result file carried a reference digest. I re-ran it and reproduced that digest byte for byte, on a runtime the record never named. That run took under 2 minutes and needed nothing from the party that published it, which is the whole property this document is about.

The other half was not, and the missing input was the runner. Both endpoints resolved. The driver between them existed nowhere: I searched the working tree of the repository the claim named, then all 83 of its remote branches, then the repository that published the claim, and ran a positive control on each search path first so that an empty result meant an empty result. Nothing in the table distinguished the two halves. The thread it sits in had run 68 days by the time I read it, and carried 48 comments and 0 reviews, so no maintainer had yet had cause to ask which half was which.

The same claim also compressed a figure. The published run behind it recorded 24 members with 0 failures, and its author classified 6 of those 24 as deliberately out of scope, by name, in the same paragraph: 4 outside its numeric range and 2 needing a validation stage it does not implement. The table cell reads as a whole numerator, with no footnote. The runner scored 18 members. A reader carries away 24.

Neither half of that is dishonest. As best I can tell both follow from a table with 1 column over a record that has 3.

## Where these vectors land upstream

The conformance suite for this protocol takes a test case as two artifacts, and a vector family for a record contract seems no exception. Its own guide puts the constraint plainly: "fewer scenarios, more checks", because each scenario spins its own server in continuous integration for every implementation.

A requirement row per rule, one per rule in [The rule](#the-rule), goes in the suite's per-proposal traceability file, src/seps/sep-<NNNN>.yaml. Each row carries either a check: slug that an emitted check must match exactly, or an excluded: reason naming why the rule is "not observable at the protocol level".

One scenario class per family lives in src/scenarios/server/ and emits many checks rather than many scenarios.

I would register the class in src/scenarios/index.ts, the suite's registry and the only place a scenario becomes reachable.

I would add an entry to requirements/<spec-version>.yaml only where a revision requires the family to be scored.

The contribution rules ask for an issue first and a run against a real implementation before a pull request, and they say to "reuse the CLI runner" rather than add a second entry point. Nothing here proposes one: the checker in this repository is a reference for the rule, and the upstream shape is a scenario emitting one check per rule above.

## What this does not claim

It does not say a claim failing the rule is false. It says the claim is an assertion, which is a statement about what a reader can do with it rather than about whether it holds. A self-report from a careful engineer is frequently correct and is not evidence. That distinction is the entire content of this document, and I would rather state it plainly than have it inferred.