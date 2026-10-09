# Held-out conformance: a design

register: edelman

Status: built for the ACS-Core suite. The runner is `agent-evidence-heldout` in the package (source `packaging/agent_evidence_vectors/heldout.py`, cases in `scripts/heldout-runner-test.py`). Suites are data under `packaging/agent_evidence_vectors/suites/`. Who holds the seed is still each standard's governance question; the mechanism below works for whoever that is.

```sh
pip install agent-evidence-vectors
agent-evidence-heldout commit --seed-file seed          # steward publishes this digest
agent-evidence-heldout seal --seed-file seed --out held # steward keeps held/ private
agent-evidence-heldout run --sealed held/SEALED.json -- ./my-adapter
agent-evidence-heldout verify heldout-run.json --transcript heldout-run.transcript
agent-evidence-heldout reveal --seed-file seed --sealed held/SEALED.json  # after the release
```

The adapter reads one JSON line per member, `{"question": ...}`, and answers one line, `{"verdict": "allow"|"deny"|"unmeasurable", "code": "<registry name>"|null}`. A sealed member is a published member with every opaque identifier respelled through a seed-keyed map that keeps equality inside the member, so it asks the same question in bytes nobody has seen. `agent-evidence-heldout self-test` runs the runner's own controls: a lookup table of the public corpus passes every public member and must fail the sealed slice, a constant answer and an adapter that leaves early must not exit 0, and an edited record must stop verifying.

## The contradiction

A maintainer of that standard wrote it down exactly:

> "Only a held-out corpus tells a real implementation from a lookup table, and
> holding vectors back conflicts with publishing them."

Both halves are true, and the measurement behind the first half is worse than it reads. His own premortem puts the mechanism plainly: "An adapter whose first statement discards the input scored 19/19 and exited 0, because the vector `id` encodes the verdict class. Redacting the id doesn't fix it." An adapter whose first statement discarded its input scored 19 of 19 against a published suite and exited 0, because each vector's identifier encoded its verdict class. Emptying the question to an empty object, handing the adapter nothing at all, still passed every vector through a 7-line walk of the interpreter's own call stack, in his words "a seven-line sys._getframe walk". A published corpus cannot prove enforcement, and nobody reviews, contributes to, or checks a corpus they cannot read, least of all the party the claim is made to.

3 resolutions are already ruled out by measurement.

Redacting the identifier relocates the leak. I tried it on a corpus of 272 vectors at suiteRevision 28, for an attestation predicate. Over each vector's whole manifest-relative path, a cheap classifier predicted the verdict from the identifier alone with a separability of 1.0000 against a permutation null of 0.5879. Stripping the verdict prefix left the authoring slugs at 0.9936; stripping the family token as well left 0.7260; the description words alone scored 0.7307, against a null near 0.585. As best I can tell the leak was not the prefix.

It was the vocabulary: one side of a corpus says missing, mismatch, duplicate and wrong, and the other says clean, canonical and pass. There is no spelling of a published mapping from old names to new that carries no label. What closed it was naming every vector after a digest of its own bytes and keeping the verdict only in the manifest, after which the identifier surface measured 0.5075 against a null of 0.5075 and the whole surface fell from 0.9906 to 0.5567 against a null of 0.5817.

Publishing nothing seems to remove review altogether. A suite nobody reads is a suite whose positive controls nobody has checked, and a positive control is a mandatory allow. He wrote the consequence himself: "One contributed vector can quietly demand a bypass, at which point the runner flags the honest implementation as the broken one."

Publishing everything and calling the suite a self-certification aid is honest and gives up the thing the label is for. His own summary of what he takes from the thread reads "the suite describes itself as a self-certification aid, since a published corpus cannot separate enforcement from a lookup table". It is the right description of a suite that stops here, and this design exists to get further.

## The claim the design supports

The resolution starts by narrowing what must be unavailable. The thing an implementer must not be able to look up is the verdict, not the vector. A published corpus whose identifiers, paths, filenames and lexicon each sit inside their own measured noise floor gives a lookup table nothing to key on but the bytes of the statement, and reading the bytes of the statement is the behaviour under test.

That is not a proof of enforcement and this document does not claim it is one. It moves the honest description from "self-certification aid" to something narrower and checkable: a corpus that cannot be passed by an adapter that never opened a file, published alongside the measurement of how much its own surfaces leak, so a reader checks the claim instead of taking it. The genuinely held-out part then shrinks to a small sealed slice, which is a governance question with a mechanism rather than the thing the whole suite rests on.

## The public corpus

Every vector published, with three properties enforced by a gate rather than asserted in prose.

Content-addressed identifiers. Each vector takes its name from a digest of its own declaration. No directory per verdict, no prefix per verdict, no published mapping from any earlier naming.

A published leakage measurement. The suite ships the separability of a cheap classifier trained on nothing but each vector's identifier, scored against the same estimator with the labels shuffled. A run whose identifier surface scores above its own null fails the gate. The recipe is the contribution: anyone can run it against their own corpus, and the number is meaningful only beside its null.

A verdict asserted as a code. Never a message. Substring matching against operator prose fails a correct implementation that words a refusal differently and passes a wrong one that words the right cause.

## The sealed corpus

A small slice, generated from the same families as the public corpus and never published. Its purpose is one measurement and not a score: the difference between a run's public result and its sealed result on the same families.

Whoever holds the seed generates it, and nobody curates it. The generator is public and its seed is not, so an implementer can read exactly how a sealed vector is shaped and cannot enumerate which ones exist. A curated sealed corpus is a secret that likely degrades as it is used; a generator plus a withheld seed is a secret that regenerates.

It is small. Enough members per family to make agreement unlikely by chance, and no more. A large sealed corpus is a large secret and a large thing to leak.

A sealed member goes public once it has served its one measurement. The report carries its verdict, its bytes and every run against it. The seal buys one measurement per release, then becomes public review. A permanent secret is a permanent unfalsifiable claim, which is the defect this whole document answers.

The steward holds the seed. Who that is, and how anyone appoints them, is governance, and I propose no answer to it.

## The attested-adapter run

A run is worth reading only when a reader can tell what was run.

The adapter runs out of process, one child per suite run. In process, an adapter owns the runner: a call to exit inside one gave exit 0 with no output at all, because catching a broad exception class misses the interpreter's own exit exception. One child per vector is also wrong, apparently because it breaks every implementation with real state, which includes anything that detects replay.

The run record pins the adapter, not its name. A digest of the adapter bytes, a digest of the corpus, the suite revision, the sealed generator revision, the command line, the wall-clock start and end, and the transcript. An implementation name and a version string are a claim; a digest is a thing a second party can recompute.

The runner ships its own negative controls. Mutating a reference adapter measures the vectors and leaves the runner untested, which he reported himself: "Nineteen runner mutants found five guards with nothing behind them, two exploitable, one of which silently restores a defect a reviewer had already caught and the author had already fixed." In digits: 19 mutants of 1 runner, 5 guards with nothing behind them, 2 of those exploitable, 1 that reinstates a fixed defect. Nobody has measured the scoring code of a run whose runner carries no mutation baseline of its own.

A run that scored nothing does not exit 0. An empty capability profile that prints zero of zero vectors conformant and exits 0 is the cheapest possible pass. A scoring gate refuses it outright.

## Scoring

A scorer works per requirement, on 4 rungs, and the rung is part of the claim.

| rung | what it asserts | what establishes it |
|---|---|---|
| supported | the implementation declares the control | a declaration, and nothing else |
| configured | the control is enabled in this deployment | configuration read from the deployment |
| effective | the execution path is actually intercepted | a public-corpus run under an attested adapter |
| observed | traffic has been seen traversing that path | a run record with a transcript |

Without the ladder, a declaration reads as an enforcement result. A runtime may emit correct traces for a tool action while the execution path bypasses the enforcement hook entirely, and one resolved package instance may carry instrumentation while a second does not. Both are supported and neither is effective, and a scoring surface with one column cannot say so.

A requirement reaches effective only where a vector the row names kills a weakening of that requirement, run under the conditions [The attested-adapter run](#the-attested-adapter-run) sets out. A row proves the requirement is named; it proves nothing about whether the named test would fail on a violation; and a table shows those 2 properties identically.

Three further columns travel with each row, because the verdict cannot carry them:

basis, substrate or artifact: whether the expectation rests on an observation of the run or on a record the run emitted about itself. A party holding the enclosing signing key and not the observation key can move every row to artifact, drop the observation records those rows no longer need, and emit something byte-identical to what an honest producer with no observation vantage emits from the same configuration. No function of the carried bytes separates them, so only a required declaration does.

witness scope, SELF, PEER or EXTERNAL: who can check the row without the enforcement point's cooperation. A row is SELF unless a concrete artifact path exists that lets the named witness check it without relying on the enforcement point's own account.

stop reason: which branch produced the verdict. A guard that fires before anything evaluates the property emits a verdict word indistinguishable from the one a real check produces, and when it stops on the correct side nothing catches it. An assertion on the stop reason catches that, and it costs almost nothing.

## What the label then means

Four claim forms, and the unqualified word is not one of them.

emission-conformant. The implementation emits the shapes the specification defines. It asserts no enforcement, and the public corpus alone establishes it at the supported rung.

operationally conformant, self-attested. Every requirement is effective under an attested-adapter run of the public corpus, with the leakage measurement public. The runner publishes its own mutation baseline. Every row is SELF.

operationally conformant, sealed-checked. The above, and two further steps. The steward runs the sealed slice and compares its result against the public result on the same families, then releases those sealed members. This is the rung at which "not a lookup table" stops being an argument and becomes a measurement, and it is a measurement with a stated confidence rather than a proof.

operationally conformant, externally verifiable. The above, plus at least one requirement whose row is EXTERNAL: an artifact a party outside the trust domain can check without the enforcement point's cooperation. On the wire format as it stands, 0 rows reach this, and one measurement of it puts 132 of 132 enforcement obligations at no external witness basis at all. I record that as a finding about the format.

Unqualified "conformant" overclaims, so nobody writes it. A suite that publishes only what it covers seems to have the same problem one level up as a label with nothing behind it, so the suite also publishes what it fails to force: how many normative conditions it cites, how many are forced by a vector no other condition's vectors duplicate, how many are covered only redundantly, how many are not forced at all, and which failure codes a conforming implementation may decline to emit entirely.

## What this does not buy

It does not prove enforcement. A sealed-slice agreement, in the sense [The sealed corpus](#the-sealed-corpus) gives it, is probably evidence that the implementation read the bytes of the statement rather than a table of answers, at a confidence set by how many sealed members ran, and it is nothing stronger than that.

It does not survive a steward who leaks the seed, and it is not meant to: the mechanism assumes the seed holder is the party whose incentive is to keep the label meaningful, and it fails loudly rather than quietly if that stops being true, because a sealed result that stops disagreeing with the public result on any implementation is itself the signal.

It says nothing about requirements the specification cannot express. Those carry the verdict unmeasurable with the reason beside it, and folding them into either column arguably commits the same error in 2 directions: a rejection credits an implementation for behaviour nothing requires, and a pass deletes the gap from the record.

## What it costs

The public corpus, its leakage gate and its verdict-code discipline are the bulk of the work and are worth doing whether or not the sealed half is ever built. The sealed generator is small. The attested-adapter contract is a document plus a runner change. The scoring surface is a schema.

The part that is not engineering is the steward, and this document deliberately proposes no answer to it.