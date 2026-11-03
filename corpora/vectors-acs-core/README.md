# ACS-Core negative conformance suite

Negative conformance vectors for the mandatory profile of the OWASP Agent
Control Standard, read from `GenAI-Security-Project/agent-control-standard` at
four commits and one issue: `9d4a9da` on `main`, the head of the release/0.1.4
pull request (`7efa539`), the heads of pull requests 272 (`f2304bf`) and 278
(`7d9b7ff`), and the body of issue 264. The normative files
the vectors cite are vendored in `spec-vendored/`, pinned by sha256 in
`MANIFEST.json`, and each `specVendored` entry names the commit and the
upstream path its bytes came from and whether they are upstream's or a
proposal. Every member file quotes the sentences it turns on, with that commit,
under `requirementText`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

## Nothing has been run against this

There is no reference adapter in the specification's repository at the pinned
commit, and the two pull requests that carried one are closed. So this corpus
ships with a self-check and with no observed results. `MANIFEST.json` carries
an empty `observedRuns` array and `aee-verify` refuses a non-empty one,
because a run row is added by whoever ran it, naming what they ran and what
they ran it against. The counts here describe inputs with declared
expectations. They are not a score, and nothing in this directory is evidence
that any implementation does anything.

One run has since happened, on 2026-09-18, against the reference Guardian in
`reference-implementations/agt` of the specification's repository at commit
`dc26547` on `integration`, which postdates the pinned commit. It is not
recorded in `observedRuns` because the row shape is not yet defined here, and
a run against a Guardian validating a later schema than the one this corpus
pins is a result about that pairing, not about the pinned specification. The
four members of family `acs-f-9` were written from that run.

Another run, on 2026-09-12 and 2026-09-27, drove the Claude Code shim
(`hosts/claude-code`) in the same `reference-implementations/agt` outside any
host, on Windows 11, at commits `7d2dd3c` and `27799c2` on `integration`.
Under Bun 1.4.2 at both commits, with the Guardian running, the shim exited 0
with nothing on either stream and sent no handshake and no `toolCallRequest`;
with the Guardian stopped, at `7d2dd3c`, it exited 0 with nothing on either
stream and created no audit log.
Under Bun 1.3.11, the version that repository's CI pins, the same shim at
`27799c2` with the Guardian stopped rendered a fail-open allow and wrote one
audit entry per step. The head was not run; nothing under
`reference-implementations/agt` changed between `27799c2` and `db5c89e`, and
the reference README at all three says every fail-open proceed is written to
the audit log. The reject member of `acs-f-5` whose payload carries
`host_hook_output` was written from that run. It is not recorded in
`observedRuns`: no member of this corpus was run, and the row shape is not
defined here. The 2026-09-12 run is reported upstream as
GenAI-Security-Project/agent-control-standard#111.

## Identifiers are minted here, and bound to a sentence

The specification carries no requirement identifiers. Its normative sentences
are addressable by section number and by line, and both move on an edit that
changes nothing about the requirement, so a vector citing either would keep
citing after a reword and quietly mean something else. Each row in the
requirement table quotes its normative sentence; `gen_vectors.py` locates that
sentence in the vendored copy, records the line it derived rather than one
typed by hand, and hashes the NFC bytes. A reword stops the build.

That is the whole argument for the identifier scheme, and it is why the
identifier is opaque. `ACS-R-004` names a sentence. A name built out of a
section number names a position, and a position is the thing that moves.

## A verdict is a code, never prose

Every member asserting a refusal names a value from the specification's own
fixed error registry, and `aee-verify` refuses a member that invents one.
Substring matching against operator messages fails a correct implementation
that words a refusal differently and passes a wrong one that words the right
cause, which are the two errors that matter in opposite directions.

The disposition vocabulary the specification calls free is deliberately not
asserted anywhere here. A field the specification does not fix is a field two
conformant implementations may spell differently, and scoring on it would
measure agreement with one of them.

## Three verdicts, because two hide a gap

A member is `allow`, `deny`, or `unmeasurable`. The third exists because the
specification has requirements whose violation it gives a deployment no
conformant way to detect: the revoked-mandate member is one, since revocation
propagation is listed as pending in the specification's own identity overview,
and the HMAC wrong-signer member is another, since under the symmetric baseline
the verification key is the signing key.
Scoring that member as a rejection would credit an implementation for behaviour
nothing requires. Scoring it as a pass would delete the gap from the record.
Every `unmeasurable` member carries the reason it cannot be measured, and the
self-check refuses one that does not.

## Every rejecting family accepts something

`aee-verify` refuses a corpus in which a family rejects and never
accepts. A suite of rejections alone awards full marks to a deployment that
denies every input, and that deployment governs nothing. The sequenced family
carries a sequenced control for the same reason: a single-step positive
satisfies the gate in appearance only, because it cannot tell an engine
honouring a turn boundary from a harness that reset the counter.

## Two columns beyond the verdict

Each member declares an `evidenceBasis` of `substrate` or `artifact`, and a
`witnessScope` of `SELF`, `PEER` or `EXTERNAL`. The first says whether the
expectation rests on an observation of the run or on a record the run emitted
about itself; a party holding the enclosing key and not the observation key can
move every row to `artifact` and emit something byte-identical to what an
honest producer with no observation vantage emits, so only a declaration
separates them. The second says who can check the member without the
enforcement point's cooperation. Most rows are `SELF`, and that is a finding
about the wire format rather than a failure of the corpus.

A `coverage` field says which rung of the coverage ladder a member exercises:
`supported`, `configured`, `effective`, `observed`. Declared support and
effective enforcement are different properties, and a corpus that does not
separate them scores a deployment on what it says about itself.

## Layout

| path | what it is |
|---|---|
| `vectors/` | one file per member, named after a digest of its own declaration |
| `spec-vendored/` | the normative files the requirements are read from, each pinned by digest and by upstream commit |
| `MANIFEST.json` | the requirement table, the families, the scope-away list, counts and corpus digest |
| `INDEX.md` | every requirement and every member in one table |
| `gen_vectors.py` | regenerates the corpus byte-identically |

## The October text: release 0.1.4, pull requests 272 and 278, and issue 264

Families `acs-f-12` to `acs-f-19` are minted from text that landed, or was
proposed, between 2026-10-12 and 2026-10-16. Each member carries a
`doesNotAssert` line beside its verdict, because an accepting member read as
evidence of more than the one property it turns on is the error a corpus like
this one invites.

**Release 0.1.4.** The pin is the head of pull request 281, read before it
merged and before any `v0.1.4` tag existed. Its specification files are
byte-identical to `integration` at `685367d`, where each change the release
carries had already merged. Families `acs-f-15`, `acs-f-16` and `acs-f-17` take
the Trace rules it makes normative: every step span carries the join pair, a
join keys on session and request together, a conditional attribute is emitted
exactly when its source field is present, parallel arrays are padded rather
than shortened, a reader never counts a decision as enforced when either
party's stream holds a failure event for its pair or when the OCSF event is
flagged late, the Observed Agent records every decision failure in the
deployment's own log, a Guardian emits no failure event for a replay, a failure
detail never copies request bytes, and the OCSF decision event's
`disposition_id`, `is_alert`, `authorizations` and `correlation_uid` follow the
release's tables.

**Pull request 272.** Open and unmerged at its pinned head, so its members test
a proposal and the vendored entries say so; a change to the proposal before it
merges is a reword that stops this build. Family `acs-f-13` holds the HKDF
derivation the pull request fixes. The derivation is computed here, not typed:
the generator recomputes the key the pull request publishes for its worked
example and refuses to build if the two disagree, and every signing member
carries the signed input, its digest and the derivation the signer used, so a
checker can recompute the MAC without deciding how to canonicalize. The
rejecting members are signed with derivations the pre-fix sentence admitted (the
session id as the salt, no derivation at all), with a long output, and with
another session's key, and each must fail with `SIGNATURE_INVALID`. The same
family holds the `key_id` rule: an unknown label is refused with no fallback to
another secret, the label is never derived from the secret, a rotation holds
both labels, and the Guardian answers under the label the request named.
Family `acs-f-14` holds the `request_id_ref` rule from `hooks.md`: a reference
the Guardian cannot resolve within the session is recorded whatever the
decision, and the decision stays the deployment's policy.

**Pull request 278.** Open and unmerged at its pinned head, so family
`acs-f-18` tests a proposal. It reads the allow row and rule the pull request
adds to `events.md`, and the `required_fields` default it adds to
`ocsf-mapping.json`, which is vendored beside it. An allow goes to class 6002,
Application Lifecycle, at severity 1, carries the disposition in
`unmapped.acs.decision`, and sets `correlation_uid` to the step's pair. The
rejecting members caption the class Application Activity, which is its category,
raise the severity, drop the disposition or the request id, or reverse the pair.
The opt-in that records allows as Detection Findings has an accepting member and
one that breaks the decision event's `is_alert` rule. The `activity_id` of a 6002
allow is left open by the pull request, so no member turns on it.

**Issue 264.** An open proposal with no specification text of its own. Family
`acs-f-12` reads sections 6.3 and 6.5 at the release pin, where the substitution
the issue is about is already required: a MODIFY the Observed Agent cannot apply
becomes DENY, or keeps the original summary at `postCompact`, and an audit event
records it. The members cover a substitution recorded correctly, one omitted, and
one whose record claims a modification that never happened, which is the harm
section 6.5 names. One indeterminate member there records that a reader holding
only a trace at the release pin cannot tell an applied MODIFY from a substituted
one.

Family `acs-f-19` takes the Trace form the issue proposes, from the issue body
itself. The body is vendored and pinned by its sha256, because an issue has no
commit, and the manifest records the edit time it was read at. The members hold
the event `acs.decision.substituted` on the Observed Agent's step span, the same
event with no applied outcome, and the event on the Guardian's span, which only
the Observed Agent can see. They hold the reader rule both ways, and a same
request id in another session, which a join on session and request together
keeps apart. When the Trace text lands, these members are minted again from it.

A requirement quoting a sentence that runs on past a section sign is quoted as
ASCII fragments, because the Go reader hashes only ASCII and a digest it cannot
reproduce would report an intact corpus as broken.

## Running it

```
aee-verify vectors-acs-core/       # self-check, from the repository root
python3 gen_vectors.py             # regenerate, byte-identically
python3 gen_vectors.py --check     # refuse a tree the generator does not emit
```

`aee-verify` is the one harness for every corpus in this repository. It reads
the `suite` field of a `MANIFEST.json`, judges the members that suite declares,
and refuses by name a suite it does not know. Each corpus used to carry a
Python self-check of its own, so the command a reader was told to run differed
per corpus and three of the six were wired into no workflow at all. Build it
with `go build -o aee-verify ./cmd/aee-verify`.

## What is deliberately absent

An open pull request is moving four surfaces of the mandatory profile, and no
vector is written against any of them. `MANIFEST.json` lists them with the
reason. The list is the part of a corpus a reader cannot reconstruct from the
corpus, so it is recorded rather than left implicit.

A second list, `awaitingText` in `MANIFEST.json`, holds cases raised on the
specification's tracker that no sentence at the pinned commit says. A member
for one of them would cite a requirement that does not say what it tests, so
each waits for its sentence and is minted from that sentence when it lands.

## The same property at two witness scopes

The sealed-session members in `acs-f-6` come in a pair per profile. A seal that
drops a head the Guardian already published is refused with `CHAIN_MISMATCH`
under both the HMAC baseline and ACS-Crypto, and only the witness scope
differs: `PEER` under the baseline, where the Observed Agent holds the session
key and the heads already published to it, and `EXTERNAL` under ACS-Crypto,
where the public key lets a third party show which heads the Guardian signed.
The baseline stops at the peer because the Guardian holds the same key and can
re-sign a shorter chain, so the Core half never claims a third-party witness.

## A wrong signer and an undeterminable one

Family `acs-f-10` carries one substitution under both signature profiles, the
HMAC baseline of ACS-Core and the asymmetric ACS-Crypto profile: the Observed
Agent signs a chain head and presents it as the Guardian's. Here the two
profiles do not differ only in witness scope; they give different verdicts.
Under ACS-Crypto the signature verifies only under the Observed Agent's own key
while its `key_id` resolves to the Guardian's, so it fails verification and is
refused with `SIGNATURE_INVALID`, and a party holding only the Guardian's
public key can see the wrong signer, which makes the member `EXTERNAL`. It has
an accepting twin signed by the Guardian. Under the HMAC baseline both parties
hold the session key, the Observed Agent's MAC verifies under the key the
`key_id` resolves to, and nothing in the head or the public material says who
computed it. That member is `unmeasurable`, citing the section 8.6 sentence
that puts non-repudiation in ACS-Crypto, and `SELF`, because the only accounts
of who signed are the two key-holders' own. The specification gives a
verifier no answer meaning "the signer cannot be determined", so that member
is exempt rather than scored, and `awaitingText` in `MANIFEST.json` records
the sentence it waits for.

A third member refuses the claim rather than the signature. An HMAC head the
Guardian did sign, presented to a third party as proof of which Guardian issued
it, is graded `deny`, because the symmetric tier cannot carry that claim and a
surface that only calls it weak lets it through. The member forbids a registry
code (`forbidsRegistryCode`) rather than leaving the code unasserted:
`SIGNATURE_INVALID` there would report a signer nobody can determine as one
determined to be wrong, which is the ACS-Crypto member's answer, so a verifier
that gives it fails. That is where the corpus keeps "the signer is wrong" and
"the signer cannot be determined" from taking one shape. The member names the
wrong answer and not the right one: until the specification gives a verifier
an answer for an undeterminable signer, a deny that carries no code is all it
can require. It is
`EXTERNAL`: the algorithm and the claim are both in the presented bytes, so an
outside party can refuse it without the Guardian's account or the key. Its
accepting twin presents the same head to a key-holder as integrity evidence, so
a verifier that refuses every HMAC head fails the family rather than passing it.

## The trust anchor is part of the input

Every `acs-f-10` member carries `key_id_resolves_to`: which key a `key_id`
names and who holds the signing half. Section 10 defines no in-band key
exchange, so in a deployment that binding is distributed out of band and is
the consumer's own trust anchor. The members take it as given and test what a
verifier does with it: a signature that verifies only under a key the binding
does not name is `SIGNATURE_INVALID`. No member asserts that `guardian-k1`
belongs to any real Guardian, and none could, because that fact differs per
deployment and a self-contained vector cannot fix it. This is the boundary row
U5 of the AEE coverage matrix (`docs/COVERAGE-MATRIX.md`) draws for the AEE
corpus, where the per-consumer anchor stays out of every vector and the
evidence tier is pinned under two supplied key policies instead.

## A session that starts with no Guardian

Family `acs-f-5` holds a step that proceeds without a decision after the
handshake completed: section 6.4 requires an audit event, and a Guardian exists
to receive it. Family `acs-f-11` holds the same property one level up. When
`handshake/hello` produces no ServerHello, section 4.1 has the Observed Agent
apply a startup posture configured out of band, `proceed` by default, and
requires the unguarded start to be recorded in the deployment's own audit log,
because there is no Guardian to receive the event. The two families want
different witnesses, so they are two families; every `acs-f-11` member is
`SELF`, because the deployment's own log is the only record.

What the family turns on is whether a record of the start exists, not whether
the session started: a member that asserted only the start would score the
default posture as evidence of enforcement. Each rejecting member sits one
field away from the accepting member with no answer at all, so each names the
one fact it turns on. Remove the record and the start is unrecorded. Replace
the silence with `SESSION_REFUSED` and the posture has been applied over a
decision, which section 4.1 forbids, so the session is refused with the code
the Guardian sent. Set the posture to `refuse` and the session should never
have started. A second accepting member answers the hello with a JSON-RPC
internal error, which is an error without a ServerHello and not one of the
refusals section 4.1 lists, so an Observed Agent that reads every error as a
decision fails it. The record's shape is not fixed by the specification, so
the members assert that a record exists and never how it is spelt.

The two paths were named on
GenAI-Security-Project/agent-control-standard#33.

Nothing here tests content filtering, model robustness, or prompt injection
detection. The member about attributed content tests one property: that
provenance establishes lineage and confers no authority. A suite that reached
past that would be measuring a judgment rather than a rule.
