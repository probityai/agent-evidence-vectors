# Predicate type: Observed Effect

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect

Version: 0.2.0

Predicate Name: Observed Effect

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer and
> make registration under `https://in-toto.io/attestation/` a step that follows
> vetting rather than a precondition for issuing; two predicates discussed in
> in-toto/attestation#554 are issued from their authors' own domains today. This
> document is the shape a promotion filing would carry, and it is normative for
> the implementation that emits it now.
>
> The URI does not resolve yet. GitHub Pages is not enabled for this repository,
> so a reader following it today gets a 404, and this document at
> `spec/predicates/observed-effect.md` is the authority in the meantime. A
> `predicateType` is an identifier rather than a retrieval address and the in-toto
> guidelines require no dereference, so nothing depends on it resolving; enabling
> Pages is the small change that makes it resolve, and it is tracked. The URI
> itself is stable and will not move: every vector in
> `vectors-observed-effect/` carries it inside signed bytes, so changing it
> re-signs the corpus and changes all 31 member identifiers.

## Purpose

Records a **mutation interval** observed from a vantage the observed party does
not control: the state root before, the state root after, the path scope the
observation covered, and the digest of the authority under which mutation was
permitted. A change maps to one interval, a diff renders one, a session is a
chain of them.

The interval itself is not the contribution and is not claimed as one.
[ASQAV] Section 8.2 already specifies an interval and its re-derivation, down
to the ordered base resolution and the empty-tree terminal case, and this
predicate adopts that rule rather than restating it differently. What this
predicate adds is the part that specification leaves out by construction:
**binding an interval to independently observed execution.**

The gap is visible in [ASQAV]'s own text. Its authoritative tier re-derives a
subject digest by re-fetching bytes from the source host, and Section 8.4 says
of that protocol that it "requires network access to independent surfaces" and
that "'independent' here never means 'offline'". Section 8.2 then states the
honest limit: "Reproducibility does NOT make the attestation unbypassable: a
client that never requests an attestation bypasses it entirely", and, where the
host's rendering of a range changes, "the re-derived digest changes and the
earlier attestation no longer re-derives". So the strongest tier in that profile
rests on a surface the observed party writes to, reachable only online, and
absent entirely for any interval the observed party declined to report.

Section 8.3 draws the consequence explicitly, and it is the sentence this
predicate exists to answer: emission topologies "with no independent-evidence
capture_layer counterpart (browser_extension, ebpf_observer, mcp_proxy) can
never mint an authoritative attestation", and Section 8.5 repeats that "the
eBPF-observer and passive-telemetry topologies ... remain observation-only
evidence classes". That ruling follows from defining independence as
re-fetchability from a third-party host. Under that definition an observer
sitting *below* the party it watches is demoted to hearsay, which inverts the
actual trust ordering: the observer below cannot be bypassed by a party that
declines to report, and its bytes cannot be rewritten by a force-push.

This predicate defines independence the other way. A record is authoritative
when its observation was made from a layer the observed party cannot address,
and the fields that carry that claim are checkable **offline**, from the
statement alone, with no host to re-fetch from and no network at all.

What that buys, stated exactly and without overclaim: the required fields make
a record *unwritable as specified* by a party that only observed itself, for
every forgery this document enumerates as closed, and they make the remaining
forgeries **legible** rather than silent. Section [What a self-observing party
can still forge] names each residual and does not round it down. A predicate
whose author reports no residual did not look.

## Use Cases

-   An admission controller gating a deployment on evidence that the mutation
    it is about to accept is the mutation an observer below the agent watched,
    rather than the mutation the agent reported making. The record answers
    "what changed, under whose authority, within what scope" from a vantage the
    agent could not edit.
-   An auditor resolving a dangling reference. [TRACE] defines the relation
    `behavior-trace` as "A behavioural record of what the agent did, of which
    this record is the environment evidence", and then rules that "A
    `references` entry is a pointer, not evidence ... a verifier MUST NOT treat
    a resolved reference as attested evidence." An Observed Effect statement is
    an artifact that relation can point at whose content a verifier is permitted
    to read as evidence, because the evidence travels inside the signature
    rather than behind the pointer.
-   A verifier holding a decision record and asking whether the authorised
    action occurred. The layering argued through in-toto/attestation#554
    separates the decision from the effect, and the observed-effect layer of
    that layering is the one nobody registered. This predicate is that layer.
-   A reviewer comparing two vantages on one interval. Where a fact is
    observable from both sides, the record carries both numbers and a
    three-valued agreement, so a producer that lies about a fact its own
    reported side also carries is caught by arithmetic rather than by trust.

Existing predicates cover adjacent ground and answer different questions.
[Runtime Traces] carries observed activity from a monitor with no interval, no
scope statement and no authority binding. [SCAI] carries evidence-backed
attribute assertions. [VSA] and [SVR] carry verdicts computed downstream of
evidence like this. The sibling [AEE] predicate in this repository carries what
an adversarial corpus did to an artifact under containment; it models attacks
and coverage over a corpus, and it does not model a mutation interval. This
predicate makes no cross-predicate claim: composing it with a decision record
does not yield end-to-end coverage, and a consumer MUST NOT infer a composite
guarantee unless its policy binds both statements to the same interval
identifier and the same authority digest.

## Prerequisites

The in-toto Attestation Framework, [DSSE], and [RFC 8785] canonical JSON, which
every digest binding below is defined over. Producers MUST enforce the [RFC
7493] I-JSON safe-integer profile on canonicalized content: an integer of
magnitude at or above 2^53 MUST be rejected, so every rail derives identical
bytes. **A verifier MUST apply the same bound on the way in, at any depth of the
statement**, and the two halves of that rule are not interchangeable: a producer
that refuses to emit such an integer does nothing about a statement some other
producer emitted, and a hostile rail is exactly the one that does not call the
reference encoder. While the bound was enforced only on emission, a byte range
ending at 9007199254740993 was accepted, and a rail that reads it into a double
reads 9007199254740992 out of bytes whose signature verifies.

The whole statement is parsed as strict I-JSON. A duplicate member anywhere, at
any depth, makes the statement malformed, and a verifier MUST reject it
fail-closed rather than silently keep the last occurrence, because a lenient
parser lets two rails disagree on identical bytes.

## Model

The producer is an **observer**: a functionary that watches a state tree from a
layer the observed party does not control, and that can name the tree root
before and after an interval without asking the observed party what happened.
A host-side view of a guest's filesystem, a hypervisor-level view of a snapshot,
and a kernel-level view enforced below the process being watched are all such
layers. An in-process SDK, a wrapper the observed party links, and an importer
holding somebody else's log are not.

The subject is the interval's after-state, by digest, and that is a **binding
rather than a description**. `subject` MUST carry exactly one member, whose
`digest` MUST carry exactly one entry, keyed by the algorithm `hashAlgorithm`
names, whose value MUST equal `interval.afterRoot`. A verifier MUST refuse a
statement that fails any part of it.

The rule is first among equals, because a consumer decides about the subject and
every other rule in this document is about the predicate. While nothing bound the
two, a record could carry a wholly honest interval, pass every gate below, and
name as its subject the digest of an artifact the interval never produced: the
evidence described one thing and the admission decision was taken about another.
A predicate whose subject floats free has no reachable consumer, and the first use
case in this document is the one it fails.

`predicateType` MUST equal this predicate's own Type URI above, and a verifier
MUST refuse a statement carrying any other value or none. A consumer routes by
that member, so a statement typed as another predicate is a statement asking for
these field names to be read under another document's rules.

The predicate carries the
interval, the scope, the authority, the per-read and per-write bindings, and the
observation's own vantage and coverage.

Verdicts are out of scope. They belong downstream, computed over this evidence.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "<interval-name>", "digest": { "sha256": "<afterRoot, 64-hex>" } }
  ],
  "predicateType": "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect",
  "predicate": {
    "intervalId": "<producer-scoped, stable, opaque>",
    "tier": "authoritative",
    "mutation": "observed",
    "hashAlgorithm": "sha256",
    "interval": {
      "beforeRoot": "<64-hex tree root before>",
      "afterRoot": "<64-hex tree root after>",
      "baseResolution": "supplied",
      "openedAt": "2026-09-19T00:00:00Z",
      "sealedAt": "2026-09-19T00:00:04Z"
    },
    "pathScope": ["/srv/app/"],
    "authorityDigest": "<64-hex JCS digest of the authority document>",
    "observation": {
      "vantage": "below-observed",
      "origin": "first-hand",
      "coverage": {
        "scopeComplete": true,
        "gaps": []
      },
      "observedSigners": ["<hex keyid the observed party signs with>"],
      "priorCommitment": {
        "committedAt": "2026-09-18T23:59:58Z",
        "witnessNonce": "<64-hex chosen by the observer>",
        "commitmentDigest": "<64-hex over authorityDigest, beforeRoot, intervalId, witnessNonce>",
        "keyid": "<hex, observer's key>",
        "sig": "<base64 over the JCS commitment bytes>",
        "externalAnchor": {
          "kind": "rfc3161",
          "digest": "<64-hex of the token>"
        }
      }
    },
    "reads": [
      {
        "path": "/srv/app/config.yaml",
        "preStateDigest": "<64-hex tree root the read was taken against>",
        "blobDigest": "<64-hex of the whole blob>",
        "byteRange": { "start": 0, "end": 512 },
        "rangeDigest": "<64-hex, see Fields>",
        "readState": "bytes-read"
      }
    ],
    "writes": [
      {
        "path": "/srv/app/main.py",
        "preStateDigest": "<64-hex>",
        "postStateDigest": "<64-hex>",
        "inScope": true
      }
    ],
    "dualValues": [
      {
        "fact": "writes.count",
        "observedValue": "3",
        "reportedValue": "3",
        "agreement": "agree"
      }
    ],
    "doesNotAssert": ["<explicit negative-scope statements>"],
    "issuedAt": "2026-09-19T00:00:05Z"
  }
}
```

## Parsing Rules

The predicate opts in to the framework's standard parsing rules including the
monotonic principle, with three deliberate strengthenings.

**`tier` is not an independent claim.** A verifier MUST recompute it from the
rest of the predicate by the rule under [`tier`], and a `tier` the recompute
does not reproduce makes the statement invalid. The recompute is a function of
the carried predicate alone: it reads no signature, no consumer trust anchor,
and nothing outside the statement. A tier that varied with the consumer's keys
would not be recomputable.

**`mutation` binds the carried evidence to the claim.** The recompute over
`writes` MUST reproduce `afterRoot`, and a statement whose own carried rows
contradict its own claim is malformed rather than merely weak. This is the
rule the self-refutation vector in `vectors-observed-effect/` exists to hold: a
verifier that reads the claim and not the evidence accepts a record that refutes
itself, and this predicate makes that acceptance a conformance failure.

**Every required member is fail-closed.** A missing or unknown value in a closed
vocabulary makes the statement malformed. No member has a default, and no
verifier may supply one, because a verifier-invented default is a rule the
statement did not carry.

A verifier proceeds in two stages, and the sequencing is informative while the
gates themselves are normative. Stage one is byte-pure and every step is a
consumption precondition: statement well-formedness including the closed
vocabularies, the I-JSON integer bound, the timestamp grammar, the predicate
type, the subject binding and the path forms; the `mutation` coherence recompute;
the `tier` recompute; the read- and write-binding integrity rules; and the
self-recompute of any `dualValues` fact the statement determines. Stage two is
trust-relative: the envelope signature, then the prior-commitment signature
against consumer key policy, then the disjointness and ordering checks under
[`observation`], then the rest of consumer policy.

**Every timestamp in the statement is RFC 3339 UTC with the `Z` designator and no
fractional second**, and a verifier MUST refuse any other spelling. The rule
exists because the ordering gates compare timestamps, a lexical comparison is a
comparison of instants for exactly one grammar, and two records defeated it while
any RFC 3339 spelling was admitted. `2026-09-18T20:00:00-05:00` is
`2026-09-19T01:00:00Z`, an hour after an interval that opened at
`2026-09-19T00:00:00Z`, and it sorts before it as a string. And
`2026-09-19T00:00:00.000Z` sorts strictly before `2026-09-19T00:00:00Z`, because
`.` precedes `Z`, so an identical instant reads as earlier than itself. A verifier
MAY parse both sides into instants and compare those instead, which is the same
rule by another route; what it MUST NOT do is compare two spellings lexically.

## Fields

`intervalId` _string, required_

A producer-scoped stable identifier for the interval. It is not a security
boundary and a verifier MUST NOT treat it as one; it exists so that two
statements about adjacent intervals from one observer can be ordered, which is
what makes the splicing attack under [Attacks] detectable by a consumer holding
more than one record.

`tier` _string, required_

One of `voluntary`, `authoritative`, lowercase, closed. The tier is a property
the observer sets and a verifier reads. **A caller MUST NOT select the tier**,
and a producer that accepts a caller-supplied tier value MUST drop it before
signing. This rule and its wording are adopted from [ASQAV] Section 8.1, which
states it for its own two tiers.

The normative prohibition that gives `voluntary` its meaning is adopted verbatim
from that section: **a verifier MUST NOT read a voluntary attestation as
evidence that the attested content corresponds to any independently observed
fact.**

The recompute: `tier` is `authoritative` if and only if all of the following
hold, and is `voluntary` otherwise.

1.  `observation.vantage` is `below-observed`.
2.  `pathScope` is non-empty.
3.  `coverage.scopeComplete` is `true`, or every member of `coverage.gaps`
    names a path outside `pathScope`.

There are three clauses and five were drafted. Both removals were forced by the
mutation sweep in `vectors-observed-effect/mutation_check.py`, which disables one
rule at a time and requires some member to stop being refused, and both removed
clauses were **unreachable**.

A clause requiring `mutation` to agree with the write set went first: any record
whose mutation claim disagrees with its write set is already malformed under
[`mutation`], which is stage one and runs first. A clause requiring
`observation.priorCommitment` to be present and complete went the same way, once
the commitment became REQUIRED wherever `vantage` is `below-observed`: a record at
any other vantage fails clause 1 before reaching it, so no input can fail a
commitment clause here rather than earlier.

A clause no input can reach is a sentence rather than a gate, and it is worse than
absent — while the mutation clause stood, it made the coherence rule appear
measured when no vector reached that rule at all. The removals are recorded here
rather than silently dropped because the reasoning is the useful part: a tier
recompute may only carry clauses that some input can fail there and nowhere
earlier.

Clause 3 is **safe only in company**. Read alone it is satisfied vacuously by an
empty `coverage.gaps`, so an observation declaring `scopeComplete: false` and
naming no gap passes it and grades authoritative. What refuses that record is the
rule under [`observation`] making an unnamed gap malformed in stage one, and an
implementation that omits that rule while implementing this clause reintroduces
the forgery. The clause is left as written rather than strengthened here for the
reachability reason above: with the stage-one rule in place, no input reaches this
clause vacuously.

Separately, and deliberately not as a fourth clause, **a `tier: authoritative`
statement MUST carry at least one `reads` member or one `writes` member.** It is a
gate rather than a clause so that its refusal names itself: the clauses above
decide what independence means, and this one asks whether the record observed
anything at all.

A statement carrying `tier: authoritative` that fails any clause is invalid, not
downgraded. Downgrading would let a producer emit an authoritative-shaped record
and rely on the verifier to relabel it, which is the same substitution [ASQAV]
Section 8.2 forbids for an advisory digest.

`mutation` _string, required_

One of `observed`, `none`, lowercase, closed. `none` asserts that the observer
watched the interval and saw no mutation within `pathScope`; it is a positive
claim about an interval, never the absence of a record. A `mutation: none`
statement MUST carry `beforeRoot` equal to `afterRoot` and an empty `writes`,
and a `mutation: observed` statement MUST carry a non-empty `writes` whose
recompute reproduces `afterRoot`. Any other combination is malformed.

The member exists because an interval in which nothing happened is evidence,
and because omitting it lets a vacuous record pass as a covering one. The
read-only session is the worked case: a verification pass that provably changed
nothing is among the strongest things an observer can attest, and it has no
artifact to point at.

`hashAlgorithm` _string, required_

The algorithm every root, blob and range digest in the statement is expressed
in. One of `sha256`, `sha1`, lowercase, closed. It is required rather than
inferred from digest length, because the terminal case of base resolution is a
constant whose value depends on it, and a reader that guesses picks the wrong
constant silently.

`interval` _object, required_

`beforeRoot` and `afterRoot` are lowercase hex state-tree roots in
`hashAlgorithm`. Both are **unconditionally required**: there is no shape of
this predicate in which the before-state is absent, because an interval with one
end is not an interval.

`baseResolution` names how `beforeRoot` was obtained. One of `supplied`,
`recorded-parent`, `empty-tree`, lowercase, closed, resolved in exactly that
order. The rule, and the refusal at the end of it, is adopted from [ASQAV]
Section 8.2:

1.  `supplied` — a base identifier supplied with the observation request, where
    it is a full lowercase hexadecimal object name of the width
    `hashAlgorithm` implies.
2.  `recorded-parent` — otherwise the base the state host records for the change,
    which is stable across merge and squash rewrites where the underlying store
    has that notion.
3.  `empty-tree` — otherwise, where the interval opens on a parentless state,
    the empty tree object name.

**Where none of the three yields a base, the observer MUST refuse to emit rather
than infer one.** [ASQAV] Section 8.2 states the reason for the refusal in the
git case: commit parents "are ambiguous for merge and squash commits". The
refusal generalises, and this predicate carries it as a hard rule rather than a
recommendation, so that `beforeRoot` is never a guess wearing a digest's shape.

The empty-tree constant is **named per algorithm, and both are given, because a
specification that says "the git empty tree constant" without naming the hash
function carries a latent wrong-constant bug**:

-   `sha1`: `4b825dc642cb6eb9a060e54bf8d69288fbee4904`
-   `sha256`: `6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321`

Both are the digest of the bytes `tree 0\0` under their algorithm and neither is
a value to be typed from memory. A verifier reading `baseResolution:
empty-tree` MUST require `beforeRoot` to equal the constant for the declared
`hashAlgorithm`, and MUST reject a statement that carries the other one. That
check is what turns the constant into a gate instead of a comment. [ASQAV]
Section 8.2 names the `sha1` constant alone, which is coherent there because its
base is a 40-character git object name; a predicate whose roots are `sha256` and
that reused that constant would be naming a root no `sha256` store can hold.

**The empty tree holds no bytes, and a verifier MUST refuse a statement that reads
some.** Where `interval.beforeRoot` equals the constant for the declared
algorithm, no `reads` member may carry `readState: bytes-read` together with a
`preStateDigest` equal to that root. A `no-bytes-read` row at that root stays
permitted, because an attempted read that returns nothing is exactly what an empty
tree yields. The rule matters more than its size suggests: "there was nothing
before" is the one claim about the past that no later state contradicts, which
makes it the claim most worth dressing a populated tree in. An accept member of
`vectors-observed-effect/` carried this shape, 64 bytes read at an empty-tree root,
and while it did a conforming verifier was REQUIRED to accept it.

`openedAt` and `sealedAt` are [RFC 3339] timestamps in UTC with the `Z`
designator. `openedAt` MUST be strictly before `sealedAt`.

`pathScope` _array of string, required_

The paths the observation covered, as **literal absolute path prefixes**. A
member MUST NOT contain a wildcard or any glob metacharacter. A universal scope
is spelled as the single literal `"/"`, which is exactly as broad as a glob that
matches everything and, unlike the glob, says so where a policy can read it.

Every path in the statement — each `pathScope` member and the `path` of every
`reads` and `writes` member — MUST be absolute and normalized: no empty segment,
no `.` segment, no `..` segment. A trailing `/` is permitted on a `pathScope`
member and not on a row's `path`. And **"lies under" is containment at a segment
boundary, never a string prefix**: `path` lies under `scope` when it equals
`scope` with any trailing slash removed, or begins with `scope` made to end in a
slash.

Both halves are load-bearing and each closed a live forgery, neither of which
needed a single digest to be wrong. Without normalization,
`/srv/app/../../../etc/shadow` begins with `/srv/app/`, so a write to
`/etc/shadow` travelled as `inScope: true` under a scope of `/srv/app/` inside an
authoritative record. Without the boundary,
`/srv/application-secrets/id_ed25519` begins with `/srv/app`, so a policy
comparing `pathScope` against its own expectation read `/srv/app` and admitted a
write to a different directory.

`pathScope` is the machine-checkable statement an observed write set is tested
against: every `writes` member whose `path` does not lie under some member of
`pathScope` MUST carry `inScope: false`, and a `tier: authoritative` statement
carrying such a member is invalid. A write the observer saw and the scope does
not cover is a coverage admission, and it travels rather than being dropped.

`authorityDigest` _string, required_

The [RFC 8785] digest of the authority document under which mutation was
permitted: a delegation certificate, a policy bundle, a scoped grant. Required
unconditionally. A mutation interval with no named authority is an interval
nobody authorised, and this predicate refuses to represent one as a normal case:
where mutation genuinely occurred under no authority, the authority document is
the explicit deny-all document and its digest is carried, so the absence is a
signed claim rather than a missing member.

The predicate binds the authority by digest and does not carry it. A consumer
that needs the scope globs inside the authority resolves it out of band and
compares. That is the same separation [SCAI] draws for `evidence`.

`observation` _object, required_

`origin` is one of `self`, `first-hand`, `third-party-control-plane`,
`log-import`, lowercase, closed, required, with no default and no absence
reading. It says how the evidence in this record ARRIVED, which is a different
question from where the producer stood: `self` is the party that executed
reporting on itself, `first-hand` is a producer that made the observation
itself and is not that party, and the other two are assemblers holding output
somebody else produced. The values and the enum are the sibling
[agent-evidence-vocabulary] registry's `origin_kind`, three of them borrowed
there from [TRACE] Section 3.1.1 and `first-hand` added there for exactly this
record shape.

**A statement MUST NOT carry `vantage: below-observed` unless `origin` is
`first-hand`, and a verifier MUST reject one that does.** A party attesting its
own execution is not below itself, and an assembler holding somebody else's log
was not there at all.

The member exists because the predicate had no slot in which an importer could
be made to confess. A record assembled from another vendor's exported log could
be emitted as a first-hand observation made below the party it described, and
nothing in the statement was false: the lie was a claim the format could not
contradict. That is a different failure from a forged value, and the only fix
for it is a member whose absence is malformed.

`vantage` is one of `below-observed`, `peer`, `self`, lowercase, closed.

-   `below-observed` — the observation was made from a layer the observed party
    cannot address. It is the only value that supports `tier: authoritative`.
-   `peer` — the observation was made at the same layer as the observed party,
    for example a proxy the observed party routes through and could route
    around.
-   `self` — the observation was made by the observed party, or by code inside
    its process.

`coverage.scopeComplete` is a boolean asserting that the observation covered
every path under `pathScope` for the whole interval. `coverage.gaps` is an array
of literal path prefixes the observation did not cover. `scopeComplete: true`
with a non-empty `gaps` naming a path inside `pathScope` is malformed: the two
members contradict, and a verifier MUST NOT prefer either.

**`scopeComplete: false` with an empty `gaps` is malformed as well**, and that is
the direction which was open. An incomplete observation MUST say where it was
blind. Otherwise a producer admits in one member that it did not cover its own
scope, declines in the next to say which part, and still grades authoritative
through clause 3 of the `tier` recompute, which an empty list satisfies vacuously.
The unnamed gap is where the writes went, and an admission of incompleteness that
withholds its location is worth less than no admission at all, because it reads as
candour.

`observedSigners` is the set of key identifiers the observed party signs its own
records with, as the observer knows them. It is required and MAY be empty, and
an empty set is a claim that the observer knows of no such key.

`priorCommitment` is the member that carries the vantage claim, and it is
required when `vantage` is `below-observed`. It is the observer's commitment,
made **before the interval opened**, to the before-state and to a nonce the
observer chose:

-   `committedAt` — [RFC 3339] UTC, and MUST be strictly before
    `interval.openedAt`. A commitment made after the interval opened commits to
    nothing the observer could not have learned from the observed party.
-   `witnessNonce` — 64 lowercase hex chosen by the observer. It exists so that
    the commitment is not a function of the before-state alone: a party holding
    only the before-state cannot reproduce the commitment digest without also
    holding the nonce.
-   `commitmentDigest` — the digest over the [RFC 8785] canonical bytes of
    `{"authorityDigest": <authorityDigest>, "beforeRoot": <beforeRoot>,
    "intervalId": <intervalId>, "witnessNonce": <witnessNonce>}`. A verifier
    recomputes it from the carried members; a mismatch is malformed.

    All four members are inside the preimage, and each closes a specific attack
    the first draft left open. `beforeRoot` and `witnessNonce` alone were not
    enough. `authorityDigest` is in there because the predicate binds the
    authority by digest and does not carry the document, so without a prior
    commitment to it an observer could select a permissive authority **after**
    seeing what the interval did. `intervalId` is in there because two intervals
    can share a before-root, and a commitment over the root alone is replayable
    across them. Both values are members the observer already holds before the
    interval opens, so binding them costs nothing and removes two forgeries that
    needed no second key.
-   `keyid` and `sig` — the observer's signature over those canonical bytes.
    **A verifier MUST verify `sig`**, against the observer key it anchored out of
    band, over the [RFC 8785] canonical bytes of the commitment preimage. While
    that gate was named in [Parsing Rules] and implemented nowhere, sixty-four
    zero bytes in `sig` produced an authoritative record, so the member carrying
    the whole vantage claim carried it unsigned.

    Verifying it also narrows attack A1, which no anchor requirement could
    narrow. A self-observing producer still needs a second key, and that key must
    now be one the **consumer has anchored as the observer's**, rather than any
    key the producer generates and never declares. What remains open is stated in
    A1 and is not rounded down.

-   Every key identifier in this predicate, `keyid` and every `observedSigners`
    member alike, MUST be non-empty lowercase hexadecimal. One spelling per key is
    a requirement of the discriminator rather than a matter of style: the check
    below is a string comparison, and while two spellings were admitted a record
    could name the committing key itself in `observedSigners` in uppercase and
    carry it lowercased in `keyid`. The record then SAID the committing key
    belonged to the observed party, and the discriminator passed, with no second
    key anywhere.

-   The `keyid` MUST NOT appear in `observedSigners`. That check is the offline
    discriminator, and its exact strength is stated below rather than implied.
-   `externalAnchor` _optional_ — `kind` one of `rfc3161`, `transparency-log`,
    `opentimestamps`, and `digest` the digest of the token. Where present, a
    verifier MAY check the token's own timestamp against `committedAt`.

`reads` _array, required, MAY be empty_

Each member binds one claimed read to four things, and the arrangement is the
point:

-   `path` — literal absolute path.
-   `preStateDigest` — the tree root the read was taken against. MUST equal
    `interval.beforeRoot` for a read taken before any write in this interval,
    and otherwise MUST equal the `postStateDigest` of the write it follows.
-   `blobDigest` — digest over the whole blob.
-   `byteRange` — `{start, end}`, a half-open interval, `end` strictly greater
    than `start`, both non-negative safe integers.
-   `rangeDigest` — the digest over the concatenation
    `blobLength || start || end || blob[start:end]`, each integer encoded as its
    decimal ASCII representation followed by a single `\0`. The length and the
    offsets are inside the preimage on purpose: a digest over the range bytes
    alone is reproducible from any blob containing those bytes anywhere, so it
    binds the bytes and not the read.
-   `readState` — one of `bytes-read`, `no-bytes-read`, `unavailable`,
    lowercase, closed. A read that returned nothing is `no-bytes-read`, which
    carries no `byteRange` and no `rangeDigest`. **A zero-length range is
    malformed**, because the digest of an empty range is a constant that verifies
    against every blob and therefore binds nothing while looking bound.

Three of the four bindings are checkable by a stranger holding the blob and no
substrate at all: the blob's digest, the range digest against the named offsets,
and the leaf's consistency with `preStateDigest` where the store admits a
membership proof. The fourth — that the file at `path` held that blob at the
moment of the read — is not checkable from the statement, and is exactly what
the vantage claim is for.

`writes` _array, required, MAY be empty_

Each member carries `path`, `preStateDigest`, `postStateDigest` and `inScope`.
The ordered composition of `writes` MUST reproduce `afterRoot` from
`beforeRoot`: the first member's `preStateDigest` MUST equal `beforeRoot`, each
subsequent member's `preStateDigest` MUST equal its predecessor's
`postStateDigest`, and the last member's `postStateDigest` MUST equal
`afterRoot`. A break anywhere in that chain makes the statement malformed. This
is the rule that makes a self-refuting record refusable.

`dualValues` _array, required, MAY be empty_

For every fact the observer and the observed party both report, one member
carrying `fact` (a dotted name), `observedValue`, `reportedValue` (both strings,
so an integer is never re-serialized differently by two rails) and `agreement`.

`agreement` is one of `agree`, `disagree`, `one-sided`, lowercase, closed, and
its value MUST be derivable from the two values: `agree` when they are equal
byte-for-byte, `disagree` when both are present and unequal, `one-sided` when
exactly one is the empty string. A declared `agreement` the two values do not
support is malformed. **A row in which both values are the empty string is
malformed**, because a comparison of nothing against nothing is not a comparison.
It was read as `one-sided`, which let a record carry any number of rows that
looked like cross-checks and asserted nothing, for a consumer that counts them.

**For a fact the statement determines about itself, `observedValue` MUST be the
value the statement determines, and a verifier MUST recompute it.** The closed set
of such facts at this version is `writes.count`, `reads.count`,
`pathScope.count`, `interval.beforeRoot`, `interval.afterRoot` and
`authorityDigest`. One consequence is worth stating: `one-sided` is not available
on the observed side of those facts, because an observer that carries the rows
always knows how many it carried.

The rule exists because the member is advertised as the one that catches a lying
producer, and it caught nothing while the observed side was a free string. A
record carrying two `writes` could declare `writes.count` observed as `7`, report
`7`, and grade `agree`: a cross-check contradicted by the same signed bytes that
carry it. A fact the record determines is not a matter of report, and the
discipline the [`mutation`] rule applies to the write chain applies here.

This member is the one field in the predicate that catches a lying producer
without trusting anyone. A vantage claim tells a reader how much to trust one
number and can never produce a contradiction; two numbers and a comparison can.
A `disagree` is not a defect in the record and a verifier MUST NOT reject on it:
it is the record working, and a consumer policy decides what a disagreement
means for admission.

`doesNotAssert` _array of string, required, MAY be empty_

Explicit negative-scope statements. Required so that the absence of a claim is
written down rather than inferred from silence.

`issuedAt` _string, required_

[RFC 3339] UTC, at or after `interval.sealedAt`.

## What a self-observing party can still forge

The design constraint this predicate is written against: the required fields
must make a record unwritable by a party that only observed itself, and a
verifier must tell the two apart offline. Held against that bar, honestly, field
by field.

**Checkable offline and not forgeable by shape alone.** The `mutation`
coherence chain, the range-digest preimage, the empty-tree constant match, the
`agreement` derivation, the commitment-digest recomputation, the ordering of
`committedAt` before `openedAt`, and the disjointness of the commitment `keyid`
from `observedSigners`. Each is a function of the carried bytes; each refuses a
statement that fails it; none needs a network.

**Forgeable, and the predicate says so.** Every root, every blob digest and
every path in the statement is chosen by whoever builds the statement. A party
that controls the tree can build any tree, and a membership proof proves
membership in a root the prover picked. No arrangement of carried bytes
distinguishes an independent observer from a self-observing party that chose the
bytes — **unless at least one input to the record was fixed by someone other
than the observed party before the interval opened, and is bound into the signed
bytes.** That is the whole reason `priorCommitment` exists, and it is the whole
reason this predicate does not claim more.

What the commitment actually buys, exactly: it converts a free forgery into one
that must be **pre-planned**. A self-observing party can hold two keys, sign the
commitment with the second, omit it from `observedSigners`, and satisfy every
clause. It cannot do so *after* learning what the interval contained, because
the commitment binds the before-root and the timestamps are ordered and signed.
So the residual forgery requires the forger to have decided to lie before it
knew what it would be lying about, and to have kept a second key it never
declares. Both are detectable outside the statement — by a key inventory, or by
an `externalAnchor` token the forger had to obtain early — and neither is
detectable inside it.

**Stated as the rule a consumer should apply:** `vantage: below-observed` is an
assertion about the world that the statement makes checkable-for-coherence and
never self-proving. A consumer that needs the vantage to be true anchors the
observer's key out of band, exactly as it would anchor any signer, and reads
`tier: authoritative` as "this record is coherent with the vantage it claims"
rather than as "this vantage is proven".

That sentence is the honest ceiling of any offline evidence format, and writing
it down is what separates this predicate from one that implies otherwise.

## Attacks on this predicate

Constructed against the schema above, each a record that satisfies every
required field as originally drafted and still misrepresents what executed. The
three marked CLOSED are closed by rules now in [Fields]; the three marked OPEN
are reported rather than hidden.

**A1. Tier laundering by key duplication. OPEN.** A self-observing producer
generates two keys, signs the interval with the first, lists only the first in
`observedSigners`, signs `priorCommitment` with the second, declares
`vantage: below-observed`, and passes every clause of the `tier` recompute. The
patch considered and rejected: requiring `externalAnchor` unconditionally. It
does not close the attack, because a self-observer can obtain a timestamp token
as easily as anyone, and making it mandatory would trade a real refusal for the
appearance of one. What the anchor does buy is stated under [What a
self-observing party can still forge] and nowhere overstated. **This attack
works and the predicate documents it.**

**A2. Vacuous authoritative record. CLOSED, and it took two goes.** Empty
`pathScope`, `beforeRoot` equal to `afterRoot`, empty `reads`, empty `writes`,
`tier: authoritative`: a record that asserts nothing and grades as the strongest
tier. The first closure was clause 2 of the `tier` recompute requiring a non-empty
`pathScope`, plus `mutation` being required, which forces the no-mutation case to
be a positive claim rather than an empty shape. **That closed one spelling.** The
same record with `pathScope: ["/"]` and `baseResolution: empty-tree` at both ends
satisfies every clause: the scope is non-empty, the mutation claim is positive, and
the record says the entire filesystem was empty and nothing happened anywhere, at
the strongest tier. Closed now by the rule that an authoritative statement carries
at least one `reads` or one `writes` member. The lesson is the part worth keeping:
a closure aimed at one spelling of an empty claim is not a closure of the empty
claim, and the corpus member that proved it is
`vacuous-authoritative-universal-scope`.

**A3. Range-digest laundering. CLOSED.** A read claiming `byteRange: {0, 0}`
with `rangeDigest` the digest of the empty string, against a `blobDigest` the
producer never read. The three-of-four offline check passes trivially, because
an empty range hashes to a constant under every blob. Closed twice over: a
zero-length range is malformed, and the range preimage now carries the blob
length and both offsets, so the digest is bound to a position in a blob of a
known size rather than to a bag of bytes.

**A4. Scope widening. CLOSED as legibility, OPEN as truth.** `pathScope:
["**"]` makes every write in-scope and the scope check never refuses. Closed as
a legibility matter: glob metacharacters are now forbidden and a universal scope
must be spelled `"/"`, which a policy can read and refuse. Not closed as a
truth matter, because an observer may declare a wide scope honestly, and no
function of the statement separates a broad honest scope from a broad
self-serving one. The consumer-side rule is therefore to compare `pathScope`
against its own expectation rather than to accept whatever arrives.

**A5. Interval splicing. CLOSED against a multi-record consumer, OPEN against a
single-record one.** Take `beforeRoot` from one interval and `afterRoot` from a
later one, and emit a record whose interval spans work the observer never
watched continuously. Every field verifies, and the write chain can be made to
reproduce the spliced `afterRoot` by carrying the intervening writes. A consumer
holding the observer's adjacent records detects the splice by `intervalId`
ordering; a consumer holding one record cannot, and no field inside a single
statement closes it. Reported as a bound on what one statement can mean.

**A7. Read-set omission. OPEN, and it is the likeliest real misuse.** An
observer that watched a read of a sensitive path simply omits the row. `reads`
is required and may be empty, `doesNotAssert` is required and the producer
chooses its contents, and no function of the carried bytes detects a row that
was never written. This is the same class as the sibling [AEE] predicate's
statement that a producer claiming LESS is not detectable from the statement,
and the reasoning there holds here unchanged: a statement that withdraws a
claim is a statement an honest observer with weaker instruments emits from the
same configuration, so no rule refuses the one without refusing the other, and
no quantity of additional carried material changes it, because additional
material is material a withholding producer also declines to carry. What the
predicate can do, and does, is make the withholding visible where the observer
is honest about it: `coverage.gaps` and `doesNotAssert` exist so that a known
blind spot travels. Neither is a defence against a producer that lies about
having one. **This attack works and there is no version of this predicate in
which it does not.**

**A8. Authority substitution. CLOSED by the commitment patch.** The predicate
binds the authority by digest and does not carry the document, so a first draft
in which the prior commitment covered only the before-root let an observer pick
a permissive `authorityDigest` after the interval closed and still satisfy every
clause. Closed by putting `authorityDigest` inside the commitment preimage: the
authority is now fixed before the interval opens, under the observer's
signature, and a verifier recomputes the binding from members it already holds.

**A9. Commitment replay across intervals. CLOSED by the same patch.** Two
intervals can legitimately share a before-root — a second interval opening on a
tree a first one left unchanged is the ordinary case for a read-only interval
followed by a write. A commitment over the root and a nonce alone is therefore
replayable: one signed commitment serves both records, and the second record
inherits a prior commitment that was never made about it. Closed by putting
`intervalId` inside the preimage.

**A20. Subject decoupling. CLOSED.** A statement whose predicate is entirely
honest and whose `subject` names the digest of an artifact the interval never
produced. Every rule in this document held, because every rule in this document
was about the predicate and nothing read the subject. A consumer decides about the
subject, so the whole document was unreachable from the decision it was written to
inform. Closed by the subject binding under [Model]: one subject, keyed by the
declared algorithm, equal to `afterRoot`.

**A21. Commitment ordering by string comparison. CLOSED.** A `committedAt` of
`2026-09-18T20:00:00-05:00` against an `openedAt` of `2026-09-19T00:00:00Z`. The
commitment was made an hour after the interval opened and sorted before it, so the
gate that makes a commitment PRIOR — the gate A8 and A9 rest on — passed on a
commitment that was not. A fractional second does the same with no offset at all,
since `2026-09-19T00:00:00.000Z` sorts before `2026-09-19T00:00:00Z`. Closed by
fixing the timestamp grammar so that a lexical comparison is a comparison of
instants.

**A22. Scope escape by traversal. CLOSED.** `pathScope: ["/srv/app/"]` and a write
to `/srv/app/../../../etc/shadow`, labelled `inScope: true`, inside an
authoritative record. The path begins with the scope, so prefix containment did
the work and no digest had to be wrong. Closed by requiring normalized paths.

**A23. Scope confusion at a non-boundary. CLOSED.** `pathScope: ["/srv/app"]` and
a write to `/srv/application-secrets/id_ed25519`. A policy comparing `pathScope`
against its own expectation reads `/srv/app` and admits a write to a different
directory. Closed by defining containment at a segment boundary.

**A24. Bytes read out of the empty tree. CLOSED.** `baseResolution: empty-tree`,
`beforeRoot` the constant, and a `reads` row with `readState: bytes-read` taken at
that root: the record claims there was nothing before and reads 64 bytes from the
nothing. It was not merely accepted; an ACCEPT member of the conformance corpus
carried it, so a conforming verifier was required to accept it. Closed by the rule
that the empty tree holds no bytes, and the corpus member was repaired to take its
read after the write that creates the file.

**A25. Coverage incomplete and blind spot unnamed. CLOSED.**
`coverage.scopeComplete: false` with `coverage.gaps: []`, `tier: authoritative`.
Clause 3 of the recompute asks whether every member of `gaps` lies outside
`pathScope`, and an empty list satisfies that vacuously, so a producer could admit
it had not covered its scope, decline to say where, and still grade authoritative.
Closed by making an unnamed gap malformed in stage one.

**A26. The discriminator defeated by case. CLOSED.** `observedSigners` naming the
committing key in uppercase while `keyid` carries it lowercased. The record SAYS
the key that made the prior commitment is a key the observed party signs with, and
the disjointness check passed, because it is a string comparison and two spellings
of one key are two strings. No second key was needed, which makes this cheaper
than A1 and it was open at the same time. Closed by one lowercase hexadecimal
spelling per key identifier.

**A27. The unsigned prior commitment. CLOSED.** Sixty-four zero bytes in
`priorCommitment.sig`. The commitment is the only member that fixes an input to
the record before the interval opened, [Parsing Rules] names its signature as a
stage-two gate, and no implementation verified it, so the entire authoritative
tier rested on a signature nobody checked. Closed by verifying it against the
anchored observer key, which also narrows A1 as recorded there.

**A28. Dual-value fabrication. CLOSED.** A record carrying two `writes` that
declares `writes.count` observed as `7`, reported as `7`, and `agree`. The member
this predicate advertises as the one that catches a lying producer without
trusting anyone was, on its observed side, a free string, so it could carry a
number the same signed bytes refute. Closed by recomputing every fact the
statement determines about itself. The variant with both values empty and
`agreement: one-sided` is closed in the same place: a comparison of nothing
against nothing is not a comparison, and a consumer that counts dual values as
corroboration counted it.

**A29. Predicate type confusion. CLOSED.** An observed-effect body carrying
another predicate's `predicateType`, or none. A consumer routes by that member, so
the record asks for these field names to be read under another document's rules,
and nothing refused it. Closed by requiring the type URI.

**A30. The I-JSON bound enforced in one direction. CLOSED.** A `byteRange` ending
at 9007199254740993. The reference encoder refuses to produce it, which is the
producer half working, and a hostile rail does not call the reference encoder. A
verifier that consumes it hands one number to a rail with 64-bit integers and
another to a rail with doubles, from bytes whose signature verifies. Closed by
applying the bound on consumption at any depth.

**A31. The importer with no member to confess in. CLOSED.** A record assembled
from another vendor's exported log, or from a control plane the producer does not
operate, and emitted as a first-hand `vantage: below-observed` observation. No
value in it was false, because there was no member in which an importer had to
say that it imported: the lie was a claim the format had no slot to contradict,
which is a different failure from a forged value and is not fixable by any rule
over the members that existed. Closed by the required `origin` member and the
rule binding `below-observed` to `first-hand`.

Closing it moved the sibling [agent-evidence-vocabulary] registry too, and that
is worth recording because the two artifacts were incompatible at the seam. That
registry's `origin_kind` borrowed a three-value enum from [TRACE] Section 3.1.1,
which is written from the perspective of a record about its own execution, so it
had no value for a producer that observed somebody else's execution and the only
spelling available for this predicate's own records was `self`. A required field
with no true value is a field that gets filled with a false one. `first-hand` is
registered there now, with the same binding rule, and the departure is recorded
in that repository's TRACE crosswalk.

**A6. The self-refuting record. CLOSED, and it is the vector shape this
repository lacked.** A record declares `mutation: none` with `beforeRoot` equal
to `afterRoot`, and carries a `writes` member whose `postStateDigest` differs
from both. Its own carried evidence refutes its own claim, and a verifier that
reads the claim without recomputing over the evidence accepts it. Closed by the
`mutation` coherence rule: the write chain MUST reproduce `afterRoot`, and a
`mutation: none` record with a non-empty `writes` is malformed. The
corresponding accept and reject twins are in `vectors-observed-effect/`, which
is the first corpus in this repository to carry that shape.

## Example

See `vectors-observed-effect/statements/`. Every member of that corpus is a
complete statement under this predicate, and `MANIFEST.json` carries what a
verifier is supposed to decide about each one, never the file itself, so a
member cannot be scored without being read.

## Consumer policy obligations

A consumer implementing this predicate MUST, at minimum:

1.  Anchor the observer's key out of band and never from the statement.
2.  Run every stage-one gate before reading any field for meaning.
3.  Treat `tier: authoritative` as coherence with a claimed vantage, not as
    proof of it.
4.  Compare `pathScope` against its own expectation rather than accepting the
    declared scope.
5.  Decide explicitly what a `disagree` in `dualValues` means for admission, and
    never treat its presence as a reason to reject the record.
6.  Refuse to read a `voluntary` record as evidence of any independently
    observed fact, per the prohibition under [`tier`].

## Changelog and Migrations

0.2.0 adds thirteen rules and one required member, and removes one `tier`
clause. Every addition refuses a
record 0.1.0 accepted, which is a conformance break rather than an addition, and
the version moves for that reason. The rules are the subject binding, the
predicate type, the I-JSON bound on consumption, the timestamp grammar, path
normalization, boundary containment, the empty tree holding no bytes, the named
gap, the required prior commitment at `below-observed`, one lowercase spelling per
key identifier, the verified commitment signature, the dual-value self-recompute,
the rows requirement on an authoritative record, and the `origin` member with
the rule binding `below-observed` to `first-hand`. A 0.1.0 producer that emitted honest records emits valid 0.2.0 records with one
addition and two spellings to fix: every record now carries `origin`, and a
producer that spelled a key identifier in uppercase, or a timestamp with an
offset, has to spell it the one way. Attacks A20 through A30 in the section
above are the records that forced each one, and each is a pinned member of
`vectors-observed-effect/`.

0.1.0 is the first published version. A member is born when a normative reader
consumes it: a future version that makes a currently unchecked property
checkable acquires a normative reader at that version, and the member becomes
required then, not retroactively and not through a verifier-invented heuristic
in the meantime.

Two members are named now as candidates for that treatment, so that the
commitment is on the record rather than invented later. `externalAnchor` becomes
required at the version that defines an offline token-validation rule. A
`continuity` member committing the observer's ordered interval list becomes
required at the version that defines its recompute, which is what would close
A5 for a single-record consumer.

[AEE]: adversarial-execution-evidence.md
[agent-evidence-vocabulary]: https://github.com/probityai/agent-evidence-vocabulary
[ASQAV]: https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/08/
[DSSE]: https://github.com/secure-systems-lab/dsse
[RFC 3339]: https://www.rfc-editor.org/rfc/rfc3339
[RFC 7493]: https://www.rfc-editor.org/rfc/rfc7493
[RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
[Runtime Traces]: https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md
[SCAI]: https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md
[SVR]: https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md
[TRACE]: https://github.com/agentrust-io/trace-spec/blob/main/spec/trace-v0.2.md
[VSA]: https://github.com/in-toto/attestation/blob/main/spec/predicates/vsa.md
