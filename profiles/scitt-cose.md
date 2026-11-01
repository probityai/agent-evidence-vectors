---
register: edelman
---

# Carrying adversarial execution evidence as a SCITT Signed Statement

Profile identifier: `aee-scitt-cose/v0.1`. Conformance vectors: `vectors-scitt-cose/`.

RFC 9943 Section 6 states the requirement this profile answers: "Signed Statements
produced by Issuers must be COSE_Sign1 messages, as defined by [STD96]. Profiles and
implementation-specific choices should be used to determine admissibility of
conforming messages. This specification is left intentionally open to allow
implementations to make Registration restrictions that make the most sense for their
operational use cases."

That openness leaves 14 questions unsettled for execution evidence, and 2
implementations can answer all 14 differently while both conform to RFC 9943. Section 6
of the same document lists in-toto supply chain description metadata among the payload
formats an Issuer may choose, and stops there.

This profile fixes the protected header, the subject
binding, the leaf definition and the consumer obligations for one payload type, an in-toto
Statement whose predicate type is the adversarial execution evidence predicate.

The corpus in `vectors-scitt-cose/` carries 27 members, 6 accept, 17 reject and 4
indeterminate, and each one cites the section below that decides it. Every requirement below therefore has a
vector, meaning a frozen input plus the verdict a conforming verifier owes it, and a reader
who disagrees with a requirement can run its vector against their own implementation and
read off which of the two of them is wrong.

## 1. What an adversarial execution evidence statement is, before any of this

An adversarial execution evidence statement records what an observer saw an agent do,
and where the observer stood. The predicate and its own conformance corpus live in
`vectors/`. The type URI is the predicate-type field of that corpus manifest. It is not
restated here, because a copy of a version is a cache that nothing invalidates.

An observer position is the field that distinguishes such a statement from a log. It
records where the observation was made: from inside the process it observes, from a host on
the outside of that process, or from a vantage the observed party could not reach at all. A verifier
that drops that field still reads a well-formed record of an execution, and it no longer
has the column a relying party needs in order to decide whether the observation could have
been produced by the party it describes.

## 2. The signed statement

A Signed Statement under this profile is a tagged COSE_Sign1, CBOR tag 18, whose payload
is the in-toto Statement serialized with RFC 8785 canonical JSON.

A producer MAY detach the payload, per RFC 9943 Section 6.2: "Statement payloads might
be too large or too sensitive to be sent to a remote TS. In these cases, a Statement can
be made over the hash of a payload rather than the full payload bytes." Where the wire
form detaches it, the signature still covers the payload in full, because RFC 9052 Section
4.4 field 5 puts "The payload to be signed ... The full payload is used here, independent
of how it is transported" into the Sig_structure that the signer signs. A verifier therefore
needs the payload bytes out of band before it can verify the signature. The header checks
in Section 6 run before that one. They screen the protected header. They settle nothing about the
statement.

### 2.1 The protected header

Seven parameters are REQUIRED and every one of them sits in the protected bucket.

| Label | Name | Value under this profile |
| --- | --- | --- |
| 1 | alg | -19, Ed25519, the fully-specified registration of RFC 9864 Section 4.2.1 |
| 3 | content type | `application/x.aee-scitt-cose-statement+cose` |
| 4 | kid | the issuer key identifier, resolvable by the verifier |
| 15 | CWT_Claims | a map carrying iss (1) and sub (2), per RFC 9597 Section 2 |
| 16 | typ | `aee-scitt-cose/v0.1` |
| -70001 | observer position | the vantage map of Section 3 |
| 2 | crit | the one-element array naming label -70001 |

A producer encodes that map under the Core Deterministic Encoding Requirements of RFC
8949 Section 4.2.1: shortest-form arguments, keys sorted in bytewise lexicographic order
of their own deterministic encodings, and each key occurring exactly once in the map. A verifier MUST refuse any
other encoding. The protected header sits inside the Sig_structure, so two encoders that
serialize one map differently produce two different signatures over one statement.

The algorithm is -19 and not -8 or -7. In RFC 9864 Section 4.2.2 IANA updated both of
those to "Recommended: Deprecated", and a polymorphic identifier additionally makes a
verifier infer the curve from the key, which is precisely the inference the
algorithm-confusion vector exploits.
Every worked example in RFC 9943 and RFC 9942 carries the value -7, so a producer copying
the architecture's own figures emits a deprecated identifier. A verifier under this
profile MUST refuse -8 and -7 by identifier.

The type parameter is present because RFC 9942 Section 4.4 asks for it: "Profiles of
proof signatures that define additional protected header parameters are encouraged to
make their presence mandatory to ensure that claims are processed with their intended
semantics. One way to include this information in the COSE structure is use of the 'typ'
(type) header parameter."

The content type sits in the unregistered tree RFC 6838 Section 3.4 reserves with the
`x.` prefix, because this profile has registered no media type. Section 8 records what
that costs.

### 2.2 Why crit carries the observer position

RFC 9052 Section 3.1 defines the parameter: "crit: This header parameter is used to
indicate which protected header parameters an application that is processing a message
is required to understand." Two sentences later, the same section adds: "When present,
the 'crit' header parameter MUST be placed in the protected-header-parameters bucket.
The array MUST have at least one value in it."

Listing label -70001 there converts an unimplemented field into a refusal. A verifier
that does not implement this profile meets a critical parameter it cannot process and
stops. A verifier that does implement it reads the vantage and applies it. Neither one
silently accepts an execution record while ignoring the column that says who saw it. The
profile calls that behaviour fail-closed.

That behaviour follows from the base standard and needs no extension to anyone's
document. It also inverts the more common profile rule, which tells a verifier to ignore
what it does not recognize.

Label -70001 falls in the Private Use range of the COSE Header Parameters registry, so the
field needs no IANA action of its own and cannot collide with a future registration. A
registered label would change the bytes of every vector in the corpus, which is why Section 8
holds it open rather than this section settling it.

## 3. The observer position

The value is a CBOR map, and this revision fixes three members. A text string named
vantage says where the observation was made from. A second text string, observedFrom,
names the layer. A boolean, reachableByObserved, states whether the observed party could
reach the observing component.

The boolean is the member that carries weight. Set false, it states that the code under
observation had no path to the recorder, which is the condition a relying party checks when
it needs to distinguish an observation from a self-report. This profile does not define the vocabulary of the vantage string; that
belongs to the predicate and to the corpus that tests it.

## 4. Subject and issuer binding

RFC 9943 Section 6 says of the two claims: "The iss and sub Claims, within the CWT Claims
protected header, are used to identify the Artifact the Statement pertains to."

RFC 9943 nowhere says how an Issuer derives that value, and two conforming producers that
name one artifact differently leave a relying party with no way to tell a real mismatch
from a difference of naming convention. This
profile binds the subject claim to the subject's own digest:

```
sub = "sha256:" || lowercase-hex(statement.subject[0].digest.sha256)
```

A verifier recomputes that string from the payload and refuses a statement whose subject
claim does not match. The binding is therefore derived from the payload rather than
asserted beside it.

The issuer claim names the observer that made the statement. It is signer-asserted until
something binds it to the verification key, and this profile defines no mechanism for
that binding. It does need one thing of a verifier. Hold an identity alongside each
trusted key, and refuse a statement whose issuer claim is not the identity bound to the
key that verified it. RFC 9943 Section 7.1 states the same obligation from the relying
party's side: "A Relying Party MUST trust the verification key or certificate and the
associated identity of at least one Issuer of a Receipt."

The CWT Claims header parameter MUST appear exactly once across the 2 buckets, as RFC
9597 Section 2 requires. A statement carrying label 15 in both breaks that rule, and a
verifier MUST refuse it rather than prefer one copy. The reject vector for this condition
carries two copies that agree with each other, so a verifier that silently prefers one
bucket returns the same answer as a conforming one and the defect is only observable when
the copies disagree.

## 5. The receipt

RFC 9943 Section 7 describes the construction: "The Client ... that registers a Signed
Statement and receives a Receipt can produce a Transparent Statement by adding the
Receipt to the unprotected header of the Signed Statement."

A Receipt under this profile is a tagged COSE_Sign1 with a detached payload. Its
protected header carries alg (1), kid (4) and vds (395); its unprotected header carries
vdp (396) with an inclusion proof under proof type -1. RFC 9942 Section 5.2.1 marks all
four REQUIRED and gives the reason for the third: "The VDS in the protected header is
necessary to understand the inclusion proof structure in the unprotected header."

The verifiable-data-structure value MUST be 1, RFC9162_SHA256. RFC 9942 Table 2 registers
0 Reserved and 1 and nothing else, and Section 4.3 makes checking it an obligation: "When
the 'receipts' header parameter is present, the verifier MUST confirm that the associated
VDS and VDPs match entries present in the registries established in this specification."

The payload is detached, and RFC 9942 Section 4.4 asks that of a profile: "The payload
in such definitions SHOULD be detached. Detached payloads force verifiers to recompute
the root from the proof and protect against implementation errors where the signature is
verified but the payload is incompatible with the proof." A verifier therefore never
receives the root as an input. It derives the root from the proof and the entry bytes, then
checks the Receipt signature against that derived value.

### 5.1 The leaf, which neither document defines

A Transparent Statement contains its own receipts, so no verifier could check a proof
taken over its bytes. RFC 9943 Section 7 makes the construction obvious in one direction
only: the Transparent Statement is the Signed Statement with the Receipt added.

The registered entry is the Transparent Statement with label 394 removed from its
unprotected header. That operation is well defined, since receipts live in the
unprotected bucket and removing them changes no byte the signature covers. A verifier
MUST reconstruct the entry that way before applying any inclusion proof, since a proof
applied to any other byte string verifies against a root no transparency service signed.

## 6. What a consumer must check

The order below is normative. A failure at any stage is a refusal, and a stage a verifier
cannot evaluate is a refusal rather than a skip.

1. Decode the outer object as a tagged COSE_Sign1 and refuse anything else. Confirm the
   protected header sits in RFC 8949 Section 4.2.1 map order, and refuse any other
   encoding.
2. Read crit. Refuse when it lists a label absent from the protected bucket. RFC 9052
   Section 3.1 already makes that fatal: "If the 'crit' value list includes a label for
   which the header parameter is not in the protected-header-parameters bucket, this is a
   fatal error in processing the message." Refuse when it lists a label this profile does
   not define. Refuse when label -70001 sits in the protected header and crit omits it.
3. Confirm the algorithm is -19, and refuse -8 and -7 by identifier before touching the
   signature.
4. Resolve kid to a trusted key. Where one identifier resolves to more than one key, try
   each and accept only if exactly one verifies. Report an identifier that matched more
   than once as ambiguous. Reattach the payload where the wire form detaches it, and verify
   the signature per RFC 9052 Section 4.4.
5. Confirm the protected CWT Claims appear exactly once and carry both the issuer and subject
   claims. Recompute the subject claim from the payload's subject digest and compare it.
   Compare the issuer claim against the identity bound to the key that verified in stage
   4.
6. Evaluate exp and nbf where present against the verifier's own clock. A present
   expiry in the past and a present not-before in the future are each a refusal.
7. Reconstruct the registered entry by removing label 394, per Section 5.1. For each
   Receipt, confirm the verifiable-data-structure value is 1, read the inclusion proof,
   and refuse when the leaf index is greater than or equal to the tree size. RFC 9942
   Section 5.2 quotes that bound from RFC 9162 as a normative block. Apply the proof to
   the entry bytes per RFC 9162 Section 2.1.3.2. Verify the Receipt signature over the
   recomputed root.
8. Accept only when at least 1 Receipt completed stage 7. RFC 9943 Section 7.1 permits a
   narrower rule here: "A Relying Party MAY decide to verify only a single Receipt that
   is acceptable to them and not check the signature on the Signed Statement or Receipts
   that rely on VDSs they do not understand." This profile narrows that permission rather than
   contradicting it: a Relying Party may still ignore a Receipt whose verifiable data
   structure it does not understand, and it may not skip the Signed Statement signature. Then read the observer position and apply it. A statement whose
   reachableByObserved is true is a self-report, and a policy treating it otherwise falls
   outside this profile.

## 7. What this profile requires of a receipt, and what it does not

Four properties are required. A Receipt carries an inclusion proof, proof type -1, taken
over the reconstructed entry. It declares the verifiable-data-structure value 1 and the proof
structure that value names. Its signature verifies over the root the verifier recomputed
and never over a root it received. And its key is a transparency-service key the verifier
already trusts.

The rest of this section is what falls outside the profile.

Non-equivocation. A single inclusion proof does not give an offline holder
non-equivocation, and detecting a fork needs consistency proofs together with log
monitoring that this profile specifies nowhere. One indeterminate vector carries 2
receipts from one service at one tree size with different roots. It records that the reading which accepts and the
reading which detects the fork are both conforming readings of the same two documents.

Registration time. RFC 9943 Section 7 says "The Registration time is
recorded as the timestamp when the TS added the Signed Statement to its VDS" while no
header in either document carries it, and RFC 9942 Section 7.2 adds that "The details of
expressing validity periods are out of scope for this document." A Receipt can therefore be complete
under this profile and place its registration nowhere in time.

Revocation and suspension. RFC 9942 Section 7.3: "In some cases, receipts
should be 'revocable' or 'suspendable' after being issued, regardless of their validity
period. The details of expressing statuses are out of scope for this document." This
profile adds no status mechanism.

Consistency proofs: RFC 9942 registers proof type -2 and this profile
requires only -1. The truth of the observation itself. A verified statement
establishes that a named issuer signed a record and that a named transparency service
registered it, and it establishes nothing at all about whether the agent behaved as the
record says, whether the observation was complete, or whether any external effect
occurred. And the
registration policy, which stays a transparency service's own business under RFC 9943
Section 6.3.

## 8. Open items

This profile registers no media type, so nothing makes 2 conforming producers pick the
same content type value, and a transparency service that dispatches policy on that value
will treat two conforming statements as two different formats. A vector records the fork rather than resolving it.
Registration is the first IANA action a later revision should request.

The observer position sits at a Private Use label. A registration in the COSE Header
Parameters registry is a later step, and it changes the bytes of every vector.

Requiring proof type -2 alongside -1 would raise what a Receipt establishes. This
revision does not specify it.

## 9. Conformance

The corpus in `vectors-scitt-cose/` is the executable form of this document. Every reject
member declares the accept member it is 1 mutation from, so a verifier that refuses every
input scores 0 rather than full marks. Every indeterminate member declares the readings a
conforming verifier could take, because the documents cited above do not choose between
them. A corpus that chose would publish a rule the standards do not carry.

The checker at `vectors-scitt-cose/check_vectors.py` re-derives every claim from the
bytes on disk, and it states RFC 9162 Section 2.1.3.2 a second time rather than importing
the generator's tree code. A fault in that code then produces a corpus together with a
refusal, where an imported checker would produce a corpus and its own agreement with it.
An implementer replaying this corpus should hold the same rule for the same reason: a
verification routine that shares its arithmetic with the routine that built the inputs
cannot disagree with them, so a fault common to both is invisible to the replay.

## 10. References

RFC 9943, An Architecture for Trustworthy and Transparent Digital Supply Chains, carries
the architecture, and RFC 9942, COSE Receipts, carries the receipt format. The COSE structures and
process come from RFC 9052 and its initial algorithms from RFC 9053, with the
fully-specified algorithm registrations in RFC 9864. CWT claims in COSE headers are RFC
9597, the type header parameter is RFC 9596, and CWT itself is RFC 8392. The verifiable
data structure is the Merkle tree of RFC 9162, Certificate Transparency Version 2.0. CBOR
is RFC 8949 and its JSON canonicalization counterpart is RFC 8785. The media type
registration procedures are RFC 6838.
