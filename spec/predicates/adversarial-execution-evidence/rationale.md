<!-- Long-form companion to the Adversarial Execution Evidence predicate. -->

# Adversarial Execution Evidence: purpose, use cases and model

Long-form companion to the registry page for predicate type
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

The text below is verbatim from the single-document revision of the
specification (source SHA-256 `2b7f3bc08123cbe1981d287cf20193858ae5ea6d55ca067e06363a1e71a573d7`, lines 13-308 of
`spec/predicates/adversarial-execution-evidence.md`). The registry page is the
normative statement of the predicate and carries the schema, the parsing
rules, the field list and the examples; this file carries the reasoning,
the bounds and the cases that do not fit a registry entry, so that nothing
the single document argued is lost when the page is read on its own.

Where the rest of it went:

| material | file |
|---|---|
| the predicate itself: type URI, schema, parsing rules, field list, examples | the registry page, `spec/predicates/adversarial-execution-evidence.md` upstream |
| purpose, use cases, model | [`rationale.md`](rationale.md) |
| encoding profile, I-JSON, nesting bound, BMP rule, run binding | [`wire-profile.md`](wire-profile.md) |
| parsing rules in full, consumer policy obligations, the policy example | [`verification.md`](verification.md) |
| every field, coverage validity, evidence tier, reserved record members | [`fields.md`](fields.md) |
| per-version history from 0.3 to 0.7 | [`changelog.md`](changelog.md) |

A cross-reference in the verbatim text below that reads "above", "below",
"under Prerequisites" or "under Consumer policy obligations" points at the
single document's own layout. Read it against the table above.

---

## Purpose

Records the evidence produced by deliberately executing an untrusted or
under-trusted software artifact (an agent tool, an MCP server, a plugin, a
build step) inside an instrumented containment substrate while a known corpus
of adversarial inputs is thrown at it. The predicate carries what was thrown,
what the substrate was configured to catch, what was actually observed (each
observation as an independently signed record: every interception, the armed
vantage the run was observed under, and the seal that the vantage stayed armed
to run-end), and an explicit statement of the observation's coverage bounds.

The design goal is that a consumer can recompute the outcome from the
attestation alone, with no call back to the producer's infrastructure and no
dependency on a document that does not travel with the statement. That goal
is met on one half and not on the other, and the split is worth stating at
the top. The reduction of the carried rows to a `result` is deterministic and
recomputable: the coverage denominator is committed by digest, so the
producer cannot assert it unilaterally, and each observation record verifies
on its own before it is read. The construction of those rows is not
recomputable. Mapping an observation to attack semantics is an
assembly-plane assertion no verifier can check, because the substrate sees a
dropped packet or a changed inode and has no notion of where one attack
begins and another ends. The substrate cryptographically proves what was
observed; the assembly plane asserts what it means.

A producer therefore cannot claim more than the carried evidence supports. A
producer claiming less is not detectable from the statement, and that
sentence is exact rather than cautious: a statement that withdraws a claim is
a statement an honest producer with weaker instruments emits from the same
configuration, so no function of the carried bytes refuses the one without
refusing the other, and no quantity of additional signed material changes
that, because additional material is material a withdrawing producer also
declines to carry.

Between claiming more and claiming less, one rule decides where a commitment
can help and where it cannot: a commitment carried on a record binds
precisely the attacks that need that record, and none of the attacks that can
delete it. `batchRoot` is on the wrong side of that rule and it is worth
keeping the reason in sight. It is recomputed over the records the statement
carries, so it can never detect a missing member; what it binds is the
carried set against a party who cannot re-sign the enclosing envelope, which
is a network attacker rather than the assembly plane the substrate key
separation is written against. The run-end `sealed` record is on the right
side of it, because a party deleting an interception cannot also delete the
seal and still present a statement carrying a `basis: substrate` row. The
run-start `arming` record is on the right side of it for coverage inflation,
because inflation fabricates rows that must point at run-level records the
inflated statement therefore has to keep. Completeness of the record set
against the run is still nowhere proven: what the run-end commitment below
establishes is that the carried set is the emitted set, never that the
emitted set is everything that happened.


## Use Cases

-   An admission controller (e.g. a Kubernetes policy engine) gating a
    third-party MCP server or agent tool image on evidence that it was
    executed against a named attack corpus under an enforcing catch policy,
    with the policy digest and network posture pinned in the evidence.
-   An auditor re-verifying, offline and without trusting the producer's
    infrastructure, that a specific interception happened: the signed
    observation record binds the destination, the payload commitment, and the
    substrate context.
-   A security team comparing two runs of the same artifact: because the
    corpus manifest is digest-committed at attack granularity, a consumer
    can check "both runs assessed the same attacks" rather than take it on
    the producer's word.

Existing predicates cover adjacent but different ground. [Runtime Traces]
carries raw observed activity from a monitor, with no corpus binding, no
coverage denominator, and no per-event signature. [SCAI] carries
evidence-backed attribute assertions but does not model an adversarial corpus
or recomputable outcomes. [VSA] and [SVR] carry policy verdicts computed at
verification time, downstream of evidence like this. [Test Result] carries
test outcomes without cryptographic binding of the inputs or the
interceptions. This predicate is the evidence layer those verdict predicates
can consume. This predicate makes no cross-predicate claim: composing it with
a sibling execution predicate (for example a runtime trace of a different
execution) does not yield end-to-end coverage, and a consumer MUST NOT infer a
composite guarantee unless its policy binds both attestations to the same
execution (for example through a shared subject digest and run identifier).


## Model

The producer is a containment substrate operator: a functionary that runs the
subject artifact inside an isolated, instrumented environment (a microVM, a
sandbox, an eBPF-supervised process), injects the corpus, and signs what the
substrate observed: each interception, the armed vantage it occurred under,
and the seal that the vantage stayed armed. The subject is the executed
artifact, by digest. Every
attestation references a substrate by subject (the `substrate` field is
required); that substrate SHOULD in turn carry its own attestation, e.g. build
provenance for the substrate image, so the evidence can inherit a substrate
trust chain rather than a bare name. Verdicts (pass/fail against an
organization's policy) are deliberately out of scope; they belong in a
downstream summary predicate such as [VSA], computed over this evidence.

[DSSE]: https://github.com/secure-systems-lab/dsse
[ResourceDescriptor]: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
[Runtime Traces]: https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md
[SCAI]: https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md
[SVR]: https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md
[Test Result]: https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md
[VSA]: https://github.com/in-toto/attestation/blob/main/spec/predicates/vsa.md
