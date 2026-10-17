# Predicate types this host answers for

A `predicateType` is the one string a third party writes **inside the bytes they
sign**. Stripping it invalidates their own signature, so it cannot be changed
after publication and it cannot be allowed to stop resolving: a verifier that
dereferences a type URI and is handed a 404 has no way to tell a type that was
never published from one that was withdrawn, and both readings are wrong.

This file is the list of type URIs under
`https://probityai.github.io/agent-evidence-vectors/predicate/`, and the site
build reads it rather than carrying a list of its own. A URI added to a signed
payload and not added here is a URI that will 404 the first time somebody checks
it, which is the defect this file exists to make visible in review.

Each entry says which of two kinds it is, and the distinction is the point:

- **Defined here.** The normative field definitions are a tracked document in
  this repository, the conformance corpus for the type is in this repository,
  and the page served at the URI is that document.
- **Registered here.** This host is the naming authority for the URI and
  nothing more. The normative field definitions are published elsewhere, by
  the implementation that emits the type or in the document the entry names,
  and are not vendored here. A verifier must
  not read the served page as the field definition; it is a statement that the
  name is taken, by whom, and in what shape.

## Defined here

### `predicate/v1/observed-effect`

- Document: `spec/predicates/observed-effect.md`
- Corpus: `vectors-observed-effect/`, suite `observed-effect-conformance`
- Rails: `corpora/observedeffect.go` and `observedeffect/` in this repository

The predicate carries an observed effect of an execution, separately from the
claim an executor makes about it, so that a consumer recomputes the effect from
carried bytes instead of accepting an asserted one.

### `predicate/v1/self-reported-record`

- Document: `spec/self-reported-record/v1.md`
- Corpus: `vectors-self-reported-record/`, suite `self-reported-record-conformance`
- Rails: `corpora/selfreported.go` in this repository

The predicate carries an agent's own record of a session, with each field
declaring whether a substrate observation covers it or the record's own
attesting key alone, so a consumer can tell the observed fields from the
self-asserted ones.

## Registered here

### `predicate/v1/kernel-substrate`

- Predicate body: a version, alone.
- Statement subject: the approved bytes, under the conventional subject name
  `guest-kernel`. A verifier binds on the digest map and must not bind on the
  name.
- Status: addresses bundles already minted under it. Not withdrawn.

### `predicate/v2/kernel-substrate`

- Predicate body: a version, alone.
- Statement subject: as above.
- Status: current. `v1` and `v2` are both live, because a document that
  normatively fixes a wire form cannot change that form in place.

### `predicate/v2/launch-chain`

- Predicate body: the rest of a boot pre-image -- an initrd digest, a kernel
  command line, and dm-verity root hashes -- bound to the kernel it belongs to.
- Status: current.

### `predicate/v1/agent-audit-record`

- Document: the Internet-Draft `draft-gilda-wimse-agent-audit-record`,
  <https://datatracker.ietf.org/doc/draft-gilda-wimse-agent-audit-record/>,
  which fixes this URI in revision 00 and defines the format. It is not
  vendored here.
- Envelope: an in-toto Statement carried in a DSSE envelope.
- Predicate body: seventeen required members and one optional member, defined
  in Section 5 of the draft. Each required member is required unless a rule in
  that section makes it conditional, and no member has a default. Revision 02
  added the required `evaluation` member and the optional `oversight` member,
  so a revision 01 record is malformed under revision 02.
- Corpus: `vectors-agent-audit-record/`, suite `agent-audit-record-conformance`,
  one member per row of Appendix B of revision 02, each carrying its Appendix B
  identifier, then members for sentences of Sections 5.4 and 5.5 that Appendix B
  has no row for, each naming its section in `draftSection`. Judged by
  `packaging/agent_evidence_vectors/auditrecord.py`.
- Status: current. The URI will not move, because a record carries it inside
  the bytes its producer signed.

### `predicate/v1/govops-trace-record`

- Predicate body: one GovOps TRACE record (`eat_profile`
  `tag:govops,2026:trace-v1`) without its `signature` member, as section 1 of
  [GovOpsWG/GovOps `govops-trace-profile.md`](https://github.com/GovOpsWG/GovOps/blob/131cb66bc87cd266e224d7df6f7b9401c00f3ef7/govops-trace-profile.md)
  (commit `131cb66`) defines the record. The record format is published there
  and is not vendored here.
- Envelope: an in-toto Statement carried in a DSSE envelope, whose subject
  digest is the record's content digest, as `interop/govops-trace-profile/README.md`
  writes the carriage down.
- Corpus: `interop/govops-trace-profile/`, judged by its `check_vectors.py`.
- Status: current. The URI will not move, because a carried record holds it
  inside the bytes its producer signed.

The entries in this section are registrations, not specifications. Their field
definitions are normative where they are published, which is not here, and no
count, field list or wire form on this page may be read as authoritative for
them.

## Types served from another host

Two types defined in this directory have their URIs under
`https://w3id.org/agent-evidence/predicate/v1/`, a persistent identifier namespace
that is not served from this repository. The site build here publishes no page for
them, and the scan in `scripts/predicate-uri-gate.py` does not cover that host.
Each document is the authority for its type until the human-readable pages are
live, and no signed statement carries either URI before then.

- `done-contract`: `spec/predicates/done-contract.md`, corpus `vectors-done-contract/`.
- `done-receipt`: `spec/predicates/done-receipt.md`, corpora `vectors-done-receipt/`,
  `vectors-spoofed-tool-output/`, `vectors-test-tampering/` and
  `vectors-grader-isolation/`.

`spec/predicates/done-records.md` defines the records both read and no type URI.
