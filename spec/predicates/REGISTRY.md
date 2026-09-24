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
- Predicate body: sixteen members, defined in Section 5 of the draft. Each is
  required unless a rule in that section makes it conditional, and no member
  has a default.
- Corpus: Appendix B of the draft lists the conformance vectors. They are not
  yet published in this repository.
- Status: current. The URI will not move, because a record carries it inside
  the bytes its producer signed.

The entries in this section are registrations, not specifications. Their field
definitions are normative where they are published, which is not here, and no
count, field list or wire form on this page may be read as authoritative for
them.
