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
- Corpus: `corpora/vectors-observed-effect/`, suite `observed-effect-conformance`
- Rails: `corpora/observedeffect.go` and `observedeffect/` in this repository

The predicate carries an observed effect of an execution, separately from the
claim an executor makes about it, so that a consumer recomputes the effect from
carried bytes instead of accepting an asserted one.

### `predicate/v1/signature-coverage`

- Document: `corpora/vectors-signature-coverage/README.md`
- Corpus: `corpora/vectors-signature-coverage/`, suite `signature-coverage/v1`
- Rails: `corpusreaders/signaturecoverage.go`, `packaging/agent_evidence_vectors/signaturecoverage.py`

The predicate carries one signed structure: the source as readers see it with repeats
kept, the signed payload with its signature, the keys declared outside the signature, and
the paths a consumer reads. The signature input must determine everything a reader can
read: two records that read differently may not share one.
### `predicate/v1/evidence-state`

- Document: `corpora/vectors-evidence-state/README.md`
- Corpus: `corpora/vectors-evidence-state/`, suite `evidence-state/v1`
- Rails: `corpusreaders/evidencestate.go`, `packaging/agent_evidence_vectors/evidencestate.py`

The predicate carries one system's declared evidence state, a code of the vocabulary term
`evidence_state` (`ES0` to `ES8`), beside the observations that ground it. The state is
the highest code whose entry condition the observations meet; a declared code that
differs is refused, and a silence is declared clean (`ES1`) only over measured coverage.

### `predicate/v1/incident-evidence-cell`

- Document: `corpora/vectors-incident-evidence-cell/README.md`
- Corpus: `corpora/vectors-incident-evidence-cell/`, suite `incident-evidence-cell/v1`
- Schema: `spec/schemas/incident-evidence-cell-v1.schema.json`
- Rails: `corpusreaders/evidencecell.go`, `packaging/agent_evidence_vectors/evidencecell.py`

The predicate carries one coded cell of an incident decision table inside an in-toto
Statement v1 whose subjects are the source documents the cell was coded from. The cell
names its table, row and column, an `evidence_state` code URI, a `response_function`
value, a support label, and either the value it records or an empty marker; an empty
cell is labelled `unknown`. The producer signs the Statement in a DSSE envelope with its
own key, and the record's `doesNotAssert` says the signature shows who coded the cell,
not that the cell is true.

### `predicate/v1/monitor-coverage`

- Document: `corpora/vectors-monitor-coverage/README.md`
- Corpus: `corpora/vectors-monitor-coverage/`, suite `monitor-coverage/v1`
- Rails: `corpusreaders/monitorcoverage.go`, `packaging/agent_evidence_vectors/monitorcoverage.py`

The predicate carries one monitor's verdict over one window: the monitor's vantage and
the channels it reads, the collector-side coverage count, an effect another source
observed, and the verdict with its decision and effective-action counts. A clean verdict
stands only on complete collector coverage of the channel the effect used, and a claim
that a defence reduced harm needs at least one effective action.

### `predicate/v1/containment-journal`

- Document: `spec/predicates/containment-journal.md`
- Corpus: `corpora/vectors-containment-journal/`, suite `containment-journal/v1`
- Rails: `corpusreaders/containmentjournal.go`, `packaging/agent_evidence_vectors/containmentjournal.py`

The predicate carries one multi-agent run as a hash-chained journal: the starting
communication graph, each delivery between agents, each containment decision with the
edges it removed and added, each fallback with its declared failure posture, and each
restart, assessment, restoration and response, and from revision 1.1 each retrieval with its
inclusion path to the attested snapshot and each tool call with its refusal and grant chain,
beside the defence's claims about the run.
Every claim is recomputed from the entries: a cut edge that still delivers under an
enforcing router, a return without an external score below its threshold, a closure
claimed over an advisory topology, an isolated agent's tool call that was not refused, or an
admitted document outside the snapshot is refused.

### `predicate/v1/blast-radius-receipt`

- Document: `spec/predicates/containment-journal.md`
- Corpus: `corpora/vectors-containment-journal/`, suite `containment-journal/v1`
- Rails: `corpusreaders/containmentjournal.go`, `packaging/agent_evidence_vectors/containmentjournal.py`

The predicate carries the reach of one agent through a containment journal it names by
run, head digest and entry count: the agents it reached from one entry on through
deliveries the router did not drop, and the deliveries and tool calls that reach
involved. It is judged only beside an allowed journal, and a reach that leaves an agent
out or adds one is refused.

### `predicate/v1/propagation-step`

- Document: `corpora/vectors-propagation-step/README.md`
- Corpus: `corpora/vectors-propagation-step/`, suite `propagation-step/v1`
- Rails: `corpusreaders/propagationstep.go`, `packaging/agent_evidence_vectors/propagationstep.py`

The predicate carries one hop's attribution between two agents: the message log, the
digest chain the attribution cites, each agent's exposures to outside sources and when
the receiver acted. Propagation needs a connected chain that reaches the receiver before
it acted; a shared exposure with no edge is a common cause, never propagation.

### `predicate/v1/uncertain-effect`

- Document: `corpora/vectors-uncertain-effect/README.md`
- Corpus: `corpora/vectors-uncertain-effect/`, suite `uncertain-effect/v1`
- Rails: `corpusreaders/uncertaineffect.go`, `packaging/agent_evidence_vectors/uncertaineffect.py`
  and the runtime contract in `packaging/agent_evidence_vectors/uncertaineffect_runtime.py`

The predicate carries one runtime's trail for an operation whose reply may have been
lost: its attempts and their replies, the leases they were sent under, the effect
owner's reconciliation answers and ledger count, the reservation held for it and the
outcome the runtime reported, so a consumer can tell a settled effect from an
unknown one and a safe resend from a duplicate.

### `predicate/v1/decision-client-failure-modes`

- Document: `corpora/vectors-decision-client-failure-modes/README.md`
- Corpus: `corpora/vectors-decision-client-failure-modes/`, suite `decision-client-failure-modes/v1`
- Rails: `corpusreaders/decisionclient.go`, `packaging/agent_evidence_vectors/decisionclient.py`
  and the runtime contract in `packaging/agent_evidence_vectors/decisionclient_runtime.py`

The predicate carries one decision a client took when it asked a decision point
whether an action may run: the request, the client's mode and timeout, the facts of
the exchange (reached, timed out, HTTP status, whether the body parsed and the
verdict it carried), the condition, outcome and basis the client recorded, and
whether the action was performed, so a consumer can tell a policy decision from a
fallback and an allow from a fault read as one.

### `predicate/v1/refusal-reason-priority`

- Document: `corpora/vectors-refusal-reason-priority/README.md`
- Corpus: `corpora/vectors-refusal-reason-priority/`, suite `refusal-reason-priority/v1`
- Rails: `corpusreaders/refusalreason.go`, `packaging/agent_evidence_vectors/refusalreason.py`

The predicate carries one attestation response and the facts it answered over: which
conditions of the closed refusal vocabulary applied, the observation the answer relied
on, any diagnostic read, and at the lease instant the boundary the deployment declared.
The reason must be the first applicable value of the list, none when no condition
applies, with null as the only permit; the observation member stays null when the relied-on
observation is absent or not fresh, and a diagnostic read neither authorizes nor renews.
Records are from draft-li-rttp-iqa-addressing-02 sections 6.1, 7.2, 8.1 and 8.2.

### `predicate/v1/evaluation-claim`

- Document: `spec/predicates/evaluation-claim.md`
- Corpus: `packaging/agent_evidence_vectors/claim_record/corpus/`
- Rails: `packaging/agent_evidence_vectors/claim_record/reader.py`, run as
  `agent-evidence-vectors claim`

The predicate carries an evaluation claim in which every coordinate is present
(applicability, population, vantage, bytes, epoch, settlement), each a value or
not applicable under a reason the profile pinned by the relying party's
acceptance rule authorises, so that a case nobody ran is never read as a pass.

### `predicate/v1/self-reported-record`

- Document: `spec/self-reported-record/v1.md`
- Corpus: `corpora/vectors-self-reported-record/`, suite `self-reported-record-conformance`
- Rails: `corpora/selfreported.go` in this repository

The predicate carries an agent's own record of a session, with each field
declaring whether a substrate observation covers it or the record's own
attesting key alone, so a consumer can tell the observed fields from the
self-asserted ones.

### `predicate/v1/peer-verification`

- Document: `spec/predicates/peer-verification.md`
- Corpus: `packaging/agent_evidence_vectors/verdict_evidence/corpus/`, suite `acs-verdict-evidence/v1.0.1-draft`
- Rails: `packaging/agent_evidence_vectors/verdict_evidence/reader.py` in this repository

The statement a second party signs when it checked a conformance requirement itself:
the vector, the requirement, and the client run or retained transcript it used. A
verdict record names it by digest to lift `witness_scope` above `SELF`; the runner
cannot write one.

### `predicate/v1/incident-action-authorization`

- Document: `spec/predicates/incident-action-authorization.md`
- Profile: `profiles/restoration-evidence.md` (`restoration-evidence/v1`)
- Corpus: `corpora/vectors-restart-records/` (released with the checker)

Record R1 of the restoration evidence profile: who authorized one incident response action, the role each named party held, the kind of grant the authorizer acted on, and whether the authority was committed before the action ran.

### `predicate/v1/revocation-sweep`

- Document: `spec/predicates/revocation-sweep.md`
- Profile: `profiles/restoration-evidence.md` (`restoration-evidence/v1`)
- Corpus: `corpora/vectors-restart-records/` (released with the checker)

Record R2 of the restoration evidence profile: the credential population a revocation sweep ran over, its partition into revoked, retained and unassessed, and the coverage the producer claims, so that a claim wider than the partition is visible from the record alone.

### `predicate/v1/re-enable-decision`

- Document: `spec/predicates/re-enable-decision.md`
- Profile: `profiles/restoration-evidence.md` (`restoration-evidence/v1`)
- Corpus: `corpora/vectors-restart-records/` (released with the checker)

Record R3 of the restoration evidence profile: one decision to resume, stage or keep restricting a stopped agent system, its approvers, and for every evidence slot either a digest or an explicit statement that it was not addressed.

### `predicate/v1/joint-authority`

- Document: `spec/predicates/joint-authority.md`
- Profile: `profiles/restoration-evidence.md` (`restoration-evidence/v1`)
- Corpus: `corpora/vectors-restart-records/` (released with the checker)

Record R4 of the restoration evidence profile: which party may act on which asset when an incident spans organisations, under what kind of grant, and which indicators they share.

### `predicate/v1/revocation-boundary`

- Document: `spec/predicates/revocation-boundary.md`
- Profile: `profiles/restoration-evidence.md` (`restoration-evidence/v1`)
- Corpus: `corpora/vectors-restart-records/` (released with the checker)

For one declared sink and test window, whether an effect from a task in flight committed after a credential revocation took effect, with the counts a reader needs to judge it. It names no mechanism.

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

- Document: the Internet-Draft `draft-gilda-audit-agent-audit-record`,
  <https://datatracker.ietf.org/doc/draft-gilda-audit-agent-audit-record/>,
  which replaces `draft-gilda-wimse-agent-audit-record`, the draft that fixed
  this URI in its revision 00. It is not vendored here.
- Envelope: an in-toto Statement carried in a DSSE envelope.
- Predicate body: seventeen required members and one optional member, defined
  in Section 5 of the draft. Each required member is required unless a rule in
  that section makes it conditional, and no member has a default. Revision 02
  of the earlier draft added the required `evaluation` member and the optional
  `oversight` member, so a revision 01 record is malformed under revision 02;
  revision 00 of the replacing draft requires `evaluation.inputs`, so a revision
  02 record is malformed under it.
- Corpus: `corpora/vectors-agent-audit-record/`, suite `agent-audit-record-conformance`,
  one member per row of Appendix B of draft-gilda-audit-agent-audit-record-00,
  each carrying its Appendix B identifier, then members for sentences of
  Section 5.4 that Appendix B has no row for, each naming its section in
  `draftSection`, then rows of revision 01 (`CS1` to `CS40`) that bind
  consumption state to the agent's operation key, and rows written for revision
  04 (`CS41` to `CS54`) that add a paid call's payee and settled terms; `CS7`, `CS8`, `CS17`, `CS18` to `CS22`, `CS25` to `CS33`, `CS38` to `CS40`, `CS48`, `CS49`, `CS53` and `CS54` are
  files of several records judged as a set. Rows R1 to R9 are retained records
  judged by the dating check of Section 4.7. Rows `PR1` to `PR11`, written for revision 04, test
  the optional `principal` member, the authenticated principal bound to the agent's credential
  digest and to the issuer key's RFC 7638 thumbprint
  ([proposed text](../../docs/proposals/audit-record-04-principal.md)). Rows `DS1` to `DS10`,
  written for revision 04, test the optional `dataSubject` member, a keyed reference to the
  person whose data a call read, kept apart from the delegated subject, and a purpose taken from
  the server's declared list
  ([proposed text](../../docs/proposals/audit-record-04-data-subject.md)).
  Judged by `packaging/agent_evidence_vectors/auditrecord.py`.
  Releases up to v0.25.0 test revision 02 of the earlier draft.
- Status: current. The URI will not move, because a record carries it inside
  the bytes its producer signed.

### `predicate/v2/agent-audit-record`

- Document: Section 8 of the Internet-Draft
  `draft-gilda-audit-agent-audit-record-03`,
  <https://datatracker.ietf.org/doc/draft-gilda-audit-agent-audit-record/03/>,
  which publishes this URI as the `v1` URI read as `v2`. It is not vendored here.
- Envelope: as `predicate/v1/agent-audit-record`.
- Predicate body: the members of Section 5 of revision 03, with the closed set
  of Section 5.4 extended by the input `principal-standing-source`. A record
  carrying that input is malformed under the `v1` URI; every other rule is the
  same under both.
- Corpus: rows `PS1` and `PS2` of Appendix B of revision 03, marked there for
  the next release of `corpora/vectors-agent-audit-record/`; no released member carries
  this URI yet.
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

### `predicate/v1/evidence-scope-disclosure`

- Predicate body: A signed statement about a published piece of evidence: which detection-stack layers it covers, its tier, whether it is a real capture or a representative fixture, and what it deliberately does not show. It carries no verdict.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/launch-chain`

- Predicate body: The rest of a boot pre-image -- an initrd digest, a kernel command line, and dm-verity root hashes -- bound to the kernel it belongs to. Minted before `predicate/v2/launch-chain`; both are live.
- Status: addresses bundles already minted under it. Not withdrawn. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/ml-bom`

- Predicate body: An execution-grounded bill of the model weights a frozen microVM mapped into memory, each region resolved to a full-file identity by a host-side source.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/quotation-fidelity`

- Predicate body: A signed assertion that a quoted span appears verbatim at a stated position in a committed source, checkable against a 32-byte root by a reader who holds none of that source, with how the source was obtained.
- Status: draft. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/scorecard-verdict`

- Predicate body: A multi-layer assessment record about one system under test: a tri-state outcome (`pass`, `degraded`, `fail`), the per-layer results it was folded from, and a coverage statement naming what was not assessed. Two disjoint producer profiles share the type behind a normative discriminator.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/security-verdict`

- Predicate body: A statement that a named artifact was run in isolation against a pinned attack corpus and given a pass or fail verdict with per-attack evidence, so an admission controller can decide without re-running the scan.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/signed-evidence`

- Predicate body: One signed statement carrying the guest-memory Merkle commitment, the value binding that ties it to a signed session and a verdict subject, and the cross-host differential-snapshot fold pins. It is not a type for evidence-scope disclosures.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/static-scan-verdict`

- Predicate body: The outcome of a static scan of an MCP server or A2A agent over its declared surface, without booting a microVM and without executing its tools.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/substrate-integrity`

- Predicate body: A statement about the isolation substrate that scans run on, emitted once per substrate release and referenced by digest from each security verdict.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v1/sut-provenance`

- Predicate body: A statement that a scanned system-under-test image was built from a known base image and a fully integrity-pinned dependency closure, bound to the image by OCI digest.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v2/a2a-mesh-scorecard`

- Predicate body: A composition-safety verdict about a mesh of agent-to-agent microVMs: whether authority attenuated correctly across the delegation graph the mesh produced. The subject is the mesh manifest, an aggregate of its member microVMs.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

### `predicate/v2/mesh-quiescence`

- Predicate body: A statement about freeze atomicity of an isolation substrate: that co-resident microVMs were brought to a hypervisor-enforced quiescent state with bounded, measured timing, and no in-flight inter-VM segment escaped the freeze.
- Status: current. The URI will not move, because a record carries it inside the bytes its producer signed.

The entries in this section are registrations, not specifications. Their field
definitions are normative where they are published, which is not here, and no
count, field list or wire form on this page may be read as authoritative for
them.

## Types served from another host

Types defined in this directory with a URI under
`https://w3id.org/agent-evidence/predicate/v1/` are served from a persistent identifier
namespace that is not this repository. The site build here publishes no page for
them, and the scan in `scripts/predicate-uri-gate.py` does not cover that host.
`scripts/build_predicate_pages.py` writes their pages under `pages/predicate/v1/`,
the organisation Pages site serves those pages at the targets of the w3id.org
rules, and `scripts/check_uris_resolve.py --network` requests every one of them
each day. Each document is the authority for its type.

- `done-contract`: `spec/predicates/done-contract.md`, corpus `corpora/vectors-done-contract/`.
- `done-receipt`: `spec/predicates/done-receipt.md`, corpora `corpora/vectors-done-receipt/`,
  `corpora/vectors-spoofed-tool-output/`, `corpora/vectors-test-tampering/`,
  `corpora/vectors-grader-isolation/` and `corpora/vectors-done-probes/`.
- `agent-card-receipt`: `spec/predicates/agent-card-receipt.md`, corpus
  `corpora/vectors-agent-card-receipt/`.
- `credential-release`: `spec/predicates/credential-release.md`, corpus
  `corpora/vectors-credential-release/`.

`spec/predicates/done-records.md` defines the records both read and no type URI.
