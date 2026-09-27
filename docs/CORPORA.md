# The corpora

What each corpus tests, which specification it follows, and how the specification references stay honest. Part of the [agent-evidence-vectors](../README.md) documentation; the [index](README.md) lists every page.

<p>
  <img src="https://img.shields.io/badge/AEE%20vectors-281-e8951c" alt="281 AEE conformance vectors">
  <img src="https://img.shields.io/badge/AI%20Agent%20Action%20vectors-62-e8951c" alt="62 AI Agent Action conformance vectors">
  <img src="https://img.shields.io/badge/artifact--binding%20vectors-8-e8951c" alt="8 artifact-binding conformance vectors">
  <img src="https://img.shields.io/badge/SCITT%2FCOSE%20vectors-27-e8951c" alt="27 SCITT/COSE carriage conformance vectors">
  <img src="https://img.shields.io/badge/rails-Go%20%C2%B7%20Python-546274" alt="Go and Python rails">
  <img src="https://img.shields.io/badge/predicate-in--toto%20AEE%20v0.7-6f57c2" alt="in-toto AEE v0.7 predicate">
</p>

## What the suite judges

This is a recomputable execution attestation toolkit for two in-toto predicates:
**Adversarial Execution Evidence**, predicate version 0.7, and **AI Agent
Action**, predicate version 0.1, proposed in
[in-toto/attestation#588](https://github.com/in-toto/attestation/pull/588).
Each has its own corpus, `vectors/` and `vectors-ai-agent-action/`.

A third corpus, `vectors-scitt-cose/`, tests something else: how an adversarial
execution evidence statement is CARRIED as an IETF SCITT Transparent Statement,
signed as a COSE_Sign1 and proved by an RFC 9942 Receipt. `profiles/scitt-cose.md`
is the profile it enforces. The split of that carriage suite is 6 accept,
17 reject and 4 indeterminate. The indeterminate members are the ones to read
first: each records a question RFC 9943 and RFC 9942 leave open, and the readings
a conforming verifier could take, because a corpus that answered them would be
inventing a rule the standards do not carry.

**The AI Agent Action vectors test #588 as it reads at `a5dd509`, and every
rejection names the text it rests on.** Each reject member in
`vectors-ai-agent-action/MANIFEST.json` declares a basis: the lines of the
vendored specification that make it rejectable, with a quotation `aee-verify`
finds in those lines on every run. All but one rest on the pull request's own
text. The exception is the member-name ordering condition, `aia-c-15`, which
rests on the BMP-only rule this project offers into that pull request
([`docs/ai-agent-action-canonicalization.md`](ai-agent-action-canonicalization.md));
its basis also cites the #588 lines that read the other way, so a verifier
conforming to #588 alone accepts that member and should say so rather than be
scored against it. Members whose verdict depends on a deployment choice #588
leaves to configuration, whether a chain_break with `priorHead: null` is
permitted, name the profile they hold under.

**Three different numbers on this page are called a version, so every one of
them names its axis.** A *predicate* version belongs to a specification in
in-toto and changes when that specification changes; there are two of them here
and they are unrelated to each other. A *release* tag belongs to this
repository and changes when anything here ships. They move independently: the
suite reached release v0.8.0 by adding a second corpus while still implementing
predicate v0.7, so those two numbers disagreeing is the normal state rather
than a defect. A bare number cannot tell you which axis you are reading, which
is why none is written bare.

A third corpus sits beside those two and is not a predicate at all.
`vectors-artifact-binding/` tests the contract in
[`spec/artifact-binding/v1.md`](../spec/artifact-binding/v1.md), which binds an
agent-evaluation result to the saved artifacts and grading inputs it names so
that a regrade is auditable rather than merely repeatable. It is versioned
separately from both predicates because the AEE specification puts downstream
verdicts out of its own scope, and folding an evaluation record into it would
put a verdict inside a predicate designed to carry observations. That corpus
answers three verdicts rather than two: `verified`, `failed`, and
`not-established` for a record that cannot be checked to a conclusion because
something required was never captured. The tool that produces and checks those
records is `tools/artifact-binding/`, and `demo/four-arms.sh` runs the four
demonstrations end to end from a fresh clone.

[`vectors-source-coverage/`](../vectors-source-coverage/README.md) checks whether
selected passages appear in a bound report under a consumer-pinned capture and
time window. Six synthetic cases ship in the wheel and require a named verifier.

The [optional WS4 prior-witness candidate](../interop/ws4-prior-witness-candidate/README.md)
exercises provenance for the proposed CoSAI WS4 Section 7.4 integration draft.
Its fixtures use an author-held test key and consumer-stipulated pins; they
establish no outside witness custody or WS4 conformance.

The [optional AgentID offline reader](../interop/agentid-offline/README.md) recomputes
eight byte, signature and request relationships from a pinned signed fixture and
saved key. It retains separate claims and refusal controls, without asserting
historical key authority, unique action-tuple binding or a formal Pack #3 result.

The [framed action tuple candidate](../interop/action-tuple-framed-v1/README.md) defines
a separate unsigned profile with explicit UTF-8 byte lengths and a fixed versioned
domain. Its accept/refuse corpus distinguishes the native concatenation ambiguity
without changing the historical AgentID fixture or interpreting its signature under
the candidate construction.

The [live MCP named-tool case](../interop/agentavow-live-mcp/README.md) uses author-owned synthetic definitions to compare a prior digest with later served definitions; it does not verify a JWS or a live endpoint.

The [provisional A2A retained-field gate](../interop/a2a-s3-retain-2026-10-01/README.md)
recomputes 13 source-pinned signature cases. It accepts signer-side dual signing
while rejecting verifier fallback that would leave an altered legacy URL unsigned.
This optional consumer policy is separate from A2A's pending canonicalization ruling.

`vectors-w3c-report/` is the conformance set for v0.1 of the per-check
reporting format of the W3C public-agent-conformance community group: every
rejection row of the frozen table backed by a report that must be rejected
under it and one that must pass, the two late additions of 18 September, the
rules the thread settled beside the table, the 42 delta-related pairs a
participant counted in his own corpus re-cut against v0.1, and members of two
further subject types, the Run object of `draft-arsentev-agent-run-metrics-00`
and the discovery snapshot of `draft-arsentev-llm-context-discovery-00`. The
rows are the group's; the texts are vendored and pinned by digest, and each
identifier is bound to a sentence. Two readers judge it, `corpora/w3creport.go`
and `packaging/agent_evidence_vectors/w3creport.py`, held byte-identical by
`scripts/w3c-rails-parity-test.py`; the same Python module is the reference
emitter that writes a v0.1 report from this harness's own report
(`agent-evidence-vectors --emit-w3c-report`), and
[`docs/W3C-V01-CONFORMANCE-APPENDIX.md`](W3C-V01-CONFORMANCE-APPENDIX.md)
is the appendix rendered from the manifest for the editor to reference.

`vectors-receipt-signature/` tests verifiers of signed decision receipts under
`draft-farley-acta-signed-receipts-03`: whether the signature is checked over
the canonical signing input, whether the key comes from an external key set and
is held to its validity window, and three further rules of Section 6.6. Each
member is judged twice, with the key set's windows and without them, so the
expected verdict is a property of the receipt and the keys presented rather
than of what a verifier says about itself. The window check is a SHOULD in that
draft, so those members are graded as the corpus README describes. Two of its
cases, each a reject and its conformant twin, were written by giskard09 and are
reproduced byte for byte from `giskard09/argentum-core`. Two readers judge it,
`corpora/receiptsignature.go` and
`packaging/agent_evidence_vectors/receiptsignature.py`, held to the same output
by `scripts/receipt-signature-rails-test.py`. Besides `vectors`, it is the only
corpus whose README writes down the contract the packaged harness runs a named
verifier through.

Neither predicate version above is typed by hand. Both are derived from the
`predicateType` each corpus manifest declares, and `scripts/count-gate.py`
refuses a version written here that its manifest does not support — the same
rule the vector counts already live under, for the same reason.

The AEE predicate's model is execute-and-attest, not match-and-assert: the
consumer recomputes the outcome from carried bytes instead of trusting a
producer-asserted verdict. This repository is a second, independently usable
implementation of that contract: any future producer of the predicateType
can self-certify; any consumer can reject a lying emitter.

Spec line references throughout the code are to the vendored predicate
specification (`spec/predicates/adversarial-execution-evidence.md`), in the
coordinate frame of the commit it was vendored at and no other. That commit is
recorded in [`spec/VENDOR-PIN.json`](../spec/VENDOR-PIN.json), written from git at
vendor time rather than by hand, and re-vendoring remaps every reference onto
the new line numbers in the same pass that copies the bytes.

Two gates keep the references honest, because a reference that points at the
wrong prose reads as evidence. `scripts/spec-drift-gate.py` covers the
`spec:<anchor-id>@<digest>` citations in the sources and
`scripts/spec-anchor-gate.py` covers the `Lnnn` anchors in the vector tables.
Both ask the same two questions, and the second is the one that matters: not
only whether a reference still resolves to text, which a stale pointer does
perfectly well, but whether it still addresses the prose it was written for.
[`spec/CITATION-ANCHORS.json`](../spec/CITATION-ANCHORS.json) and
[`spec/ANCHOR-PINS.json`](../spec/ANCHOR-PINS.json) record the text each reference
was drawn around, so a reference that comes to address different prose fails
rather than resolving quietly. A citation names an anchor rather than a line
number for the reason the paragraph above gives: line numbers into a file that
is periodically re-vendored rot by construction, and an anchor and its digest
survive a reflow that moves every line. The shared machinery is
`scripts/specpins.py`.

Both ledgers are refreshed by the same command that re-vendors, which is the one
operation that moves references, so they also have to be trustworthy across
their own refresh. A refresh refuses to record a reference that came off prose
the document still contains: upstream may rewrite a passage freely and the
excerpt follows it, but a remap that simply lost track of a passage stops the
vendoring and names what it lost. Shortening counts, and it is the quiet case. A
range that still opens on its subject and now stops before prose it used to
cover has walked away from that prose as surely as one that jumped elsewhere, so
the refusal prints the lines it dropped and does not care whether they were lost
by a remap or removed by hand. A move onto genuinely different prose is still
allowed, one citation at a time and by name, because no gate can read a claim
and judge which paragraph settles it.
