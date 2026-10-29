# Verifying the provenance of supply-chain artifacts: what a relying party checks

Outline for a working-group paper, proposed to the OpenSSF Global Cyber Policy working group as the follow-on to the joint OpenChain and OpenSSF white paper. It starts from [ossf/wg-globalcyberpolicy#118](https://github.com/ossf/wg-globalcyberpolicy/issues/118).

**Audience.** Procurement and compliance staff, open source program offices, stewards and maintainers who receive SBOMs, provenance, attestations and review records and have to decide whether to rely on them.

**Method.** Every check in the paper is stated in terms of the public standards (in-toto attestations, SLSA provenance, DSSE, Sigstore) and can be run against the shared test records in [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors), which ship with expected verdicts and negative cases. The pinned install line is `pip install agent-evidence-vectors==0.30.0`.

## Sections

1. **The gap.** The white paper asks producers for artifacts and does not say how a receiving party tells a genuine one from a fabricated one. Draws on: the white paper's evidence sections; issue 118.
2. **What a relying party holds.** The artifact, the signer, the claim and the thing described, and which of the four the receiver can recompute for itself. Draws on: in-toto statement layout, DSSE envelope.
3. **Bind the artifact to what it describes.** An artifact names its subject by a digest the receiver recomputes, so a valid signature cannot be carried over to a different build. Draws on: SLSA provenance subjects; the artifact-binding corpus.
4. **Say what question it answers.** An artifact carries the question it answers, the version it answers for and its date of issue, and the receiver rejects one that answers a different question. Draws on: in-toto predicate types; the artifact-binding and dependency-selection corpora.
5. **Who may sign, and who vouches for the signer.** Signer identity, key custody and the transparency log, and what each does and does not establish. Draws on: Sigstore (Fulcio, Rekor), DSSE; the receipt-signature corpus.
6. **A history that was not rewritten.** Chains and anchors, so deleting, reordering or rolling back records signed by the system itself is detectable after the fact. Draws on: the anchored-chain corpus.
7. **Deciding, and what stays unchecked.** The relying party's own policy turns checks into an accept or reject, and each check lists what it cannot show. Draws on: the admission corpus; the CRA and AI Act table in [orcwg/cra-hub#364](https://github.com/orcwg/cra-hub/pull/364) for the regulatory consumers of this evidence.

## Status

Outline only, published for the working group to react to. Section drafts follow in this repository's `docs/` as pull requests, each runnable against the corpora named above.
