This vendors the reject corpus from the issue-1 comment into `conformance/anchor-stream/`. One workflow runs it against anchors_verify.py on every push that touches either. It is a draft because the shape needs agreement before the corpus contents do.

The workflow is a ratchet rather than a conformance gate, and that distinction is the whole design. Today 27 of the 32 members agree with anchors-verify-v0.10. A gate demanding 32 would go red the moment it landed. A gate that goes red on arrival lasts a week. So the recording in recordings/anchors-verify-v0.10.json names which members agree right now. The job fails only when a member that agreed stops agreeing.

It stays silent about the 5 that already disagree: those are the findings in the comment, and they are yours to close or to decline on their own terms.

I checked that it discriminates before proposing it. Pointed at the build it recorded, the ratchet exits 0. Pointed at anchors-verify-v0.4, it exits 1 and names 16 members by identifier, each with the outcome that build now returns, so a change to line splitting, boundary rules or binding arithmetic surfaces in the job that ran it. Nobody on your side has to remember what the last tag did.

Two commands, stdlib only, no network at run time, no install step. gen_vectors.py --check asserts the vendored copy is byte-identical to what the generator emits, so a local edit to any vector cannot pass unnoticed.

Whether the corpus does what its manifest claims is answered in my repository rather than yours, by a Go verifier that reads every corpus by its manifest and needs nothing from your CI: go build -o aee-verify ./cmd/aee-verify && ./aee-verify corpora/vectors-anchor-stream/ exits 0 over 32 members, 12 accept and 20 reject, and exit 1 names the member whose bytes moved.

The second command is the ratchet described above. The job borrows the actions/setup-python@v5 at 3.12 that census-diff.yml already uses. Its path filter keeps it off every other push.

Two things about the vendored copy itself deserve a note. VENDORED.json carries the upstream commit and the corpus digest. Re-vendoring is then a diff against a named revision rather than a fresh act of trust. And spec-vendored/ holds ANCHORS_VERIFY.md at anchors-verify-v0.4, pinned by sha256. That is the contract text I wrote the members against, and a tag is a name that can move.

That text, as written, requires two of the ten conditions. The other eight are corrections the corpus proposes, and every member carries a contractBasis field saying which: nothing here reads as a conformance failure against what you have actually published.

reason-map/ is the contested part. Every reject member declares a stop reason as well as an outcome, and the runner scores both. That is your own rule from 20 August, turned on your own verifier. Scoring a reason means matching your prose, because the stream format publishes no reason codes: that file is a per-implementation map, and it goes stale the moment you reword a message. A reason code in the format deletes the file. Until there is one, somebody maintains it, and that somebody belongs with the format, not with the corpus.

If you would rather not carry a directory, say so and I will close this. The corpus stays where it is. The run command in the comment still works against any tag, and nothing about the findings depends on whether this lands.
