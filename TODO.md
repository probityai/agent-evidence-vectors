# agent-evidence-vectors — roadmap

Open work for the conformance-vector suite and reference verifier of the in-toto
Adversarial Execution Evidence (AEE) predicate. Contributions welcome.

> **Session code-health audit 2026-07-24:** `go build ./...` + `go vet ./...` + `mypy` all
> **CLEAN** — no findings for this repo. Combined cross-repo report:
> an internal audit report.

## Status: v0.7 review (in-toto/attestation#570)

The reviewer's independent from-spec checker went 138/138 on the earlier corner-case
features and conceded every open corner. The predicate has since moved to v0.7 and this
repository has moved with it: the specification is vendored, both reference rails
implement the four commitments it adds, the corpus is regenerated at the new type, and
the forcing ratchet is re-measured. The reviewer has now read v0.7 as well, at
suiteRevision 22 on
2026-08-03: a blind first run of 179/232 and a directed pass of 232/232, both recorded in
`docs/INDEPENDENT-RUNS.json` with the null-digest caveat that checker's own index carries
for the blind build.

- [ ] **Await the reviewer's read on the revised proposal** — no code change pending on
  our side; the next step is the reviewer's call.
- [ ] **Ask for a run at the current suiteRevision.** The v0.7 run is at suiteRevision
  22 and the corpus is three revisions past it; the ledger records no run for any
  revision after that one and every published claim says so. The disclosure discipline
  for the revised vectors applies — publish the vectors without the text or the text
  without the vectors, never a note naming the failing vector and its fix.

## The corpus should not be scoreable without the specification

A rail's published score is only worth what the corpus makes it worth. If a vector's
label can be predicted from its surface then a rail can post a good number without
having implemented anything. `scripts/surface-leakage-gate.py` measures that directly.

The threshold is the corpus's own NULL: the same estimator over the same features with
the labels shuffled. That correction matters more than any single leak it found. The
gate first shipped refusing above a flat 0.55, and permuting the labels showed that a
corpus carrying no information at all scores about 0.54 on average and over 0.585 one
run in twenty, because the statistic compared is folded and cannot go below 0.5. A
round-number threshold was therefore unsatisfiable by any corpus of this size, and
calibrating it retired four rows that had confident causal explanations written
against what turned out to be sampling noise.

- [x] **Both readings a rail can take of a vector are compared** (2026-09-02), over both
  corpora, with every collision declared in `docs/VECTOR-COLLISIONS.json`.
- [x] **The surface-leakage gate is live, ratcheted and null-calibrated** (2026-09-02).
- [x] **The log-line vector has a statement of its own** (2026-09-02). It was
  byte-identical to the member-ordering vector, so the log-line condition was
  credited with a discriminator two other conditions already carried. This also had to land before
  identifiers can be content-addressed: a digest cannot give two byte-identical vectors
  two names.

Still open, and the first is the largest thing on this page:

- [x] **The historical corpus reader is deleted, and the gate that watched for its
  reason to lapse went with it** (2026-09-04). `historical_corpus_files` and
  `historical_corpus_digest` existed for one caller: `scripts/consumer-lag-gate.py`
  materializes the DEFAULT BRANCH's tree to learn what the consumer rails could actually
  have vendored, and until suiteRevision 28 landed there, that tree carried the retired
  per-verdict layout. It landed with the push of `7fcaebe`, and
  `scripts/historical-reader-expiry-gate.py` turned red on the very next CI run, which is
  what it was written to do. **The deletion was forced by a check rather than remembered
  by a person, and that is the whole point of the row.** Gone in this commit: both
  reader functions, the `KINDS` tuple that only they used, the two-layout dispatch that
  was the only place in the repository reading two layouts, the expiry gate itself, and
  its workflow step. `vectors/CHANGES.md` keeps its suiteRevision 28 entry describing the
  gate, because that entry was true of that revision and the ledger is not rewritten.
- [x] **`scripts/uncited-obligations-proof.py` fails its own sentence guard, and did so
  before this work** (2026-09-02). It pinned the specification at a normative/obligation
  sentence split that the vendored text no longer produces, so it refused before any case
  ran. Verified pre-existing by running it unchanged at the commit this work started from,
  where it fails identically. **The defect is that no workflow references it at all** --
  `ci.yml` never invoked it -- and the failing assertion is only how that became visible. A
  check nothing runs is the first member of the family the sixteen repointed readers belong
  to: it cannot report anything, so it cannot report that it has stopped applying.
  Both halves are done. The guard fired correctly on the re-vendor from `237f83b9` to
  `0dbe10bc`, and the sets were RE-DERIVED rather than the constants raised: each of the
  forty-five cited obligation lines was matched to its new line by the sentence text, all
  forty-five survive the re-vendor verbatim, and the two sentences it added are both
  dispositioned already -- L634 a SHOULD newly cited by `vd538496f284b4761`, L1556 a
  pointer to the rule stated normatively at L931-934. The proof now runs in `ci.yml`'s
  `go` job, which is where the Go toolchain it builds the external rail with lives.
  Two defects surfaced underneath it, both fixed in the same change: the row selector read
  the index tables by identifier prefix and both prefixes had stopped matching, so the
  ratchet was comparing the condition registry alone against the full set on record -- it
  now finds the vector table by its HEADER and refuses outright when it finds none, with a
  case in `uncited-obligations-proof-test.py` proving that refusal fires; and the
  `scoped_refs` mutation now kills three vectors where the pin named one, because the
  corpus gained `vc19ea5aaacc5b72a` and `v1a3d0ce04c3f7524`, which force the same sentence
  in shapes the first cannot reach. A coverage gain, pinned at three with the reason.

- [x] **The AI Agent Action corpus is content-addressed and flat** (2026-09-02). Every
  member is named after a digest of its own bytes and lives in `statements/`; there is no
  `accept/` or `reject/` directory and no prefix. Its identifier surface went from 1.0000
  — a perfect predictor — to 0.5245 against a null of 0.5245, and its whole surface from
  0.9238 to 0.7810. No old-to-new mapping is published: such a file would list a retired
  `ok-`/`bad-` name beside a live identifier for every member, which is the surface the
  change removed. `check_vectors.py` no longer branches on an identifier prefix; the one
  place it did now reads the conditions the vector declares, which is the better question
  anyway.
- [ ] **Content-address and flatten the AEE corpus too.** Its identifier surface is the
  same perfect predictor (1.0000 over the whole path) and the whole surface is 0.9906
  against a null of 0.6003. Simulating the fix puts it at 0.5568 against 0.5836, inside
  the noise floor, so this corpus goes fully clean where the smaller one did not.
  **`GOVERNANCE.md` does not block it**: the commitment is that an identifier is never
  REUSED, and renaming with permanent retirement is that clause honoured.
  It is structurally harder than the corpus already done, for one reason worth knowing
  before starting: **`vectors/accept/INDEX.md` is hand-authored AND is the input
  `vectors/gen_manifest.py` reads to derive every accept vector's id, kind, conditions and
  expectations.** A content-addressed id is a function of generated bytes, so a person
  cannot write it into that table by hand. The accept index therefore has to become
  generated — its per-row prose moving into `gen_valid_vectors.py` beside each vector, the
  way the reject generator already holds it — or the manifest has to stop deriving accept
  vectors from a markdown table. Neither is hard; both are larger than a rename.
  The rest is mapped: the name is chosen at five sites, no name appears inside any emitted
  vector's bytes (so there is no fixpoint problem), and the two-pass build used for the
  smaller corpus transfers directly. What must migrate with the ids: `INHERENT_EXTRA` (23
  keys), `OBSERVED_EXTRA` (19), `TIER_EXPECTATIONS` (6), `_SWAPPED` (14 pairs), `PARENTS`
  (21 prose keys), 22 `accept_parent()` literals and 195 `vec()` parent arguments. All four
  of those tables now refuse a key that names no vector, so a migration that drops one
  fails loudly instead of shipping a weaker pin.
  One consequence to state in the release: the corpus digest hashes `"{kind}/{name}"` into
  its preimage, and that definition is duplicated in every consumer rail's vendoring
  script, so flattening moves the digest for all of them at once. `vectors/CONSUMERS.json`
  records opaque ids and says on purpose that which checkout each refers to is supplied at
  sync time, so the rails cannot be updated from this repository. Naming the consequence is
  the deliverable; performing it is not ours to perform.

## The predicate moved to v0.7 and the corpus moved with it

Landed at suiteRevision 18. The vendoring, the rules, the regeneration and the ratchet
are one revision, which is what the drift gate was refusing the state between.

- [x] **Re-vendored and regenerated in one revision** (2026-07-31). The nineteen refused
  anchors were re-aimed by reading each against the claim beside it; three clusters
  moved, and the three sites quoting the passage the revision rewrote now quote what it
  says.
- [x] **Every statement and every rail re-typed** (2026-07-31), across both reference
  rails, the attestor schema, both generators, the manifest, and the three consumer
  rails in the sibling repositories.
- [x] **The conformance conditions minted with their vectors** (2026-07-31), twelve of
  them, because the registry gate refuses a row no vector cites and a vector citing no
  row.
- [x] **The reject side kept to one declared fault each** (2026-07-31). Forty-five
  vectors briefly carried the mandatory seal as a second fault and none does now: four
  parent shapes gained the seal, the seal-constraint family gained a healthy unreferenced
  one so it still measures its own rule, and the twenty-one that carry a second condition
  as an unavoidable consequence of their single mutation declare it in one table with one
  reason.
- [x] **Every new rule scored on the forcing harness** (2026-07-31). The first pass found
  eight rules the corpus did not force: each had a second acceptable condition an older
  rule reported first. Eight vectors were written for them and every rule is forced on
  both reference rails.

Still open here:

- [ ] **The vendored consumer directory carries a version number nothing derives.** It is
  named for the retired version and the version it actually carries is in the stamp
  beside it, which is checked. Renaming it to the new number would put the same unchecked
  constant back in the same place; the rename that fixes the class is to a version-free
  name, and it is a cross-repository path change touching the vendoring script, both
  consumer gates, the rego corpus generator, the differential fuzzer and several website
  tests. File: `scripts/vendor_aee_corpus.py` in the consumer repository.
- [ ] **The admission rego module reaches nine of the twenty-six new rejects.** The other
  seventeen are settled inside a base64 observation record that module deliberately never
  decodes, so they sit on its denylist with that reason. Reaching them means teaching the
  module to decode a record payload, which is a scope decision about the admission gate
  rather than a defect in it. File: `deploy/admission/rego/` in the consumer repository.

## The indeterminate bucket (added at suiteRevision 17)

`vectors/indeterminate/` carries the statements on which the specification settles the
verdict and not the condition. It has one family, `signature-count-vs-payload-decode`,
and the enumeration behind that number is in `docs/interpretation-decisions-open.md`
under suiteRevision 17.

- [x] **The three consumer copies carry the published corpus** (2026-07-31). All three
  were re-vendored at suiteRevision 18 and the ledger records what each carries;
  `scripts/consumer-lag-gate.py --check` is green.
- [ ] **Ask upstream for the envelope-shape-before-payload sentence.** If it lands, the
  family becomes a reject vector and the readings collapse to one. The ask is recorded in
  `docs/interpretation-decisions-open.md`; nothing here is blocked on it.
- [ ] **A discriminating member for the `bad-749` wrong-type question.** The parse
  catch-all versus the specific condition is the same class of open question, and it stays
  a reject vector only because no second member exists that could separate the two
  readings. A family of one member and two readings cannot be incoherent, so it would be a
  widened expectation wearing a different hat. Construct the member or leave the reading
  argued.
- [ ] **The consumer-policy freedoms are still invisible.** A consumer MAY admit
  `pass_indirect`, MAY reject `unattested` substrate rows outright, MAY bound a key with a
  validity window, MAY run the posture coherence check. None of these can move the verdict
  this suite reads, so no single-statement vector can see them, and two conformant
  admission policies can differ completely while scoring identically here. Closing it needs
  an admission-level surface in the external-rail contract, which is a bigger change than
  this bucket and should not be smuggled into it.

## Standards-ecosystem interoperability

- [ ] **SARIF v2.1.0 output** — an `aee-in-sarif` convention doc + emitter so a verifier
  run lands as findings in the GitHub Security tab and any SARIF-consuming tool. Speaks a
  format security teams already ingest.
- [ ] **Framework crosswalk (`.md` + machine-readable `.json`)** — map the AEE evidence
  model and each conformance-vector class to OWASP MCP Top 10, the OWASP Agentic Security
  Initiative Top 10, OWASP AIVSS, and MITRE ATLAS, so findings land in the frameworks
  defenders already report against. Regenerate the table from the vectors; do not hand-edit.
- [ ] **`GOVERNANCE.md`** — document the decision process for new conformance vectors and
  schema changes, deprecation policy (IDs never reused), and the crosswalk-update process.
  Publish the record `$schema` at a stable URL.

## Suite hygiene & citability

- [ ] **Paired positive/negative fixtures per vector** — for each conformance vector, a
  short `<id>_positive` / `<id>_negative` fixture pair so any implementation's detection
  logic can be tested against the standard, with the logic living in the implementer's repo.
- [ ] **Claim -> verdict-token -> reproduce-command manifest** — a table mapping each thing
  the suite asserts to (a) the exact verdict token a verifier emits and (b) a one-line
  command an evaluator runs to reproduce it, so nothing has to be taken on trust.
- [ ] **Shippable tamper-evidence demo** — a dependency-free script that corrupts a copy of
  a signed record two ways (flip one byte, drop one entry) and shows the verifier catches
  each, recomputing from the record's own stored bytes (no re-serialization false alarms).
- [ ] **Citable dataset DOI** — mint a Zenodo (or equivalent) DOI for a tagged release of
  the conformance-vector corpus so it can be cited in papers and reports.
- [ ] **Cut the vendored-revision tag so the pin stops being merely currently-true**
  (OPERATOR, remote write — deliberately not done here). `spec/VENDOR-PIN.json` now names
  `astrogilda/attestation` at branch `predicate/adversarial-execution-evidence`, which
  contains the pinned commit today. A branch head moves, and this one already has: the
  branch tip was `0dbe10b` when the corpus was built and is `a4cb887` now, with a third
  commit sitting unpushed locally. A tag pointing at the commit does not move. Two
  commands, run against a checkout of the fork:

  ```
  git -C ~/Documents/git-clones/attestation tag -a vendored/aee-0dbe10bc \
      0dbe10bcc959b63dc42370a5db09812c9476f59a \
      -m "Specification revision the agent-evidence-vectors corpus certifies against"
  git -C ~/Documents/git-clones/attestation push fork vendored/aee-0dbe10bc
  ```

  Then re-derive the pin, which flips `refKind` from `branch` to `tag`, and regenerate the
  two documents that quote it:

  ```
  python3 scripts/vendor-spec.py --from ~/Documents/git-clones/attestation \
      --ref vendored/aee-0dbe10bc --remote fork
  python3 vectors/reject/gen_invalid_vectors.py
  python3 scripts/condition-forcing-gate.py
  ```

  That whole sequence was dry-run against a throwaway clone of the fork before being
  written down, which is how the annotated-tag peel bug in `vendor-spec.py` was found: the
  pin recorded the tag OBJECT's sha as `commit` and the digest check passed anyway. Fixed
  before this was committed, so the commands above are the corrected ones.

## Supply-chain posture

- [ ] **OpenSSF Scorecard workflow** — add `ossf/scorecard-action` and publish the badge.

## Predicate ergonomics

- [ ] **`honest_limits[]` + `contract_version` fields** — machine-readable declaration of
  exactly what a given evidence record does and does NOT cover, and the predicate contract
  version it was produced under, so a consumer can reason about scope explicitly.
- [ ] **Fail-closed client hygiene** — for any network path a verifier may use, enforce
  immutable config, single-flight, error-on-redirect, and coerce-unknown-toward-reject.

## Known gaps in the gates

- [ ] **The packaged harness judges three of the eleven corpora it ships** -- found
  2026-09-25 while cutting 0.12.1. Until then `agent-evidence-vectors --corpus <name>`
  ran the AEE reference rail over eight other predicates' corpora and printed that rail's
  failures as the corpus verdict: most members of `vectors-aci` and every member of
  `vectors-scitt-cose` printed as failing, and each corpus is judged clean by its Go reader. The harness now refuses those suites by name with
  exit 2 and points at `aee-verify <corpus-dir>`, and the release replays every shipped
  corpus and accepts only judged-clean or refused-by-name. What remains: a `pip install`
  user cannot judge eight shipped corpora without Go. Fix: port the eight readers in
  `corpora/` (aci, acs-core, ai-agent-action, anchor-stream, artifact-binding,
  mcp-record-contract, mcp-response-phase, scitt-cose) into
  `packaging/agent_evidence_vectors/`, each with a parity test against its Go reader in
  the shape of `scripts/w3c-rails-parity-test.py`. Gain: the wheel alone judges every
  corpus it ships, and the release replay can then require exit 0 for all of them.
- [ ] **The external-verifier contract is written for the AEE corpus only, yet a named
  verifier runs against every suite whose manifest the generic evaluator reads.** A
  verifier run over `vectors-aci` reports conform and reason-parity figures computed by
  the AEE evaluator's reading of another predicate's manifest, and no document says the
  comparison means the same thing there. Fix: write a per-suite external contract
  (verdict, codes, what `expected` means) beside each corpus, and have the harness refuse
  a named verifier on a suite with no written contract, as it already does for the W3C
  report and Observed Effect corpora. Gain: every figure the action reports for a
  non-default corpus is backed by a stated contract.
- [ ] **A merge subject is linted only after it lands on `main`.** On 2026-09-25 the
  merge `fb24c6d` carried a 76-character subject and `commit-message-lint` failed on
  `main`. The next push cleared it, because the lint scopes each push to `before..HEAD`,
  but `main` sat red in between. `gh pr merge --subject` posts the subject as typed and
  nothing checks it first. Fix: a `pull_request` job that lints the subject this
  repository composes for a merge (`merge: <lowercase PR title>`), and a line in
  CONTRIBUTING.md stating that convention so the subject is derived rather than typed.
  Gain: no red `main` from a merge subject.

- [ ] **The pre-push gate reads the revision it was handed and the push sends whatever
  the ref points at when it connects** — observed 2026-09-11. The hook was handed
  `b0da972` on stdin, printed `running every workflow shell step against b0da972`, ran
  the full mirror for eighty-nine minutes, and passed. During those eighty-nine minutes a
  commit landed on `main`. The push then reported `93deb47..b0da972`, and
  `gh api repos/.../git/ref/heads/main` came back `9371c5d` -- a commit the gate never
  read. It went green on the remote, so nothing was lost this time, and that is exactly
  what makes it worth a row: the hook's own header names the FALSE PASS (fix a file,
  do not commit it, and the gate reads the repaired tree while the push carries the
  broken commit) and this is the same false pass arriving through a different door,
  opened by the mirror being slow enough for the tree to move underneath it. The fix is
  for the hook to re-read the ref after the gate returns and REFUSE when it no longer
  matches the revision gated, naming both. Do not close this by making the mirror
  faster; a shorter window is still a window.

- [ ] **`messagesDigest` pins one implementation's message prose, and the property it
  stands for does not** — `vectors-artifact-binding/MANIFEST.json` gives every member a
  digest over the reference verifier's own sorted message list, and
  `vectors-artifact-binding/check_vectors.py` recomputes it. It exists for a real hole,
  measured: a member already expected to fail absorbs a second fault of the same class
  in silence, because both faults raise the same code and the member identifier covers
  the record rather than the files the record names. What it hashes, though, is English.
  Porting the check into `corpora/artifactbinding.go` verbatim failed two of eight
  unmutated members, because the Go reader words its findings differently, so the digest
  as specified cannot be satisfied by a second implementation without copying the first
  one's wording. That is why this corpus keeps a Python checker after the other five were
  deleted, and why the Go reader carries only the implementation-independent half of the
  same fix (the emitted code set must equal the declared one, not merely contain it).
  Replacing the digest with an invariant any implementation can meet, over the set of
  FILE PATHS the findings name rather than their prose, would let the check move into the
  Go reader and the Python checker go the way of its five siblings. The operator's call;
  nothing is broken while it stands.

- [x] **The corpus cannot be regenerated from the sources it declares** — CLOSED at
  suiteRevision 16. Both generators now build all seven vectors, both index tables carry their
  rows, `python3 vectors/gen_manifest.py` exits 0 and is idempotent, and the heading check in
  `scripts/count-gate.py` reads the manifest with a one-row-per-vector-per-family assertion
  beside it. The two accept vectors regenerate byte-identically from the committed files; the
  five reject vectors do NOT, and the reasons are the two rows below.
- [x] **Nothing asserts that the manifest is reproducible** — CLOSED by
  `scripts/regenerability-gate.py`, wired into `.github/workflows/ci.yml`. It copies the tree,
  empties the generated set, runs all three generators and diffs. Run against suiteRevision 15
  unmodified it names all seven vector files and the manifest.
- [x] **The whole tier derivation was forced by one vector** (2026-07-31) -- the corpus pinned
  the derived per-row evidence tier for one of its fifty-two accept vectors, and the harness
  compares a tier column only where the manifest states one. Measured by mutation, five
  single-site weakenings of `aee/tier.go` were killed by `ok-024` and by nothing else, so
  retitling or dropping it would have retired five rules at once with every gate green. The
  tier-partition invariant added the same day hardens the Go rail and cannot see this: the
  measurement replays through `cmd/aee-verify` under `packaging/run_vectors.py` and never loads
  a Go test file. Five more accept vectors now pin their columns -- three whose index rows
  already asserted a tier in prose, two that gained the claim -- each derivable from the
  vector's own bytes rather than recorded from a rail's answer. The five sites move to between
  two and four forcing vectors, three sites outside `tier.go` gain vectors for the same reason,
  and the delta is additive everywhere: nothing lost a vector, nothing changed class.
  Mutation-checked by deleting `ok-024` outright: without the new pins all five go SILENT, with
  them all five stay KILLED.
- [x] **A directory of vectors in another encoding was invisible to the corpus runner**
  (2026-07-31) -- `checkManifestClosure` asked whether an unrecognised directory held vector
  files and decided vector-ness by file suffix, so a directory carrying the same statements as
  `.cbor` held no matching file, passed the kind check silently, and contributed to no per-kind
  count either. The two non-vector directories are named explicitly now and every other
  directory must be a manifest kind whatever it holds. Verified both ways against a real
  non-JSON vector directory. File: `aee/vectors_test.go`.
- [x] **The published harness scored a vector no manifest row named, and only noted it**
  (2026-07-31). Copying an accept vector to an unlisted name and running
  `python3 packaging/run_vectors.py` exited 0, printed a total one greater than the corpus size
  with every vector passing, scored the unlisted file PASS against a verdict derived from its
  directory, and reported the fact as a `note:` line. That was the wrong way round twice over:
  this is the rail the forcing measurement replays through and the one a third party runs, and
  the total it prints is where the published corpus size comes from, so an unlisted file
  inflated it silently while the Go runner refused the same tree by name. The note is a refusal
  now, and the closure is the one the Go runner makes: both directions per kind, the manifest's
  own counts block checked against the tree, every row's declared file member checked against
  the path the rail reads, and every directory under the suite root required to be a manifest
  kind or one of two named non-vector directories whatever it holds. `discover_vectors` took
  its three directory names from a literal, so a fourth was walked by nothing; it reads the
  kinds the manifest declares now, and a kind no contract here scores is refused by name rather
  than falling through to the reject contract. Suite-level refusals are carried in the totals
  in their own right, because reporting them only through the exit status leaves a table
  reading zero failures beside a non-zero exit. Mutation-checked over a copied tree against
  eleven weakenings -- an unlisted file, a deleted file, a fourth directory holding JSON, the
  same directory holding another encoding, a count inflated by one, a count naming an absent
  kind, the counts block dropped, a row retyped to a kind nothing scores, a whole kind removed
  from the manifest, a row's file member pointed elsewhere, and a vector smuggled into the
  keys directory -- each refused by name with the untouched copy green.
  File: `packaging/run_vectors.py`.
- [ ] **No statement carrying a pinned row can recompute above `fail`, so the attribution
  assignment cannot be exercised at a result any threshold-only consumer would admit.**
  Measured 2026-07-31 by construction and replay rather than read off the rules, because the
  reading this replaces cited `bad-982` as the demonstration and `bad-982` cannot be one: it
  carries `result: fail` with both rows caught, so a threshold consumer refuses it for the
  result and the assignment is never reached. The sweep builds every statement shape the
  reject generator can express -- record pools over every subset of the five record kinds,
  every reference subset within each pool, both bases, both methods, a caught
  label, a clean label and one outside the carried vocabulary, and coverage both complete and
  incomplete -- and scores each on the reference rail twice over, changing nothing between the
  two runs but the value of `attribution`. Under `paired` the sweep reaches `pass`,
  `pass_indirect` and `degraded`. Under `pinned` every valid statement recomputes to `fail`
  and not one reaches higher, and every shape the control reached above `fail` turns
  `attribution-pinned-recordless` the moment the member is raised. The reason is two coverage
  requirements this corpus already forces against each other: a pinned row must resolve an
  interception record (`bad-958`, `bad-973`) and a clean row must resolve none (`bad-950`), so
  a valid pinned row always carries a caught label, and a caught label floors the recompute.
  The consequence for `bad-982`, which exchanges the pinned assignment between two rows, is
  that no rewriting of it and no vector anyone could add would lift it above `fail`: a consumer
  admitting on `result` alone refuses it for the result and never reaches the assignment. The
  pair that does discriminate is already published -- `ok-051` carries the same two pinned rows
  with the assignment intact -- so a consumer that credits rows separates the two and one that
  does not gives both the same answer. What is left is a question for upstream rather than a
  gap here: an axis that acquired a normative reader at this version is readable only on
  statements a threshold consumer has already refused, and it is worth asking whether that is
  intended.
- [ ] **Three shipped reject vectors carried a signature that does not verify, and nothing
  in the corpus could see it.** `bad-900`, `bad-901` and `bad-902` were minted by copying the
  parent's signature across a mutated payload. The reject generator's own second-fault
  self-check refuses all three on sight, and this directory publishes the invariant that every
  committed signature verifies, because signature verification is tier territory rather than
  validity. The three are rebuilt and correctly signed at suiteRevision 16, so the instance is
  closed; what is open is that no gate would have caught it. `packaging/run_vectors.py` never
  verifies a signature it is not asked about, and the generator self-check only sees bytes the
  generator built. A check that ran the self-check over the COMMITTED files, rather than over
  the freshly-built ones, would close it. File: `vectors/reject/gen_invalid_vectors.py`.
- [ ] **The two vector generators carry two different constant sets for one suite.** The
  accept generator's catch-policy pre-image, posture pre-image, run-entropy pre-image, corpus
  name and corpus uri all differ from the reject generator's, and each index publishes its own
  as THE determinism recipe. Five vectors were minted with the accept set and filed under the
  reject recipe, which no reader of either index could have detected and which is invisible to
  every gate here. Unifying them is a revision-scale change rather than a fix: every reject
  vector and every digest it carries would be re-minted. Recording it is the point until then.
  File: `vectors/reject/gen_invalid_vectors.py`, `vectors/accept/gen_valid_vectors.py`.
- [ ] **`ok-900` and `ok-901` each cite `aee-c-1` and neither is about the result
  vocabulary.** `ok-900` pins the minimum composition, which is `aee-c-2` with `aee-c-3` and
  `aee-c-6` beside it; `ok-901` pins the fail-closed basis branch, which is `aee-c-5`. The ids
  were hand-typed into the manifest at suiteRevision 15 and are preserved verbatim so the
  manifest's per-vector content did not move while its regenerability was being fixed.
  Correcting them is a one-line edit to each index row and a manifest regeneration.
  File: `vectors/accept/INDEX.md`.
- [ ] **Forcing is measured against ONE rail, so a rule only the Python rail states is
  invisible to it.** `scripts/forcing-gate.py` weakens `aee/` and replays; a rule the Go rail
  does not implement has no mutation site and therefore no row, and the two first-party rails
  are held to one vocabulary by `scripts/code-contract-gate.py` but not to one rule set. The
  same measurement over `packaging/run_vectors.py` needs a Python mutation operator set and a
  second baseline. File: `scripts/forcing-gate.py`.
- [ ] **A weakening the operator set cannot express is scored as nothing at all.** The twelve
  operators switch off a guard, a disjunct, a conjunct, a switch arm, a bool return or an
  emission, or close a collection loop after one member. A rule that lives in a constant (a
  bound, a depth cap, a media type), in the ORDER
  of two checks, or in a data table is not a site, so it appears in no class -- not even as a
  gap. 808 sites is the size of what can be asked, never the size of the rail. File:
  `cmd/mutgen/mutate.go`. PARTIAL: the quantifier case, which was the largest named hole in
  this row, is now expressible -- `LOOP_FIRST` turns "for every member, P" into "for one
  member, P" and found 31 universals this corpus does not force as universals. The constant,
  the ordering and the data-table cases are untouched, and this row stays open for them.
- [ ] **Twenty-four universals sit on a loop every vector enters and no vector exercises
  twice.** The quantifier operator records 26 DEAD sites, and 24 of them carry
  `branch: taken`, which is the sharp reading -- vectors do reach the loop, and none of them
  carries a second member whose treatment matters, so the rule's "every" is untested while
  the rule itself is covered. Each is a vector somebody could write, and unlike the
  never-taken pair they need no new reachability. The named ones a specification universal
  maps onto directly: `validity.go::anyObservationRefOutOfRange` (`aee-c-11`, every ref index
  on every row), `tier.go::recordVerifies` (`aee-c-33`, every covering signature verifies),
  `verify.go::tierPolicySatisfied` (`aee-c-34`, every substrate row unattested without a
  pinned root), `commitments.go::sealsCommitToCarriedSet` (`aee-c-97`, every carried sealed
  record), `commitments.go::sealNamedAttacksCaught` (`aee-c-98`, every attack the seal
  names) and `statement.go::gate0ExpectedPayloads` (`aee-c-103`, every key and every array).
  File: `docs/FORCING-BASELINE.json`, `vectors/reject/gen_invalid_vectors.py`.
- [ ] **The 185 unforced rules on branches no vector takes are a list, not a plan.** The
  nightly sweep re-derives which surviving mutants sit on a branch the corpus never enters,
  which is the evidence separating a mintable gap from one no new vector could close. Nothing
  yet drives that number down, and nothing distinguishes the rules worth a vector from the
  ones that are unreachable for a reason. The figure in this row is also not derived by any
  gate: the count gate accepted 157 here and accepts 185, so nothing was holding it to the
  baseline while the baseline moved under it. File: `docs/FORCING-BASELINE.json`.
- [x] **A sweep taken across two corpora was recorded as a measurement of one** (2026-08-02) --
  the worker trees symlink the corpus rather than copying it, so every mutant re-reads the
  vector files, while the manifest, the per-vector self-check and the unmutated observations
  each mutant is diffed against are read once at the start. A corpus written mid-campaign
  therefore makes a vector answer one way for the baseline and another for whichever mutants
  are in flight, and the difference is scored as those mutants killing it. That is how one rule
  came to be recorded as forced by two vectors that cannot reach its branch. CLOSED: the
  campaign now digests the manifest and every vector before the unmutated replay and again
  after the last mutant, and refuses rather than reporting a number.
- [ ] **A killed mutant on a branch no vector executes is a contradiction, and nothing says so.**
  The wrong row above sat next to measured coverage evidence, in the same file, saying the line
  it mutates is never executed -- and next to an equivalent mutation of the same line carrying
  the opposite class. The obvious check refuses a KILLED classification whose site line has an
  execution count of zero, and it is NOT sound as stated: `IF_OFF` rewrites a condition to
  `false && (COND)`, which short-circuits, so a guard whose CONDITION has side effects can be
  killed with its branch never taken. `types.go::parseEnvironment::IF_OFF::d57c9f848201` is
  exactly that -- the condition is `!decodeManifest(env.Corpus)` and the call populates the
  manifest for every statement -- and it is legitimately killed by most of the corpus at once.
  Making the check sound needs
  `cmd/mutgen` to report whether the expression it mutates contains a call, and the refusal
  restricted to the sites where it does not. File: `scripts/forcing-gate.py`,
  `cmd/mutgen/mutate.go`.

- [ ] **A corpus change that lands and is never followed by a refresh reddens the
  default branch, not the change that caused it.** The consumer-lag gate measures the
  vendored copies against the corpus the default branch publishes, because that is the
  only corpus a rail in another repository can fetch; a branch that adds vectors
  therefore passes, correctly, since no rail is behind anything yet. The obligation
  arrives at the merge and the signal is a red default branch until every copy is
  refreshed and `--sync` records it. Nothing here can make the signal arrive earlier
  without requiring a rail to vendor an unpublished commit, which is the deadlock the
  measurement was changed to remove: the branch could not be pushed until the rails
  carried it, the rails could only carry a published corpus, and the corpus could not be
  published because the push was refused. File: `scripts/consumer-lag-gate.py`.
- [ ] **A vendored copy that is refreshed, recorded, then reverted stays green.** The
  consumer-lag gate compares `vectors/CONSUMERS.json` against the corpus the default
  branch publishes,
  and that ledger records what each copy carried when it was last synced. A copy reverted
  after its sync would keep a stale ledger entry that still matches, and the copy's own
  stamp check cannot see it either, since a revert plus a re-stamp is internally
  consistent. Closing it needs this repository to read the consumer, which is the
  cross-repository read the gate is built to avoid. File: `scripts/consumer-lag-gate.py`.
- [ ] **A vendored copy no document advertises and no ledger row records is invisible.**
  A copy absent from `vectors/CONSUMERS.json` was reported as success, because the gate
  counts the rows it was told about and its message says it counts the copies that exist.
  That is now closed on one axis: the number of rails the implementation report names has
  to equal the number of rows, so a rail advertised with nothing recorded behind it fails.
  What is left is the copy nobody wrote down anywhere. The report and the ledger agree
  with each other, both are silent about it, and no reading of either surfaces it — only
  a sweep of the consuming stacks would. File: `scripts/consumer-lag-gate.py`.
- [ ] **A citation cut short of its subject is invisible when every word it lost was also
  rewritten.** The sync now asks its own question line by line as well as span by span,
  which closes the truncations that dropped prose upstream left alone. What remains is
  the case where the dropped words were themselves amended: nothing survives to be
  looked for, the span is simply shorter than it was, and that is the same event as a
  legitimate narrowing onto a tightened rule. Measured over every re-vendor where the
  remapper was live, no rule on the two documents separates them. The extent of the span
  is the only signal left and it does not discriminate: at suiteRevision 14 a three-line
  citation collapsed to one line inside a rewritten paragraph and was wrong
  (`aee/pae.go::IsLowerHex64`, which lost the words naming the digest value form), while
  at suiteRevision 13 six anchors collapsed three lines to one in the same way and were
  right (`bad-810` and its siblings, where the heading alone carries the requirement).
  Both narrow to a third of their former text. Further out the order inverts: a span cut
  to a sixth was accepted (`bad-727`, where the old anchor had run past its subject into
  the next clause) while spans cut to a fifth were repointed. Deciding between them needs
  the words the claim beside the citation depends on, which was measured and rejected
  when these pins were built, because a claim may name an identifier in passing and a
  citation may legitimately cover several passages, so it needed a standing per-citation
  exemption list. That list is the blessing the ledger exists to remove. The honest
  position is that this residue is a review question with the evidence attached, not a
  gate, and the sync prints the dropped prose so the reading is targeted rather than
  exhaustive. File: `scripts/specpins.py`.
- [ ] **The number profile is integers-only and the specification asks only for safe
  integers.** `checkSafeInteger` rejects any JSON number carrying a fractional part,
  anywhere in a canonicalized payload, including inside members the specification leaves
  to the producer ("everything else in the payload stays producer territory", L977-979).
  What the document states is the safe-integer bound (L83-85, and L856-858 for record
  payloads); it declares every numeric member it defines an integer and states no rule
  against a fractional number elsewhere. The rails reject one anyway, so cross-language
  float formatting can never split them, which is a real reason and a different one from
  conformance. No vector distinguishes the two readings, so a from-spec verifier that
  accepts `1.5` in producer territory is conformant and passes this corpus today. Decide
  whether to ask upstream for the stricter profile or to narrow the rails. File:
  `aee/jcs.go`.

- [x] **A duplicate record and an undecodable one shared a guard, and no statement
  paired them** (suiteRevision 22). Both rails ran the duplicate scan inside the same
  condition as the batch-root recompute -- did every record decode -- so one record
  failing base64 switched off both, and a statement carrying a duplicate beside an
  undecodable record reported the decode failure and dropped `duplicate-record`. The
  corpus could not see it because no statement carried both conditions;
  `v7622b2c58c2e272d` does now. The Go rail was split first, the
  Python reference rail carried the same masking with a comment saying it was mirroring
  the Go rail, and both are split now: the scan runs over the records that decoded and
  skips the ones that did not, and the root check stays behind the decode guard, where
  it belongs. Files: `aee/validity.go`, `packaging/run_vectors.py`.
- [ ] **The vector above cannot fail the harness, and no reject vector in its shape
  could.** A reject expectation is a code SET the harness conforms a rail's answer by
  INTERSECTING, deliberately, so that a strict rail naming one condition and a
  superset-emitting rail naming every condition both pass the same manifest. Both of this
  vector's conditions sit in one expected set and in one gate stage, and
  `record-undecodable` is emitted first, so the primary code is the same with the defect
  present or absent -- measured: the whole corpus replays green through a rail with the
  shared guard restored. So the assertion that both conditions are reported lives in each
  rail's own oracle instead (`TestSetEmissionOnPairedRecordFaults`, and two checks in
  `run_vectors.py --self-test`), which is where a claim about THESE rails belongs rather
  than in the contract a third party is held to. What is still missing is any way for the
  corpus to say "a rail that emits sets must emit both of these" without demoting a
  single-code rail, and until there is, a defect of this shape is visible to the forcing
  campaign as a changed observation and to nothing else. Files: `packaging/run_vectors.py`,
  `aee/vectors_test.go`.
- [ ] **`bad-817` cites `aee-c-19` for a decode failure, and `aee-c-19` is the media-type
  rule.** The registry has no condition for the rule a payload breaks by not
  strict-decoding from base64 -- the DSSE envelope sentence at L1243-1245 -- so the only
  reject vector for `record-undecodable` borrowed the id belonging to `bad-204`, and its
  spec anchor `L1231-1234` addresses prose about `basis` and `method` that has nothing to
  do with encoding. The pin ledger froze that anchor because it can only judge an anchor
  that MOVES, never one that was wrong when it was first recorded, which is worth stating
  separately: it is a real limit of the mechanism. `bad-410` cites `aee-c-29` alone and
  anchors L1243-1245 directly rather than repeating the wrong id. Closing it means minting
  the missing condition, re-citing both vectors, re-syncing the anchor pin and the
  accept-anchor baseline, and restating the traceability figure, which is why it is a row
  and not a patch. Files: `vectors/reject/gen_invalid_vectors.py`, `spec/ANCHOR-PINS.json`.
- [ ] **The three consumer copies are behind suiteRevision 22.**
  `scripts/consumer-lag-gate.py --check` is red by design until each vendored copy is
  refreshed in its own repository and this ledger is re-read from the copies with
  `--sync`. Nothing here can close it: the sync reads each rail's own stamp on purpose, so
  that a run against a stale copy records the stale digest instead of greening itself.
  File: `vectors/CONSUMERS.json`.

- [ ] **Nothing compares an interpretation entry's anchors with the anchors its own
  prose quotes, outside the registry.** The registry gate now requires an entry's
  `specAnchors` to cover every line reference its title or reading makes, which is what
  found four entries whose recorded anchor sat two lines above the words the entry puts
  in quotation marks. The same disagreement is possible in `vectors/CHANGES.md`,
  `vectors/coverage-unforced.json` and `docs/interpretation-decisions-open.md`, which
  carry anchors and prose side by side with no equivalent check.
  File: `scripts/interpretation-registry-gate.py`.
- [x] **A row selector could go dead and every count derived from it stayed plausible**
  (2026-09-02) -- the anchor gate's vector-row selector was spelled `bad-\d` and matched
  zero of the two hundred and nine reject-index rows from the day identifiers became
  content digests, so only the condition rows of that file were compared against the source
  row that records them and every vector row fell into a whole-file question that passes
  whenever any unrelated entry cites the same line. Every selector in the gate now declares
  the files it is aimed at and `dead_selectors()` refuses a run in which one matches
  nothing, on `--sync` as well as on a check; a deliberate zero must say so in
  `Selector.silent` in writing. The gate publishes the keyed-versus-unkeyed split on every
  run, so the figure moves when a reader goes blind and is read from the run rather than
  copied to here, where nothing would re-derive it. Mutation-checked by restoring the dead
  spelling, which the gate refuses by quoting the pattern back.
  Files: `scripts/spec-anchor-gate.py`, `scripts/spec-anchor-gate-test.py`.
- [x] **An accept vector's specification anchor was pinned, remapped and compared by
  nothing** (2026-09-02) -- `vectors/accept/gen_valid_vectors.py` was in neither the anchor
  gate's `AUTHORED` nor its `GENERATED` list, so `L1700` had no pin; `ANCHOR_PATHS` in
  `scripts/vendor-spec.py` omitted the same file, so a re-vendor would have moved the line
  out from under an anchor it never touched; and the index row carrying it was matched by
  the dead selector above. All three are closed and `spec/ANCHOR-PINS.json` carries two new
  pins. The re-vendor omission was found only because pinning the anchor made the gate's
  own re-vendor test go red.
- [x] **`L1700` was a one-line anchor on a rule that spans four lines** (2026-09-03) -- the
  accept anchor map recorded `L1700`, which carries only the rule's subject, while both of
  the sentence's `MUST NOT`s sit on the two lines below it;
  `scripts/uncited-obligations-proof.py` had cited the same obligation as `L1700-1703` all
  along. One of the two had to move and the corpus says which: anchors in the three indexes
  are ranges far more often than single lines, a single line is used where that line carries
  the obligation, and suiteRevision 25 records widening four anchors for this exact reading
  -- a rule enforced while the anchor named a different line. Swept across all three indexes,
  no other span opened a sentence bearing a normative keyword and closed before the keyword
  landed. The map now records `L1700-1703`, `vectors/accept/INDEX.md` was regenerated, and
  both pins in `spec/ANCHOR-PINS.json` now close on `values and MUST NOT compose it by
  weakest input across records or rows`, which is the ledger's own proof that the span
  reaches the rule. The proof script is unchanged because it was already right.
  Files: `vectors/accept/gen_valid_vectors.py`, `vectors/accept/INDEX.md`,
  `spec/ANCHOR-PINS.json`, `docs/UNCITED-OBLIGATIONS.md`.
- [ ] **Two files carry `Lnnn` anchors that no ledger pins and no re-vendor remaps.**
  `vectors/indeterminate/INDEX.md` carries ten distinct spans over fourteen occurrences and
  `docs/UNCITED-OBLIGATIONS.md` carries more, and neither file is in the anchor gate's
  `AUTHORED` or `GENERATED` lists or in `ANCHOR_PATHS` in `scripts/vendor-spec.py`, so
  nothing pins them and no re-vendor moves them. This is the same shape as the
  accept-index gap closed on 2026-09-02, arrived at from the same direction: an anchor in no
  ledger survives a re-vendor pointing at whatever prose arrives, and nothing says so. The
  indeterminate index is hand-authored rather than generated, so it belongs in `AUTHORED`
  directly; the uncited-obligations document needs a reader's decision first, because its
  first column is a sentence identifier on the measurement's axis rather than an anchor and
  pinning the two axes alike would confuse them.
  Files: `scripts/spec-anchor-gate.py`, `scripts/vendor-spec.py`.

## Recently landed

- [x] **A named verifier runs, or the run fails** (2026-09-25, released as 0.12.1) --
  `--verifier` used to probe the command's first token for the predicate type URI and,
  when the probe missed, replace the verifier with the reference rail and exit 0 on that
  rail's pass. The harness now resolves the command the way a shell would, refuses one
  it cannot start with exit 2, records `verifier.vectorsExecuted`, and fails a short
  count; the action fails a job unless the verifier ran on every vector.
  `scripts/verifier-must-run-test.py` restores the fallback in a copy of the harness and
  requires itself to go red. Affected releases are listed in SECURITY.md.
- [x] **Make forcing a measured property rather than a periodic audit** (2026-07-30) -- what the
  corpus obliges a verifier to implement is now a number CI holds, not an argument. A vector
  count never measured it: the evaluator satisfies a vector when any expected code in a stage is
  observed, so deleting the `result-vocabulary` emission turns two vectors' gate-0 column FAIL
  and the suite still reports 186 of 186, exit 0. `cmd/mutgen` enumerates 590 single-site
  weakenings of the rail and applies one at a time, `cmd/mutrun` replays the whole corpus in
  process under both key policies, and `scripts/forcing-gate.py` scores each replay with the
  harness's own `evaluate_vector` and holds the result as a tighten-only ratchet against
  `docs/FORCING-BASELINE.json`: 331 KILLED, 17 SILENT, 237 DEAD, 5 INCONCLUSIVE. Site identity is
  content-addressed (file, function, operator, digest of the mutated source), so an inserted rule
  disturbs one row instead of renumbering every row below it. Proven able to fail in both
  directions: deleting `v495bb03f306ef6aa`, the sole forcer of the lowercase-hex digest
  rule, turns four rows red by name and restoring it turns them green, and deleting the
  `len(s) != 64` check from `IsLowerHex64` is refused as two retired rules. Per push CI runs the
  rules recorded as forced -- the complete set where a regression is possible, and the set already
  known to terminate -- for about 1670 CPU-seconds, against about 3370 for the full sweep a nightly
  workflow runs, which is the only scope that can see forcing improve or falsify an annotation. Two
  independent full sweeps produce a byte-identical baseline.

- [x] **Separate unmintable from unminted, and both from unmeasurable** (2026-07-30) -- the
  baseline carries three states plus two annotations rather than a single gap list. INCONCLUSIVE
  is its own class, never folded into unforced: two mutants do not terminate, two do not build,
  one crashes, and nothing is asserted about any of them. Four sites are annotated as ones where
  "unforced" is the wrong word -- three true equivalent mutants (an empty case arm in a switch with
  no default; `case ResultFail: return 0`, whose deletion sends fail to a rank that still sorts
  bottom; `!hasStillArmed`, which `objBool`'s contract makes redundant beside `!stillArmed`) and
  one masked rule where an earlier check reaches every input that could distinguish it. Both
  annotation kinds are falsifiable and the gate falsifies them: an annotated site that is ever
  KILLED fails the build, so an annotation cannot decay into a suppression.

- [x] **Correct three rules the first forcing measurement recorded as unforced** (2026-07-30) --
  that campaign replayed each vector once, under the pinned key only, and reported
  `tiers_without_key: None`. The evaluator skips a tier column it was handed nothing for, so
  GATE 2's no-TOFU rule was compared against nothing and its three implementing sites --
  `DeriveTiers`'s `policy == nil || len(keys) == 0` guard, its `policy == nil` disjunct, and
  `anchorPolicyCodes`'s `policy == nil` -- scored DEAD on never-taken branches. Replaying under
  both key policies, as `run_vectors.observe_external` does, kills all three: `ok-024` forces
  them. The ground-truth gate is what surfaced it, refusing to score a run whose fast path
  disagreed with the real CLI on that column.

- [x] **Ask the sync's re-aim question line by line, not only span by span** (2026-07-29) --
  the synchronise refused to move a citation off text still in the document, but only
  ever looked for the span's text as one piece, so an amendment touching any part of a
  cited passage made the search fail and everything the remap abandoned went unexamined.
  The same question asked of each line refuses the citation that dropped prose upstream
  left in place, and names that prose in the refusal. Replaying the suiteRevision 14
  re-vendor against the parent commit reproduces the defect exactly: as the check stood,
  all twenty-six mis-aimed spans passed and both ledgers were written; with the line
  question, the re-vendor stops and names nine of them, every one of which the commit
  went on to repoint. Measured over every re-vendor where the remapper was live and
  scored against what a person did next, it refuses twenty-six spans, fifteen repointed
  and eleven deliberate narrowings cleared one at a time through `--accept-reaim`, which
  records nothing and so cannot rot. That aggregate carries eight of the nine above; the
  ninth sits in a section the same commit renamed, which leaves the automated pairing
  nothing to compare it against. Mutation-checked in
  both directions: with the line question stubbed out the replay writes both ledgers and
  refuses nothing, and the pre-existing whole-span refusal still fires with its own cause
  when a citation is aimed at unrelated prose. Replaying the corrected re-vendor produces
  ledger entries byte-identical to the committed ones for every citation the commit did
  not add or rename, so a correctly performed re-vendor reaches the same place and only
  stops earlier.

- [x] **Vendor the two amendments the corpus already implemented** (2026-07-29) --
  the pin moves two commits along the upstream predicate branch. The first binds the
  carried observation vocabulary and the carried network posture into the run identity
  and declares the posture vocabulary a closed four-value registry with an append-only
  rule; the second adds the fourth `result` value and restates the recompute as the
  minimum of three independent conditions. Both readings were already in the rails and
  the corpus, so no vector file moved and the replay was green against the new text
  before it arrived. The two entries in `docs/interpretation-decisions-open.md` that
  recorded the corpus running ahead are closed, and their readings become registry
  decisions 19 and 20.

- [x] **Re-aim every `spec:NNN` citation onto the passage its own claim names** (2026-07-29) --
  eighty-seven of ninety-eight citation spans across thirteen files were corrected by
  hand, each accepted through `--accept-reaim` by name so the ledger records a decision
  rather than a sweep. The backward measurement that found the drift returns zero over
  every citation not named that way, and reverting any single correction turns it red
  again. The classes separate as follows. Thirty-eight spans were mechanically drifted,
  and correcting thirty of them put the citation back on the text it was written for.
  Twenty-six are aimed somewhere their old text never went, because they were pointed at
  the wrong passage when they were written; eighteen of those the mechanical test could
  never see at all, since a citation still sitting on the prose it was first pointed at
  looks correct from history no matter what the claim beside it says. The remaining
  thirty-one address passages upstream has since rewritten, which the measurement cannot
  classify either way, and they were corrected on reading like the rest.

- [x] **Force reason-map membership on all three coverage sets** (2026-07-26, `7a081d4`) —
  the spec already made the three coverage sets a disjoint partition of the manifest's
  classes, but only `bad-819` forced the `assessedClasses` side. Added
  `vb3c92d4ecb62bbfb` and `ved230b46692c0ada`: each puts
  an unknown class key in one reason map, leaves the result alone, and is rejected as
  coverage-incomplete. Both reference rails (Go `aee/statement.go`, Python
  `_coverage_partition_ok` in `packaging/run_vectors.py`) already enforced it, so the two
  vectors lock the written rule and mutation-prove the rails (reverting the reason-map
  accounting flips both). Corpus now suiteRevision 3, 140 vectors (35 accept + 105 reject);
  full local gate green and remote CI green.
- [x] **Extend registry decision 14** (2026-07-26, `7a081d4`) — recorded the two new
  vectors in `vectors/interpretation-decisions.json`, and added a `CHANGES.md`
  suiteRevision-3 section.
- [x] **Document the registry as a post-run reconciliation surface** (2026-07-26, `7a081d4`) —
  added a note to `docs/interpretation-decisions-open.md` clarifying that the interpretation
  registry is read for post-run reconciliation, not as a pre-implementation answer key.
- [x] **Correct the CI vector-replay label 138 -> 140** (2026-07-26, `7a081d4`).
- [x] **Update the multi-implementation report** (2026-07-26, `7a081d4`) —
  `docs/IMPLEMENTATION-REPORT.md` now records the reviewer's re-run as a third
  fully-independent column on the earlier corner-case features (138/138 spec-diff-led,
  132/138 unchanged).

---
_Detailed rationale and cross-repo tracking live in the private product backlog; this file
is the public roadmap for the open conformance artifact._
