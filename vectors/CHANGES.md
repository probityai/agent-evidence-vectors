# Conformance suite changelog

The vector corpus is a versioned, immutable-per-revision artifact. A published
`suiteRevision` is never mutated in place; a normative change to the predicate
or a corpus addition bumps the revision and regenerates the vectors
byte-identically from the generators.

## suiteRevision 30 (the result recompute is total, and the two rails are measured against each other)

- **This corrects a defect in one of our own reference rails, and the defect was a
  VERDICT rather than a code.** The specification defines `result` as "a total,
  deterministic, severity-independent function of the predicate". The Python rail
  declined to evaluate it when the predicate carried no readable
  `observationVocabulary` or no `attackResults` rows, guarding on
  `labels is not None and caught is not None and rows`; the Go rail built empty
  carried sets and answered. On a statement carrying `attackResults: []`, a
  coverage map that accounts for every manifested attack, and a declared `result`
  the recompute does not derive, the Go rail answered **invalid**
  (`result-recompute-mismatch`) and the Python rail answered **valid** and
  published a result token the definition never produces. The guard is gone: an
  absent or unreadable vocabulary contributes empty carried sets, which places
  every row's label outside the carried labels, and an absent or empty
  `attackResults` contributes zero rows.
- **Two new vectors, and the reason they are two.** `ve3c7f7a8d918c70c` carries the
  discriminating shape above and both rails now refuse it with the same single
  code, so a rail that declines to recompute over zero rows fails it on the
  verdict. `v6945133925a03e15` is the twin of the shipped no-vocabulary vector with
  its carried result re-derived under the total recompute; across the pair, a rail
  reading an absent vocabulary as admitting every label inverts both emissions,
  which neither vector can show alone.
- **Nothing in this repository compared the two rails, and now something does.**
  `aee/vectors_test.go` asserts the Go rail's PRIMARY code is in each vector's
  declared set. `scripts/observed-code-closure-gate.py` pins what the Python rail
  emits and says in its own words that it is a check over "the REFERENCE rail",
  singular. Both looked complete and neither looked at the other.
  `scripts/rail-parity-gate.py` replays both over every member, refuses a verdict
  split outright, and holds every code-set difference to a recorded row in
  `docs/RAIL-PARITY-BASELINE.json` -- thirty today, twenty-seven of them the Go
  pipeline stopping at an earlier gate than the one that produced the code.
- **What this revision does NOT exercise.** The gate compares the rails on the
  shapes the corpus carries, so it would have passed the day before this fix: the
  defect was reachable only on a shape no vector had. The vector is what puts the
  shape into the membership and the gate is what stops the next one drifting. The
  thirty recorded divergences are also not closed by this revision; they are a
  consequence of one rail stopping at the first failing gate while the other
  accumulates, which `vectors/MANIFEST.json` already declares measured rather than
  normative, and closing them would mean rewriting a rail's reporting
  architecture.
- **The corpus contained no exponent-form number literal at all, so the
  safe-integer rule's own domain was untested.** The covering-payload rule puts
  two independent number rules on the same bytes -- the payload MUST be
  "canonical per RFC 8785" AND "valid I-JSON per RFC 7493 (... integers within
  the safe range ...)" -- and the first is over a literal's SPELLING while the
  second is over the VALUE it denotes. Every number in the corpus was written in
  integer form, so nothing separated them and nothing distinguished a rail
  reading the safe-integer bound over values from one reading it over notation.
  The second reading accepts `1e21`, which both first-party rails refuse with
  exact rational arithmetic and a comment naming that exact literal. Four vectors
  close the axis and split across the two rules rather than piling onto one:
  `vd3ead02f7ed16d0a` carries `1e21`, whose value is integral and at or above
  2^53, and is refused by the safe-range half; `vd5e0b3f3d1fabb05` (`1E2`),
  `v97c6888cf7e88f42` (`1.0e2`) and `v13ede3e42645eb1a` (`-0e0`) all carry values
  the safe-range half ADMITS and are refused by the canonicality half alone. The
  absence they close was measured by decoding every payload in the corpus rather
  than by searching its text, which cannot see inside base64.
- Corpus: **281 vectors (61 accept, 218 reject, 2 indeterminate)**, six more than
  suiteRevision 29. No existing vector file changes, so only the six new
  statements and `corpusDigest` in `vectors/MANIFEST.json` move; the vendored
  specification does not move, because every reading this revision fixes is one
  its current text already states.

## suiteRevision 29 (the three empty predicate states are one input)

- **Three reject vectors, one per empty `predicate` state**, under a new condition
  `aee-c-109`: the member absent, present as `null`, and present as `{}`. Each is
  ok-002 with one edit to the `predicate` member, so the three differ from a valid
  statement and from each other in nothing but how `predicate` is spelled.
- Corpus: **275 vectors (61 accept, 212 reject, 2 indeterminate)**, up from 272.
- **Nothing in the corpus had exercised any of the three.** No vector carried an
  absent, null or empty `predicate`, and `"predicate": null` did not occur in the
  repository at all. Under that silence the two rails had drifted: the Go rail
  refused an absent member with a parse error mapped to `statement-malformed` and
  read `null` as empty, while the Python rail answered `predicate-type-unsupported`
  -- a code about the type URI -- for both absent and null, on statements whose type
  URI was correct, and gave the empty object one code fewer than the Go rail.
- **The rule is written down.** `spec/v1/statement.md` is new and carries this
  repository's statement-layer conformance profile: a verifier treats all three
  spellings as one input and emits the identical verdict and the identical reason
  codes for all three. It quotes the in-toto sentence that resolves unset against
  set-but-empty, and lifts verbatim the SLSA build-provenance sentence that resolves
  `null` alongside them.
- **Both rails were changed to implement it**, and both now emit the identical
  six-code set for all three states. The Python rail also reports an absent
  `attackResults` member as `statement-malformed`, which the Go rail always did and
  which the empty predicate is the first vector to reach.
- **The traceability gap widens by one, and this one cannot be closed.** The
  pairing still holds at the coarser granularity: all 212 reject vectors declare
  a parent that ships as an accept vector. The finer one is the conditions cited
  only by refusals, measured and ratcheted against
  `docs/ACCEPT-ANCHOR-BASELINE.json`. That second number is 34 of 77 today, up
  one because `aee-c-109` is cited by three reject vectors and by no accepting
  one. Unlike the rest of that list it is not a gap an accept vector could
  close: the empty predicate is missing every required member, so no valid
  statement exercises the equivalence.
- **165 of the 212 reject vectors are now exactly one mutation from their declared
  parent**, two more than at revision 28: the absent and null spellings each carry
  a single edit to a single member of ok-002. The remaining 47 cannot express their
  declared fault in a single edit and stay declared in
  `docs/MULTI-MUTATION-VECTORS.json` with a count and a reason each. The empty
  object joins that list: `predicate` becoming `{}` removes all seven members at
  once and cannot be fewer, while the absent and null spellings measure one because
  the member goes with them.
- **Each of the three carries a `statementLayer` verdict in the manifest: `valid`.**
  The same bytes answer two questions. An AEE verifier must reject them, because the
  empty predicate lacks every required member; an in-toto Statement parser must
  accept them, because the framework types `predicate` as optional. The in-toto
  reference bindings refused the absent and null spellings until
  in-toto/attestation#598, so a Statement parser can be run against these three to
  see which side of that fix it is on. The field is additive and informative; the
  comparison surface is unchanged, and `scripts/statement-layer-test.py` executes
  the recorded verdict rather than trusting it.
- **The equivalence is enforced by a gate rather than by the corpus contract.**
  `vectors/MANIFEST.json` declares reject codes measured rather than normative and
  the reject contract grades by intersecting the declared and observed code sets, so
  two rails rejecting one statement for different reasons both pass. That is right
  for a third-party rail and wrong for the two rails here, which share one code
  vocabulary, so `scripts/predicate-state-gate.py` drives both directly and refuses
  unless every outcome is identical.
- **What this revision does not exercise.** A `predicate` that is present and
  neither an object nor `null` -- a string, a number, an array -- is a different
  fault, keeps its own code, and no vector in this revision carries one.

## suiteRevision 28 (identifiers name the bytes, not the answer)

- **This corrects a defect in our own corpus, found by a gate in this repository.**
  Every vector carried its verdict twice: an `ok-`/`bad-` prefix in its name and an
  `accept/` or `reject/` directory around it. Measured over each vector's whole
  manifest-relative path, a cheap classifier predicted accept-or-reject from the
  identifier alone with a separability of **1.0000** against a permutation null of
  0.5879 -- a perfect score, on a corpus whose whole purpose is to measure whether an
  implementation read the statement. A rail could have certified against this suite
  without opening a single file.
- **Every vector is now named after a digest of its own bytes and lives in
  `statements/`.** There is no directory per verdict and no prefix. The verdict is in
  `vectors/MANIFEST.json`, which is where a scoring harness reads it. The identifier
  surface measures **0.5075 against a null of 0.5075** -- it carries nothing, because
  shuffling the labels produces the same figure -- and the whole surface fell from
  **0.9906 to 0.5567 against a null of 0.5817**. Every surface of this corpus is now
  inside its own noise floor.
- **The slug surface is why no old-to-new mapping is published.** Run through the same
  classifier and the same null, the authoring slugs score 0.9936 as they stand, 0.7260
  with the family token removed, and 0.7307 on the description words alone, against a
  null near 0.585. The leak is not the prefix, it is the vocabulary: a slug says
  `missing`, `mismatch`, `duplicate` and `wrong` on one side and `clean`, `canonical`
  and `pass` on the other. There is no spelling of a published map that carries no
  label, and a corpus shipping its own decoder would have relocated the leak rather
  than closed it. **That is a general result about naming test cases, not a fact about
  this corpus.** Identifiers are retired with the vectors that carried them, none is
  reused, and the way to get current results is to re-run the suite.
- **`corpusDigest` moves for every vector**, because its preimage commits to each
  vector's path and every path changed. Every consumer rail must re-vendor. The digest
  function reads both layouts, since the consumer-lag gate computes it over the default
  branch's tree, which predates this revision.
- **No expectation moves and no vector is weakened.** Every vector keeps its
  conditions, its expected verdict and its expected codes; 272 replay green on the
  reference rail and both Go modules pass. A fresh checkout builds the corpus
  byte-identically through the documented generator sequence.
- **A gate was drawing its own vocabulary out of the identifiers, and would have
  stopped measuring in silence.** The spec-anchor gate's aim test decides whether an
  anchor is drawn around a rule the decision it belongs to is actually about, and it
  built the decision's term set from its title, its reading, and its forcing vectors'
  identifiers with the hyphens turned into spaces. That worked only for as long as an
  identifier was a description. Under content-addressed identifiers the term set would
  have shrunk toward nothing and the test would have gone on reporting anchors as
  aimed -- a check that narrows itself without failing, which is the second instance of
  that shape found in one day. It now reads each vector's index-row prose instead:
  what a vector does, rather than what it is called.
- **One definition of an identifier, referenced everywhere.** The commit that found and
  fixed four silent droppers shipped with five, because the indeterminate row reader
  carried its own inline copy of the pattern instead of importing the shared one; when
  identifiers changed shape it stopped matching, skipped both rows without complaint,
  and dropped them from the manifest. It was invisible precisely because it looked like
  the four that had been fixed. Every reader now imports one definition. Two spellings
  survive in exactly one place, the prose mask in the count census, because the retired
  form still occurs throughout this file -- which is history and is not rewritten -- and
  the current form needs masking too; that site says so and says why.
- **This revision does not earn 1.0.0, and the gate on it is written down here rather
  than remembered.** A 1.0 would declare the corpus stable, and the AI Agent Action
  suite still measures 0.7810 against a null of 0.6458 -- a real, named, unfixed leak in
  the Appendix B family, which sits entirely on the accept side with no reject
  counterpart. Declaring stability over a known leak is a claim that would fail the
  first time anybody measured it, which is the one kind of claim this repository must
  not make. Pre-1.0 semantics already license the breaking change, so nothing is lost by
  waiting. **1.0.0 is what the Appendix B fix earns.**
- **One way to find a vector, and one reader that is scheduled to die.** The rename
  briefly left four readers able to parse both layouts. Three were aliases and are
  deleted: `cmd/mutrun`, the reference rail and the Go conformance runner each read
  `statements/` and nothing else now, and refuse a tree without it rather than falling
  back. Keeping a reader for the retired layout would have kept the leaky structure
  alive in code, where something could write it again, and would have meant every future
  change had to be correct twice on a path nobody exercises. An old vendored copy gains
  nothing from it either: `corpusDigest` moves for every vector, so such a copy is
  already incompatible on the digest whatever a runner can parse.
- **The fourth reader is an exception, and it carries its own expiry.**
  `scripts/consumer-lag-gate.py` materializes the DEFAULT BRANCH's tree to learn what
  the consumer rails could actually have vendored, and until this revision lands there
  that tree is the retired layout -- a published artifact this repository does not
  control and cannot rewrite, which is the same argument that keeps this changelog's own
  history unrewritten. It is a SEPARATELY NAMED reader, so the historical path is
  unreachable for this repository's own corpus rather than merely discouraged.
  **It refuses, loudly, the moment it is handed a tree that is already flat**, naming
  that its purpose has expired and that it is to be deleted. So the first run after this
  revision reaches the default branch turns it red on its own account, and removing it
  is the last step of this change rather than an optional tidy. A reader that expires
  silently is the same defect as a gate that narrows silently, and two of those were
  found in the course of this revision.
- **A rename touching every identifier changed nothing about what the corpus forces,
  and that was verified rather than asserted.** Re-running the whole forcing campaign
  after the rename reported 40 sites whose forcing vectors had "changed". Every one of
  them was checked AS A SET: all 40 were identical in membership and differed only in
  order, because the identifiers were substituted in place while the campaign emits them
  sorted. Zero sites gained or lost a vector. The baseline is re-recorded so the ordering
  matches what the campaign produces, which is a diff of 12,561 lines that moves no
  meaning. Ground truth over the same run: 272 vectors, 0 discrepancies against the Go
  verifier through the Python rail, across every enumerated mutation site.
- **Removing the fallback is what revealed that sixteen readers had stopped
  measuring, and that is the most useful thing this revision produced.** When the
  three dual-layout readers were deleted, sixteen steps of this repository's own
  CI went red at once. Every one was a reader still deriving a path from the
  per-verdict layout, and every one had gone on working while a fallback was
  present. **The fallback was not compatibility. It was concealment.**
  Four of the sixteen would have reported success while measuring nothing at all,
  which is the failure mode this suite exists to make impossible in others:
  - three gate tests staged their fixtures from `accept/` and `reject/` and so
    copied NO vectors, meaning each control ran against an empty corpus and each
    reported `CONTROL FAILED` only by luck of a later assertion;
  - the forcing gate's corpus fingerprint walked the same directories and would
    have hashed the manifest alone -- a fingerprint that agrees with every corpus
    -- and now refuses an empty read;
  - the liveness probe's `--corpus` mode globbed an `ok-` prefix that matches
    nothing, and would have reported a clean probe over an empty selection; it
    refuses that too.
  The remaining twelve were honest breakages: hard-coded vector paths, per-kind
  directory counts in two counting gates, a fixture builder, and one workflow
  step. None of them is interesting on its own. What is interesting is that a
  compatibility path had been holding all sixteen upright, so the corpus could
  not have told anyone which of its own gates were still checking something.
  A conformance corpus whose gates were partly inert, found by deleting the thing
  that hid it, is worth publishing as plainly as any result about the vectors.
- **The historical reader cannot outlive its reason, and a gate enforces that
  rather than a comment.** `scripts/historical-reader-expiry-gate.py` reads the
  published ref and the reader's own source and holds a four-row rule: while the
  default branch publishes the per-verdict corpus the reader must exist, and the
  moment it publishes the flat one the reader must be gone. Both failing rows were
  watched to fire. It is a gate of its own because the obvious placement cannot
  work -- making the consumer-lag gate refuse a flat default branch would make it
  fail its own test, whose fixtures stage a self-contained repository from this
  corpus and are therefore always flat. This one has no fixtures to collide with.
- Corpus: **272 vectors (61 accept, 209 reject, 2 indeterminate)**, unchanged in
  size from suiteRevision 27. Every vector file changes, so `corpusDigest` in
  `vectors/MANIFEST.json` moves; the vendored specification does not move, because
  this revision renames the corpus and changes no rule and no reading.

## suiteRevision 27 (a reject vector IS its parent plus one mutation, and the gate says so)

- **The rail's own output is now pinned, which it was not.** A reject vector is
  graded by INTERSECTING the codes a rail emits with the codes the entry declares,
  so a code emitted outside that set was compared against nothing at all. Measured
  over the corpus as it then stood, nineteen were in that state -- 17 reject and both indeterminate
  members -- carrying 24 unpinned emissions between them, of which
  `caught-row-uncovered` accounted for ten. `bad-817` was the worst of them,
  declaring two codes and emitting four, and it is where this was found: when the
  corpus-wide rewrite above moved its declared parent from a caught row to a
  reconstructed one, one of its two undeclared codes changed with it, from
  `caught-row-uncovered` to `reconstructed-row-uncovered`. That change was correct
  and nothing in the repository could see it.
- **The pin is a new declaration, not a wider expectation.** Each of those 19 rows
  gains an `(also emits: ...)` clause naming what the reference rail reports beyond
  what the vector declares, and `vectors/gen_manifest.py` carries it into the
  manifest as `expected.alsoEmits`. No expectation moves, no vector is weakened,
  and no vector file changes, so `corpusDigest` is exactly what the rest of this
  revision published.
- **Nothing changes for a third-party implementer, and that is a design constraint
  rather than a happy result.** `comparisonSurface` still declares the verdict and
  an accepted statement's result token normative and the condition codes measured;
  README still promises that a strict single-code implementation and a
  superset-emitting one certify against one manifest. `alsoEmits` is compared
  against nothing an external rail produces. That is why the check is
  `scripts/observed-code-closure-gate.py`, driving the reference rail alone, and
  not a rule inside `packaging/run_vectors.py`, which external rails replay
  through: a closure rule there would have promoted this repository's private
  vocabulary into an obligation on everybody, which is the one thing the manifest
  promises it will not do.
- **It is also not spelled as an `also carries` clause**, which would have been the
  smaller edit. That clause is the second-fault self-check's exemption key, and
  `payload-not-canonical` -- one of the two codes `bad-817` has to declare -- sits
  in the binding fault family, so the smaller edit would have bought the pin by
  switching `_sfa_binding` off on the very vector that motivated it. A declaration
  that a rail emits something must never be spelled as an exemption from a check.
- **The gate refuses in both directions**: an emitted code that no field of the
  entry names, and a code pinned as emitted that the rail no longer emits. Its
  mutation proof reconstructs the `bad-817` drift verbatim and requires both arms
  to fire on it, and one of its six cases patches the reference rail rather than
  the manifest, because every manifest-only case would also pass a gate that
  compared the manifest against nothing but itself.

- Corpus: **272 vectors (61 accept, 209 reject, 2 indeterminate)**, fourteen more
  than suiteRevision 26. Every reject vector file changes, so `corpusDigest` in
  `vectors/MANIFEST.json` moves. No expectation is widened and no vector is
  removed or weakened: every refusal keeps its conditions and its expected code.
  The additions are the `ok-055` / `bad-986` pair below and the twelve refusals
  of the quantifier round after it. The vendored
  specification does not move: `specDigest` and `specUpstreamCommit` are exactly
  what suiteRevision 26 carried, because this revision corrects the corpus and
  changes no rule and no reading. With the additions, all 209 reject vectors
  declare a parent that ships as an accept vector.
- **Twelve more universals that the corpus proved it ran and never proved it
  quantified.** `LOOP_FIRST` weakens "for every member, P" to "for the first
  member that reaches the end of the body, P" by closing a range body with a
  `break`, and it enumerated 53 sites in `aee/`. Twenty-six of them survived the
  weakening with byte-identical output on every vector then shipped, and
  twenty-four of those twenty-six sat on a branch the corpus demonstrably
  ENTERS: vectors reach the loop, and not one of them carries a second member
  whose treatment could differ from the first's. Twelve are now forced.
  Each new refusal is its declared accept parent plus one mutation, and each
  puts a well-formed member ahead of the offending one, which is the only shape
  that separates a universal from an existential:
  `bad-987` (a third assessed identifier the manifest does not declare),
  `bad-988` (a second chain-scope token outside the closed vocabulary),
  `bad-989` (a second payload commitment that is not lowercase 64-hex),
  `bad-990` and `bad-993` (an out-of-range `observationRefs` index behind an
  in-range one, and behind a fully covered row),
  `bad-991` and `bad-992` (a malformed `expectedPayloads` entry and an
  undeclared key, both behind well-formed ones),
  `bad-994` (the second of two clean rows carrying an actualLayer that is not
  `none`),
  `bad-995` (the second attack a seal names, whose row is clean),
  `bad-996`, `bad-997` and `bad-998` (a second sealed or arming record, bound to
  the same run, contradicting the first). Twelve of the twenty-four sites move
  from DEAD to KILLED in `docs/FORCING-BASELINE.json`; the remaining twelve are
  recorded there as they were measured, and two of them range over a Go map,
  where a single-witness reading picks its witness at random and no vector can
  refuse it deterministically.
- **A rule quantified over a set, and a corpus that only ever handed it one
  element.** The third part of the pinned-attribution rule reads "every
  `interception` record it resolves carries in its `aeePayloadCommitment` at
  least one value from that entry" (L614-623), and it is a consumption
  precondition, so a statement violating it is invalid. Every pinned row this
  corpus shipped -- 23 of them across the whole suite -- resolved exactly ONE
  interception. At cardinality one a universal and an existential agree, so a
  rail that compares the first resolved interception and stops cleared all 258
  vectors. `ok-055-pinned-row-two-interceptions` hands the rule two, both
  predicted by the corpus for that row's attack, and
  `bad-986-pinned-second-interception-unmatched` is that statement with the
  second commitment replaced by the value the corpus declared for the OTHER
  attack and nothing else touched -- valid authorisation, one observed effect
  that corresponds to it, and a second that corresponds to a different declared
  attack. Measured both ways on both first-party rails: weaken the loop to stop
  after the first resolved interception, in `packaging/run_vectors.py` and again
  in `aee/commitments.go`, and `bad-986` is the ONLY vector of the 260 that goes
  red. Nothing else in the corpus reaches that arm. `bad-960` is the weaker
  neighbour, where the commitment matches no declared attack at all; the
  cross-row form is `bad-982`; and the ungated `paired` form stays cell U7 in
  `vectors/coverage-unforced.json`, where the specification puts it.
- **The fault, which was ours.** Both indexes, and the accept-anchor gate's own
  docstring, describe a reject vector as "a fully valid parent statement plus
  exactly one mutation". That was a statement about shape. Nothing compared the
  bytes, and under the gap the relation rotted. Compared as raw JSON leaves,
  exactly ONE of the 196 reject vectors then shipped was within one leaf of the accept vector
  it declared and the rest ranged from six to forty-one. Compared the way the
  new check compares -- over the semantic pre-image, with the derived fields
  absorbed -- four measured one and the rest ranged from five to seventeen, and
  three of those four are vectors whose file does not parse at all, where a
  single sentinel stands for the whole statement and the count says nothing.
  Both figures are recorded because they answer different questions and the
  second is the one the gate now holds. suiteRevision 26 published `vate-1a` and
  `vate-1d` as a control pair and said in three places that they were one
  mutation apart, and they differed in eleven leaves. That pair was repaired in
  this revision's first commit; this is the rest of it.
- **The cause was one shape built twice.** The accept generator and the reject
  generator each carried their own synthetic environment fixtures. The
  catch-policy and network-posture pre-image objects, the run-entropy and
  unchecked-binding pre-images, the corpus name and purl, the value an
  interception record commits to and the note beside it, and the reasons a
  coverage declaration carries each had two spellings, and the two sets never
  agreed. A reject vector built to mirror an accept vector therefore got the same
  SHAPE and never the same STATEMENT. The accept-anchor gate resolved a declared
  parent by whole-id membership among the shipped accept vectors, which is a check
  that the parent EXISTS and never a check that the child is that parent plus one
  mutation.
- **The fix deletes the second construction rather than reconciling it.** The
  reject generator imports the accept generator's fixtures instead of restating
  them, and every parent builder is replaced by a read of the shipped accept
  vector. A reconciliation drifts again; a deletion cannot, because there is no
  second copy left to drift. The regenerability gate runs the accept generator
  before the reject one, so the file each parent reads is the one that run just
  wrote, and an unreadable file is a hard failure rather than a rebuilt
  approximation.
- **Three parents named an accept vector they were not**, which the whole-id check
  could not see because the vector they named does ship. The reconstructed parent
  is `ok-031` and not `ok-006`; the two-caught-row parent is `ok-046` and not
  `ok-011`; the multirecord parent is `ok-030`, whose record set the previous
  builder did not produce at all. Each is re-pointed at the vector it is. Two
  builders both claimed `ok-007` and only one of them could be it, so the artifact
  family now has one builder and it is the shipped shape.
- **Three vectors now express the same fault in one edit rather than several.**
  `bad-817` moves to the parent whose covering payload has slack trailing bits,
  because a non-canonical base64 encoding of the same bytes exists only where the
  payload length is not a multiple of three. `bad-960` and `bad-983` alter the
  commitment alone instead of the commitment and the producer note beside it.
- **The relation is now enforced, which is the half that was missing.** Check 4 of
  `scripts/accept-anchor-gate.py` diffs every reject vector against the accept
  vector it declares and refuses when the count is wrong, naming the vector, its
  parent, the count and every differing path. The comparison is over the semantic
  pre-image: a derived field -- a signature, a batch root, a run binding, the
  carried result, a digest OF material the statement also carries -- collapses to
  a token where BOTH sides agree with their own derivation, and is compared as
  written where either does not. So a field that moved because the mutation moved
  is not counted, and a field set to a value the derivation does not produce IS
  the mutation and is counted where it was set. The arithmetic and its reasoning
  live in `scripts/mutationdiff.py`.
- **163 of the 209 reject vectors are now exactly one mutation from their declared
  parent, up from one.** The remaining 46 cannot express their declared fault in a
  single edit, and each is declared in `docs/MULTI-MUTATION-VECTORS.json` with its
  count and the reason -- the seal-constraint family carries a second healthy seal
  so the defective one is not also the only covering record; the laundering family
  is a vector plus a reference move by construction; a run-chain declaration is
  members that only exist together; a record replaced by one of another kind
  carries different members. The gate refuses an UNDECLARED multi-mutation, a
  declared count the vector has outgrown, a row for a vector nobody ships, a row
  with no reason, and a row that has stopped being an exception. The last one
  matters most: an allowlist recording which vectors were excused and not why is
  the same defect one level up.
- **Found by an outside reader.** The pair that exposed all of this was reported
  by an independent implementer who reproduced the corpus at 258 of 258 and
  regenerated the generated files byte-identically before raising it. Three
  earlier corrections from the same review are already carried in suiteRevision 26.

## suiteRevision 26 (what this predicate does not read across an external admission)

- Corpus: **258 vectors (60 accept, 196 reject, 2 indeterminate)**, up from 250.
  Eight vectors are added and no existing vector file changes, so `corpusDigest`
  in `vectors/MANIFEST.json` moves and nothing published before this revision is
  disturbed. The vendored specification does not move: `specDigest` and
  `specUpstreamCommit` are exactly what suiteRevision 25 carried, because this
  revision adds no rule and changes no reading. With the vectors added, all 196
  reject vectors declare a parent that ships as an accept vector.
- **Where they came from, and what they are not.** Three conformance cases from
  the Verifiable Agent Trust Envelope (VATE) discussion draft asked what this
  predicate natively establishes across an external admission. The pins those
  cases were read at are preserved with the vectors and repeated here so that a
  reader can go back to them: VATE commit
  `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus
  `VATE-AL2-Verifier-Admission-v0.3`, corpus digest
  `sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. The
  three case identifiers are `post-execution-admission-digest-mismatch`,
  `post-execution-effective-constraints-aggregate-exceeded` and
  `post-execution-runtime-mismatch`. The vectors are AEE-native boundary vectors
  prompted by those cases: not VATE conformance results, not a projection into
  another format, and not evidence about any implementation other than a rail run
  against this corpus. The corpus digest above is recorded as a pin and not
  reproduced as a validation of anyone's canonicalization profile.

### Source of the vate-* cases, resolvable

Stated once for the whole family rather than repeated on each vector. A commit
hash and a local case identifier stop resolving the moment this repository is no
longer the reader's entry point, so the repository and the three case files are
named by URL at the fixed commit they were read at.

- Source repository:
  <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope>
- Fixed review commit:
  <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be>
- The pinned cases, at that commit, under `conformance/al2-vate-v0.3/cases/`:
  - <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be/conformance/al2-vate-v0.3/cases/post-execution-admission-digest-mismatch.json>
  - <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be/conformance/al2-vate-v0.3/cases/post-execution-effective-constraints-aggregate-exceeded.json>
  - <https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/ce00121d7bd658c7a1fcd861b386ea9ea7ce66be/conformance/al2-vate-v0.3/cases/post-execution-runtime-mismatch.json>

The links locate the source; they do not transfer any claim. Every expectation
in the vate-* vectors remains this predicate's own, decided by this suite's own
rails, and nothing here is a conformance result about that repository.
- **The case-1 trio is one shape, so that it instantiates the source case's
  relation.** Two synthetic admission receipts, A and B, are derived from
  published one-line preimages, and all three vectors of that case are built
  from the A-bound statement: receipt A in the sole subject slot, the run
  binding derived over A, both records signed under it. `vate-1d` ships that statement unchanged.
  `vate-1a` is that statement with the subject digest moved from A to B and the
  records left exactly as the producer signed them. `vate-1b` is that statement
  with the arming payload carrying receipt B's `vateAdmissionDigest` and the
  reference naming B. Both objects in the relation are therefore admission
  receipts, as they are in the pinned case, which hashes a referenced admission
  receipt and compares the value with the digest a post-execution receipt
  asserts -- not an executed-artifact digest against a receipt digest, which are
  different object categories and differ by construction. The conclusion the
  trio makes executable is one sentence: AEE binds its sole subject against
  record splicing, and does not perform VATE's referenced-admission-receipt
  digest comparison.
- **Five accepts, and they are the load-bearing half.**
  `vate-1b-carried-admission-digest-unread` carries admission receipt B's digest
  and reference in a covering payload while admission receipt A is the subject
  every record is bound to, and is valid and `pass`, because AEE never performs
  that comparison.
  `vate-2a-aggregate-overrun-unread` carries two side-effect amounts each below a
  carried maximum and summing above it, and recomputes `pass`, because no row
  carries a quantity and the composition law is a minimum over three booleans.
  `vate-3b-admitted-vs-observed-runtime-unread` declares an admitted and an
  observed runtime that differ, and is valid, because a statement carries exactly
  one `observationEnvironment` and there is no second runtime to compare against.
  `vate-1d-admission-receipt-as-sole-subject` pays the full price of the case-1
  anti-splice: admission receipt A is the sole subject, so the binding covers the
  admission identity and the statement names no executed artifact at all. Each is
  a negative pin, and a negative pin states a boundary more precisely than a
  sentence can.
- **`vate-3c-substrate-substituted-and-resigned` is here because it refutes the
  strongest reading of the two splice refusals.** The whole run is re-bound to
  the substituted substrate digest and re-signed: the binding is recomputed over
  the second observation-substrate identity and every record re-signed under the
  published substrate-observation test key. Nothing is spliced, so nothing is
  detected, and the statement is valid and recomputes `pass`. The binding is
  anti-splice and
  explicitly not anti-forge, so `vate-1a` and `vate-3a` establish that records
  were not MOVED and never that the identity they name is the true one. That
  separation belongs to the substrate key and the evidence tier, and it bounds
  every sentence about what these vectors establish.
- **Three rejects, two of them narrow and one of them a price rather than a
  rule.** `vate-1a-admission-receipt-substituted-splice` moves the subject from
  admission receipt A to admission receipt B and `vate-3a-substrate-substituted-splice`
  substitutes the observation-substrate identity; each moves a binding input the
  corpus had not previously substituted, and both refuse `run-binding-mismatch`.
  `vate-1c-two-subjects-artifact-and-admission` extends no rule that `bad-607`
  and `bad-728` do not already carry; what it adds is that binding an admission
  receipt is not additive, because the pre-image reads only the first subject and
  a second entry is malformed. It is recorded that way rather than as a new
  discriminator.
- **The traceability gap narrows by one.** That second number is 33 of 76 today,
  down one because `aee-c-22`, the requirement that a record's `aeeRunBinding`
  equal the binding derived from the statement, is now cited by two accepting
  vectors as well as by refusals: `vate-1d` and `vate-3c` both derive their
  binding over an input the corpus had never varied, and both are valid. Until
  this revision a reader following that id from the registry reached only
  refusals. It stays measured and ratcheted in
  `docs/ACCEPT-ANCHOR-BASELINE.json`.
- **Two generator parameters and five gate patterns changed, and no vector
  moved.** `run_binding` in the accept generator takes the subject and the
  substrate as parameters defaulting to this suite's constants, because a vector
  that asks what the binding does when one of those inputs names a different
  identity has to derive the binding over that identity, and the alternative is a
  second copy of the pre-image that diverges silently. `make_statement` takes the
  subject and substrate objects on the same terms. The five patterns that
  enumerated vector ids by prefix now admit `vate-`; each was a pattern that
  would otherwise have skipped the new vectors and reported the corpus clean,
  which is the shape of failure those gates exist to prevent. The fifth was
  found late, by the review this revision was corrected under: the
  regenerability gate's owned-file globs matched `ok-*.json` and `bad-*.json`
  only, so the eight new vector files were neither wiped nor compared, and the
  gate reported a total that agreed with itself while eight generated files sat
  outside it. Every previously committed vector regenerates byte-identically.

## Spec pin refresh after suiteRevision 25 (no new revision; `corpusDigest` unchanged)

- The vendored specification moved again, from the `237f83b9` head recorded
  below to `0dbe10bcc959b63dc42370a5db09812c9476f59a`, six edits further along
  the same upstream pull request: the moat-down primary condition and a
  quantifier rewording, on top of four changes already covered when
  suiteRevision 25 was cut. `spec/VENDOR-PIN.json`, `vectors/MANIFEST.json`'s
  `specUpstreamCommit`, and `docs/FORCING-HONESTY.md` all carry the new commit;
  this file did not get an entry for it until now, which is the gap this entry
  closes. No vector was added or changed and `corpusDigest` did not move, so
  this is not a new `suiteRevision` -- the count stays 250 (55 accept, 193
  reject, 2 indeterminate), exactly as suiteRevision 25 left it. Two obligations
  already present in the vendored text became citable for the first time: the
  moat-down requirement (forced by mutation, not merely asserted) and a pointer
  to a rule stated normatively elsewhere.

## suiteRevision 25 (a rule written before the members it governs exist, and then a vector that carries one)

- Corpus: **250 vectors (55 accept, 193 reject, 2 indeterminate)**, up from 248.
  Two vectors are added and no existing vector file changes, so `corpusDigest` in
  `vectors/MANIFEST.json` moves for the first time since suiteRevision 23. With
  the vectors added, all 193 reject vectors declare a parent that ships as an
  accept vector. What also moves is the vendored specification, from upstream commit
  `c0c4da67defdf0f186f162e7ecb3f9527b6a94f8` to
  `237f83b9f1445720c165e1c5f076212dfa063f92`, which is the head of
  in-toto/attestation#570 at the time this revision was cut. Two upstream commits
  are spanned rather than one, and the second exists because the first was too
  narrow; the pair is vendored together so that no published revision carries the
  narrow reading.
- **What moved in the specification, exactly.** The paragraph that grants producer
  territory outside the reserved `aee` prefix now carries a constraint on what a
  verifier may do with anything a producer defines there. No member of that
  territory is read by a conforming verifier: it MUST NOT affect structural
  validity, `result`, or the evidence tier, whether or not its values can be
  ordered. An ordered axis, meaning any member whose values a reader might rank,
  keeps a sentence of its own saying a verifier MUST NOT rank its values and MUST
  NOT compose it by weakest input across records or rows. A changelog entry
  records both halves. Every other byte of the vendored document is identical to
  the copy suiteRevision 24 shipped.
- **The rule was published one notch too narrow, and an implementer found it the
  same day.** The first version constrained an ordered axis and nothing else. An
  implementation applying it to its own tree reported that it also emits an
  unordered producer member, per-channel loss counters, which no reader would
  rank, so the sentence did not reach it. The boundary was never about
  rankability, so the general rule now leads and the ordered case is named as the
  one a verifier is tempted to read. The same report is why structural validity is
  named at all: applying the narrow text, that implementer found a checker of
  theirs gating AEE validity on a producer member's value, which their own design
  document forbade. A rule written only about ranking is blind to that failure,
  and it is the failure that was actually made.
- **Why the rule sits at the grant rather than at a member.** The two axes this
  predicate orders, `basis` and `method`, are ordered because a normative reader
  consumes them: the recompute reads one and the gate reads the other. That is the
  criterion the predicate has applied since v0.5, and an axis a producer spells in
  the same payload acquires no such reader by sharing the envelope. Writing the
  constraint at each future member would mean writing it after the first producer
  had already shipped one; writing it at the grant means an implementer meets it
  before the member exists. The immediate case is the `assay` family proposed
  upstream, which is legal producer territory a conforming verifier ignores.
- **This entry claimed the revision adds no coverage, and
  `ok-054-producer-ordered-axis-inert` is the correction.** The claim was that the
  rule constrains a verifier's treatment of members no vector carries, so there
  was no accept vector to add and no reject vector to write. The second half
  holds: a suite that refused a statement for carrying a producer-defined member
  would enforce the opposite of what the sentence says. The first half does not.
  Inertness is an ACCEPT-side property and it is checkable, so the vector carries
  a covering interception payload with `exampleFidelity: "reconstructed"` -- a
  producer-defined member whose value is a token this predicate itself orders --
  beside a signed `aeeMethod` of `intercepted`. A rail that folds that member into
  the weakest-input method composition caps the row at `reconstructed` and reports
  `method-cap-exceeded` on a statement no requirement refuses. `ok-021` already
  carried producer members, but content-free ones, so it forces only that such a
  member does not stop a record covering; this is the vector a ranking rail fails.
  What remains true is that the rule's own failure case, a checker gating AEE
  validity on a producer member's value, is caught by reading the sentence rather
  than by carrying a vector.
- **`bad-1017-sole-seal-moat-down-all-caught` separates the two readings of the
  sealed existential.** Every dirty seal in this corpus was paired with a clean
  witness, on purpose, so no vector could tell a rail reading the existential
  narrowly apart from one reading it broadly, and the question stood open in
  review while both readings scored identically over the whole corpus. It is
  single-fault: the same statement with `aeeStillArmed` true is valid. It
  discriminates because a reject expectation is graded by intersection, so its
  `codes` cell pins `sealed-record-absent` alone and declares
  `sealed-covers-nothing` in the also-carries clause. Widening that cell to name
  both would let either reading satisfy it and the only discriminator this corpus
  owns would measure nothing, which is why `scripts/expectation-slack-gate.py` now
  checks the property on every reject vector instead of leaving it in a docstring.
- **What this revision still does not move.** The forcing baseline, the coverage
  matrix classes and the condition registry are unchanged; the anchors and
  `spec:NNN` citations move only because inserted prose sits above them, and they
  are remapped mechanically by `scripts/vendor-spec.py` rather than re-judged.
  Four further sentences gain citations by widening the anchors of vectors that
  already forced them: those rules were enforced while the anchor named a
  different line, which reads as covered and is not.

## suiteRevision 24 (the vendored copy catches up with the rule the corpus forces)

- Corpus: **248 vectors (54 accept, 192 reject, 2 indeterminate)**, unchanged from
  suiteRevision 23. No vector is added, removed, or regenerated to different bytes,
  and `corpusDigest` in `vectors/MANIFEST.json` holds the value it held at
  suiteRevision 23. What moves is the vendored specification, from upstream commit
  `23bee586d651c79ba6a1dd55d4b29b7c2ef2cff2` to
  `c0c4da67defdf0f186f162e7ecb3f9527b6a94f8`, which is the head of
  in-toto/attestation#570 at the time this revision was cut.
- **The suite was enforcing a rule its own bundled specification did not state.**
  suiteRevision 23 shipped `bad-1001` through `bad-1016` against the requirement
  that every carried record binding to the run whose payload names a covering kind
  satisfies that kind's constraints, whether or not any row resolves an
  `observationRefs` index to it. That requirement was written upstream after the
  commit this repository had vendored, so the corpus refused sixteen statements on
  a sentence a reader of the bundled copy could not find. An implementer who pins
  this bundle and implements from it alone -- which is the whole reason the copy is
  vendored -- would have read the sixteen refusals as the suite overreaching its
  own text. Re-vendoring is the repair; nothing about what the corpus forces
  changes.
- **What moved in the specification, exactly.** Two edits and no others: the
  coverage-validity preamble now counts six further requirements rather than five,
  and the sixth is the universal-quantifier partner of the sealed-record-presence
  requirement beside it, with a changelog entry upstream recording the same. Every
  other byte of the vendored document is identical to the copy suiteRevision 23
  shipped.
- **What this revision does not exercise.** It adds no coverage. The rule the
  re-vendored text now states is exactly the rule suiteRevision 23's sixteen
  vectors already forced, so the forcing baseline, the coverage matrix classes and
  the condition registry are unchanged in substance; the anchors and `spec:NNN`
  citations move only because prose was inserted above them, and they are remapped
  mechanically by `scripts/vendor-spec.py` rather than re-judged. No new failure
  code is introduced and no existing code changes its condition. A reader looking
  for what changed in the suite's behaviour will find nothing, and that is the
  point of the revision.

## suiteRevision 23 (a rule read only where a row points)

- Corpus: **248 vectors (54 accept, 192 reject, 2 indeterminate)**, up from 232.
  Sixteen reject vectors are added, one existing reject vector gains a second
  declared condition, and no accept vector moves. The vendored specification does
  not move and the predicate type is unchanged. With the vectors added, all 192
  reject vectors declare a parent that ships as an accept vector.
- **A one-integer edit voided a whole reject family.** Every vector whose subject
  is a defective `sealed` record carries a healthy seal beside it, on purpose, so
  that "this seal covers no clean row" stays separable from "this statement has
  no valid seal at all". Point the clean row's `observationRefs` at the healthy
  seal instead and the defective record is still carried, still signed under the
  same substrate key, and simply never read. Fourteen vectors returned
  `valid / pass (recompute-confirmed)`, exit 0. The laundered defects include a
  seal signed `aeeStillArmed: false`, a drop count with no bound, an over-bound
  count, a posture the run never pinned, `aeeMethod: reconstructed` on a seal,
  and a negative drop count.
- **The obligation attaches to the record, not to the reference.** The kind
  constraints were read on two paths and the producer chose both: the per-row
  gate reads the records a row resolves, and the sealed-record-present
  requirement reads records until it finds ONE that passes. Neither says anything
  about a failing record carried beside them. From this revision, every carried
  record that binds to the run and whose `aeeKind` names a covering kind must
  satisfy every constraint of that kind, whether or not any row resolves an index
  to it. The candidate set is the one the presence requirement already admits, so
  this is the same predicate under the other quantifier and not a second reading
  that could drift from the first. The failure code is the kind's own: a reader
  who resolves a defective record from a row and a reader who finds it carried
  beside the rows have found one fault in one record.
- **The same gap held three other kinds open, and each is now a vector.**
  `bad-1015` carries a second `arming` record with no `armedAt`, referenced by
  nothing; `bad-1016` carries an `examination` record signed
  `aeeMethod: intercepted`, referenced by nothing and inside the seal's
  `aeeObservedSet`. Both were accepted by both rails before this revision. The
  fourth kind, `interception`, has the same hole and is closed by the same rule:
  `interception-record-orphaned` forces a caught row to resolve the record, but
  the per-row gate returns early on any row that is not `basis: substrate`, so a
  caught row of another basis satisfies the reference while nothing reads the
  payload. It ships without a vector, and that is said here rather than left to
  be found: the only shape that reaches it is an `artifact` row carrying
  `observationRefs`, which this suite deliberately leaves unpinned, and a reject
  vector built on it would pin an interpretation the corpus has not taken.
- **The fourteen are DERIVED from the vectors they are about.** Each rebuilds the
  original statement and swaps the row's seal reference for the other carried
  seal; nothing is hand-written and nothing is re-stated. A hand-written copy
  would be free to differ from its original in some way that also explained the
  refusal, which is the confusion these vectors exist to remove. The swap is
  expressed as "the other sealed index" rather than as a literal, so it reads the
  same on `bad-1007`, whose covering seal precedes the defective one, as on the
  thirteen where it follows.
- **`bad-902` gains `arming-covers-nothing` as a declared second condition.** Its
  mutation IS a second arming record carrying a posture the run never pinned, and
  that record breaks its own kind's constraint. Until this revision it was
  dropped on the floor, because class-match needs one valid arming record and the
  statement has one. The second condition is the new rule working on a statement
  the corpus already held, so it is recorded as inherent rather than as a second
  mutation: a differently-built vector cannot avoid it, because the wrong-posture
  arming record is the vector.
- **The traceability gap widens by one, and it is the new condition itself.**
  That second number is 34 of 76 today, up one because `aee-c-108` is cited by
  sixteen refusals and by no accepting vector. That is the honest state and not
  an oversight: an accept vector citing it would be a statement carrying a
  covering record that satisfies its kind while no row resolves it, which every
  accept vector in the suite already is, so citing the id there would record a
  property rather than measure one. It stays measured and ratcheted in
  `docs/ACCEPT-ANCHOR-BASELINE.json`.

## suiteRevision 22 (the duplicate an undecodable record was hiding)

- Corpus: **232 vectors (54 accept, 176 reject, 2 indeterminate)**, up from 231.
  One reject vector is added and two indeterminate vectors' bytes change. No
  verdict on any earlier statement moves, the vendored specification does not
  move, and the predicate type is unchanged. With the vector added, all 176
  reject vectors declare a parent that ships as an accept vector.
- **`bad-410-duplicate-and-undecodable-record` is the statement no revision had
  written.** It carries a byte-identical second copy of the arming record and a
  fourth record, of an unknown kind, whose payload is re-encoded as
  non-canonical base64 so it no longer strict-decodes. Both rails guarded the
  duplicate scan and the batch-root recompute behind one condition -- did every
  record decode -- so a single record failing base64 switched off both.
  Suppressing the ROOT is right: an undecodable record contributes no leaf, and
  a root recomputed without it would be a root over a leaf set no producer
  committed to. Suppressing the DUPLICATE scan is not. The records that decoded
  still carry whatever duplicate they carried, and a statement holding both
  conditions reported the decode failure and dropped `duplicate-record`
  entirely.
- **The undecodable record is a fourth one, and the unknown kind is not
  decoration.** Faulting either half of the duplicated pair leaves no duplicate
  to find. Faulting a covering record instead would put the statement's seal and
  the verifier's recompute of `aeeObservedSet` on opposite sides of a record
  nobody can read, and the vector would then carry the extra condition -- a
  vector about masking, carrying a mask. An unknown kind is excluded from that
  commitment by the producer and by the verifier for different reasons that
  agree, so the decode failure is the only thing the record contributes.
- **What this vector cannot do, said here rather than left to be discovered.**
  A reject expectation is a code SET and the harness conforms a rail whose codes
  INTERSECT it, so that a strict rail naming one condition and a superset-emitting
  rail naming every condition it found both pass the same manifest. That contract
  is right and this revision does not touch it. It also means this vector's own
  PASS/FAIL cannot move: both conditions sit in one expected set, `record-undecodable`
  is emitted first and is therefore the primary code either way, and the whole
  corpus replays green through a rail with the defect restored. Measured, not
  argued. What the vector does change is that the weakening stops being invisible:
  before it, restoring the shared guard produced byte-identical observations on
  every statement in the corpus. The assertion that both conditions are reported
  belongs to each rail's own oracle rather than to the conformance contract, and
  that is where it now lives -- `TestSetEmissionOnPairedRecordFaults` replays this
  vector's committed bytes through the Go rail, and the Python rail's self-test
  asks the same of a statement it builds itself.
- **The indeterminate family was carrying a duplicate nobody declared, and the
  reason it was invisible is the same defect.** Both members are built on a
  clean statement plus a spare unreferenced seal, added so that faulting one seal
  does not additionally leave the statement with no valid seal at all. The spare
  was byte-identical to the seal it stood beside: same run binding, same observed
  set after resealing, so the same signed bytes. `ind-001` faults a record's
  base64, which switched the duplicate scan off, and `ind-002` faults one of the
  two seals, which stops them being identical -- so the only member that could
  have shown the duplicate was the member that disabled the check. The spare now
  carries a drop bound the parent's seal does not, which is an honest thing for a
  run-end seal to say and makes it a second record rather than a second copy.
  Both members report the same two conditions again, which is what a family whose
  members differ only by a role exchange is supposed to do.

## suiteRevision 21 (two identifiers were addressing one statement)

- Corpus: **231 vectors (54 accept, 175 reject, 2 indeterminate)**, unchanged from 231.
  No vector is added or removed and no verdict moves. One reject vector's bytes
  change, and one gate is added that would have refused the state this revision
  corrects.
- **`bad-713-only-sealed-ref-noncovering` was byte-identical to
  `bad-707-sealed-stillarmed-false`.** Same sha256, two identifiers, two
  different conditions credited: `aee-c-68` for one and `aee-c-65` for the other.
  So `aee-c-68`'s only reject vector was a copy of another condition's, and the
  corpus credited a condition with a discriminator it did not have.
- **The cause was a design decision in a different builder.** `_seal_mut` appends
  an unreferenced, fully-covering sealed record on purpose: without it, a vector
  about a seal that covers no clean row would also assert "this statement carries
  no valid seal at all", and a rail could pass it having implemented neither rule.
  `bad-713` was hand-built to place a covering seal beside a non-covering one --
  which is what `_seal_mut` had come to do for every vector in its family. The
  two converged, and the later of them stopped testing anything the earlier did
  not.
- **The repair makes the ordering load-bearing rather than incidental.** The
  covering seal now precedes the referenced non-covering one, and the row
  references indices 0 and 2. A rail that resolves the row's referenced set still
  rejects. A rail that scans the record list and stops at the first seal that
  covers now accepts, and is caught. Under the old ordering that same rail had to
  scan past the bad seal to reach the good one, so the vector could not separate a
  first-match scanner from a correct implementation. It can now, which is a
  discriminator the corpus did not previously hold.
- **`scripts/vector-distinctness-gate.py` refuses the class.** Two identifiers may
  never address one statement. The manifest carries no per-vector digest, so
  before this nothing in the repository pinned vector content: a vector could be
  replaced by a copy of its neighbour and every count would still add up.
- **The check that should have seen it could not, and that is the wider finding.**
  `docs/FORCING-HONESTY.md` is this suite's own published weakness report, and it
  counted two vectors for `aee-c-68` because it counts DECLARED CONDITIONS and
  never DISTINCT STATEMENTS. A report whose purpose is to say where the corpus is
  weak was structurally unable to see that two of its inputs were one artifact.

## suiteRevision 20 (a planted probe on every channel, and an anchor for every refusal)

- Corpus: **231 vectors (54 accept, 175 reject, 2 indeterminate)**, up from 226.
  No statement changes shape, no run binding moves, the vendored specification
  does not move and the predicate type is unchanged: the revision adds five
  vectors and changes no verdict on any earlier one.
- **Detector liveness becomes a construction over carried bytes, and it needs
  no new member.** A check that never fires may be guarding a well-designed
  boundary or may be dead, and from outside the two are indistinguishable,
  because both emit the same clean run. The only thing that separates them is a
  planted stimulus the check must catch. Five members this version already
  carries do that: `classes` says which channel an attack belongs to,
  `expectedPayloads` is the value a corpus author predicted for what that
  attack looks like on the wire, `aeePayloadCommitment` is what the substrate
  committed to, `attribution: pinned` is the row asserting the two are
  comparable, and `aeeObservedAttacks` on the run-end seal is what the
  substrate attributed. A channel is demonstrated when all five line up for one
  of its attacks. `scripts/liveness-probe.py` computes it, per channel, over
  any statement.
- **The claim is strictly per channel, so the fixtures are per channel.** A
  probe caught on one channel establishes nothing about the channel beside it,
  so a corpus that plants one probe and reports a live detector has measured a
  sample and called it a census. `ok-052-liveness-probe-per-channel` carries
  three channels, three planted probes and three demonstrations at once. Three
  rather than two, because a rail that decides on the first row and the last
  passes a two-channel statement while skipping everything between, and the
  three refusals beside it each place their fault on a channel that is not the
  first: `bad-983` commits the middle channel's interception to a value no
  corpus entry declares, `bad-984` drops the last channel's `expectedPayloads`
  entry while its row keeps declaring `pinned`, and `bad-985` deletes the
  middle channel's interception and re-points its row at the seal.
- **Liveness is not a validity requirement, and one accept vector exists to
  keep it from becoming one by accident.**
  `ok-053-liveness-probe-uncaught-on-one-channel` carries the same three
  planted probes with the middle channel's row clean, its attribution at the
  honest floor and its attack absent from the seal. That is a producer whose
  detector did not fire saying so, and it MUST be accepted: refusing it would
  refuse the honest report along with the dishonest one, and `bad-985` is the
  dishonest report of the same run. What the format does instead is make the
  difference legible -- three probes declared, two named on the seal -- and
  leave the decision with the consumer, where this document's Consumer policy
  obligations already put it.
- **Every refusal in the corpus is now checked to ship beside a vector that
  must be accepted.** A verifier that rejects its input unconditionally passes
  every reject vector ever written and scores perfectly against a reject-only
  corpus. `scripts/accept-anchor-gate.py` checks the pairing at two
  granularities: all 175 reject vectors declare a parent that ships as an
  accept vector, and the conditions cited only by refusals are measured and
  ratcheted against `docs/ACCEPT-ANCHOR-BASELINE.json` rather than described in
  prose. That second number is 33 of 75 today, down one because `ok-052` cites
  `aee-c-104`, and it is a traceability gap rather than a coverage hole: most
  of those conditions are satisfied by accept vectors that do not cite them,
  and saying which it is matters because overstating it would be its own
  defect.

## suiteRevision 19 (two kinds get a name, and the splice gets a vector)

- Corpus: **226 vectors (52 accept, 172 reject, 2 indeterminate)**, up from 221.
  Every vector is regenerated, because the vendored specification moves and its
  digest is a corpus input. No statement changes shape, no run binding moves and
  the predicate type is unchanged: the revision carries two additions that make
  no verdict on any earlier statement different.
- **`moat-drop` and `uncommitted-observation` are registered kinds, and neither
  covers anything.** Producers were already signing both under this run binding
  with no spelling in the document for either, and forward compatibility was
  carrying them: an unrecognized kind covers nothing, is otherwise ignored,
  still contributes its leaf to `batchRoot`, and can only weaken a claim. That
  is the right outcome reached by accident, and the alternative a producer
  reaches for when a name is missing is worse than the absence, because a record
  of either shape stamped `interception` carries no `aeePayloadCommitment`, and a
  malformed interception is still a carried interception, so the whole statement
  falls.
- **The registration is verdict-preserving, which is why the type does not
  move.** A verifier that does not implement the two names treats each as
  unrecognized and reaches the same answer over the same bytes. What changes is
  the name of the refusal: a rail reports `moat-drop-covers-nothing` or
  `uncommitted-observation-covers-nothing` rather than the unrecognized-kind
  condition, because a citation of a kind that covers nothing by registration
  and a citation of a kind the verifier has never heard of are different
  producer errors, and telling the first to upgrade a current verifier does not
  help it. `bad-980` and `bad-981` force that distinction; `bad-714` keeps
  forcing the unrecognized case beside them, and a rail routing both through one
  condition passes it and fails the new pair.
- **What each kind CANNOT be used to claim is stated in the document, in its own
  voice, beside what it is.** A `moat-drop` record evidences that one path
  refused one packet and nothing about another path, a retry that succeeded, or
  a payload that never reached the enforcement point; it cannot make a caught row
  caught or a clean row clean, and it is not the run's dropped-observation
  counter, which counts what the substrate failed to record rather than an
  enforcement action it did. An `uncommitted-observation` record cannot stand in
  for an interception anywhere, including the existence requirement a `pinned`
  row must satisfy, and may not carry `aeePayloadCommitment` at all.
  `ok-050-registered-noncovering-kinds` is the accept side: both records are
  referenced by a clean row and signed with the weaker `aeeMethod`, so the vector
  fails on any rail that lets either cover, enter the method cap, enter
  `aeeObservedSet`, or demand a caught row.
- **The cross-row `observationRefs` splice is now a vector rather than a rail's
  own unit test.** `attribution: pinned` kills the splice, and that was proven at
  suiteRevision 18 -- but against a statement hand-built inside `aee/`, because
  every pinned vector in the corpus carried a single row and permuting one row is
  the identity. A control the corpus cannot exercise is a control no consumer
  copy is measured against, and three vendored copies replay this suite.
  `ok-051-two-pinned-rows` carries two pinned rows in different coverage classes,
  each resolving its own interception; `bad-982-pinned-assignment-spliced` is
  that statement with the two rows' `observationRefs` exchanged and the record
  set, every signature and the batch root left exactly as the producer signed
  them. Measured both ways: the splice reports `attribution-pin-unmatched`, and
  with the comparison switched off it is accepted, so the vector forces the rule
  rather than passing beside it.
- **Cell U7 is not narrowed further and not retired.** Its residual is the
  `paired` half, which is unchanged: a producer declaring `paired` on every row
  violates nothing and emits a statement no rail can distinguish from the honest
  one, so the closure against it stays a consumer obligation the document states.
  What moved is the evidence for the other half. The cell's witness sketch used
  to read as though four single-row vectors covered the splice, and they did not;
  they force the three parts of the pinned rule while the operator the rule
  exists to refuse was unreachable from the corpus.

## suiteRevision 18 (the predicate revision that makes four descriptions checkable)

- Corpus: **221 vectors (50 accept, 169 reject, 2 indeterminate)**, up from 187.
  Every vector in the corpus is regenerated, because every statement carries a
  new `predicateType` and a new required row member. The vendored specification
  moves with it, so this is a normative revision on the wire, on the corpus and
  on every published conformance record.
- **The type is `.../v0.7` and the earlier one is retired**, with no alias and
  no dual-accept window, under the same single-canonicalization rule that
  retired the 0.4 basis values. The bump is not housekeeping: three members
  become required and a record that was conditionally required becomes
  unconditional, so a statement valid under the earlier version can be
  malformed under this one.
- **A sealed record is required on every statement carrying a `basis:
  substrate` row**, whether or not any row resolves an index to it, and it
  carries `aeeObservedSet`: a commitment to the leaf hashes of every
  interception and examination record the substrate emitted. Nine accept
  vectors carried a substrate row and no sealed record and all nine gained one;
  four reject parent shapes did too, which is why forty-five reject vectors
  briefly carried the condition as a second fault and none does now.
- **Two structural requirements join coverage validity and read no signed data
  at all**: a clean row may resolve no index to an interception record, and
  every carried interception record is resolved by at least one caught row. The
  second is breaking on the accept side. `ok-029-artifact-with-records` rested
  on two interception records no row resolved, which is the shape the rule
  refuses; its records are now examinations, so the vector keeps its subject
  (a batch root over records no row resolves) and stops making a claim the
  statement then reports nothing about. Ten reject vectors carry the condition
  as a declared consequence of the mutation they already name.
- **`aeeObservedAttacks` on the seal names the attacks the run attributed at
  least one of its own observations to**, and obliges a caught row for each.
  The rule reads in one direction only, and that direction is what
  `ok-046-seal-attacks-lower-bound` exists to pin: without it a rail reading
  the sets as equal passes the whole corpus.
- **`aeeAssessedAttacks` on the arming record names what the run declared,
  before injection, that it would assess**, and the assessed set carried at run
  end must be a SUBSET of it. A subset and not an equality, so a run that lost
  coverage part-way can still disclose the loss, which `ok-004` already is.
- **`expectedPayloads`, `aeePayloadCommitment` and the required row member
  `attribution` together make the row-to-record assignment checkable** wherever
  the corpus was willing to predict what the substrate would commit to. This is
  the change the versioning discipline pre-authorised, and it is the one that
  moves a measurement this repository has carried as a null since it was
  written: exchanging `observationRefs` between two caught rows used to leave
  the whole report byte-identical, and now does so only while both rows declare
  `paired`. `TestPinnedAttributionKillsTheSplice` is the new half of that
  measurement and cell U7 is narrowed rather than retired, because a producer
  declaring `paired` throughout still violates nothing.
- **Twenty-six reject vectors and four accept vectors are new.** Seven of the
  twenty-six exist because a mutation campaign found the first nineteen did not
  force what they named: each had a second acceptable condition that an older
  rule reported first, so the newer rule could be deleted and the older one
  carried the vector. A vector that passes for a rule other than the one it
  names measures nothing about that rule.
- **The generator now asserts the new requirements over its own parents.** Four
  parent shapes violated the mandatory-seal rule the moment it landed, which no
  existing assertion could see, so `commitments_check` runs the whole set of
  them over every parent and the second-fault pass refuses a seal left
  committing to a pre-mutation record set.

## suiteRevision 17 (a third bucket, for the questions the specification leaves open)

- Corpus: **187 vectors (46 accept, 139 reject, 2 indeterminate)**, up from 186.
  One reject vector moved into the new bucket and one vector is new. No accept
  vector, no other reject vector, no record set, batch root, run binding or
  signature moved.
- **The bucket, and why the corpus needed one.** An accept vector says every
  conformant verifier admits these bytes. A reject vector says every conformant
  verifier refuses them and names a condition this suite pins. Neither sentence
  can say that the verdict is settled and the condition is not, and there are
  statements about which that is the only true thing to say: the specification
  carries no failure-code vocabulary at all, and of its own two-stage
  verification description it says that "the sequencing itself is informative"
  (L413-415). Two rails can therefore reject the same bytes, name different
  conditions, and both be right.
- **What was there instead.** `bad-748` pinned one of those answers as a reject
  vector, and `docs/interpretation-decisions-open.md` said in the same breath
  that a rail giving the other answer "is conformant to the specification and
  fails this corpus, and that is the corpus overreaching rather than the
  verifier erring". The prose and the vector disagreed for eight revisions. The
  other option available under two buckets was to name both codes in the
  expected set, which is worse: the harness compares code SETS, so a widened set
  is satisfied by either answer and by a rail that emits both, and the vector
  would have stopped measuring the question rather than started.
- **What an indeterminate vector declares.** A DETERMINED verdict --
  indeterminacy is scoped to the condition, because a vector whose verdict were
  open would certify nothing -- and a set of READINGS, each naming the condition
  that reading predicts for that member. Three requirements follow: the verdict,
  CLOSURE (the rail's answer is one some declared reading predicts), and
  COHERENCE (one reading explains the rail's answers across the whole family).
  Either answer is admissible. No answer is not, and neither is a pair of
  answers straddling two readings, because the reported condition is then a
  function of incidental structure rather than of a policy the rail applies.
- **The one family, and why it has two members.**
  `signature-count-vs-payload-decode` carries a statement with one record whose
  payload does not strict-decode and one that carries no signature entry. The
  readings are `set-level` (the count is asked once over the record set before
  any payload is decoded), `positional` (asked per record inside the decode
  loop, so wire order decides) and `decode-first` (every payload decoded before
  any count). `ind-001` orders the faults undecodable-then-empty and separates
  `set-level` from the other two; `ind-002` orders them the other way and
  separates `positional` from `decode-first`. The profile no reading predicts is
  answering `ind-001` with the missing signature and `ind-002` with the decode
  fault, which is what a primary-code selector that overwrites rather than
  sets-if-unset produces. A single-fault corpus can never see it.
- **What is not in the bucket, and the finding that says so.** The
  specification's other open corners were enumerated against the vendored text
  before the bucket was built, and only this family qualified. The producer
  assertions about what the run executed (L513-528) and the shared-reference
  evidencing obligation on a row declaring `paired` (L928-940) are LIMITS rather
  than choices: every conformant verifier must accept those statements, and the
  second says outright that "a conforming verifier neither can nor may invent an
  evidencing heuristic in its place". The consumer MAY
  clauses (L495-496, L1159-1162, L1247, L1263-1267) sit outside the verdict this
  suite reads, because validity "is a function of carried bytes alone and holds
  identically for every consumer" (L1828-1831). The producer options are forced
  on the verifier and already carried by accept vectors. One family with two
  members is the honest size of this bucket.
- **The reference rails read `set-level`, and that is now recorded rather than
  required.** The harness reports which reading each rail took, reading the
  optional `primaryCode` a rail may publish beside its code set; a rail that
  publishes only the set has declined to answer and is recorded as such. That
  report is the point: two rails that agree on every verdict and disagree here
  have had nowhere for the disagreement to show up, and the two findings this
  corpus has taken from an outside reader were both of exactly that shape.
- **Consumers must re-vendor.** The corpus content digest moved and the vendored
  layout gained a directory, so the TypeScript rail, the standalone Python rail
  and the MCP server rail carry suiteRevision 16 until they are refreshed;
  `scripts/consumer-lag-gate.py` fails until they are.

## suiteRevision 16 (the corpus is regenerable, and was measured to prove it)

- Corpus: **186 vectors (46 accept, 140 reject)**, unchanged in size, in
  membership, in declared conditions and in expected failure codes. Five reject
  vector files changed bytes. Every other vector file, every record set, every
  batch root, every run binding and every signature is untouched.
- **Why a revision for a change that adds nothing.** The seven vectors
  suiteRevision 15 added were minted by hand and committed as files. No builder
  was added to either generator and no row was added to either index, so the
  corpus had five reject vectors and two accept vectors that no generator could
  produce, against a determinism recipe both indexes publish and nothing had ever
  run. A published revision is not mutated in place, so the repaired corpus is a
  new one.
- **What was wrong with the five files, beyond being unbuildable.** Three of them
  -- `bad-900`, `bad-901`, `bad-902` -- carried a sealed or arming record whose
  signature does not verify: the mutated payload had been written with the
  parent's signature copied across it. The reject generator's own second-fault
  self-check refuses all three, and this directory's published invariant is that
  signature verification is never a vector's fault because it is tier territory
  rather than validity. All five also carried the ACCEPT generator's constant set
  -- a different catch-policy digest, a different posture digest, a different
  corpus name and uri, a different run-entropy pre-image -- inside a directory
  whose determinism recipe names the other one. They are now built by the reject
  generator from its own parents, its own constants and a real signature.
- **What was checked before the bytes were allowed to move.** Each rebuilt vector
  reports the same single failure code as the file it replaces, read from
  `cmd/aee-verify -json`: `sealed-covers-nothing` for `bad-900`, `bad-901` and
  `bad-902`, `vocabulary-not-canonical` for `bad-905`, `environment-incomplete`
  for `bad-906`. The harness output over the whole corpus is byte-identical to
  the run before the change, and the forcing ratchet rebuilt and replayed every
  mutant it records as killed and found all of them still killed. Nothing this
  corpus is measured to force was traded for regenerability.
- **The manifest was also not its generator's output.** suiteRevision 15 rewrote
  `vectors/MANIFEST.json` with the reject section first, where the generator
  emits accept first, so the file disagreed with `vectors/gen_manifest.py` for
  every one of its entries and not only the seven. Per-vector content is
  unchanged; the document is now the one the generator writes.
- **What now stops it recurring.** `scripts/regenerability-gate.py` copies the
  tree, empties the generated set, runs all three generators and diffs, so a file
  no generator produces fails on the push that adds it. Both generators' drop
  tripwires read the vector directory instead of a typed count, and
  `scripts/count-gate.py` checks each index table against the manifest rather
  than against the heading above it. Run against suiteRevision 15 unmodified, the
  new gate names all seven files and the manifest.
- **Consumers must re-vendor.** The corpus content digest moved, so the
  TypeScript rail, the standalone Python rail and the MCP server rail carry
  suiteRevision 15 until they are refreshed;
  `scripts/consumer-lag-gate.py` fails until they are.

## suiteRevision 15 (the corpus is measured, and forces seven rules it did not)

- Corpus: **186 vectors (46 accept, 140 reject)**, up from 179. Seven vectors
  added; no existing vector file changed, and no record set, batch root, run
  binding or signature moved. Every addition was mutation-checked before it
  landed: each fails on a rail with its target check removed and passes on the
  rail as shipped.
- **Why these seven.** The corpus was mutation-measured for the first time --
  590 single-site weakening changes across every rail file, each replayed over
  all 179 vectors. 316 were killed, 250 were byte-identical on the whole corpus,
  19 were seen and tolerated. These seven vectors move twelve rules out of the
  unforced set. The measurement, its harness and its full tables are recorded
  outside this repository; what belongs here is the corpus delta.
- **What the measurement corrected about this repository's own harness.** A
  prior reading of `packaging/run_vectors.py` concluded that a vector's stage
  passes when any expected code in that stage is observed, and therefore that a
  rule is forced when its code is alone within its stage. Stages populate a
  DISPLAY column only. The verdict fires on an empty intersection across all
  stages, so a per-stage failure never fails a vector. Deleting the
  `result-vocabulary` emission entirely leaves the suite at 179/179 and exit 0
  while printing a failed gate on two rows -- a rail with no result-vocabulary
  check at all was fully conformant. The forcing bar is
  sole-across-the-whole-code-set, and it is lower than anyone had stated.
- **Two divergences in the Python reference rail, both found by the new
  vectors, both fixed here.** Neither was a new regression; both had existed
  for as long as their rules had, invisible because nothing forced them.
  - `bad-902-sealed-posture-ne-arming` -- the sealed posture must equal every
    referenced arming record's posture claim as well as the pinned digest
    (spec:1023-1028). Go, TypeScript, the standalone Python verifier and the
    server rail all enforced both equalities; this rail enforced only the
    pinned one. The vector needs TWO arming records, because with one the
    pinned-posture check always fires first and the second equality is
    unreachable -- a rule can be unforced because the corpus shape cannot
    express its precondition, not because nobody wrote the vector.
  - `bad-906-corpus-manifest-absent` -- an absent `corpus.manifest` is
    `environment-incomplete` on the Go rail (`aee/statement.go:249-251`) and was
    silently accepted here, so the same statement verified `invalid` on one rail
    and `valid` on another.
- **The largest gap closed.** `ok-900-fail-outranks-degraded` exercises the
  composition rule that decides every mixed run. Before it, zero of 179 vectors
  carried both a fail-forcing row and a non-empty coverage gap, so the ordering
  that makes a real failure outrank a coverage gap had never been tested; a rail
  that ranked them the wrong way round passed the entire suite.
- Added: `ok-900-fail-outranks-degraded`, `ok-901-row-missing-basis`,
  `bad-900-sealed-method-reconstructed`, `bad-901-sealed-negative-dropcount`,
  `bad-902-sealed-posture-ne-arming`, `bad-905-vocabulary-labels-absent`,
  `bad-906-corpus-manifest-absent`.
- **Deliberately NOT added.** Two further candidates were built and
  mutation-checked and do not kill: the checks they target are masked by sibling
  conditions and cannot be forced as this corpus is shaped. They are recorded as
  unmintable rather than unminted, because a gap list that conflates the two
  sends the next implementer to write vectors that cannot pass. Two mutants that
  no vector can ever kill are recorded on the same reasoning.

## suiteRevision 14 (the vendored text catches up with the corpus)

- Corpus: **179 vectors (44 accept, 135 reject)**. Every vector file is
  byte-identical to suiteRevision 13, and the record set, the batch roots, the
  run bindings and every signature are untouched. This revision vendors words
  rather than bytes: the two amendments the corpus had already implemented now
  exist in the text it certifies against, so nothing the generators emit had to
  move to agree with them.
- **What was vendored.** The pin moves two commits along the upstream predicate
  branch, from `a2d173a` to `f2ea2aa`. The first binds the carried
  `observationVocabulary` digest and the carried `networkPosture` object into
  the run identity as version 2 of the binding, and declares the posture
  vocabulary a closed registry of four values with an append-only rule across
  minor versions. The second adds the fourth `result` value, `pass_indirect`,
  and restates the recompute as the minimum of three independent conditions
  rather than as a cascade. Both were held back only because the vendoring
  script reads bytes from a git ref, so an uncommitted upstream edit cannot
  honestly be pinned.
- **Why no vector moved.** Both readings landed in the rails and the corpus at
  suiteRevisions 12 and 13, ahead of the text, and both were recorded at the
  time as the corpus running ahead of what it certified against. The
  amendments say what the corpus already does, so the replay was green against
  the new text before the new text arrived. That is the whole of the evidence
  that the two edits describe the implemented reading rather than a second one.
- **The two records of that gap are closed.** The `suiteRevision 12` and
  `suiteRevision 13` entries in `docs/interpretation-decisions-open.md` each
  stated an upstream ask and named the vectors a from-spec verifier could fail
  while conformant to the vendored copy. Both asks are carried in full by the
  vendored text now, so both entries are closed and retained as the record of
  why the corpus moved first. The closed posture registry becomes registry
  decision 19 and the four-value recompute becomes decision 20, which is where
  a reading goes once the text forces it.
- **Citations and anchors moved with the prose, and twenty-six spans were
  repointed by hand.** The re-vendor remapped 85 `spec:NNN` citations and 291
  `Lnnn` anchors. Both ledgers were allowed to refuse and neither did, because
  every span whose text changed sits in a passage these amendments rewrote,
  which is what an ordinary amendment looks like to the check. Eight citations
  and eighteen anchors were repointed afterwards, all of them cases where the
  remap landed on prose that no longer carries the whole claim beside it: the
  binding pre-image gained two members on lines past the end of the remapped
  span, the digest-value-form citation lost the words `lowercase 64-hex` when
  the sentence it cited was split in two, the coverage-gap condition became its
  own sentence while its citations stayed on the fail-closed one, and the
  posture citations now address the registry paragraph rather than the sentence
  that used to introduce the values as examples. That last class is the one the
  ledger cannot judge, since a citation truncated onto prose that was itself
  rewritten reads as an ordinary amendment; it is a known limit of the check
  and it held here. The refusal path was mutation-checked on each ledger rather
  than inferred from a green run.

## suiteRevision 13 (the top result stops being reachable without a substrate)

- Corpus: **179 vectors (44 accept, 135 reject)**. Four vectors move their
  expected result and one reject vector moves the result it carries; four
  vectors are new. Every other file is byte-identical, and the record set, the
  batch roots, the run bindings and every signature are untouched, because the
  change is to a function over rows and reads nothing a record carries.
- **What moved.** The `result` recompute gains a third independent condition
  and a fourth value. A statement is `pass_indirect` rather than `pass` when
  some clean row declares a `basis` other than `substrate` or a `method` other
  than `intercepted`, and the answer is now the minimum of the three
  conditions under `fail` < `degraded` < `pass_indirect` < `pass` rather than a
  cascade. The minimum matters on exactly one shipped shape: `ok-033` carries
  an indirect clean row and discloses a coverage gap, and it reads `degraded`,
  the lower of the two contributions.
- **What the condition is for.** The top result was reachable by a statement
  carrying no substrate evidence at all. A party holding the enclosing envelope
  key and not the substrate's observation key takes a run that recomputes to
  `fail`, relabels every row clean, moves every row to `basis: artifact`, and
  drops the observation records, the batch root and the run entropy that only a
  substrate row required. Nothing it leaves behind is malformed and the result
  it lands on was `pass`.
- **Why the condition does not claim to detect that.** Driven over all eleven
  finding-bearing accept vectors, the statement that mutation produces is
  byte-identical, under sorted canonical bytes, to one an honest producer with
  no substrate vantage emits forward from the same run configuration. Eleven of
  eleven, none differing. A verifier is a function of the carried statement, so
  no rule refuses the first without refusing the second, and refusing both would
  remove the producer whose attack classes have no substrate vantage to observe
  from at all. The condition therefore prices both below a live interception
  instead, which is the only separation the carried bytes support.
- **The honest producer is the one to check first.** `ok-007` is that producer:
  an artifact-only statement with no records, no batch root and no run entropy,
  reporting what it saw from the executed artifact's own account. It stays
  VALID, and it reaches the best result its evidence supports.
- **Four new vectors, two in each direction.** `ok-044` carries the one
  basis/method pairing the closed vocabularies permit that nothing here
  exercised, a clean row indirect in vantage while claiming a live method,
  which is exactly the shape the downgrade produces. `ok-045` pins the
  quantifier: a live intercepted clean row beside an artifact-basis one still
  reads `pass_indirect`, so a direct row cannot carry an indirect one back up.
  `bad-009` is the downgraded statement still carrying `pass`, which is the
  attacker's own bytes and is now a recompute mismatch. `bad-010` carries
  `pass_indirect` over rows that are all direct, because equality is
  two-directional and the new token is not a floor a producer may volunteer
  down to.
- **What moves and what does not.** `ok-006`, `ok-007`, `ok-029` and `ok-038`
  move from `pass` to `pass_indirect`; `bad-818` moves the result it carries so
  that it keeps isolating its `clean-row-layer-not-none` defect rather than
  gaining a second code. `bad-003` and `bad-004` are unchanged: both recompute
  to `fail` against a carried `pass`, and a fail-closed row is not a clean row,
  so the new condition never reaches them. The manifest-floor vectors are
  unchanged too, because a statement with no rows has no clean row.
- **What the condition deliberately cannot see.** It reads the DECLARED `basis`
  and `method` and never the evidence tier, because the tier is key-relative and
  a result that moved with a consumer's trust anchors would not be
  recomputable. So an `unattested` substrate clean row still reaches `pass`,
  which the clean-row ordering ranks with `artifact`. That half of the weakness
  belongs to the tier and is outside any byte-pure function.
- **The vendored copy is deliberately unmoved, and the corpus runs ahead of it
  for the second revision running.** The authority this corpus certifies against
  still defines `result` over three values. Closing that needs the amendment to
  exist upstream first, because editing the vendored copy in place would make
  the vendor pin name a commit that does not contain those bytes, which is the
  single thing the drift gate exists to refuse. The pin and the recorded
  `specDigest` are unchanged from revision 11, and the two new reject vectors
  anchor on the recompute-equality requirement, which is the rule they actually
  test and which has not moved.

## suiteRevision 12 (the run identity gains the vocabulary and the posture)

- Corpus: **175 vectors (42 accept, 133 reject)**. Every vector carrying a
  decodable record identity was re-minted, because the identity itself moved:
  126 of the 165 that existed, 29 accept and 97 reject. 32 carry no decodable
  record identity and are byte-identical. Seven carry an identity that matches
  neither construction on purpose, and all seven were re-derived by the
  generators that express that purpose rather than rewritten to a value someone
  chose. Ten vectors are new.
- **What moved.** The run-binding pre-image is now `aeeBindingVersion: 2`. It
  gains `observationVocabulary`, the carried vocabulary digest, and its
  `networkPosture` input becomes the RFC 8785 canonical digest of the carried
  posture OBJECT rather than the value of that object's own digest member.
  Nothing else about a statement changed: both inputs are configuration the wire
  already carried, so no accept vector gains a byte, and both close through the
  equality every record's `aeeRunBinding` was already put to. Version 1 is
  retired with no alias and no dual-accept window.
- **Why each input belongs there.** Both are run configuration fixed before
  corpus injection, which is the admission test for any binding input rather
  than a coincidence: the arming record carries the digest inside its own
  signature and is signed before injection, so a value the producer could not
  know then would make the arming record unsignable. Before the change, a party
  holding only the outer envelope key could narrow the caught set and turn a
  caught row into a clean one, or swap the posture between two registered
  values, and in both cases change no digest and break no signature.
- **Two vectors inverted rather than moved.** `bad-303` was named for a pre-image
  the rails did not implement and is now named for the one they retired: its
  records are minted under version 1, which is a digest a real producer could
  have emitted last revision, where a version nobody has implemented would
  reject whether or not the rule holds. `bad-726` declared the version the
  verifier does not implement and had been left declaring `2`, which the rails
  now implement, so it asserted nothing; it declares `3`. Both were caught by
  asking what would have to change for each to go red, not by reading them.
- **The posture registry is exercised for the first time.** Every vector in the
  suite carried the same posture string, so a rail admitting only that one
  string and a rail admitting any string at all scored identically on the whole
  corpus. Three accept vectors carry the other registered values and three
  reject vectors carry the three shapes that are not one: an unregistered value,
  a value of the wrong JSON type, and a value wrapped in an array. The last is
  the shape that took two rails down before it was fixed, because testing
  membership of an unhashable value against a set raises rather than returning
  false, which is a crash and a cross-rail split at once.
- **Three vectors pin the change itself**, and each names a mutation that was
  free before it: a posture swapped between two registered values (`bad-305`), a
  caught set narrowed with its own digest re-derived (`bad-306`), and a producer
  member added to the posture after the arming record was signed (`bad-307`),
  whose accepted twin `ok-043` carries the same member with records that commit
  to it. The pair states the rule as one about when the member was added rather
  than about whether the posture may carry one.
- **The vendored copy is deliberately unmoved, and the corpus now runs ahead of
  it.** The authority this corpus certifies against still describes the
  seven-member version-1 pre-image and still introduces the posture values
  illustratively. Closing that needs the amendment to exist upstream first,
  because editing the vendored copy in place would make the vendor pin name a
  commit that does not contain those bytes, which is the single thing the drift
  gate exists to refuse. The pin and the recorded `specDigest` are therefore
  unchanged from revision 11, and the gap is recorded with the exact upstream
  ask in `docs/interpretation-decisions-open.md` rather than left to be noticed.

## suiteRevision 11 (the amendment run vendored, with the corpus unmoved)

- Corpus: **165 vectors (38 accept, 127 reject)**. Every vector file is
  byte-identical to revision 10, verified by digesting all 165 before and after
  regeneration rather than inferred from the absence of a generator change. No
  conformance claim moves and no rail has anything new to replay.
- **Why a revision exists at all.** The authority the corpus certifies against
  moved. The vendor pin advances from `b9a585a` to `a2d173a` and the recorded
  `specDigest` to `4939d450...`, taking in four upstream amendments. A revision
  is how this suite records which bytes of the predicate a conformance claim was
  measured against, so a pin that moves is a revision even when the vectors do
  not, and an implementer diffing the vendored copy against the commit the pin
  names gets an answer that is true of exactly one revision.
- **Why the corpus does not move.** Of the four amendments, one was already
  forced when it was written: revision 10 carries the seven vectors for the
  timestamp profile, drawn against upstream text that had not yet been committed,
  which is why its closing bullet asked for this re-vendor. The other three land
  outside what a single self-contained statement can exercise. Dropping the
  condition code from the manifest requirement and adopting the framework's
  descriptor type where it fits are both statements about how the document types
  and names things the rails already agreed on. The last is a consumer
  obligation in stage two, which the byte-pure validity gate does not reach.
- **The correction the last amendment makes.** The document had told a consumer
  it may bound a named key with a validity window checked against `issuedAt`.
  That field is producer-asserted, sits inside no substrate signature, and is not
  among the run binding digest's inputs, so the party a key bound exists to
  constrain moves it with a one-field edit that changes no digest and breaks no
  signature; back-dating alone rehabilitates every record a revoked key ever
  signed. The window keeps its choice about whether to exist and loses its choice
  of operand: it is evaluated against an `armedAt` inside an `arming` record that
  verifies under the bounded key, and a statement carrying no such record is
  refused rather than falling back. This suite cannot force that rule, because
  a corpus of single statements has no key lifetime to place them in, and the
  requirement is recorded in the unforced complement rather than left implicit.
- **The citations and anchors were remapped, and the remap was checked rather
  than trusted.** The completing pass of that revision moved 28 `spec:NNN`
  citations and 110 `Lnnn` anchors onto the new line numbers. All 294 pinned citations recompute
  to the digest and the excerpts they were pinned to, so not one of them came out
  of this remap addressing prose it was not drawn around. That is the opposite
  outcome to the pass before it, where nine anchors came out of the remap wrong
  and were found by a person reading the excerpt diff. The refresh now asserts
  this for itself rather than leaving it to that reading: it refuses to record an
  anchor that came off prose the document still contains, and re-running the
  earlier pass against the current tooling stops it and names eight of the nine.
- **One entry for the run, not one per pass.** The pin was caught up in two
  passes, and neither moved a vector byte. Bumping on each would publish two
  revisions carrying an identical corpus, which tells a reader that something
  about the vectors changed twice when nothing about them changed at all, so the
  earlier pass deliberately left the number alone and this entry covers both.

## suiteRevision 10 (one timestamp profile, cited from both fields that carry it)

- Corpus: **165 vectors (38 accept, 127 reject)**. Five rejects and two accepts
  for a rule the predicate now states once and cites twice.
- **What was wrong.** `armedAt` was pinned to a zero UTC offset and `issuedAt`
  was typed only as a lowercase "RFC 3339 timestamp", so a statement carrying
  `"issuedAt": "2026-01-01T05:00:00+05:00"` was conformant and off-guideline at
  the same time, and all five rails accepted it there while refusing the same
  instant on the pinned field. The sentence that left the offset open also left
  the case of the RFC 3339 designators open, and there the rails had already
  parted: `"issuedAt": "2026-01-01t00:00:00z"` was refused by the Go reference
  rail with `issued-at-malformed` and accepted by the Python reference rail with
  zero codes and `result: pass`, an accept-on-one reject-on-another split inside
  this repository, on the rail a third party runs standalone. No vector reached
  it.
- **The fix is a type adoption, not a new rule.** The framework's `Timestamp`
  field type already requires RFC 3339 in the UTC timezone, and the predicate's
  protobuf already typed `issued_at` as `google.protobuf.Timestamp`; only the
  markdown was looser than both. The amended field entry types `issuedAt` as
  `Timestamp` and states on it the two choices that type leaves open, and the
  arming record cites the profile instead of restating half of it.
- **Lowercase designators are not conformant.** The pinned field named `Z` and
  `+00:00` and lowercase `z` is neither, so the Python reference rail was
  already non-conformant against text that predates this revision. Its
  `RFC3339_RE` carried `[Tt]` and `[Zz]`; the character classes are narrowed to
  `T` and `Z`, and the zero-offset test folds into the same parse, so both
  timestamps run through one function on every rail.
- **Each half of the profile is tested by the half of the code that carries
  it.** Four rails expressed the zero-offset rule as a suffix test,
  `endswith("Z", "+00:00", "-00:00")`, which admits exactly the strings a
  zero-offset test admits and also refuses a lowercase `z` on the way past. That
  is a check reading more than it says: with it in place, no lowercase mutant
  can distinguish a rail that enforces the case rule from one that does not, and
  the case rule would have shipped untestable. Each of the four now reads the
  parsed offset instead, which is the shape the Go rail already had, so the
  pattern owns the case and the offset owns the zone. The corpus follows the
  same split: one lowercase vector per designator per field rather than one
  carrying both lowercased, since a both-lowercase mutant stays rejected however
  the case rule is written.
- **`-00:00` is conformant, and the reason is written into the specification so
  it is not rediscovered.** RFC 3339 section 4.3 gives `-00:00` the distinct
  meaning that the instant in UTC is known while the offset to local time is
  not. That is a statement about where the producer stood, not about when it
  signed, and the instant is the only thing this predicate reads from either
  field. All five rails already accepted it; excluding it would have cost five
  changes to gain nothing, and it went unnamed in every document, which is how
  it stayed untested.
- **The vectors.** `bad-820-issuedat-non-utc-offset`,
  `bad-821-issuedat-lowercase-separator` and
  `bad-822-issuedat-lowercase-zone-designator` derive from `ok-007`, the parent
  the rest of the `issuedAt` block already uses, so the whole block derives from
  one statement. `bad-750-armedat-lowercase-separator` and
  `bad-751-armedat-lowercase-zone-designator` derive from `ok-002` and are the
  case half of the rule `bad-727` carries the zone half of.
  `ok-038-issuedat-negative-zero-offset` and
  `ok-039-armedat-negative-zero-offset` carry the spelling the profile admits
  and the old sentence never named, so a rail reading "zero offset" as "`Z` or
  `+00:00` only" is caught by the suite rather than by a third party. Each
  mutant names the same instant as its parent, so ordering and every digest
  input are unchanged and the spelling is the only variable.
- **No new failure code.** Both `issuedAt` rejections report
  `issued-at-malformed`, which `aee-c-85` already covers whole, following the
  precedent `bad-727` set when an offset violation folded into the field's
  existing code. A distinct code would change the reason map an external checker
  keys on and buy a verifier nothing it could not already conclude.
- **Vendoring sequence.** The corpus is written against the amended `issuedAt`
  entry, which is upstream and not yet in a commit, so the vendored copy under
  `spec/` still carries the pre-amendment wording and the pin still names
  `b9a585a`. `spec/ANCHOR-PINS.json` therefore records the pre-amendment excerpt
  against the `bad-820`, `bad-821` and `bad-822` claims. Re-vendor with
  `scripts/vendor-spec.py` once the upstream commit lands: it remaps the anchors
  and re-pins them in the same pass, and the excerpts then describe the rule the
  vectors were drawn against.

## suiteRevision 9 (one condition, three spellings, and a fixed precedence)

- Corpus: **158 vectors (36 accept, 122 reject)**. specDigest unchanged at
  `1590b988...`; no normative change, two new vectors closing two rail
  divergences the corpus could not see.
- **How they were found.** A review of the freshly landed signature-entry
  condition read the rails side by side and found two of them answering
  differently. Nothing in the corpus disagreed, because the condition had
  exactly one vector and that vector could not reach either question.
- **The first divergence: when the count is evaluated.** Four rails ask "does
  any record carry no signature entry" once over the whole record set, before
  any payload is decoded. One asked it per record, inside the payload-decode
  loop. Both readings report the same condition for a statement carrying one
  fault, which is every vector in the suite. Give a statement a first record
  whose payload does not decode and a second carrying no signature entry and
  they part: the per-record rail meets the decode fault first and names it, the
  set-level rail names the missing signature. Which condition a verifier reports
  is the conformance contract, so this is a divergence rather than a matter of
  style.
- **The set-level reading is the one the spec gives.** The predicate's
  verify-then-read discipline is normative: a consumer verifies each record's
  signature "before relying on any field inside the payload", and a payload's
  fields "mean nothing until its signature verifies". A record with no signature
  at all is therefore settled ahead of the bytes it carries. The spec does not
  decide the sequencing directly and says so, since it makes only the
  consumption preconditions and the tier normative in its two-stage ordering and
  calls the sequencing itself informative. The suite has to decide, because a
  primary condition is what it compares. Because the text does not force it, the
  pick is written down as a spec ask rather than as a registry decision:
  `docs/interpretation-decisions-open.md` carries the argument, the sentence to
  add upstream, and the plain statement that until it lands a from-spec verifier
  evaluating the count per record is conformant to the specification and fails
  this corpus.
- **The second divergence: what a wrong-typed member is.** A `signatures` member
  holding a string, an object or a number carries no entry, so four rails report
  the entry-count condition. One decoded the member into a typed list, failed,
  and reported the parse catch-all for the whole statement. The catch-all names
  neither the record nor the member, and the registry had already decided this
  question for the absent-member spelling, which reports the specific condition
  even though a missing required member would otherwise be a parse fault. Absent,
  empty and wrong-type are one requirement failing three ways, so they report one
  condition. A wrong-typed value INSIDE a signatures array is untouched and still
  reports the catch-all: an array carries entries, so a fault in one of them is a
  fault in the entry rather than in the count.
- **`bad-748-signatures-empty-precedes-undecodable-record`.** Derived from the
  `ok-002` clean shape: the arming record's payload is re-encoded as
  non-canonical base64 so it no longer strict-decodes, and the sealed record's
  signatures array is emptied, in that wire order. Swapping the two roles makes
  every rail agree, so the order is the vector. Neither mutation moves a
  commitment: signatures sit outside the PAE pre-image and a lenient decode of
  the tampered payload returns the parent's exact bytes, so the leaf, the
  batchRoot, the run binding and every carried signature are what the parent
  carried.
- **A precedence pin has to be compound, and its expectation must not widen.**
  This is the suite's first vector that is compound by design rather than
  because deriving it singly was impossible. Its expected set names ONE
  condition, so a rail reporting the other fails rather than passing on a set
  widened to accommodate it. The second-fault self-check, which exists to prove
  a vector carries only its declared fault, would have flagged the deliberate
  companion; the corpus now declares such companions explicitly under
  `alsoCarries`, exempting only what was declared, so an UNdeclared second fault
  in the same vector still fails the check.
- **`bad-749-record-signatures-not-an-array`.** Derived from the `ok-001` caught
  shape by replacing the covering record's signatures member with the JSON
  string `"sig"`. It reads as the likeliest producer bug of the three spellings,
  since a substrate that emits one signature object where the schema wants an
  array of them produces exactly this. Nothing is rederived, for the same reason
  `bad-745` rederives nothing.
- **Verified by mutation, per divergence.** With the Go rail's typed decode of
  the member restored, `bad-749` is the only failing vector of the 158 and fails
  as "primary code statement-malformed not in expected set". With the Go rail's
  count moved back inside the decode loop, `bad-748` is the only failing vector
  and fails as "primary code record-undecodable not in expected set". Each
  vector goes red for exactly the divergence it was written for.
- **Independent checker status.** `Rul1an/aee-checker`'s last author-run is
  **suiteRevision 6 at 153/153** (2026-07-28, aee-checker#4), a run its author
  records as directed. It has not run suiteRevision 7, 8 or 9, so this suite
  publishes no score for it at any of the three.

## suiteRevision 8 (a corpus that declares no attack is not a corpus)

- Corpus: **156 vectors (36 accept, 120 reject)**. specDigest advances to
  `1590b988...` at upstream commit `b9a585a`. Two new vectors, one normative
  reason.
- **The defect.** A valid, passing, policy-admitted statement about an
  arbitrary subject could be minted with no substrate, no substrate key, no
  substrate run, no `observationRecords`, no `batchRoot`, no `runEntropy` and
  every carried digest fabricated. The verifier returned valid with result
  `pass` and the shipped admission policy returned compliant. This is a total
  bypass of the substrate, which is categorically worse than lying about a
  real run: there is nothing to lie about.
- **The mechanism, one step at a time.** Coverage integrity is an equality
  between two unions of attack identifiers, and an equality between two empty
  sets holds, so a manifest declaring nothing satisfied it vacuously. Zero
  declared attack identifiers means zero rows. Zero rows means zero
  `basis: substrate` rows. With no substrate row the predicate already
  permitted `runEntropy`, `observationRecords` and `batchRoot` to be absent.
  Every structure that would have required a substrate signature therefore
  dropped out of the statement, and what remained still verified.
- **The normative change.** The manifest now carries a floor: it MUST declare
  at least one attack identifier across all of its classes, and a manifest
  declaring none makes the statement malformed under the condition
  `corpus-manifest-no-attacks`. It sits with well-formedness rather than with
  `result` because a corpus declaring no adversarial inputs is not an
  adversarial corpus; scoring it would concede that a zero-attack run is a
  legitimate statement that merely scores badly, and that concession is the
  thing the floor refuses.
- **Why the rule counts identifiers and not classes.** Both
  `{"classes": {}}` and `{"classes": {"XA": []}}` were measured valid, passing
  and admitted before the fix. A rule phrased as "an empty classes object is
  malformed" closes only the first and leaves the second, which carries a real
  class name and reads far more plausibly as an assessment that found nothing.
  Counting identifiers closes both.
- **`bad-746-manifest-empty-classes` and
  `bad-747-manifest-class-declares-no-attacks`.** Two vectors because the
  bypass has two shapes and one vector leaves the other untested. Both derive
  from the `ok-007` artifact-only recordless shape, which already carries no
  records, no `batchRoot` and no `runEntropy`, so emptying the manifest is the
  whole distance between a valid statement and the bypass. The rederive chain
  drops the row the emptied manifest no longer declares and rebuilds the
  coverage partition around what is left; leaving either behind would add
  `row-attack-unknown` or `coverage-incomplete` and the vector would stop
  testing the floor. Everything else in both files still checks out: the
  corpus digest re-derives over the emptied manifest, coverage partitions it
  exactly, and the recompute returns `pass`.
- **What the floor does not touch.** A manifest that declares attack
  identifiers and assesses none of them stays valid. The honest fully-skipped
  run -- every class disclosed under `outOfScope`, no rows, result `degraded`
  -- was measured valid before this revision and is still valid after it,
  because its manifest declares an attack identifier. The Go rail pins that
  case as an explicit control beside the two new rejects.
- **Both reference rails.** The Go rail carries the check as
  `corpus-manifest-no-attacks` in `gate0Corpus`; the Python rail gained the
  identical condition code this revision in `_corpus_declares_attack`.
  Verified by mutation: with the Python check disabled, `bad-746` and
  `bad-747` are the only failing vectors of the 156 and both fail as "expected
  invalid, observed valid" -- the pre-fix bypass, reproduced.
- **Independent checker status.** `Rul1an/aee-checker`'s last author-run is
  **suiteRevision 6 at 153/153** (2026-07-28, aee-checker#4). It has not run
  suiteRevision 7 or suiteRevision 8, so this suite publishes no score for it at
  either revision.

## suiteRevision 7 (a record must carry a signature to be a record)

- Corpus: **154 vectors (36 accept, 118 reject)**. specDigest advances to
  `da840f9e...` at upstream commit `3502c52`. One new vector, one normative
  reason.
- **The normative change.** `observationRecords` described a DSSE envelope as
  `payload`, `payloadType` and `signatures` without saying how many signature
  entries the last of those must carry, so a record carrying an empty array was
  a well-formed record by the letter of the definition. The definition now
  requires at least one entry. The revision also reconciles the verify-then-read
  order the same section states with the byte-pure gates that read payload
  fields before any verification: those gates read ahead deliberately, because a
  consumer holding no key material must still be able to run them, and what they
  produce is a stage rather than a conclusion. Coverage validity is restated in
  the same terms — it establishes that a statement is well formed and never that
  it is true, and it becomes a security property only in combination with
  observation-record signature verification.
- **Why the corpus could not see the zero case.** A DSSE leaf is
  `H(0x00 || PAE)` and the PAE pre-image spans `payloadType` and `payload` only,
  so signatures sit outside every commitment the predicate makes. Stripping
  every signature entry from every record leaves the leaf hashes, `batchRoot`,
  the run binding and the recomputed `result` bit for bit unchanged, leaves the
  statement valid, and drops only the derived evidence tier. A consumer gating
  on `result` alone therefore admitted an entirely unsigned attestation, and no
  check at the byte-pure layer could notice.
- **`bad-745-record-signatures-empty`.** Derived from the `ok-001` shape by
  emptying the covering record's `signatures` array, with an empty rederive
  chain — the only vector in the suite that alters a record and moves no
  committed digest at all, which is the finding stated as a construction. An
  absent member and an empty array are the same fault, since both are a count of
  zero. The check is byte-pure and proves nothing about the entries it counts: a
  record carrying one fabricated signature stays valid here and is caught only
  by verification at the tier, so the vector closes the literal zero-signature
  case and no more.
- **Both reference rails.** The Go rail carries the check as
  `record-signatures-empty` in `checkRecordsStatementLevel`; the Python rail
  gained the same code this revision, since without it the two rails disagreed
  on a statement with an empty `signatures` array — the Python rail answered
  valid where Go answered invalid. Verified by mutation: with the Python check
  disabled, `bad-745` is the only failing vector of the 154 and fails as
  "expected invalid, observed valid".
- **Independent checker status.** `Rul1an/aee-checker`'s last author-run is
  **suiteRevision 6 at 153/153** (2026-07-28, aee-checker#4). It has not run
  suiteRevision 7, so this suite publishes no score for it at this revision.

## suiteRevision 6 (the depth boundary and the noncharacter exclusion)

- Corpus: **153 vectors (36 accept, 117 reject)**. specDigest advances to
  `606215de...` at upstream commit `aa9aa9c`, which adds two paragraphs to the
  Prerequisites: the noncharacter exclusion below, and a normative-honesty
  sentence stating that a reading no vector exercises is untested rather than
  confirmed. Four new vectors, two normative reasons.
- **The depth boundary the previous revision could not discriminate.** Revision 5
  made the nesting bound normative at 128 with `bad-741`, but `bad-741` is a
  scalar leaf at open-container depth 130 — the one shape a verifier that counts
  per parsed value rejects correctly — and nothing in the corpus sat at the 128
  boundary, so a constant-only fix and a correct counting rule scored identically.
  The independent checker named this precisely. `ok-036` (accept) puts a scalar
  leaf at open-container depth 128, the exact bound; `bad-742` (reject) puts an
  **empty-container** leaf at open-container depth 129, one level past it. The
  empty-container shape is the discriminator: a verifier that charges nesting per
  parsed child never charges an empty container its own level, so it slips one
  past the bound.
- **A first-party split the pair also closed.** That exact shape was live in the
  reference Go rail: `decodeValue` charged depth per child, so `aee/jcs.go`
  accepted an empty-object leaf at open-container depth 129 where the Python rail
  (`run_vectors.py`, a bracket counter) rejected it — the two reference rails
  disagreeing on identical bytes at one depth, which is the parity the bound
  exists to guarantee. The guard moved into the container branch so an empty
  container is charged when it opens; `bad-742` is the regression pin (reverting
  the guard makes the buggy rail accept it). The same off-by-one was fixed in the
  TypeScript payload parse.
- **The noncharacter exclusion (`bad-743`, `bad-744`).** The string
  well-formedness rule cited strict I-JSON, and RFC 7493 section 2.1 forbids the
  66 Unicode noncharacters (U+FDD0..U+FDEF and U+nFFFE/U+nFFFF in every plane) in
  the same sentence as surrogates, but every rail accepted U+FFFF. A noncharacter
  is a valid scalar value that nothing substitutes for, so it is not a cross-rail
  decoding split — identical bytes give identical digests everywhere — but a
  verifier implementing the RFC 7493 label rather than the narrower scalar-value
  wording would reject a record another accepts. `bad-743` carries U+FFFF in a
  vocabulary label (statement position); `bad-744` carries it in a payload value.
  Every rail now rejects noncharacters wherever a string literal appears, at any
  depth and in both member-name and value position.
- **Independent checker status.** `Rul1an/aee-checker` reached **153/153 on this
  revision** (2026-07-28, aee-checker#4), 36/36 accepts and 117/117 rejects, on a
  record naming checker source `sha256:1c3e2e78` and suite commit `6aa7c60`. It
  is the revision that checker's CI now verifies continuously. The unchanged revision-5
  build scored 151/153 against it: `ok-036` and `bad-742` passed on the
  container-branch counter already in place, and `bad-743` and `bad-744` did not,
  because that build had not implemented the RFC 7493 section 2.1 noncharacter
  exclusion this revision makes normative. The author's own reading of the run is
  that it is directed, and that reading is the author's to give: "the rule was written and the vectors named
  before this checker ran, so what it demonstrates is that the corrected rule is
  implementable from the text, not that an independent reader found it." A
  previous edition of this bullet carried our own derived expectation for
  `bad-743`/`bad-744`, which the run has now replaced. The revision-5 fix that
  precedes this one also retires the 148/149 note recorded under revision 5
  below: with the bound at 128, no vector fails that checker for a bound
  difference.
- **Note on reproducing the record.** The suite commit the record names,
  `6aa7c60`, no longer resolves in a fresh clone of this repository: its history
  was rewritten here after the record was pinned. `6aa7c60` carries the identical tree and
  therefore the identical 153 vectors, and is where a reproduction should point
  until the record is repinned.

## suiteRevision 5 (byte-level tier: the quadrant that had no coverage)

- Corpus: **149 vectors (35 accept, 114 reject)**, specDigest unchanged from
  revision 4. Nine new reject vectors, `bad-733` through `bad-741`.
- **The gap this closes.** Revision 4 made encoding well-formedness and the
  nesting bound normative and said plainly that the corpus exercised neither.
  It exercised nothing nearby: decoding all 140 files and all 219 base64
  payloads found no escape sequence of any kind, no non-UTF-8 byte and no raw
  control character anywhere. That is also the quadrant where the rails had
  actually diverged in the field, so it was the largest unguarded surface in
  the suite.
- **Statement position** (`statement-malformed`): unpaired high surrogate
  escape (`bad-733`), unpaired low (`bad-734`), reversed pair (`bad-735`),
  CESU-8 (`bad-736`), overlong UTF-8 (`bad-737`), raw U+0001 (`bad-738`). Each
  appends the fault to an `observationVocabulary` label and **recomputes the
  vocabulary digest over the mutated content**, so a rail that decodes leniently
  sees a self-consistent vocabulary and has no other rule left to catch the
  statement on. That is the construction that verified valid on one rail and
  invalid on three.
- **Payload position** (`payload-not-ijson`): unpaired surrogate escape
  (`bad-739`), CESU-8 (`bad-740`), nesting one level past the bound (`bad-741`).
- **New vector tier.** `bad-736`, `bad-737` and `bad-738` are not valid JSON
  texts, so they cannot be produced by a serializer and are written verbatim in
  binary. The generator asserts the property rather than assuming it: a vector
  declared byte-level that parses as a JSON text is an error, because the fault
  was lost in serialization. The runner reports whether its parse was faithful
  and skips the derived-commitment self-check when it was not, since every
  digest recomputed from a lossy reconstruction would mismatch for the
  substitution rather than for a second fault.
- **`bad-741` failed the independent from-spec checker when this revision
  published, and that was the point.** On identical bytes the reference rails
  answered invalid and `Rul1an/aee-checker` answered **valid**, because its bound
  was 256 and the bound is now normative at 128. The 127-depth divergence
  recorded in revision 4 stopped being an argument and became a reproducible
  corpus failure. The honest parity figure for that implementation was therefore
  **148/149**, never rounded up, until the fix landed. It landed in the fuller
  form recorded under revision 6 above, moving both the constant and the counting
  rule, and the figure at this revision is **149/149**.
- Verified by mutation on both reference rails: removing the Go string-scalar
  scan changes every statement-position vector to `vocabulary-digest-mismatch`
  and the payload vectors to `payload-not-canonical`; removing the Python one
  restores the original `UnicodeEncodeError` crash, which is the defect the
  whole tier exists to keep closed.

## suiteRevision 4 (encoding well-formedness and a normative nesting bound)

- Corpus: 140 vectors (35 accept, 105 reject), verdicts and codes unchanged.
  New specDigest `39233b27b7f2...`, vendored from in-toto/attestation#570 at
  commit `98328d1`.
- **Normative change.** Strict I-JSON previously named only its duplicate-member
  half, and the string half was scoped to BMP-only, which constrains WHICH
  scalar values may appear rather than whether the bytes denote scalar values at
  all. The spec now requires, statement-wide and fail-closed, that every string
  literal be a well-formed sequence of Unicode scalar values: valid UTF-8 with no
  overlong form and no surrogate encoded directly in UTF-8, no unpaired surrogate
  escape in either order, no raw character below U+0020, and a `\u` escape of
  exactly four hexadecimal digits with no sign, whitespace or radix prefix. The
  check is required on the raw bytes, before any decoded string is read.
- **Normative change.** JSON nesting depth is bounded at 128, with the counting
  rule stated (open containers, not parsed values). It was previously unstated,
  so implementations chose their own: the reference rails chose 128 and the
  independent from-spec checker chose 256, which made identical bytes valid
  evidence to one conforming verifier and malformed to another across 127 depths.
- **Why no vectors changed.** Both rules codify what the reference rails already
  enforced, so no existing vector flips. That is also the honest limit of this
  revision: **the corpus does not yet exercise either rule.** Decoding all 140
  vector files and all 219 base64 record payloads finds no `\u` escape of any
  kind, no non-UTF-8 byte, and no raw control character anywhere, in either
  statement or payload position. An implementation can pass this revision at
  140/140 while getting the new rules wrong.
- **Follow-up, tracked.** A declared raw-bytes vector tier covering unpaired
  surrogate escapes, CESU-8, overlong forms, raw control characters and the
  depth boundary, in both positions. It is a tier rather than ordinary vectors
  because a vector carrying invalid UTF-8 cannot satisfy the generator's
  existing invariant that every emitted vector re-parses as JSON text.

## suiteRevision 3 (round-8 reason-map membership)

- Corpus: 140 vectors (35 accept, 105 reject). No normative spec change; the
  specDigest is unchanged. Two forcing vectors close the reason-map side of the
  coverage-partition membership rule already carried by the spec (L912-914): the
  three coverage sets are a disjoint partition of the manifest's classes, so
  membership runs both ways, but only `bad-819` forced the `assessedClasses`
  side. New reject vectors `bad-731-outofscope-unknown-class` and
  `bad-732-routedelsewhere-unknown-class` force it for the two reason maps (an
  unknown class key in `outOfScope` / `routedElsewhere`, `result` left alone,
  must be rejected `coverage-incomplete`). Both reference rails already enforced
  it (Go `aee/statement.go`, Python `_coverage_partition_ok`); the vectors lock
  the rule and mutation-prove the rails (reverting the reason-map accounting
  flips both vectors). Surfaced by the independent from-spec checker as an
  untested consequence of the written rule (in-toto/attestation#570 round-8,
  Rul1an). Registry decision 14 gains the two vectors.

## suiteRevision 2 (round-7 chain-scope redesign)

- Corpus: 138 vectors (35 accept, 103 reject). Normative change to the
  `aeeChainScope` arming-payload member: a free-form producer string becomes a
  duplicate-free array of tokens from the closed dimension vocabulary
  (`subject`, `corpus`, `networkPosture`), sorted in `observationVocabulary.labels`
  canonical order (UTF-16 code-unit). Each token pins a projection to a value
  already carried on the wire; a consumer compares the declared dimension set
  against its demanded scope (equality: neither finer nor coarser) and keys the
  gap/fork/genesis rules on the evaluated tuple, not the token set. No alias: the
  old string form fails closed.
- New reject vectors: `bad-721-chain-scope-not-array` (old string form),
  `bad-722-chain-scope-unknown-dimension`, `bad-723-chain-scope-not-canonical`,
  `bad-724-artifact-ref-out-of-range`. `ok-034-arming-chain-genesis` rewritten to
  the array form `["subject"]`.
- Out-of-range `observationRefs` is now a structural fault on ANY row, regardless
  of `basis`, fail-closed (previously enforced only on substrate rows).
- The whole statement is parsed as strict I-JSON: a duplicate member anywhere in
  the statement (not only inside a record payload) makes it malformed. New reject
  vector `bad-725-statement-duplicate-member` (raw statement bytes; the dict form
  cannot carry a repeat).
- `aeeBindingVersion` MAY be carried explicitly in the arming payload: a verifier
  reads it before deriving and rejects, fail-closed, a version it does not
  implement (the arming record covers nothing), distinguishably from a
  run-binding digest mismatch. Absent defaults to `1`; the carried value never
  drives the derivation. New reject vector `bad-726-arming-binding-version-carried`.
- Interpretation-decision hardening (from the independent from-spec checker's
  eleven recorded interpretation decisions, in-toto/attestation#570). Three
  forcing vectors lock spec-mandated readings the corpus did not yet exercise:
  `ok-035-unknown-kind-excluded-from-cap` (a referenced unknown-`aeeKind` record
  signed reconstructed covers nothing and is excluded from the method cap),
  `bad-818-artifact-clean-row-layer-not-none` (the clean-row `actualLayer: none`
  rule is not scoped to a basis, so an artifact clean row is held to it too), and
  `bad-819-assessed-class-not-in-manifest` (coverage is an exhaustive, disjoint
  partition of real manifest classes, mirroring `bad-816`). New machine-readable
  registry `vectors/interpretation-decisions.json` maps each of the eleven
  decisions to its spec anchor(s) and forcing vector(s), gated by
  `scripts/interpretation-registry-gate.py`. The four open corners (duplicate
  `attackId` rows; `assessedClasses` overlapping the gap maps; artifact-only
  multi-subject; and out-of-range artifact-row refs, already locked by
  `bad-724`) are recorded in `docs/interpretation-decisions-open.md`; the three
  genuine design calls among them are flagged for operator/spec resolution and
  deliberately left un-locked.
- `armedAt` zero UTC offset locked (decision 8 offset sub-case, a real rail bug).
  The spec says "RFC 3339 UTC" but both rails accepted a non-zero offset (e.g.
  `+05:00`) as a valid instant. Both rails now reject a non-zero offset; the spec
  pins `Z` or `+00:00`; new reject vector `bad-727-armedat-non-utc-offset`.
- Subject cardinality made unconditional (open corner C resolved). `subject` MUST
  contain exactly one entry on a statement of ANY basis; only the six
  binding-digest inputs stay substrate-scoped. Both rails previously enforced
  cardinality only under `hasSubstrateRows`, so an artifact-only two-subject
  statement was wrongly accepted. The spec text at L210-213 is split accordingly;
  new reject vector `bad-728-artifact-two-subjects` (`bad-607` keeps the substrate
  case). Registry decision 12.
- Duplicate `attackId` rows are now malformed (open corner A resolved). "One row
  per executed attack" is a well-formedness invariant; both rails detect a
  duplicate `attackId` across rows before the set-based coverage comparison
  (which silently collapsed it before) and emit `statement-malformed`. Spec
  paragraph at L920-932 gains the uniqueness sentence; new reject vector
  `bad-729-duplicate-attackid-rows`. Registry decision 13.
- Coverage sets pinned as a disjoint partition (open corner B resolved, the one
  editorial call; reversible at vetting). A class appears in exactly one of
  `assessedClasses`, `outOfScope`, `routedElsewhere`; a class in more than one is
  malformed. This was a live divergence (our rails reject overlap; the from-spec
  checker accepts it) that no vector exercised. Rails unchanged (both already
  reject via the disjoint-partition check); the spec text at L907-912 now matches
  them; new reject vector `bad-730-coverage-class-overlap`. Registry decision 14.
  With these three corners resolved, `interpretation-decisions.json` has no open
  corners remaining.

## suiteRevision 1 (first public release)

- Corpus: 125 vectors (34 accept, 91 reject) for the Adversarial Execution
  Evidence predicate v0.6, tracking in-toto/attestation#570 at commit `4a36b19`
  (which folds in the review revisions, including the BMP-only string profile
  and the optional arming-payload run-chaining members). `MANIFEST.json`
  enumerates every vector with its expected verdict, result, and code set.
- Each reject vector is broken exactly one way; each accept vector exercises a
  distinct valid shape.
- Notable coverage worth calling out for a reimplementer:
  - Canonicalization: a supplementary-plane `observationVocabulary.labels`
    entry (`bad-612-labels-non-bmp`, `vocabulary-not-canonical`) and a covering
    record payload whose member NAME carries a supplementary-plane code point
    (`bad-208-payload-member-non-bmp`, `payload-not-canonical`). Each stays
    byte-canonical under both the UTF-16 and the code-point member order, so the
    BMP-only rule is the single fault.
  - Type strictness: a caught row carrying `actualLayer` as a JSON number
    (`bad-506-actuallayer-json-number`, `statement-malformed`). A wrong-typed
    row member is a decode-layer fault, deliberately distinct from an absent
    member, so every rail rejects at the same altitude.
  - Run-chaining member syntax (`bad-718`/`bad-719`/`bad-720`,
    `arming-covers-nothing`): `aeeRunSeq` positive, `aeeChainScope` required
    whenever `aeeRunSeq` is present, and `aeePrevRunBinding` a lowercase 64-hex
    digest present exactly when `aeeRunSeq` exceeds 1. The genesis form is the
    accept vector `ok-034-arming-chain-genesis`.
  - Coverage partition: a whole manifest class left out of every coverage set
    with the result forced to pass (`bad-816-coverage-class-dropped`,
    `coverage-incomplete`), the class-granularity fail-open.
  - Base64 canonicality: a record payload re-encoded as non-canonical base64
    (`bad-817-payload-noncanonical-base64`, `record-undecodable`). The Go rail
    decodes with `base64.StdEncoding.Strict()` and the Python rail
    re-encode-compares, so both reject where a lenient decoder would accept.
