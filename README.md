<p align="center">
  <img src=".github/assets/banner.svg" alt="agent-evidence-vectors" width="820">
</p>

<p align="center">
  <a href="https://github.com/probityai/agent-evidence-vectors/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/probityai/agent-evidence-vectors/ci.yml?branch=main&label=build" alt="build status"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0">
  <a href="https://pypi.org/project/agent-evidence-vectors/"><img src="https://img.shields.io/pypi/v/agent-evidence-vectors?label=PyPI&color=3775a9" alt="agent-evidence-vectors on PyPI"></a>
  <a href="https://doi.org/10.5281/zenodo.22758687"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.22758687.svg" alt="DOI 10.5281/zenodo.22758687"></a>
  <img src="https://img.shields.io/badge/AEE%20vectors-275-e8951c" alt="275 AEE conformance vectors">
  <img src="https://img.shields.io/badge/AI%20Agent%20Action%20vectors-53-e8951c" alt="53 AI Agent Action conformance vectors">
  <img src="https://img.shields.io/badge/artifact--binding%20vectors-8-e8951c" alt="8 artifact-binding conformance vectors">
  <img src="https://img.shields.io/badge/SCITT%2FCOSE%20vectors-27-e8951c" alt="27 SCITT/COSE carriage conformance vectors">
  <img src="https://img.shields.io/badge/rails-Go%20%C2%B7%20Python-546274" alt="Go and Python rails">
  <img src="https://img.shields.io/badge/predicate-in--toto%20AEE%20v0.7-6f57c2" alt="in-toto AEE v0.7 predicate">
</p>

## Used by

- [in-toto's AI Agent Action predicate proposal](https://github.com/in-toto/attestation/pull/588/files) names this suite as its conformance corpus, pins release `v0.8.0` by commit and digest, and makes passing it a MUST.
- Listed in the OECD.AI [Catalogue of Tools and Metrics for Trustworthy AI](https://oecd.ai/en/catalogue/tools/agent-evidence-conformance-suite), published 2026-09-14.
- [Rul1an/aee-checker](https://github.com/Rul1an/aee-checker/pull/21), an independent Rust verifier written from the specification alone, scores 272/272 on suiteRevision 28 (its own index calls the run revision 27) with its build frozen before the corpus moved.
- [giskard09](https://github.com/a2aproject/a2a-tck/pull/228#issuecomment-5359047401) ran the 57 RFC 8785 vectors blind against argentum-core before opening the generators: 57/57.
- The maintainer of [VATE](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/main/docs/interop/aee-native-boundary-review.md) regenerated all 308 generated files byte for byte and recorded 258/258 in his own repository.
- Curated in [awesome-agent-runtime-security](https://github.com/bureado/awesome-agent-runtime-security/blob/main/README.md) under attestation and recompute-verify, and on the [awesome-ai-security-tools watchlist](https://github.com/scadastrangelove/awesome-ai-security-tools/blob/main/WATCHLIST.md) with `Co-authored-by` credit on the curation commit.

## Run the suite against your verifier

Add one step to the workflow that builds your verifier:

```yaml
- uses: probityai/agent-evidence-vectors@v0.12.1
  with:
    verifier: ./path/to/your-verifier --json
```

Or replay the corpus from a shell, with nothing cloned:

```bash
uvx agent-evidence-vectors --verifier './path/to/your-verifier --json'
```

Both run the harness described under "The verification pipeline" against your
verifier through the external-implementation contract: the harness invokes
`<cmd> <vector-file>`, reads the verdict from the exit status and the condition
codes from the last line of stdout, and hands the key policy to the process in
`AEE_SUBSTRATE_KEYS`. Your verifier has to speak that contract and nothing
else. The reference rail replays the same vectors beside it, and the report
records where the two agree, where they disagree, and where your verifier
reached the corpus's verdict under a different condition code.

The action pins the corpus to the release you name in `uses:`, installs the
suite from that checkout, and then:

- Writes the job summary: a totals row, one row per vector that disagreed
  with the corpus, and the suite notes.
- Uploads the report JSON as the artifact `agent-evidence-vectors-results`.
  The report is the same `conformance-report.json` the harness writes locally,
  and a scoreboard in another repository pulls it by that name.
- Fails the job when any vector disagreed, the suite raised a refusal, or the
  named verifier did not run on every vector.

Inputs, all optional except the first:

| Input | What it does |
| --- | --- |
| `verifier` | Command line of the verifier under test. The first token must be on `PATH` or a path relative to the workspace. This verifier is always the program that runs: the job fails when it cannot be started or when it answered fewer vectors than the corpus holds. |
| `corpus` | The shipped corpus to replay. Defaults to `vectors`, the Adversarial Execution Evidence corpus the reference rail judges. `agent-evidence-vectors --list-corpora` prints every name. `vectors-w3c-report` and `vectors-observed-effect` are judged only by the package's own reader and define no verifier contract, so a run naming a verifier against either is refused. |
| `tag` | A release to replay other than the one the action itself is pinned to, such as `v0.12.1`. The default is the action's own ref. |
| `artifact-name` | The results artifact's name. Change it only when the action runs more than once in one workflow. |
| `report-path` | Where the report is written, relative to the workspace. |

Outputs: `report` (the report's path), `vectors` and `conform` (the totals),
`executed` (how many vectors the named verifier ran on), and `result` (`pass`
or `fail`), so a later step can act on the count rather than re-read the file.

The package is stdlib-only and carries every corpus, so `pip install
agent-evidence-vectors` needs no network access to this repository. Without
`--verifier` it judges three corpora itself: `vectors` with the reference rail,
and `vectors-w3c-report` and `vectors-observed-effect` with their own readers.
Every other corpus is refused by name with exit 2 and is judged by
`aee-verify <corpus-dir>`, whose readers cover every corpus in the tree.
`agent-evidence-vectors --self-test` runs the reference rail against its own
oracle, which is the first thing to run when a result looks wrong.

### What a conformance claim must show

A claim that an implementation passes a corpus here is a claim about one
report, and that report has to show that the implementation answered every
vector, not this package's reference rail. The report settles it in its own
fields: `rail` reads `external`, `verifier.vectorsExecuted` equals
`totals.vectors`, and `totals.conform` equals `totals.vectors` with
`totals.suiteRefusals` at zero. A specification that makes passing this suite
a requirement should require all of those in the same sentence. A pass printed
without them is the defect `SECURITY.md` records under "A named verifier could
be replaced by the reference rail", which releases before 0.12.1 carry.

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

**The 53 AI Agent Action vectors test proposed strengthening text, not #588 as
it stands.** Their accept members are conformant under the pull request's own
text; their reject members are rejectable under the canonicalization
strengthening this project offers into that pull request
([`docs/ai-agent-action-canonicalization.md`](docs/ai-agent-action-canonicalization.md)),
because the text as it stands leaves those divergences open. The badge above
counts that suite, so the count travels with this sentence: read as a
measurement of the pull request today, it claims more than the pull request
currently requires.

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
[`spec/artifact-binding/v1.md`](spec/artifact-binding/v1.md), which binds an
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
[`docs/W3C-V01-CONFORMANCE-APPENDIX.md`](docs/W3C-V01-CONFORMANCE-APPENDIX.md)
is the appendix rendered from the manifest for the editor to reference.

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
recorded in [`spec/VENDOR-PIN.json`](spec/VENDOR-PIN.json), written from git at
vendor time rather than by hand, and re-vendoring remaps every reference onto
the new line numbers in the same pass that copies the bytes.

Two gates keep the references honest, because a reference that points at the
wrong prose reads as evidence. `scripts/spec-drift-gate.py` covers the
`spec:<anchor-id>@<digest>` citations in the sources and
`scripts/spec-anchor-gate.py` covers the `Lnnn` anchors in the vector tables.
Both ask the same two questions, and the second is the one that matters: not
only whether a reference still resolves to text, which a stale pointer does
perfectly well, but whether it still addresses the prose it was written for.
[`spec/CITATION-ANCHORS.json`](spec/CITATION-ANCHORS.json) and
[`spec/ANCHOR-PINS.json`](spec/ANCHOR-PINS.json) record the text each reference
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

## How this suite is maintained

A conformance suite is only useful to a party who trusts neither the producer nor
the implementer, and such a party cannot weigh a set of bytes without knowing how
the bytes are maintained. Three files answer that without anyone having to be
asked:

- [`GOVERNANCE.md`](GOVERNANCE.md) — who decides, what the maintainer explicitly
  does not decide, what is never changed at any revision, how a revision is cut,
  and the one property a citing document should treat as unmet;
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — where a proposal goes, the single command
  that runs every gate locally, and what each gate refuses;
- [`DISPOSITIONS.md`](DISPOSITIONS.md) — every objection received from someone
  other than the maintainer, in the objector's own frame, with the resolution and
  the reason. Including the ones that were declined, which are the rows worth
  reading first.

## Verify a release without trusting us

A conformance claim names a corpus, and anyone deciding whether to cite this one
has to work out which bytes that claim covers: without taking a maintainer's word
for it, and without taking this page's word. Four commands settle it.

```bash
git clone https://github.com/probityai/agent-evidence-vectors && cd agent-evidence-vectors
git checkout v0.12.1

# 1. the digest list is what the vector files on disk hash to, recomputed
python3 scripts/release-digests.py --check

# 2. the maintainer signed exactly those bytes
cosign verify-blob --key release/cosign.pub \
  --signature release/CORPUS-DIGESTS.txt.sig \
  --insecure-ignore-tlog=true release/CORPUS-DIGESTS.txt

# 3. an RFC 3161 authority saw that signature at a stated time
openssl ts -verify -in release/CORPUS-DIGESTS.txt.sig.tsr \
  -digest "$(base64 -d release/CORPUS-DIGESTS.txt.sig | sha256sum | cut -d' ' -f1)" \
  -CAfile spec/tsa-roots.pem

# 4. so did a public calendar nobody here controls
ots verify -d "$(base64 -d release/CORPUS-DIGESTS.txt.sig | sha256sum | cut -d' ' -f1)" \
  release/CORPUS-DIGESTS.txt.sig.ots
```

This section explains what each of the four commands establishes, and then says
where a green result stops. I sign the digest list by hand at tag time, so the
last paragraph says where the key lives.

`release/CORPUS-DIGESTS.txt` carries 1 line per corpus, and each line states the
digest, the manifest it belongs to, the suite name, the vector count and the
suite revision. A generator writes it: nobody types those lines, and command 1 recomputes every
digest from the vector files through a routine each corpus publishes, so a line
that disagrees with the files on disk ends the run.

Command 2 checks the signature against `release/cosign.pub`, a public key
committed beside the corpus. `--insecure-ignore-tlog` reads alarming and is exactly right: the signature
never went to a transparency log, so no log holds an entry to look up. A
conformance consumer has to verify offline, owing nothing to a log that stays
reachable. Commands 3 and 4 carry the time evidence a log would otherwise supply.

Both stamp the raw signature bytes and not the digest list. A timestamp over the
list dates the bytes. The question worth answering is when the maintainer
committed to them.

A fresh OpenTimestamps proof stays pending for roughly 24 hours, and ots verify
exits non-zero throughout: the calendars hold the digest and the Bitcoin
attestation is not yet in a block. `.github/workflows/ots-upgrade.yml` runs weekly and
finishes it, so a green reading on command 4 within a day of a release is not
the state to wait for.

The release gate runs commands 1 and 2 on every tag. It runs 3 and 4 only behind
`--with-timestamps`, which defaults off, because command 4 reaches a public
calendar and a gate on every push cannot depend on a third party answering.
Command 3 needs no network: the token chains to the root pinned in
`spec/tsa-roots.pem`, which is why that root is committed rather than fetched. A proof that fails
to cover this signature is a hard failure at any hour, checked offline. An
unreachable calendar is reported and never asserted either way, since a failed
read and a bad proof look identical from an exit code.

That key is Ed25519, generated by cosign itself. Its private half has never sat
in this repository or in a CI secret. Signing happens on the
maintainer's machine at tag time, and CI verifies without the ability to sign.
[`docs/SIGNING-PRECEDENT.md`](docs/SIGNING-PRECEDENT.md) records what the rest of
the field publishes, with the command that re-derives it and a positive control.
That page makes an absence claim, and an absence claim is the easiest kind to get
wrong.

## Cite this

Zenodo archives releases 0.10.1 and 0.11.1. The concept DOI
[10.5281/zenodo.22758687](https://doi.org/10.5281/zenodo.22758687) always resolves to the newest
archived release; a version DOI names one release and never moves, and the
Zenodo record lists one for each archived release under "Versions". Cite the
version DOI of the release you ran where it has one, the suite revision and the
corpus digest together,
for the reason [`DISTRIBUTION.md`](DISTRIBUTION.md) gives: a citation that names
only the repository names a moving target. [`CITATION.cff`](CITATION.cff)
carries the concept DOI and, under `identifiers`, the version DOI of the
newest archived release. The tag never carries that second one:
a release is tagged before Zenodo archives it, so the DOI is written to the
default branch after the deposit and the tagged tree records only the
concept. The entry below cites the concept for the same reason. GitHub
renders a citation from the same file.

```bibtex
@software{gilda_agent_evidence_vectors,
  author    = {Gilda, Sankalp},
  title     = {agent-evidence-vectors: conformance vectors for agent execution evidence},
  version   = {0.12.1},
  publisher = {Zenodo},
  year      = {2026},
  doi       = {10.5281/zenodo.22758687},
  url       = {https://doi.org/10.5281/zenodo.22758687}
}
```

## Arriving from somewhere else

Two files carry what a reader who did not come from here needs, and neither one
of them is a summary of this page.

- [`DISTRIBUTION.md`](DISTRIBUTION.md) is the inbound page: the tag to cite, the
  module path, the release-verification recipe above, how to cite a corpus so
  the citation still resolves to the same bytes next year, and what a sibling
  `vectors-*` directory of your own has to carry. It is deliberately inbound
  only and records nothing about where this suite has been sent.
- [`RUNS.md`](RUNS.md) is the scoreboard for runs by implementations this
  repository did not write: one row per posted run, in the reporter's own words,
  under the label its own author gave it, with blind and directed kept apart
  rather than added together. The form at
  [`.github/ISSUE_TEMPLATE/independent-run.yml`](.github/ISSUE_TEMPLATE/independent-run.yml)
  is the whole reporting path, and a run that disagreed with the corpus is the
  row worth having.

`scripts/distribution-gate.py` holds the inbound page to this repository: the
recipe there is byte-identical to the one above, every tag it names is the one
`CITATION.cff` calls released, and its corpora table and that form both hold
exactly the tracked corpus set.

## Layout

```
go.mod                      core module (stdlib-only, enforced by test)
aee/                        the verification core
  statement.go              GATE 0: statement well-formedness
  validity.go               GATE 1: coverage validity (consumption precondition)
  recompute.go              pure result recompute
  tier.go                   GATE 2: evidence tier {declared|unattested|attested}
  runbinding.go             run-binding v1: exactly ONE construction, fail-closed on others
  merkle.go                 RFC 6962: domain-separated, recursive split, duplicate-reject
  pae.go                    DSSE PAEv1 + digest helpers
  jcs.go                    RFC 8785 canonicalization + RFC 7493 I-JSON checks (stdlib)
  types.go / codes.go       parsed statement model + the closed failure-code set
  *_test.go                 unit tests, known answers, the conformance-vector runner
aeetest/                    deterministic synthetic statement builder (derived TEST keys)
cmd/aee-verify/             consumer CLI: gate0, gate1, recompute, then the tier table
cmd/mutgen/                 forcing measurement: enumerate + apply one weakening at a time
cmd/mutrun/                 forcing measurement: replay the whole corpus in process
witnessattestor/            SEPARATE module: the go-witness attestor + library-mode demo
go.work.example             wiring for building the attestor module (see BUILD-NOTES.md)
```

## The verification pipeline

<p align="center">
  <img src=".github/assets/pipeline.svg" alt="A signed statement passes four byte-pure gates (well-formedness, coverage validity, result recompute, evidence tier) to a verdict; any gate fails closed with no result and no tiers." width="380">
</p>

Four byte-pure gates plus a consumer-relative evidence tier. Any gate fails
closed: no result, no tiers. The full contract, step by step:

1. GATE 0: statement well-formedness. Statement `_type` and
   `predicateType` (fail-closed: exactly one accepted construction, no
   cross-version fallback), result vocabulary, environment members,
   vocabulary shape/subset/digest, corpus manifest digest and duplicate
   attack ids, coverage integrity at attack granularity, per-row
   `actualLayer` altitude, subject cardinality and digest canonicality for
   substrate-carrying statements, `runEntropy` presence, `issuedAt`.
2. GATE 1: coverage validity. Statement-level record checks run first
   (batchRoot presence/recompute over RFC 6962 with domain separation and
   no pad-last-node, duplicate-record rejection, orphaned-root), then per
   `basis: substrate` row: refs resolve and are in range, referenced
   payloads are canonical RFC 8785 + I-JSON `+json` objects carrying the
   reserved members with a run binding equal to the derived one,
   class-match per `aeeKind` with each kind's constraints (arming armedAt
   and posture, sealed still-armed/drop-bound/joint posture equalities,
   examination method), and the row `method` capped by the weakest signed
   `aeeMethod` across covering records. On any failure the attestation is
   invalid and its `result` is never consumed; the report carries no
   result and no tiers.
3. Recompute equality. The carried `result` must equal the pure recompute
   over carried bytes; the recompute reads no records, no signature
   outcomes, no consumer policy.
4. GATE 2: evidence tier. Per row: `declared` (artifact basis), `attested`
   (every covering record verifies against a consumer-pinned substrate
   observation key), else `unattested`. No pinned key means every
   substrate row is `unattested`; the substrate root is never inferred
   from the predicate. A record's `keyid` is a lookup hint, never the
   check, and the tier never alters `result`.

## The failure-code contract

Every rejection carries a stable machine-readable code (`aee/codes.go`).
The deterministic primary code (first in pinned detection order) is the
conformance contract; message text and code order beyond the primary one
are not. A few precedence pins matter to anyone reimplementing the gates.
A missing binding input reports its own member code
(`run-entropy-missing`, `subject-sha256-missing`), not
`run-binding-mismatch`; that code is reserved for values that can be
derived but come out unequal. `records-absent` fires when
`observationRecords` is missing entirely, and `ref-out-of-range` fires
only once records exist. The method cap reads covering records only, so
records that cover nothing do not participate, and the two sealed posture
equalities (pinned digest, arming record's claim) are enforced jointly,
not independently. Signature *verification* failure is never a failure
code; it is a tier outcome. The one signature-shaped question the
byte-pure layer does answer is how many entries the array carries: a
record with zero of them (`record-signatures-empty`) is malformed, since
counting entries needs no key material. An absent member, an empty array
and a member that is not an array at all are that one fault counted three
ways, and the count is asked once over the record set before any payload
is decoded, so a record carrying no signature is settled ahead of a record
whose payload does not decode. That last sentence is this rail's READING and
not a rule the specification states, and it is the one place where saying so
required a third kind of vector; see Indeterminate vectors below.

### What the suite compares

`packaging/run_vectors.py` runs an external verifier as `<cmd> <vector-file>`,
reads the verdict from the exit status, and reads the codes, the recomputed
result and the tiers from the last line of stdout when that line is a JSON
object of the shape `{"verdict": ..., "codes": [...], "result": ...,
"tiers": [...]}`. `--verifier` takes a command line rather than a path, so a
rail whose machine-readable output sits behind a flag needs no wrapper. One
further member is read and is OPTIONAL: `primaryCode`, the single condition the
rail reports when several hold. Nothing in the accept or reject contract reads
it, because that contract compares code sets and says so below; the
indeterminate families read it and a rail that omits it is recorded as having
committed to no reading rather than as failing.

That object has to be **one line**. The harness reads the last line and parses
that line alone, so an indented encoding delivers a line reading `}` and the run
degrades to the exit status, which as the next paragraph says fails every vector
in the suite. This is not a hypothetical: `cmd/aee-verify -json` wrote
`json.MarshalIndent` for as long as the flag existed, and the first time the CLI
this repository ships was pointed at the corpus this repository ships it scored
0 of 186. `scripts/external-rail-gate.py` now runs that exact pairing in CI, and
a clean sweep by the shipped CLI is the gate.

Each vector is run **twice**, through identical argv. The consumer key policy
travels in the environment variable `AEE_SUBSTRATE_KEYS`, holding a path to
`{"substrateObservationKeys": [{"keyid": ..., "publicKeyHex": ...}]}`; argv is
fixed by the contract, so naming a flag would dictate a spelling to every rail
while naming a variable dictates only where to look. The pinned pass answers
`expected.tierWithPinnedKey` and the unset pass answers
`expected.tierWithoutKey`. Two rules only the second pass can ask about are what
the second pass is for: GATE 2's no-TOFU rule, that a consumer with no pinned
key derives `unattested` for every substrate row and never infers the substrate
root from the predicate, and the rule that deriving a tier never moves
`result`. Before the variable existed there was no key channel at all, the
harness recorded `tiers_without_key: None` for every external run, and the
evaluator skips a column it was handed nothing for -- so `ok-024`'s
`tierWithoutKey` read in the MANIFEST as a requirement on every implementation
while binding two first-party rails and nothing else.

What it compares against `vectors/MANIFEST.json` is not the verdict alone. A reject
vector's manifest entry declares an expected code set, and the codes the
implementation emits must intersect it, so a verifier that rejects a statement
for no stated reason fails the vector. An accept vector's entry declares a
`result`, and the recomputed result must equal it. An implementation that answers
with an exit status and nothing else therefore fails every vector in the suite.
That is worth stating plainly, because the runner's own description of its
external rail said the opposite for several revisions, and nothing was checking
the description against the evaluator it described.

The codes are compared as a set. Order carries nothing and message text carries
nothing, so a verifier that reports the first fault it finds and one that reports
every fault it finds both pass the same entry. That is what lets a strict
single-code implementation and a superset-emitting one certify against one
manifest. It is also why the optional `primaryCode` exists rather than the
harness reading the first entry of the set: a harness that inferred precedence
from an order this paragraph tells rails to ignore would be enforcing a rule the
corpus disclaims.

An implementation that would rather keep its own reject reasons is not shut out
of the corpus. It can emit a report in its own vocabulary and compare that report
against a recorded run of itself, which is how the independent checker described
below verifies parity without ever reading these codes. What that route does not
give is the per-condition comparison: two verifiers can agree on every verdict
and still disagree about which condition each statement violated, and that
disagreement stays invisible until the codes are compared. Two of the divergences
this suite has fixed were exactly that shape.

Grading on the intersection has a cost, paid on this side rather than yours: a
code the reference rail emits that the entry does not declare is compared against
nothing at all. `bad-817` declared two and emitted four, and when suiteRevision 28
moved its parent from a caught row to a reconstructed one, one of the two
undeclared codes changed with it and every gate stayed green. Measured before this
revision added `ok-055` and `bad-986`, nineteen of the vectors then shipped were in
that state, with 24 unpinned emissions between them. Those
emissions are now written down, in an `expected.alsoEmits` array on the entries
that carry them, and `scripts/observed-code-closure-gate.py` refuses both an
emitted code that no field declares and a declared one the rail has stopped
emitting.

**This changes nothing you are required to do.** `alsoEmits` records what THIS
rail reports and obliges no other rail to report it; a strict single-code
implementation and a superset-emitting one still certify against one manifest,
exactly as the paragraph above says, and the comparison surface is the same
verdict and result token it has always been. Nothing you emit is compared against
`alsoEmits`, and nothing you omit from it can fail a vector. The gate that reads
it drives the reference rail alone and never runs over an external one, which is
also why the rule lives in a gate and not in the replay harness that external
rails go through. Read the array as a published measurement of our verifier —
useful if you are chasing a reason-parity figure, and safe to ignore entirely if
you are not.

### Two layers, one set of bytes: `statementLayer`

A few entries carry a second verdict, in a `statementLayer` object beside
`expected`. It answers a different question from the rest of the manifest:
not what an AEE verifier must do with the statement, but what an in-toto
**Statement** parser must do with it, before any predicate is read.

Today the field sits on the three members citing `aee-c-109`: the same ok-002
statement with `predicate` absent, set to `null`, and set to `{}`. An **AEE
verifier must reject all three**, with identical codes, because the empty
predicate is missing every member this predicate requires. A **Statement parser
must accept all three**: the framework types `predicate` as optional and says
"Unset is treated the same as set-but-empty"
([`spec/v1/statement.md`](https://github.com/in-toto/attestation/blob/fd2609c16bcb0ac53443e2b4612977f997e8f9a5/spec/v1/statement.md#L62-L66)),
and `spec/v1/statement.md` in this repository records why `null` joins them.
The reference in-toto bindings refused the absent and null spellings until
[in-toto/attestation#598](https://github.com/in-toto/attestation/pull/598), so
running a Statement parser over these three tells you which side of that fix it
is on.

The field is additive and informative. Nothing in the replay harness reads it,
the comparison surface is unchanged, and a rail that implements only the AEE
layer can ignore it. `scripts/statement-layer-test.py` executes the recorded
verdict with a Statement-layer check rather than trusting it, and the generator
refuses a `statementLayer` key that no member cites.

### The registry

The codes are this suite's registry rather than the specification's. The
specification states the conditions and says nothing about what a verifier should
call them, so the spellings, the precedence pins above, and the promise that
neither of those moves are all contracts this repository carries and not that
document. `aee/codes.go` is the enumerated set.

Adding a code takes four things, and `scripts/code-contract-gate.py` checks the
last three mechanically:

- a condition the specification states that no existing code already names;
- a constant in `aee/codes.go`, in the block for the gate that detects it;
- the same spelling in the Python rail, so the two first-party rails share one
  vocabulary rather than two that happen to agree;
- at least one vector that emits it, which bumps `suiteRevision`.

What the registry guarantees:

- a published code's spelling never changes, and neither does the condition it
  names. A changed condition is a new code, not a redefined one;
- a code is never removed while any published `suiteRevision` names it;
- codes are additive across revisions, so a verifier that recognises the set at
  one revision still recognises it at the next;
- precedence is contractual only where this README pins it. Where two conditions
  can hold at once and nothing here decides which is reported, either is
  conformant — and that no longer means no vector. It means an INDETERMINATE
  vector, which declares every reading a conformant rail may take and holds the
  rail to one of them rather than to ours. The reasoning behind each open
  question still lives in `docs/interpretation-decisions-open.md`;
- message text is never part of the contract, at any revision.

### Indeterminate vectors

Two buckets can make two claims. `accept/` says every conformant verifier admits
these bytes and recomputes this result; `reject/` says every conformant verifier
refuses them and names a condition from a declared set. Neither can say that the
verdict is settled and the condition is not, and about some statements that is
the only true thing to say. The specification carries no failure-code vocabulary
at all, and of its own two-stage verification description it says that "the
sequencing itself is informative" (L366-368). Two rails can therefore reject the
same bytes, name different conditions, and both be right.

Saying it by widening a reject vector's expected set does not work: the harness
compares code SETS, so a set naming both conditions is satisfied by either
answer and by a rail that emits both, and the vector stops measuring the
question instead of starting to. `vectors/indeterminate/` is the third bucket.
A member declares a DETERMINED verdict — indeterminacy is scoped to the
condition, because a vector whose verdict were open would certify nothing — and
a set of READINGS, each naming the condition that reading predicts for that
member. A family is the members sharing one reading vocabulary, and the
generator refuses a family whose declared readings no member's answer can
separate.

A rail satisfies three requirements: the verdict; CLOSURE, its answer on each
member is one some declared reading predicts; and COHERENCE, one reading
explains its answers across the whole family. Either answer is admissible. No
answer is not, and neither is a pair of answers straddling two readings, because
the reported condition is then a function of incidental structure rather than of
a policy the rail applies — the shape a primary-code selector that overwrites
rather than sets-if-unset produces, and a shape no single-fault vector can see.

Which reading a rail took is READ and REPORTED rather than required. A rail may
publish an optional `primaryCode` beside its code set, naming the one condition
it reports when several hold; the families read it, and nothing else does. A rail
that publishes only the set has declined to answer — reporting every condition a
statement carries is a legitimate response — and is recorded as committing to no
reading. That report is the point. Both findings this corpus has taken from an
outside reader were divergences five agreeing rails could not show each other,
and a bucket that records which reading each rail took is where the next one
becomes visible without anybody having to arbitrate.

`vectors/indeterminate/INDEX.md` carries the families, the readings, and the
enumeration of what is deliberately NOT in the bucket: the specification's limits
(the passive-sensor producer assertions, the shared-reference evidencing
obligation), the consumer MAY clauses that sit outside the verdict this suite
reads, and the producer options whose verifier handling is forced.

Two codes carry a standing exemption the gate knows about.
`corpus-anchor-mismatch` and `substrate-anchor-mismatch` are consumer-policy
facts rather than validity conditions: they are recorded on the report's consumer
surface and never change the byte-pure verdict, so no single-statement vector can
exercise them, and the gate requires that none claims to.

## Conformance vectors

`aee/vectors_test.go` replays the conformance vector suite in this repository
(default `../../vectors`, override `AEE_VECTORS_DIR`): every accept vector
must verify valid with matching result and tier columns under both key
policies; every reject vector must be invalid with the primary code inside
the vector's expected code set, emitting no result and no tiers. The runner
skips with an explicit message when the suite is not yet present. The
pinned-policy key is derived from the published test-key recipe
(`seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`). Nothing
private is committed anywhere in this repository.

### What the corpus forces, as a measured number

A vector count is an upper bound on forcing and never a measurement of it. The
evaluator satisfies a vector when ANY expected code in a stage is observed, and
the per-stage column the runner prints is a display rather than a verdict: delete
the `result-vocabulary` emission from the rail and two vectors' gate-0 column goes
FAIL while the suite still reports 275 of 275, exit 0. A rail with no
result-vocabulary check at all clears this corpus.

So forcing is measured instead. `scripts/forcing-gate.py` switches off exactly one
rule in the reference rail, replays every vector, and asks whether the corpus
notices — 807 single-site weakenings of `aee/`, one rebuild and one full replay
each. A rule the corpus never notices losing is a rule no third-party implementer
is obliged to build, whatever the vector count says.

One of those weakenings does not switch a rule off at all. Where the specification
says a rule holds for EVERY member of a carried collection, the rail writes a loop,
and the quantifier operator closes that loop after one member: the rule survives
intact and is applied to a single witness. A corpus that still passes was never
forcing the "every" — it carried one member, or its defective one happened to be
the member the weakened rail still looks at. That is a gap no amount of switching
guards off can see, and the sites it finds are published below with the rest.

[`docs/FORCING-BASELINE.json`](docs/FORCING-BASELINE.json) is the result, held as a
tighten-only ratchet: **459 rules forced, 32 seen-but-tolerated, 311 unforced, 5
unmeasurable.** The four outcomes stay apart on purpose — "we could not measure it"
and "the corpus does not force it" are different claims and only one is a gap — and
four sites carry an annotation saying that "unforced" is the wrong word for them,
three because the weakened rail computes exactly what the original computes and one
because an earlier check reaches it first on every input that could get there. Those
annotations are claims the gate falsifies: an annotated site that is ever killed
fails the build.

CI runs the ratchet on every push over the rules the baseline records as forced —
the complete set where a regression is possible — and sweeps all 807 sites nightly,
which is what can see forcing improve.

**What that campaign cannot see, said here before anybody else says it.** Every
weakening is applied to the reference rail's own source, so the measurement
describes what this corpus notices about that implementation and about nothing
else. A third-party verifier is out of its reach by construction, and the reason
is worth being blunt about: this corpus is a fixed, public answer key. A candidate
handed the path to a vector can read the manifest sitting two directories above
it, or carry a table keyed on the digest of the bytes it was given, and clear the
whole suite without implementing a single rule of the specification. Until the
generators can emit a challenge set on demand that no such table can contain, read
a clean external sweep as evidence that a verifier printed the right answers
rather than as evidence that it computed them.

That baseline is keyed by rail site, which is a fact about one implementation's
source rather than about the specification. The same campaign read against the
normative condition ids the vectors cite — which of the document's own rules this
corpus obliges an implementer to get right, which it covers only redundantly, and
which failure codes a conforming verifier may decline to emit altogether — is
published in [`docs/FORCING-HONESTY.md`](docs/FORCING-HONESTY.md). Every figure
there is derived from the baseline and the manifest by
`scripts/condition-forcing-gate.py`, which CI runs with `--check`, so the published
weak spots cannot drift from the data behind them.

One number on that page is about a corpus that no longer exists: the condition
figure quoted before the page was written, taken over an earlier revision whose
own campaign tables were never committed. It is not remembered there, it is
reconstructed. [`docs/PRIOR-FORCING.json`](docs/PRIOR-FORCING.json) pins the two
git objects it is derived from — a forcing baseline and the manifest of the corpus
the figure names — and `--verify-prior` re-derives the projection from them and
refuses anything but a match, including a blob the history no longer holds. It
needs a full clone, so it runs in the nightly sweep rather than on the push path,
where a shallow checkout could not tell a disagreement from an absent object.

The reconstruction counts three more killed weakenings than that earlier note
records over the same sites, and the page closes the difference rather than
publishing it as a residue. All three sit on the branch a verifier takes when the
consumer supplies no key policy at all — the branch only the second of the two
runs each vector now gets can reach, and the run behind the note made no such
pass. `--verify-prior` derives that set from the pinned baseline, checks it
against the set the record names, and checks that the subtraction lands on the
released figure; the page states the identity and what it does not establish.

### Detector liveness, and the anchor beside every refusal

A check that never fires may be guarding a well-designed boundary or may be
dead, and from outside the two emit the same clean run. The corpus separates
them with a planted stimulus: the manifest predicts what an attack looks like
on the wire, the substrate commits to what it saw, the row asserts the two are
comparable, and the run-end seal names what it attributed. When all of that
lines up for an attack in a class, that class has shown a live detector, and
the claim holds for that class and no other — so the fixtures are per channel
rather than a sample of them. The construction adds no member to the predicate,
`scripts/liveness-probe.py` computes it from any statement, and
[`docs/DETECTOR-LIVENESS.md`](docs/DETECTOR-LIVENESS.md) says what it does not
establish, at the same length as what it does.

Beside that, a discipline the corpus had stated once and checked nowhere. A
verifier that rejects its input unconditionally passes every reject vector ever
written, so every refusal here is paired with a statement that must be
accepted: `scripts/accept-anchor-gate.py` requires each reject vector's parent
to ship as an accept vector, and measures, as a ratchet rather than a claim in
prose, the conditions that only refusals cite. It also checks the sentences
that publish those figures, because the count census skips them on the strength
of naming this gate their owner.

Requiring the parent to SHIP establishes that it exists. The same gate now also
requires the child to BE it: every reject vector is diffed against the accept
vector it declares, over a semantic pre-image in which a derived field --
a signature, a batch root, a run binding, the carried result, a digest of
material the statement also carries -- collapses to a token only where both
sides agree with their own derivation. A vector that is not one mutation from
its parent is refused, named, and its differing paths printed. The handful that
cannot express their fault in one edit are declared in
`docs/MULTI-MUTATION-VECTORS.json` with a reason each, and a row with no reason,
a row for a vector nobody ships, and a row that has stopped being an exception
are all refused too.

### Condition ids

A vector cites the specification rules it forces as `aee-c-NN` condition ids,
and those ids are the normative link between a vector and the rule it exists to
pin. **The registry that resolves them to spec lines is the condition table in
[`vectors/reject/INDEX.md`](vectors/reject/INDEX.md), and it is the only one.**
Both index files used to say the table lived in this README. It never did, in
any revision, and the effect was not cosmetic: the table that does exist listed
only the ids the reject set happened to use, so 17 ids cited by accept vectors
resolved to nothing at all. The table now covers every id the suite cites, in
either direction, and `scripts/condition-registry-gate.py` fails the build when
a cited id has no row or a row names an id no vector cites.

## The go-witness attestor (`witnessattestor/`)

A go-witness-compatible attestor package; upstream go-witness PR staged.
It follows the upstream sarif pattern: an attestor that runs after the
step's products exist, locates a substrate-emitted evidence statement
among them (`aee-evidence.json` by default), re-hashes it for integrity
against the recorded product digest, and then runs the emit seam (GATE 0
+ GATE 1 + recompute equality), returning an error rather than signing on
any failure. The signed predicate bytes are exactly the validated bytes.

The security scope, stated in the package documentation and binding on every
description of the attestor: the witness envelope key backs the
**producer-asserted plane only** (assembly, gate-validity,
recompute-consistency at pipeline step time), while the
**substrate-covered plane** travels exclusively in the signed
`observationRecords`, verified per record at the consumer's tier
derivation against consumer-pinned substrate observation keys. The
attestor never claims that go-witness observed the execution, and
go-witness's own `commandrun` tracing is never `basis: substrate`. GATE 2
never runs at emit, since the tier is relative to the consumer and
derived by definition; the optional `expect-substrate-key` producer-QA
flag checks record signatures locally and derives no tier.

`cmd/aee-witness-demo` drives the attestor through the real witness run
lifecycle as a library and prints the signed standalone AEE statement.
Consume-side, `cmd/aee-verify` (core module, stdlib-only) is the MVP; a
witness `VerifyRunType` attestor that re-emits gate outcomes as a signed
verification summary is named future work (the witness verify CLI is
currently coupled to its policy attestor).

## On independence

I wrote the Go core here, the sibling Python implementation, and the three
consumer rails in two first-party stacks. Five implementations,
one author, one reading of RFC 8785 and RFC 7493. They catch each other's
transcription errors and the differential fuzzer catches drift between them, but
they cannot catch a misreading of the specification, because they all inherit
the same one. Counting them as independent would be counting the same opinion
five times.

**The number of implementations independent of this specification's author is
one.** [`Rul1an/aee-checker`][aee-checker] is a from-spec Rust implementation
with its own I-JSON parser, RFC 8785 serializer, RFC 6962 Merkle root,
run-binding derivation, and Ed25519 tier, built with no sight of the reference
code. It cleared 125/125 at suiteRevision 1, then re-ran against the round-7
corpus and reached 138/138 at suiteRevision 2 after a spec-diff-led update
(132/138 on the unchanged build), cleared suiteRevision 3 at 140/140, cleared
suiteRevision 5 at 149/149 after it adopted the normative nesting bound of 128
and moved its depth counter from per parsed value into the container branch
(aee-checker#3), and cleared suiteRevision 6 at 153/153, 36/36 accepts and
117/117 rejects, after implementing the Unicode noncharacter exclusion RFC 7493
section 2.1 requires (aee-checker#4, 2026-07-28; the unchanged revision-5 build
scored 151/153 against it).

The same author then ran the v0.7 corpus, and it is the largest reading this
column carries.
At suiteRevision 22, on 2026-08-03, a build written from the pinned v0.7 text
alone scored 179/232 on its first run (accepts 8/54, rejects 169/176,
indeterminate 2/2), and a directed pass reached 232/232, accepts 54/54, rejects
176/176, indeterminate 2/2. The directed pass is directed twice over in the
author's own account: it followed a spec diff already read and, for one vector, an
adversarial review of that implementation. That account partitions the 53 first-run
mismatches by the message the blind build emitted, and says that is the only
partition its published run records support: 42 report that `aeeRunBinding` does
not equal the run binding derived from the statement, 7 returned `valid` with no
reason, and 4 report a carried `pass_indirect` against a recomputed `pass`. An
earlier draft of that report published a per-fix attribution, withdrawn rather
than restated, because attributing a recovery to a particular fix needs
a bisection against the blind build and that build no longer exists. The report
claims no reason-parity figure for the run at all: the checker emits free prose and no
condition codes, two constructions of a prose-to-code map over the same run
disagreed sharply, and the ambiguity is published as a runnable script rather
than resolved by picking one of them.

Each of those figures moves this column only because a record and the source
digest that produced it were posted with it. The revision-6 record names checker
source `sha256:1c3e2e78` and suite commit `6aa7c60`, and it is the revision that
checker's CI now verifies continuously. That suite commit no longer resolves in a
fresh clone of this repository, because the history it sat on was rewritten here
after the record was pinned; the commit that carries the identical tree, and so the
identical 153 vectors of suiteRevision 6, is `6aa7c60`, which is where a
reproduction of the record should point until it is repinned.

The v0.7 record splits on exactly that requirement, and the half this suite leans
on is the half with no digest. The directed build is recorded under checker source
`sha256:56f440e6…` against suite commit `4cd65a16`, and reproduces from the
author's working tree. The blind build does not, and the author says so before
anyone else could: it was never committed on its own, one commit carrying both the
v0.7 implementation and the published number, so no tree in that repository hashes
to the build that produced 179/232 and the figure is not independently reproducible,
including by its author. The checker's `reports/INDEX.json` records that as an
explicit null digest beside a `sourceUnrecoverable` field rather than borrowing the
directed build's digest, which would name a different implementation, and records
the whole thing as a breach of the rule that run's own protocol had fixed in advance.
That suite commit does resolve in a fresh clone here and carries the 232 vectors
of suiteRevision 22. This suite carries the blind figure with the null-digest
caveat attached and never without it.

The most recent reading is against the current corpus. On 2026-08-12, in the same
thread, the author posted 250/250 at suiteRevision 25 — accepts 55/55, rejects
193/193, indeterminate 2/2, reason parity 69/193 — against suite commit
`97ba4ff`, whose manifest carries 250 vectors in exactly that partition and the
vendored spec digest `759d2383` the run names. It was verified on a clean runner
at a public CI run that checks the spec digest before it counts anything. It is
directed, and the author's opening words are why this suite records it that way:
"Repinned and implemented first, then measured your open question." The record
names the suite commit, the spec digest and the runner, and it names no checker
source digest, so it is the second figure in this column carried without one and
this suite says so rather than letting a reader assume otherwise.

Only three of those figures are evidence that an outside reader reached a rule
unaided. The 125/125 was the first full corpus run with no vector-driven fixes.
The 140/140 was a first run by an unchanged build whose rule for the two new
vectors was derived from the spec text and predated them, so the vectors met a
rule that was already there rather than driving it. The blind 179/232 at
suiteRevision 22 is the third and the only one taken against the v0.7 text; in
the author's own report it is the only figure in that run bearing on whether the
text is determinate from a cold start. The other figures each
followed a spec diff the author had read, and two of them followed more than that.
In the author's own words,
kept here because paraphrasing it would soften it: "This one is directed, and
more so than revision 2 was: the rule was written and the vectors named before
this checker ran, so what it demonstrates is that the corrected rule is
implementable from the text, not that an independent reader found it." A
directed 153/153 says the corrected rule is implementable by someone who has only
the text. It is not the same evidence as 125/125 and this suite does not present
it as such.

It has not been run against suiteRevision 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27 or 29, so
this suite publishes no score for it at any of them. They are on that list for
three different reasons, and only one of them is that the requirement went
unexercised. Two of the five at the end of the list fall between that v0.7 run
and the suiteRevision-25 one: suiteRevision 23 added sixteen reject vectors and a
second declared condition on a seventeenth, and suiteRevision 24 moved the
vendored text without moving a vector. The other two fall between the
suiteRevision-25 run and the suiteRevision-28 one: suiteRevision 26 added eight
boundary vectors and moved no vendored text, and suiteRevision 27 pinned what the
reference rail emits beyond each reject vector's declared codes without changing a
vector file. The suiteRevision-28 corpus carries every vector both added. suiteRevision 29 came after that run and added three reject vectors, one per empty predicate state. suiteRevisions
7 through 21 are the opposite case and the distinction is worth being exact
about. Every vector those revisions added is inside the suiteRevision-22 corpus
that run covered, so the requirements they carry, the signature-entry requirement
and its precedence and wrong-type spellings, the corpus manifest attack floor, the
timestamp profile, the version-2 run binding, the fourth `result` value, the
registered posture vocabulary and the vendored amendments that followed, are not
unread. What no record of that checker names is the corpus AT any of those
revisions, and that is not a formality: suiteRevision 13 moved five of the
corpus's results, so a verdict set at one revision is not the verdict set at
another, and a pass at suiteRevision 22 says nothing about what this checker
would have answered at suiteRevision 13. suiteRevision 4 is on the list
for a third reason: its corpus is the revision-3 corpus, 140 vectors with
the same verdicts and the same codes, so the revision-3 run did put those bytes
through this checker. What that revision changed was the text, which made
encoding well-formedness and the 128-deep nesting bound normative over a corpus
that, as its own changelog entry says, exercised neither. A pass at 140/140 was
therefore compatible with getting both new rules wrong, and one of them this
checker did get wrong: when suiteRevision 5 published, it still read the bound as
256, and aee-checker#3 is where it adopted 128. Recording revision 4 as run
would assert a conformance no posted record carries. It keeps its own
authorship, history, and CI. The link is pinned to the build that recorded the
153/153 run.

That one reading has already earned its keep, twice. The specification did not
pin a maximum JSON nesting depth, so all five of my rails chose 128 and agreed at
every depth; the independent checker read the same text and chose 256. For the
127 depths in between, identical bytes were valid evidence to one conformant
verifier and malformed to another. Five agreeing rails could not surface that;
one outside reader surfaced it on contact, and the bound is now normative at 128.
Reading it back a second time surfaced a split the five rails had hidden from
each other: the reference Go rail counted nesting depth per parsed child, so an
empty-container leaf slipped one level past the bound where the Python rail
rejected it -- two first-party rails disagreeing on identical bytes at one exact
depth. That one is fixed and pinned by a boundary vector pair; both findings came
from the same outside reader, and neither could have come from the rails alone.

More outside implementations are wanted, and the count above is the reason.
Wiring one in means answering the external-verifier contract above: a verdict in
the exit status, a single-line JSON object carrying the codes and the recomputed
result, and a key policy read from `AEE_SUBSTRATE_KEYS` so the two tier columns
can be compared. A conformant checker passes even when it evaluates in a
different order, since the suite compares verdicts and code sets and ignores both
message text and evaluation order. The shortest way to see the whole contract
working is the CLI in this repository, which CI drives through it on every push:

```
go build -o aee-verify ./cmd/aee-verify
python3 packaging/run_vectors.py --verifier "$PWD/aee-verify -json"
```

## One harness judges every corpus here

`aee-verify` takes a corpus directory as well as a statement. The directory's
`MANIFEST.json` publishes a `suite`, the suite selects a reader, and the reader
judges every member: an intact corpus exits 0 and prints the member counts by
verdict, a member whose bytes moved exits 1 and is named, and a suite this
binary does not know is refused by name rather than skipped, because a skipped
corpus and a clean one otherwise print the same zero.

```
heavy-queue heavy-run --name go-build --timeout 3600 -- go build -o aee-verify ./cmd/aee-verify
for corpus in vectors*/; do ./aee-verify "${corpus%/}"; done
```

Every corpus used to carry a Python self-check beside its vectors, so the
command a reader was told to run differed per corpus and three of the six were
wired into no workflow at all. Two Python files remain and answer different
questions: `vectors-anchor-stream/run_verifier.py` runs this corpus against a
third party's `anchors_verify.py`, which is a measurement of that build rather
than of the corpus, and `vectors-mcp-record-contract/check_run_record.py` is the
interoperability criterion as a standalone tool for a record of your own. The
SCITT/COSE corpus keeps its own checker until a reader for it lands; the binary
refuses that suite by name and says what judging it would need.


[aee-checker]: https://github.com/Rul1an/aee-checker/tree/f8bd3a787ef0b4610e96054ee1f167368f2ccdc2
