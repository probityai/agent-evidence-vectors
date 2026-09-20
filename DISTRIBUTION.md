# Where this suite lives, and how to cite it

This file is for someone arriving from somewhere else, and it answers the
questions that reader actually has: which tag to cite, where the verifier comes
from, how to establish which bytes a release covers without taking anyone's word
for it, how to cite what you ran, how to report a run of your own, and how to put
a corpus of your own in here.

It is deliberately inbound only. It does not record where this suite has been
submitted, who was asked to look at it, or what was said in reply. A file that
enumerated our own submissions would be a marketing document wearing a
distribution heading, and it would tell a reader nothing they can check.

## The tag to cite

`v0.11.1`. The same version is in [`CITATION.cff`](CITATION.cff), which is what
GitHub's citation panel reads and what an archive deposit is cut from, and
`scripts/distribution-gate.py` refuses if this page and that file disagree.

A tag is the unit because a published tag never moves and a branch does. The
corpus is immutable per revision by policy, so a claim pinned to a tag stays
checkable after the branch has advanced past it, and a claim pinned to `main` is
a claim about whatever `main` said on a day nobody recorded.

## The one-command run

The module path is `github.com/probityai/agent-evidence-vectors`, and the
verifier is the `cmd/aee-verify` package inside it. Every tag up to `v0.11.1`
was published before the path moved, and a released tag never changes, so a
pinned install of the current release still names the former owner, which the
redirect keeps resolvable; the path above is the one that resolves from the
next tag onward. The harness and every corpus are on PyPI as
`agent-evidence-vectors`, at the same version as the tag, so the run needs no
clone:

```bash
go install github.com/astrogilda/agent-evidence-vectors/cmd/aee-verify@v0.11.1
uvx agent-evidence-vectors==0.11.1 --verifier "aee-verify --json"
```

From a checkout, which is the same harness read from the tree:

```bash
git clone https://github.com/probityai/agent-evidence-vectors
cd agent-evidence-vectors && git checkout v0.11.1
python3 packaging/run_vectors.py --verifier "aee-verify --json"
```

To run it on every push of your own repository, the section "Run it in your
CI" in [`README.md`](README.md) gives the `uses:` step.

The external contract that command speaks to is in
[`README.md`](README.md): a verdict in the exit status, one line of JSON on
stdout carrying the condition codes and the recomputed result, and a key policy
read from `AEE_SUBSTRATE_KEYS`. Any verifier that speaks it can be driven the
same way, and that is the point of the contract existing at all.

A reference consumer is public at
[`probityai/agent-evidence-admission`](https://github.com/probityai/agent-evidence-admission):
admission rails on four policy engines, each declaring per obligation what it
enforces, what it only approximates and what it cannot reach, with its CI
holding them to a tagged release of this corpus, pinned by tag and by the
commit that tag resolved to. It is what a consumer side of this contract looks like when
somebody has written one down.

**A disagreement is the interesting outcome.** If your verifier and this corpus
answer differently on a vector, open an issue. It is a defect in one of the two
of them and it does not matter which; the corpus has been corrected by an
outside reader before, and the two rules that came out of it are why the
external contract is written down.

## Verify a release without trusting us

A conformance claim names a corpus, and the first thing a citing author has to
settle is which bytes that claim covers. These commands settle it from a cold
start, without a maintainer's word and without this page's word.

```bash
git clone https://github.com/probityai/agent-evidence-vectors && cd agent-evidence-vectors
git checkout v0.11.1

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

The section of the same name in [`README.md`](README.md) says what each command
establishes, where a green result stops, and why the signature deliberately
reaches no transparency log. The block above is held byte-identical to the one
there by `scripts/distribution-gate.py`: a recipe copied into a second file is a
recipe that goes stale in one of them, and a stale verification recipe fails in
the hands of the one reader who most wanted it to work.

Command 1 needs only Python. That is a property the release gate asserts from a
subprocess that cannot see installed packages, because a corpus whose digest
routine imports a third-party library is a corpus a fresh clone cannot check.

## How to cite it

[`CITATION.cff`](CITATION.cff) is the machine-readable form and GitHub renders a
citation from it. Cite the corpus you actually ran, which means naming three
things and not two:

- the **repository**, by URL;
- the **suiteRevision** you ran against, from the head of
  [`vectors/CHANGES.md`](vectors/CHANGES.md), or the tag for a corpus that keeps
  no revision ledger;
- the **corpusDigest** from the manifest of the corpus you ran, which
  [`release/CORPUS-DIGESTS.txt`](release/CORPUS-DIGESTS.txt) also carries under
  one signature for every corpus at once.

A citation that names only the repository names a moving target. The revision
number and the digest are what make a reader able to fetch the same bytes you
had. The changelog is per revision and says, for each one, what that revision
does not exercise, which is usually the sentence a citing author needs.

## The corpora this repository ships

They are not interchangeable, and every count, every digest and every run report
is scoped to exactly one of them. A figure that does not say which corpus it
belongs to is not a figure about anything.

| Directory | Suite name in its manifest | What it tests |
| --- | --- | --- |
| `vectors/` | `adversarial-execution-evidence-conformance` | the adversarial-execution-evidence predicate this repository vendors, tracked at in-toto/attestation#570 |
| `vectors-aci/` | `aci` | the agent capability interface levels and their serialization |
| `vectors-acs-core/` | `acs-core-negative-conformance` | the mandatory profile of the agent control standard, by negative members against vendored specification text |
| `vectors-ai-agent-action/` | `ai-agent-action-conformance` | the AI Agent Action predicate proposed at in-toto/attestation#588, plus the canonicalization text this repository puts forward for it |
| `vectors-anchor-stream/` | `anchor-stream-conformance` | the anchor-stream verification contract published by aos-standard/catalog |
| `vectors-artifact-binding/` | `artifact-binding-conformance` | the artifact-binding contract, over three verdicts rather than two |
| `vectors-mcp-record-contract/` | `cross-run-record-contract` | what a cross-implementation run record has to carry to mean anything |
| `vectors-scitt-cose/` | `scitt-cose-carriage-conformance` | carriage of the predicate over SCITT and COSE receipts |
| `vectors-w3c-report/` | `w3c-report-v01-conformance` | the v0.1 per-check report of the W3C public-agent-conformance group: the five states, the cause rule, the twelve rejection rows and the two late additions, as whole reports |

The directory names and the suite names in that table are checked against the
tracked manifests by `scripts/distribution-gate.py`, so a corpus that lands
without a row here, or a row that outlives its corpus, fails on the push.

Per-corpus vector counts are deliberately not in that table. They live in
[`release/CORPUS-DIGESTS.txt`](release/CORPUS-DIGESTS.txt), which a generator
writes and a signature covers, and each corpus publishes its own in its
`MANIFEST.json`. A count restated in prose is a cache with no invalidation, and
this repository has already watched three of them go stale at different rates.

## Adding a corpus of your own

A new corpus lands here as a sibling `vectors-<name>/` directory rather than as
a new repository, on the pattern `vectors-ai-agent-action/` already sets. The
contract for one is in
[`.github/PULL_REQUEST_TEMPLATE/vectors-directory.md`](.github/PULL_REQUEST_TEMPLATE/vectors-directory.md):
a manifest, a digest routine that runs for somebody who installed nothing, a
generator that reproduces every byte, a pin to the specification text it tests,
a registration in the count gate and the release digest list, and your name on
the commit and in the manifest's provenance.

The reason it is one repository is that a reader who has verified one corpus
here has already installed the verifier, already read the external contract, and
already knows what a `corpusDigest` is worth. Splitting the corpora across
repositories would spend all of that a second time.

## Reporting a run

[`RUNS.md`](RUNS.md) records every run of these corpora by an implementation
independent of this repository, in the reporter's own words. If you run the
suite, the form at
[`.github/ISSUE_TEMPLATE/independent-run.yml`](.github/ISSUE_TEMPLATE/independent-run.yml)
is the whole reporting path. A run that disagreed with the corpus is more
valuable there than one that agreed.

## Archive and identifiers

| Surface | Identifier | State |
| --- | --- | --- |
| Source of record | `github.com/probityai/agent-evidence-vectors` | live |
| Go module | `github.com/probityai/agent-evidence-vectors`, verifier at `cmd/aee-verify` | live |
| Releases | git tags, with a GitHub Release object per tag; `v0.11.1` is current | live |
| Signed corpus digests | `release/CORPUS-DIGESTS.txt`, one line per corpus, with a detached signature, an RFC 3161 token and an OpenTimestamps proof beside it | live, derived |
| Archival DOI | concept DOI `10.5281/zenodo.22758687`, which resolves to the newest archived release; the record lists a version DOI per release, and `CITATION.cff` carries the concept DOI so a citation stays stable | live |
| Package registries | PyPI `agent-evidence-vectors`: the harness and every corpus, built and uploaded by the release workflow from the tag, at the tag's version | live |
| Mirrors | none | none |

Nothing in the rows at the bottom is a plan stated as a fact. Each cell says
what is true today, and a mirror is written there only once it exists.
