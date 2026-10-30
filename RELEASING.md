# Releasing

This file exists because the version rule was nowhere. A release was cut, a
module path moved, and the question "which number does that make it" had no
answer in the repository: `GOVERNANCE.md` states the cadence and that revisions
get tagged, `CONTRIBUTING.md` states the gates, and neither says how a version is
chosen. So it was re-derived per release, by whoever was cutting one, from
whatever seemed reasonable that day. The steps had the same problem: they live in
three scripts and two CI jobs, and the order between them is load-bearing in ways
none of them states.

Both halves are written down here. Nothing below is new policy invented for this
file except where it says so.

## The version rule

The project is pre-1.0, so the channel for a breaking change is the MINOR
position:

- **breaking change → bump the minor** (`0.11.1` → `0.12.0`)
- **anything else → bump the patch** (`0.12.0` → `0.12.1`)

A first major release changes this rule and is a decision to take then, not a
default to inherit from this paragraph.

### What counts as breaking, for this repository

A conformance corpus breaks its consumers in ways a library does not, so the list
is specific rather than a gesture at semver:

- **The Go module path changes.** Every tag declares its own path forever, so a
  consumer's manifest stops resolving at the old spelling and has to be edited.
  This is what made v0.12.0 a minor rather than a patch.
- **A corpus member is removed, or its identifier changes.** Identifiers are
  digests of member bytes, so regenerating a member renames it. A citation naming
  the old identifier stops resolving.
- **A verdict changes on a member that already shipped.** A rail that passed the
  corpus at the previous tag may fail at this one through no change of its own.
  Adding a member that a conforming rail already handles correctly is NOT
  breaking; adding one that a conforming rail fails is.
- **The manifest schema changes** in a way that an existing reader cannot parse:
  a renamed or removed field, a field whose type changes. Adding a field a reader
  may ignore is not breaking.
- **A `predicateType` URI moves.** The URI sits inside every signed payload, so
  moving it re-signs the corpus and renames every member; it is the second case
  above with a larger radius.

A new corpus, a new gate, a new rule that no existing member reaches, and any
documentation change are all patch-level.

### Where the version is written

Ordinary source preparation is not a release. Keep the build version in
`pyproject.toml`, top-level `CITATION.cff` and `uv.lock` synchronized. Leave the
candidate without `date-released`. The preferred citation names the actual
published release, including its commit and annotated tag object. Installation
pins and verification recipes use that published identity.

A local candidate tag does not prove publication. Do not advance published
install instructions while preparing source changes. The release procedure
below is a separate operation; its final public tag, package and check readbacks
must establish publication before it is reported as delivered.

The source-version files must agree. Published install pins must agree with the published citation. The 0.12.0 bump omitted the lock's root-package version;
a site build later invoked uv and rewrote it as a side effect. The citation
gate now checks that entry explicitly. The distribution gate checks the
installation pins and both copies of the verification recipe.

| File | What carries the version |
| --- | --- |
| `pyproject.toml` | `[project] version` — what the wheel is built as |
| `CITATION.cff` | `version:` for source; `preferred-citation` for the published release |
| `DISTRIBUTION.md` | the tag-to-cite section and the pinned Go, Python and checkout commands |
| `README.md` | the pinned Go and Python commands for the published release |
| `docs/guides/runner.md` | the action pin and the pinned Go and Python commands |
| `docs/reference/release-verification.md` | the checkout pin in the verification recipe |
| `uv.lock` | the `version` of the one `[[package]]` whose source is `virtual = "."` |

After bumping `CITATION.cff`, run `python3 scripts/sync-install-pins.py` to move every pin on
`README.md`, `DISTRIBUTION.md` and `docs/guides/runner.md` to the published release; CI runs it with
`--check`.

`scripts/distribution-gate.py` holds the inbound page and `CITATION.cff` to each
other and refuses any version token on the page that is not the released one.
`scripts/citation-metadata-gate.py` holds the deposit metadata. The wheel is held
to the tag by the release workflow itself, which is the only check that cannot
run until the tag is PUSHED.

The distribution gate goes one step further than agreement: it resolves the
page's `go install` pin against the object store and reads the module path
`go.mod` declared at that tag, which is byte-for-byte what a module proxy will
serve. An absent tag is a refusal and not a pass, because a clone that fetched
no tags and a tag that declares the wrong path look identical from inside the
check. That is why the tag is cut before the mirror runs rather than after it.

A module-path move is the one case where a pinned command deliberately does NOT
take the new spelling: an install pinned to a tag that predates the move must
keep the spelling that resolves at that tag, and the page says from which tag the
new path takes over. Do not "fix" that inconsistency; it is the honest one.

## The steps

Preserve existing release tags, including failed publication attempts. Repair
the source on a clean branch and cut a new patch version; do not move, replace
or delete an earlier tag.

For a new cut, capture one UTC instant before updating the metadata. Set
`CITATION.cff`'s `date-released` to its UTC calendar date, and use that same
instant with a `+0000` offset for the release commit's author and committer
dates. The citation gate reads the stored committer calendar date; it does not
reinterpret that date in the runner's time zone. Recheck the UTC date before
the final commit if preparation crosses midnight.

Run them in this order. The order matters three times. The digest list must be
written before it is signed, and the signature must exist before it is stamped,
because the stamps cover the signature bytes rather than the list. And the tag
must exist before the mirror runs, because one gate resolves the page's install
pin through it.

```sh
release_epoch="$(date -u +%s)"
date -u -d "@$release_epoch" +%F # use for CITATION.cff date-released

# 1. The digest list is what the corpora on disk hash to. A generator writes it;
#    nobody types those lines.
uv run python scripts/release-digests.py

# 2. Sign it with the corpus key. Reads the private half from the keyring
#    (service cosign, accounts aev-corpus and aev-corpus-password), signs with
#    --tlog-upload=false, and verifies its own output against release/cosign.pub
#    before exiting. It re-runs step 1 under --check first and refuses a stale
#    list, so a signature never covers a corpus that is no longer there.
scripts/release-sign.sh --with-timestamps

# 3. Step 2 already ran this. Run it alone only to re-stamp an existing
#    signature: it takes an RFC 3161 token and an OpenTimestamps proof over the
#    SIGNATURE bytes.
scripts/release-timestamps.sh stamp

# 3b. Regenerate the intake records against the signed list. A record names a
#     signed digest list exactly when the list verifies under release/cosign.pub,
#     and the intake checker then verifies that signature; before step 2 the
#     list on disk was unsigned and the records said so. CI's
#     `gen-intake-records.py --check` fails a release commit that skips this.
uv run --locked --extra generators python scripts/gen-intake-records.py

# 4. Commit the release artifacts together with the version bump. They are one
#    unit: a digest list without its signature, a signature without its stamps,
#    or records that still call the signed list unsigned, is a half-published
#    release.
git add release/CORPUS-DIGESTS.txt release/CORPUS-DIGESTS.txt.sig \
        release/CORPUS-DIGESTS.txt.sig.tsr release/CORPUS-DIGESTS.txt.sig.ots \
        release/intake
test "$(date -u +%F)" = "$(date -u -d "@$release_epoch" +%F)"
GIT_AUTHOR_DATE="$release_epoch +0000" GIT_COMMITTER_DATE="$release_epoch +0000" \
  git commit -m "chore(release): cut vX.Y.Z"

# 5. Tag the bump commit LOCALLY, before pushing anything. The tag is not
#    optional at this point and it is not early: the bump in step 4 made the
#    inbound page tell a reader `go install <module>@vX.Y.Z`, and the
#    distribution gate reads that pin and resolves it against the object store.
#    Between the bump commit and its tag the page names bytes no tag holds, and
#    the gate refuses that rather than treating an absent tag as a pass -- so
#    the two refs are one state and must not exist apart.
#    The tag is annotated and signed with the tag key, whose public half is
#    release/tag-signing-key.asc. release.yml refuses a tag that key did not
#    sign, so a lightweight or unsigned tag fails the release.
git tag -s -u 494767A5F0B0494C3A8878F320D2E0E72DF45D39 -m vX.Y.Z vX.Y.Z
python3 scripts/verify-release-tag.py vX.Y.Z

# 6. Run the leak tier and nothing more. The pre-push hook does it: the
#    runner-label check, the push-range identity scan, the push-hygiene check
#    (blob size, conflict markers) and the secret scan. Remote CI is the proof
#    (ruling of 2026-10-07). Do not mirror the CI jobs on a local machine or a
#    box: the serial mirror runs about 15 hours, and on 2026-10-29 it was still
#    at job 41 of about 220 when the v0.30.0 release was landed from remote CI.
#    Step 7's push runs the hook; the tag check below is cheap and local.
python3 scripts/verify-release-tag.py vX.Y.Z

# 7. Publish the owned feature branch and the new tag atomically. The feature
#    branch's installation pin and signed tag arrive together. The default
#    branch stays at its reviewed revision until the source pull request lands.
git push --atomic origin <branch> refs/tags/vX.Y.Z:refs/tags/vX.Y.Z

# 8. Open a source pull request from <branch> into main. Review its exact head
#    and require all hosted checks to pass, including the release tag run.
#    Merge through the normal protected landing procedure. Read back the
#    merged source tree, main checks and actual package publication before
#    reporting the release as delivered.
```

A tag that precedes its remote run cannot publish a bad release, and that is
why the order above is safe rather than merely convenient: `release.yml`'s
`publish` job declares `needs: verify`, so the tag triggers a verification
first and PyPI is reached only if the digest list, the signature, the
timestamps and the manifest all hold. If `ci` on the default branch then fails
anyway, retain its tag and failed run as evidence. Repair the source and use a
new patch version for the next cut. A failed verification is not evidence of a
published PyPI distribution.

A stranger checks a tag the same way the workflow does, against the key file
rather than their own keyring:

```sh
git fetch --tags https://github.com/probityai/agent-evidence-vectors
python3 scripts/verify-release-tag.py vX.Y.Z
```

For a run that has already selected its release inputs, carry both full object
IDs into the check. The workflow records the checkout commit and annotated tag
object before the artifact gate, then refuses a refreshed remote tag that
names different objects. The checker resolves the tag name once and verifies
that exact object, so a concurrent reference change cannot switch the object
between its type, target and signature checks.

```sh
python3 scripts/verify-release-tag.py vX.Y.Z \
  --expected-commit SELECTED_COMMIT_SHA \
  --expected-tag-object SELECTED_TAG_OBJECT_SHA
```

The signing key is not a CI secret and this is deliberate: a key in an Actions
secret is readable by every workflow that ever runs and by anyone who can land a
workflow change. Signing happens on the maintainer's machine; CI's job is the
other half, refusing a tag whose artifacts do not verify.

## What the tag triggers, and what it proves

`.github/workflows/release.yml` runs on `v*` and does two jobs.

The **verify** job re-checks the published evidence as a stranger would: that the
signed digest list verifies and that the tag holds those bytes, that the time
evidence covers that signature, and that what a citer will verify actually does.
It also re-checks every Verified by Probity grant in `docs/badge-grants.json`
against the current workflow allowlist and revocations
(`scripts/badge-grants-gate.py`), so a grant that no longer meets the evidence
rule in `docs/VERIFIED-BADGE.md` blocks the release until it is fixed or
withdrawn.

The **publish** job builds the wheel and the sdist, runs the wheel from outside
the checkout and replays every corpus it carries, asserts the wheel's version is
the tag's, and uploads to PyPI under the workflow's own OIDC identity. Nobody
uploads by hand.

Two properties of the wheel are worth stating because they have been wrong
before. The wheel carries the corpora as data, so **a corpus absent from the
`[tool.hatch.build.targets.wheel]` and `sdist` lists in `pyproject.toml` does not
reach a consumer who installs the package**, however green the tag is — a user
who installs the release and counts members will count the ones the wheel
carries, not the ones the repository holds. And every corpus the wheel carries
must end the replay in one of two states: judged clean by a reader in the
package (the reference rail for `vectors`, and the W3C report and Observed
Effect readers), or refused by name with exit 2 because the package has no
reader for its suite. Any other outcome fails the release. The refused suites
are judged by the Go readers in `corpora/`, which CI runs over every committed
corpus, so a release is covered corpus by corpus but not yet by the wheel
alone.

This paragraph said, until 0.12.1, that the replay "asserts `suiteRefusals ==
0`, so a corpus in the wheel that the packaged rail cannot judge fails the
release". The step replayed `vectors` only, and the harness ran its AEE rail
over the eight other suites and printed that rail's failures as a verdict.

## The Hugging Face dataset follows the tag

The `publish` job of `.github/workflows/release.yml` mirrors each corpus release
to the dataset `probityai/agent-evidence-vectors` on Hugging Face. It runs on the
pushed `vMAJOR.MINOR.PATCH` tag, after `verify` (the signed digest list, the tag
signature and the time evidence) has passed. It builds the dataset tree from the
tag with `scripts/publish-hf-dataset.py`, checks it, publishes the PyPI wheel,
then replaces the dataset in one commit and gives it a tag with the tag's name.
Package releases such as `jcs-admit-npm-v0.1.0` do not start it.
`.github/workflows/publish-hf-dataset.yml` only tests the build and holds no
secret.

One approval covers both destinations. The job runs in the protected environment
`public-release`, whose required reviewer is the repository owner, so neither
the wheel nor the dataset is published until the owner approves the run. The
dataset takes only the `vectors*` directories, `release/`, `LICENSE` and
`CITATION.cff`, from the commit the run is on, which must be on `main`. A tag
older than the one the Hub holds never replaces it. There is no manual trigger:
a release that was missed is published again with a new tag. The `HF_TOKEN`
secret lives in that environment, so no other job can read it.
`scripts/publish-gate-test.py` fails CI when any workflow publishes outside
this path. A dataset tag that already points at a different commit is never
moved, and the job fails instead.

To build and check the tree locally:

```sh
python3 scripts/publish-hf-dataset.py build --tag vX.Y.Z --out /tmp/aev-dataset
python3 scripts/publish-hf-dataset.py check /tmp/aev-dataset
```

`scripts/publish-hf-dataset-test.py` rebuilds v0.25.0, the first copy, and
requires the bytes the Hub served for it, so a change to the build that would
alter an earlier revision fails before it can publish a later one.

## Before you start

- The local gate is the leak tier only: runner labels, the push-range identity
  scan, push hygiene, and the secret scan. It runs in seconds. Remote CI on the
  release pull request is the proof, and the release is not delivered until
  every hosted check on it is green. `scripts/release-procedure-test.py` refuses
  a release procedure that asks for the full local mirror of the CI jobs.
- Read the count you publish off the tagged tree, by counting members in the
  manifests. Never quote it from a README: that is the defect that put a wrong
  vector count in front of a user who installed the release and counted.
