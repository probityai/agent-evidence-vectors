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

Every one of these has to say the same thing, and a gate refuses each
disagreement rather than trusting the person cutting the release. The lock is
the fifth and it was the one nobody listed: the 0.12.0 bump edited the four
above, left the lock at the previous version, and the mismatch surfaced only
because a site build happened to invoke uv, which rewrote the line as a side
effect. A version carried by a file no gate reads is a version that travels by
accident, so `scripts/citation-metadata-gate.py` now reads it too.

| File | What carries the version |
| --- | --- |
| `pyproject.toml` | `[project] version` — what the wheel is built as |
| `CITATION.cff` | `version:` — what an archive deposit and GitHub's citation panel read |
| `DISTRIBUTION.md` | the tag-to-cite section, the `go install` pin, the `git checkout` lines, and the releases row |
| `README.md` | the action pin, the `git checkout` in the verification recipe, and the citation block |
| `uv.lock` | the `version` of the one `[[package]]` whose source is `virtual = "."` |

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

Run them in this order. The order matters three times. The digest list must be
written before it is signed, and the signature must exist before it is stamped,
because the stamps cover the signature bytes rather than the list. And the tag
must exist before the mirror runs, because one gate resolves the page's install
pin through it.

```sh
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

# 4. Commit the four release artifacts together with the version bump. They are
#    one unit: a digest list without its signature, or a signature without its
#    stamps, is a half-published release.
git add release/CORPUS-DIGESTS.txt release/CORPUS-DIGESTS.txt.sig \
        release/CORPUS-DIGESTS.txt.sig.tsr release/CORPUS-DIGESTS.txt.sig.ots
git commit -m "chore(release): cut vX.Y.Z"

# 5. Tag the bump commit LOCALLY, before pushing anything. The tag is not
#    optional at this point and it is not early: the bump in step 4 made the
#    inbound page tell a reader `go install <module>@vX.Y.Z`, and the
#    distribution gate reads that pin and resolves it against the object store.
#    Between the bump commit and its tag the page names bytes no tag holds, and
#    the gate refuses that rather than treating an absent tag as a pass -- so
#    the two refs are one state and must not exist apart.
git tag vX.Y.Z

# 6. Run the local mirror of every workflow step against the tagged revision.
#    This is what step 5's ordering costs and it is the whole payment: the tag
#    now precedes the remote run, so the evidence that the run will pass has to
#    come from here instead. Nothing is pushed until this is green.
python3 scripts/workflow-steps-gate.py

# 7. Push the commit and the tag in ONE push. Two pushes leave a window in
#    which the default branch carries a page pinned to a tag the remote does
#    not have, which is the same refusal as step 5 seen from the runner.
git push origin <branch>:main tag vX.Y.Z
```

A tag that precedes its remote run cannot publish a bad release, and that is
why the order above is safe rather than merely convenient: `release.yml`'s
`publish` job declares `needs: verify`, so the tag triggers a verification
first and PyPI is reached only if the digest list, the signature, the
timestamps and the manifest all hold. If `ci` on the default branch then fails
anyway, the tag is deleted on both sides before anything can cite it -- the
release the tag would have produced never published.

The signing key is not a CI secret and this is deliberate: a key in an Actions
secret is readable by every workflow that ever runs and by anyone who can land a
workflow change. Signing happens on the maintainer's machine; CI's job is the
other half, refusing a tag whose artifacts do not verify.

## What the tag triggers, and what it proves

`.github/workflows/release.yml` runs on `v*` and does two jobs.

The **verify** job re-checks the published evidence as a stranger would: that the
signed digest list verifies and that the tag holds those bytes, that the time
evidence covers that signature, and that what a citer will verify actually does.

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

## Before you start

- The local gate is the pre-push mirror, and it is the same 89-plus steps CI
  runs: `python3 scripts/workflow-steps-gate.py`. It takes upwards of ninety
  minutes and holds a single-instance lock, so one release at a time.
- Read the count you publish off the tagged tree, by counting members in the
  manifests. Never quote it from a README: that is the defect that put a wrong
  vector count in front of a user who installed the release and counted.
