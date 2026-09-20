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
disagreement rather than trusting the person cutting the release:

| File | What carries the version |
| --- | --- |
| `pyproject.toml` | `[project] version` — what the wheel is built as |
| `CITATION.cff` | `version:` — what an archive deposit and GitHub's citation panel read |
| `DISTRIBUTION.md` | the tag-to-cite section, the `go install` pin, the `git checkout` lines, and the releases row |
| `README.md` | the action pin, the `git checkout` in the verification recipe, and the citation block |

`scripts/distribution-gate.py` holds the inbound page and `CITATION.cff` to each
other and refuses any version token on the page that is not the released one.
`scripts/citation-metadata-gate.py` holds the deposit metadata. The wheel is held
to the tag by the release workflow itself, which is the only check that cannot be
run before the tag exists.

A module-path move is the one case where a pinned command deliberately does NOT
take the new spelling: an install pinned to a tag that predates the move must
keep the spelling that resolves at that tag, and the page says from which tag the
new path takes over. Do not "fix" that inconsistency; it is the honest one.

## The steps

Run them in this order. The order matters twice: the digest list must be written
before it is signed, and the signature must exist before it is stamped, because
the stamps cover the signature bytes rather than the list.

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

# 5. Push the branch and let the remote run conclude BEFORE tagging. A tag on a
#    commit whose CI has not concluded is a tag that may have to be withdrawn,
#    and a withdrawn tag is the one thing a citation cannot survive.

# 6. Tag and push the tag. The tag is what triggers the release workflow.
git tag vX.Y.Z
git push origin vX.Y.Z
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

The **publish** job builds the wheel and the sdist, runs the wheel from outside
the checkout and replays every corpus it carries, asserts the wheel's version is
the tag's, and uploads to PyPI under the workflow's own OIDC identity. Nobody
uploads by hand.

Two properties of the wheel are worth stating because they have been wrong
before. The wheel carries the corpora as data, so **a corpus absent from the
`[tool.hatch.build.targets.wheel]` and `sdist` lists in `pyproject.toml` does not
reach a consumer who installs the package**, however green the tag is — a user
who installs the release and counts members will count the ones the wheel
carries, not the ones the repository holds. And the replay asserts
`suiteRefusals == 0`, so a corpus in the wheel that the packaged rail cannot
judge fails the release: adding a corpus to those lists means giving the rail a
reader for it in the same change.

## Before you start

- The local gate is the pre-push mirror, and it is the same 89-plus steps CI
  runs: `python3 scripts/workflow-steps-gate.py`. It takes upwards of ninety
  minutes and holds a single-instance lock, so one release at a time.
- Read the count you publish off the tagged tree, by counting members in the
  manifests. Never quote it from a README: that is the defect that put a wrong
  vector count in front of a user who installed the release and counted.
