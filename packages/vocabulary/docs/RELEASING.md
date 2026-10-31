# Releasing

A release is one commit that states the new version everywhere a reader meets
it, a squash merge, and a signed tag on the merge commit. Citers pin the tag, and
OpenCRE imports the registry's links at a tag, so nothing changes under a tag
once it is pushed.

1. On a branch, make one commit, `chore(release): version X.Y.Z`, that sets the
   version, and the date where one is stated, in:
   - `vocabulary.yaml`: `meta.version` and the `# version:` header line;
   - `CITATION.cff`: `version` and `date-released`;
   - `CONTRIBUTING.md`: the "At version" sentence and the worked example's
     `vocabulary_version_targeted`;
   - `crosswalk/TEMPLATE.yaml`: `vocabulary_version_targeted`;
   - `GOVERNANCE.md`: the two sentences that state the current version;
   - `README.md`: the quick-start URL, the sha256 of `vocabulary.yaml` as it will
     be tagged, and the Status line;
   - `docs/ABOUT.md`: the Status line;
   - `llms.txt`: the release tag.
2. Run `git grep -n "<previous version>"`. What is left should only be history
   that names an older version on purpose, such as "added in 0.3.0".
   `python3 scripts/check_release_statements.py` does the same for the install
   pin, the tags, the dates and the sha256 the files above state, and CI runs it.
3. Open the pull request, wait for every check to pass, and squash-merge it
   with an explicit conventional subject.
4. Tag the merge commit and push the tag:

   ```bash
   git tag -s vX.Y.Z -m "vX.Y.Z" -m "<what the release adds>" <merge-commit>
   git tag -v vX.Y.Z
   git push origin vX.Y.Z
   ```

   `git tag -v` must show a key whose only identity is the maintainer's name and
   address.
5. Publish the GitHub release from the tag, then confirm the digest a reader
   checks:

   ```bash
   gh release create vX.Y.Z --verify-tag --title vX.Y.Z --notes "<what the release adds>"
   curl -fsSL https://raw.githubusercontent.com/probityai/agent-evidence/agent-evidence-vocabulary-vX.Y.Z/packages/vocabulary/vocabulary.yaml | sha256sum
   ```

   The digest must equal the one in the README's quick start.

## Python data distribution

The Python package is `agent-evidence-vocabulary` 0.8.0. It contains the exact
`vocabulary.yaml` bytes from data release `v0.8.0`, with SHA-256
`76233ba8924cebdf053f0449ce023186805156aedca4121b9b156bd747a411b4`.
The repository keeps one copy of the YAML. The package maps that file directly
into `agent_evidence_vocabulary`; no generated copy can drift from it.

After building the checked wheel, install it with a selected YAML parser:

```sh
uv venv vocabulary-env --python 3.12
uv pip install --python vocabulary-env/bin/python \
  dist/agent_evidence_vocabulary-0.8.0-py3-none-any.whl PyYAML==6.0.3
vocabulary-env/bin/python - <<'PY'
from importlib.resources import files
import yaml

raw = files("agent_evidence_vocabulary").joinpath("vocabulary.yaml").read_bytes()
registry = yaml.safe_load(raw)
print(registry["evidence_dimensions"]["observation_vantage"]["values"])
PY
```

It prints `['substrate', 'artifact']`. The data comes from the installed package;
the consumer does not need a checkout. The package has no runtime dependency
on a particular YAML parser. Python 3.10 or later is supported; the installed
consumer uses Python 3.12. A package install does not promote any term or
establish that another system emits it.

The `Python distribution` workflow builds and checks wheel and source archive
contents, both grants, the data version and every wheel RECORD hash. It reads
the installed data outside the checkout, rebuilds from the source archive and
checks that installed consumer too. The artifact retains source and package
hashes, installation reports and consumer results.

The release-tool lock selects setuptools 84.2.1. The source backend requires
setuptools 77.0.3 or later for SPDX license metadata and both license files, so
compatible build environments do not have to use that exact release toolchain.

The build job has read access only. On a push to this repository's main branch,
a separate job signs build provenance for the same checked wheel and source
distribution. It checks their hashes after transfer and does not rebuild them.
That job receives only `contents: read`, `id-token: write` and
`attestations: write`. The signed bundle is retained in the separate
`python-build-provenance` artifact; the `python-distributions` artifact keeps
its original files. Verify each distribution with
[`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify),
binding the repository, workflow and exact source commit. A GitHub build
attestation is separate from a PyPI Publish attestation and registry publication.

The existing `v0.5.0` data tag stays immutable. The first Python packaging
release uses `python-v0.5.0`, which identifies the packaging source while its
package version still matches the contained registry. The separate tag names
identify two different artifacts. A later data release updates `pyproject.toml`
and the digest checks in `scripts/check-artifacts.py` and
`scripts/check-installed.py` with the other versioned files above.

A data release with a `vX.Y.Z` tag does not start the `Python distribution`
workflow's release path; only a `python-vX.Y.Z` release does.

Only a non-prerelease GitHub release with the matching `python-vX.Y.Z` tag on
main can reach the publish job. Configure an [existing or pending PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/)
with owner `probityai`, repository `agent-evidence-vocabulary`, workflow
`python-distribution.yml`, and environment `pypi`. The separate publisher
job receives `contents: read` and `id-token: write`. The pinned PyPA action uploads
[PyPI attestations](https://docs.pypi.org/attestations/producing-attestations/)
without an account-token or password fallback. A prepared workflow does not
prove the account binding exists or that publication ran.

After publication, read the registry metadata, download both artifacts, compare
their hashes and check the installed data again. Confirm provenance through
PyPI's integrity API before reporting a provenance result. Keep the raw data
download and its original release digest in the README until the package
release actually exists.

Regenerate the release-tool lock with:

```sh
uv pip compile --python-version 3.12 --generate-hashes --no-header --no-annotate \
  requirements-release.in --output-file requirements-release.lock
```
