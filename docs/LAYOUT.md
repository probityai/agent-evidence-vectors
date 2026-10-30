# Layout and releases

## Directories

| Directory | Holds | Built with |
| --- | --- | --- |
| `crates/<name>/` | one Rust crate each: `dsse`, `jcs-admit` (with its Python binding in `crates/jcs-admit/python/`) | Cargo, from inside the crate directory |
| `packages/<name>/` | one Python distribution each | uv, as members of the root uv workspace |
| `actions/` | the code behind the root `action.yml`, the one Action of this repository ([ACTION.md](ACTION.md)) | nothing to build; `run.py` uses the standard library |
| `vectors/` | the conformance corpora and their harness | uv |
| `pages/` | the pages the persistent identifiers under `https://w3id.org/agent-evidence/` redirect to, served at `https://probityai.github.io/agent-evidence/` ([predicate-pages.md](predicate-pages.md)); this repository's own Pages site does not serve them | `scripts/build_predicate_pages.py`, pins checked by `pages.yml` |

A directory appears when its part is imported. An import brings the source repository's full history under the new directory, so `git log --follow` and `git blame` keep working, and renames its tags with the part's prefix (below). The source repository is then archived, and its tags, releases, Actions and pages keep working.

The root `Cargo.toml` is a workspace that excludes `crates/`: each crate keeps its own `Cargo.lock` and `supply-chain/` audits, and `cargo publish` from the crate directory packages what it packaged before the import. The root `pyproject.toml` is a uv workspace over `packages/*`.

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request and every push to `main`. Its `changes` job asks `scripts/workspace.py` which directories a change touches, and only their checks run. A change outside every directory, other than documentation, runs everything. The `ci-ok` job passes when every job that ran passed; it is the one required check.

## Releases

Each part has its own version line. A published GitHub release whose tag is `<prefix>-v<version>` runs `.github/workflows/release.yml`, which publishes that part only. A pushed tag alone publishes nothing.

| Tag prefix | Registry | Part |
| --- | --- | --- |
| `dsse-v` | crates.io | `crates/dsse` |
| `jcs-admit-v` | crates.io | `crates/jcs-admit` |
| `jcs-admit-py-v` | PyPI | `crates/jcs-admit/python`: seven abi3 wheels and the sdist |
| `agent-evidence-vectors-v` | PyPI | the vectors distribution |
| `agent-evidence-vocabulary-v` | PyPI | the vocabulary distribution |
| `agent-evidence-admission-v` | PyPI | the admission distribution |
| `action-v` | none | the root `action.yml`: the release is the Action's version and its Marketplace listing |

`release.toml` lists the parts that have arrived. The workflow refuses a tag whose part is not listed, whose version differs from the part's manifest, or whose commit is not on `main`. Publishing uses registry trusted publishing from the GitHub environments `crates-io` and `pypi`; no registry token is stored.

### When the family pin guard refuses a release

Before any PyPI publish, `release.yml` runs `family-pin-guard`. It reads the newest published release of every other family distribution (listed in `scripts/family-packages.toml`: `agent-evidence-vectors`, `agent-evidence-vocabulary`, `agent-evidence-admission`, `agent-evidence-mcp`, `probity-verify`, `jcs-admit`) and refuses to publish when one of them requires a version of the candidate that excludes it, for example `agent-evidence-vocabulary~=0.7.0` against a vocabulary 0.8.0 release. The log names each sibling, its version and the excluding pin. It then installs the candidate wheel beside every sibling's newest release in a fresh environment and runs `uv pip check`.

When it refuses:

1. Release each named sibling first, with its pin widened to admit the candidate (`~=0.8.0`, or `>=0.7,<0.9` while both lines must install), after running that sibling's tests against the candidate.
2. Wait for the sibling's release to appear on PyPI.
3. Re-run the failed `release` workflow run. The guard reads PyPI again and passes.

A new PyPI distribution is added to `scripts/family-packages.toml` in the same change that adds its row to `release.toml`; a test fails otherwise. To try a version without releasing: `uv run --frozen --only-group dev python scripts/family_pin_guard.py check --name agent-evidence-vocabulary --version 0.9.0`.
