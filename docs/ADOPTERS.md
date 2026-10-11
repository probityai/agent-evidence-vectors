# Adopters

Projects whose own tree or build uses a corpus from this repository. Runs of a corpus by someone else's code are in [INDEPENDENT-RUNS.json](INDEPENDENT-RUNS.json); this page lists use, not results.

## Tiers

| Tier | What it means | What breaks if this repository changes |
| --- | --- | --- |
| Pinned dependency | `agent-evidence-vectors==X.Y.Z` in the project's manifest, or a Go module pin | Nothing until the project moves its pin |
| CI run | The project's CI runs the [GitHub Action](../action.yml) or the published package at a tag | The project's check, at its next run |
| Vendored copy | Corpus files copied into the project's tree | Nothing; the copy drifts |

## Listed

A row is listed only with the adopter's consent, read in the public thread named in the row.

| Project | Tier | What it uses | Consent |
| --- | --- | --- | --- |
| [a2aproject/a2a-python](https://github.com/a2aproject/a2a-python) | Vendored copy | `jcs_depth_v1` as `tests/utils/jcs_depth_vectors.json` | Merged by the project's maintainers in [a2a-python#1294](https://github.com/a2aproject/a2a-python/pull/1294), a pull request opened by this repository's maintainer |

## Add your project

Open a pull request that adds one row: the project, the tier, the corpus and the pin, and a link to a public thread or commit where a maintainer of that project agrees to the listing. A pinned dependency or a CI run is preferred over a copy, because only those two tell you when the corpus changes.
