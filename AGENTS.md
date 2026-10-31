# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing anything; these are the rules an agent
most often breaks here.

- The pre-push hook runs only the push-time checks, and remote CI is the proof. To run every CI
  shell step locally first: `uv run --with pyyaml python scripts/workflow-steps-gate.py`.
- Never write or edit a vector file by hand. Change the generator in the corpus directory, then
  regenerate; `scripts/regenerability-gate.py` refuses a file no generator produces.
- Never type a count into prose. Every published count is derived from a manifest, and
  `scripts/count-gate.py` refuses a new count-shaped integer that no source backs.
- Don't change `aee/` to make a vector pass. If the reference rail must change, that is a
  separate fix with its own reason.
- A question the specification leaves open goes in `vectors/indeterminate/`, never into a wider
  reject code set.
- Sign off every commit (`git commit -s`); the DCO check refuses a commit without it.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and
  `scripts/readme-lint.py` fails a README over 600 prose words, with no code block in its first
  45 lines, or with a relative link that resolves to no file.

Parts imported from agent-evidence (`crates/`, `packages/`, `actions/`, `pages/`, `release.toml`):

- Run `uv run --frozen --only-group dev ruff check .` and `uv run --frozen --only-group dev python -m pytest` from the root before every commit that touches them.
- Run `actionlint` after editing anything under `.github/workflows/`.
- A part adds its CI job to `.github/workflows/parts.yml` and to the `needs` of its `ci-ok` job, and its row to `release.toml`.
- A crate or package release is a published GitHub release whose tag is `<prefix>-v<version>` (prefixes in `release.toml`); `release.yml` checks it. A bare `v<version>` tag is the corpus release and publishes only the `agent-evidence-vectors` wheel.
- Never edit `pages/` by hand. Rebuild it with `scripts/build_predicate_pages.py` and commit the new pin in `pages/predicate/v1/PAGES.sha256` with the page; `docs/predicate-pages.md` says when a page may change.
