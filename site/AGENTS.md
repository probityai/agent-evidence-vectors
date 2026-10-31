# Rules for agents changing this repository

- Never edit `docs/` by hand. It is built: run `python3 tools/build.py`, and `python3 tools/build.py --check` must pass before you commit.
- Never edit `src/atlas.md` by hand. Edit `data/atlas.toml` and run `python3 tools/gen_atlas.py`.
- Every number, date or status you add to a page needs a row in `CLAIMS.md` with its source, read time, re-derive command and limit.
- Every new claim row also needs a cadence in `data/claim_cadence.toml`: use the existing rule for mutable status or fixed source evidence. A missing cadence blocks the build.
- Run `python3 tools/check_links.py` and `python3 tools/check_lab.py` before committing.
- Keep the README to one screen: `python3 scripts/readme-lint.py README.md` and `python3 scripts/readme-lint-test.py` must pass. Detail goes in a `src/` page.
- Never change `scripts/readme-lint.py`; it is a byte-identical copy shared with sibling repositories.
- Builds need pandoc 3.x; any pandoc warning fails the build.
