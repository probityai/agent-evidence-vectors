# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md) first; these are the
rules an agent most often breaks here.

- Run `python3 scripts/validate_crosswalks.py` after any change to `vocabulary.yaml` or
  `crosswalk/`. It needs only `PyYAML==6.0.3` from `requirements.txt`.
- Run `python3 scripts/check_opencre_links.py` after any change to a term's `opencre` list or to
  `docs/OPENCRE.md`. OpenCRE imports every opencre.org CRE URL in `vocabulary.yaml`, so a CRE URL
  goes only in a term's `opencre` list, never in a comment or a definition.
- Never promote a term by editing its `status`. Promotion needs an independently maintained
  issuer, and the maintainer's own systems never count toward it.
- A crosswalk claim of `exact`, `structural` or `partial` needs `evidence` and a resolvable
  `source_path`; `no_mapping` is a valid answer.
- Sign off every commit (`git commit -s`); the DCO check refuses a commit without it.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and `scripts/readme-lint.py`
  fails a README over its word limit.
