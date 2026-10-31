# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) first; these are the rules an agent most often breaks here.

- `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo doc` must pass with no
  warnings before you push.
- A new refusal comes with a test that fails without it. [docs/MUTATION-SWEEP.md](docs/MUTATION-SWEEP.md)
  records how each existing refusal was checked that way.
- Never regenerate the pinned vectors in `tests/vectors/` from this crate. They come from an
  independent Go implementation; [tests/vectors/PROVENANCE.md](tests/vectors/PROVENANCE.md) says
  where.
- Don't reimplement number formatting. It is delegated to `serde_json_canonicalizer` on purpose.
- Sign off every commit (`git commit -s`); the DCO check refuses a commit without it.
- `python/` binds the published crates, pinned exactly in `python/Cargo.toml`. A change to
  what `jcs_admit._native` exports changes `python/pysrc/jcs_admit/_native.pyi` in the same
  commit; CI runs `mypy.stubtest` against the built module. The Python tests read vectors from
  the bound crate's registry source; never copy them into `python/`.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and the repository root's `scripts/readme-lint.py`
  fails a README over its word limit.
