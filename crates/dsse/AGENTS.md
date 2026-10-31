# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) first; these are the rules an agent most often breaks here.

- `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo doc` must pass with no
  warnings before you push.
- A change to what the crate accepts comes with a test that fails without it.
- Never regenerate the pinned material from this crate. The cross-language fixtures in `vectors/`
  come only from `vectors/generate`, which uses the DSSE reference Go implementation (CI fails if
  the file differs from its output), and the vector in `tests/spec_vector.rs` comes from DSSE's
  protocol document. [PROVENANCE.md](PROVENANCE.md) records each source.
- Nothing shipped may carry an internal name, path or host, including inside base64 or hex.
  `tests/no_private_names.rs` decodes every shipped file and refuses the list CI supplies.
- `verify` returns the payload it checked. Don't add a path that reads the payload from the
  envelope after verification.
- Sign off every commit (`git commit -s`); the DCO check refuses a commit without it.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and `scripts/readme-lint.py`
  fails a README over its word limit.
