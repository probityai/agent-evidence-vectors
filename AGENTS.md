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
