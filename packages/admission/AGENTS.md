# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) first; these are the rules an agent most often breaks here.

- Run `opa test --timeout 300s rego/` after any change to `rego/`, then
  `python3 policy-controller/gen_soundness_cip.py` so the deployed manifest embeds the changed
  module; CI refuses a manifest that has drifted from it.
- Never hand-edit `PROFILE-REGISTRY.md`, `profiles/*/PROFILE-MAP.json` or
  `docs/ADVERSARIAL-RATCHET.md`. They are generated; see
  [docs/DESIGN.md](docs/DESIGN.md#the-profile-registry) for the commands.
- Never declare an obligation enforced by hand. `scripts/profile-map-gate.py` refuses a row the
  measurement doesn't support.
- Keep the three Kyverno ClusterPolicy documents' condition sets identical; the conformance
  harness compares them.
- Sign off every commit (`git commit -s`); the DCO check refuses a commit without it.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and `scripts/readme-lint.py`
  fails a README over its word limit.
