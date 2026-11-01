# Verifiers that pin this corpus

Independent verifiers whose own CI runs a corpus from this repository at a pinned release or commit. Each row was read from the project's own manifest and workflow file, and each CI link is a green run on that project's default branch. Where this repository's CI runs the verifier back, the last column links that check.

| Verifier | What it checks | Pinned | Their CI | Our CI |
| --- | --- | --- | --- | --- |
| [agmi](https://github.com/tech4biz-yasha/agent-memory-integrity) (`agmi/anchored_chain.py`) | `vectors-anchored-chain`, the anchored-record-chain/v1 cases: content tamper, tail removal, deletion, reorder, forged insertion, replay, rollback and re-anchoring | `agent-evidence-vectors==0.26.0` in its `vectors` extra ([pyproject.toml](https://github.com/tech4biz-yasha/agent-memory-integrity/blob/2f97a7f21f9ff2fcc6d38304d13174e1cdf927b0/pyproject.toml)) | [`corpus-drift` job](https://github.com/tech4biz-yasha/agent-memory-integrity/actions/runs/38759278258/job/116505930253): 14 of 14 answered, 0 disagreements | [agmi-anchored-chain.yml](../.github/workflows/agmi-anchored-chain.yml), agmi pinned at `29c2623` |
| [Rul1an/aee-checker](https://github.com/Rul1an/aee-checker) | `vectors`, the Adversarial Execution Evidence corpus, from an independent Rust implementation of the predicate | suite commit `e98de66d7296c4eb01abc38b6aee0b51b0c87a8e` and the predicate's sha256 ([conformance.yml](https://github.com/Rul1an/aee-checker/blob/main/.github/workflows/conformance.yml)) | [conformance](https://github.com/Rul1an/aee-checker/actions/runs/38446343794): requires 272 of 272 | none yet |
| [MoltyCel/moltrust-api](https://github.com/MoltyCel/moltrust-api) | `a2a-jcs-v01` as carried in a2aproject/a2a-tck, through its RFC 8785 canonicalizer, card signing and card verify paths, with a negative control that must fail | this repository's Action at `c2410b62728ab8ecab053fe4829fb9247e39181d` (v0.26.0) ([a2a-jcs-conformance.yml](https://github.com/MoltyCel/moltrust-api/blob/main/.github/workflows/a2a-jcs-conformance.yml)) | [a2a-jcs conformance](https://github.com/MoltyCel/moltrust-api/actions/runs/38272213505) | none yet |

## This repository's code in another project's CI

| Project | What runs | Pinned | Their CI |
| --- | --- | --- | --- |
| [AgentAvow](https://github.com/AgentAvow/AgentAvow) | this repository's signed-map reader (`interop/agentavow-signed-map-v1`) over AgentAvow's tool-manifest-digest v1 vectors, beside AgentAvow's own `verify.mjs` | commit `d759fb4db68a7fefcc91c2d3ad2a585471d6a53a` ([probity-pin.json](https://github.com/AgentAvow/AgentAvow/blob/main/docs/standards/tool-manifest-digest-vectors-v1/compat/probity-pin.json)) | [Probity v1 compat](https://github.com/AgentAvow/AgentAvow/actions/runs/38764345060) |

## Add your verifier

Open a pull request that adds one row: the verifier, the corpus it runs, the pin as it appears in your manifest or workflow, and a link to a green CI run on your default branch. A pin to a release or a commit is required, because a run against a moving branch cannot tell you which corpus it judged. Results of one-off runs belong in [INDEPENDENT-RUNS.json](INDEPENDENT-RUNS.json), and projects that use a corpus without verifying it are in [ADOPTERS.md](ADOPTERS.md).
