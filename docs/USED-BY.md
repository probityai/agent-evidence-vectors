# Used by

Outside projects whose own public repository runs `agent-evidence-vectors` in CI or pins it. Each row links the file that does it, in their repository, so you can check it without trusting this page.

| Project | What runs | Proof |
| --- | --- | --- |
| [ogasurfproject-jpg/horizon-shield](https://github.com/ogasurfproject-jpg/horizon-shield) | Pins `agent-evidence-vectors==0.20.0` and replays the RFC 8785 canonicalization corpus against its A2A walk client on every change to it | [workflow run 39180799548](https://github.com/ogasurfproject-jpg/horizon-shield/actions/runs/39180799548), commit `6b4841af9083` |
| [MoltyCel/moltrust-api](https://github.com/MoltyCel/moltrust-api) | Replays the `a2a-jcs-v01` corpus through `agent-evidence-vectors` in its `a2a-jcs-conformance` workflow | [pull request 721](https://github.com/MoltyCel/moltrust-api/pull/721), merge commit `36fee0b45c64` |
| [darklordVirtual/REMORA-research](https://github.com/darklordVirtual/REMORA-research) | Installs `agent-evidence-vectors` by hash and replays the invocation-axes corpus, 25 of 25 cases, in its CI | [workflow run 39350734821](https://github.com/darklordVirtual/REMORA-research/actions/runs/39350734821), merge commit `0327a04d16c3` |
| [ScopeBlind/agent-governance-testvectors](https://github.com/ScopeBlind/agent-governance-testvectors) | Installs `agent-evidence-vectors` by hash and replays the receipt-signature corpus against its pinned verifier in its `Conformance` workflow | [workflow run 38343248903](https://github.com/ScopeBlind/agent-governance-testvectors/actions/runs/38343248903), 25 of 25 vectors pass |

Counts and dates are read from the public endpoints. A pull request that is open, or a project that only mentions us, is not a row.

## Add your project

Open a pull request that adds a row, or tell us in an issue. A row needs a link to the file in your repository that runs or pins the package.
