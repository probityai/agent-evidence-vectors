# Version ledger

Component releases, source tags and the documentation built from them

Draft. Site version 0.6-draft, 2026-10-01. Rebuilt on every change; the digests let a reader check that a page matches the version recorded here.

<a id="component-versions"></a>

## Component versions

These are publication records at the read time shown. The source column names the commit behind each release or tag. Registry releases do not imply a GitHub tag; source tags name the peeled commit. A repository can publish a harness and a case package at different versions.

| Component and artifact | Publication role | Version | Source commit | Read (UTC) | Scope |
|----|----|----|----|----|----|
| [Probity Admission](start.md#artifact-digest-check) / Python digest checker | Published release | [py-v0.1.0](https://github.com/probityai/agent-evidence-admission/releases/tag/py-v0.1.0) | [`0004d2333a84`](https://github.com/probityai/agent-evidence-admission/tree/0004d2333a841c95658d4a9c75232f0913ca7141) | 2026-10-15 | This release is the digest-check package. Admission policy and budget tasks retain their own source pins. |
| [Checkout composition reference](start.md#checkout-runner) / Composition CLI and Action | Source tag | [0.2.0](https://github.com/probityai/agent-checkout-runner/tree/v0.2.0) | [`297b5b182bb4`](https://github.com/probityai/agent-checkout-runner/tree/297b5b182bb40605b62586eccbf93a9c68a4aee1) | 2026-10-15 | A bounded synthetic composition reference. The source tag pins the CLI and Action, not a registry release or a merchant deployment. |
| [dsse](start.md#dsse) / Rust crate | Registry release | [0.1.3](https://crates.io/crates/dsse/0.1.3) | [`5f1e4b5ffd61`](https://github.com/probityai/dsse/tree/5f1e4b5ffd61b6bae0f69b43766c493370004d29) | 2026-10-15 | Signature verification checks bytes under caller-selected keys, not the truth of the payload. |
| [jcs-admit](start.md#jcs-admit) / Rust crate | Registry release | [0.1.2](https://crates.io/crates/jcs-admit/0.1.2) | [`d7e65f04bf13`](https://github.com/probityai/jcs-admit/tree/d7e65f04bf13873e6579a91aa111234866020389) | 2026-10-15 | Canonicalization and raw-input admission are separate from envelope verification. |
| [Probity Observer](start.md#observer) / Python package | Registry release | [0.0.1](https://pypi.org/project/agent-evidence-observer/0.0.1/) | [`c12869620f18`](https://github.com/probityai/agent-evidence-observer/tree/c12869620f1834ce566cd924ba95918c4dde52ce) | 2026-10-15 | Root package release; separate integration profile wheels and source readers keep their own installation paths. The reviewed quick start remains a pinned source recipe. |
| [Probity Ratchet](start.md#ratchet) / Harness source | Source tag | [0.1.2](https://github.com/probityai/probity/tree/probity-ratchet-v0.1.2) | [`e2daf77f75e9`](https://github.com/probityai/probity/tree/e2daf77f75e92aa961cf184084335b67aaae7581) | 2026-10-15 | Annotated harness tag, peeled to its source commit. It is separate from the public case package. |
| [Probity Ratchet](start.md#ratchet-cases) / Public case suite | Published release | [0.2.0](https://github.com/probityai/probity/releases/tag/probity-ratchet-cases-v0.2.0) | [`b6504260db8a`](https://github.com/probityai/probity/tree/b6504260db8af7d3746e9ac87740430dd988e8d9) | 2026-10-15 | The case package has its own release. All shipped splits are public. |
| [Agent Evidence Vectors](start.md#vectors) / Go verifier and Python harness | Published release | [0.18.1](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.18.1) | [`33d545104ff2`](https://github.com/probityai/agent-evidence-vectors/tree/33d545104ff2f8c124cff465c96c013eeb809156) | 2026-10-15 | The reviewed guide also carries a 0.18.0 install recipe. Select the version required by your result. |
| [Probity Verify](start.md#verify) / Python package | Registry release | [0.1.1](https://pypi.org/project/probity-verify/0.1.1/) | [`db28cc76e5f5`](https://github.com/probityai/probity/tree/db28cc76e5f5aa6932d5122d9c6241ef7adb7fee) | 2026-10-15 | The released wheel adds packaged sample inputs. The reviewed guide deliberately retains its earlier source recipe; historical 0.1.0 builder provenance remains separate. |
| [Probity Vocabulary](start.md#vocabulary) / Python package | Registry release | [0.4.0](https://pypi.org/project/agent-evidence-vocabulary/0.4.0/) | [`59c93ac4529c`](https://github.com/probityai/agent-evidence-vocabulary/tree/59c93ac4529c1e8fdf6e7cdfff7a950740c873f3) | 2026-10-15 | Python package carries the released registry and crosswalk data. The reviewed quick start still reads the independently tagged v0.4.0 raw registry. |
| [Probity Vocabulary](start.md#vocabulary) / Vocabulary registry | Published release | [v0.4.0](https://github.com/probityai/agent-evidence-vocabulary/releases/tag/v0.4.0) | [`220a4f0a08b9`](https://github.com/probityai/agent-evidence-vocabulary/tree/220a4f0a08b90a555a430bb7d4334eb2617d05ba) | 2026-10-15 | Terms and crosswalks are versioned independently of executable packages. |

<a id="choose-the-pin-for-your-task"></a>

### Choose the pin for your task

- **Install or integrate:** use a component's [reviewed guide](start.md), then keep the exact package version or source commit its recipe selects. A guide can deliberately use an older release.
- **Repeat a tested installation:** use the recipe's recorded source, environment, command and retained output. A release number alone is not an install result.
- **Cite or replay a result:** retain the source and artifact digests in that result. [Lab records](lab.md), historical examples and citation snapshots do not move when a new release appears.

<a id="documentation-revisions"></a>

## Documentation revisions

A digest here is the SHA-256 of the artifact's source file in the site's repository, truncated to 16 hexadecimal characters for display. A change to the source changes the digest, and a change that alters what a page claims also gets a new version and a note.

| artifact | version | date | status | source SHA-256 (first 16) | note |
|----|----|----|----|----|----|
| [Home page](index.md) | 1.14 | 2026-10-15 | draft | `56c3a5383ab947a4` `src/index.md` | Links the verifier task to exact-source Action controls and their retained hosted result |
| Essay | 0.2 | 2026-09-27 | held | page not built in this repository yet | Held until it passes its release criteria |
| [Atlas](atlas.md) | 0.6.1-preview | 2026-10-16 | draft | `b81d48c0a430edec` `data/atlas.toml` | Records jcs-admit 0.1.2 and dsse 0.1.3 from full registry byte readback; other source and corpus pins stay unchanged |
| Verifier demonstration | 0.1 | 2026-09-27 | held | page not built in this repository yet | Held until it passes its release criteria |
| [Experiments](experiments.md) | 0.5 | 2026-10-16 | draft | `11e849dc1744fbdc` `src/experiments.md` | Returns from the original admission experiment to its worked article and exact presentation packet |
| Series plan | 0.1 | 2026-09-27 | held | page not built in this repository yet | Held until it passes its release criteria |
| [Claim ledger](claims.md) | 0.8.37 | 2026-10-16 | draft | `46eb456887433ecd` `CLAIMS.md` | Binds the actual native Rust registry releases and preserves separate historical guide pins |
| [Probity Open Evidence Lab](lab.md) | 0.1.16 | 2026-10-16 | draft | `d044098693f69ae7` `src/lab.md` | Repairs three retained workflow download paths without changing original bytes or results |
| [Claim status](status.md) | 0.4 | 2026-10-15 | draft | `f83d8633f8f0c709` `src/status.md` | Counts the five retained case records at their stated evidence classes; outside hosting does not imply independent custody |
| [Task-grouped rates worked example](task-grouped-rates.md) | 0.1 | 2026-10-03 | draft | `92940ce8ee827ad0` `examples/task-grouped-rates/input.json` | Authored labels, paired task resampling, explicit weighting targets and unresolved outcomes |
| [Published robot controls companion](provael-task-controls.md) | 0.1 | 2026-10-03 | draft | `20b90c1ae59c399d` `examples/provael-task-controls/source-record.json` | Original publisher simulator labels, matched controls, corrected interpretation and exact paired task weights |
| [APS and PriorSeal pilot status](pilot.md) | 0.1.1 | 2026-10-01 | proposed | `f4a3c2913444e399` `src/pilot.md` | Probity-owned proposal, merged technical replay, owner slots and acceptance gates; no formal pilot agreement |
| [Authored policy vocabulary finding](vocabulary-findings.md) | 0.1 | 2026-10-03 | draft | `f83b9c1ae54db624` `src/vocabulary-findings.md` | Fixed action vocabulary raises the finite authored score; all default quality rows hold |
| [Authored tool-argument finding](tool-argument-findings.md) | 0.1 | 2026-10-03 | draft | `8a871f92f8f890ff` `src/tool-argument-findings.md` | Preserves all native attempts, abstention failures and separate scoped-evidence publication/quality holds |
| [Project catalog](start.md) | 0.12 | 2026-10-16 | draft | `b3ec4db5d77af72a` `data/catalog.json` | Uses existing registry-release rows for actual native Rust crates without invented source tags |
| [Automation guide](automation.md) | 0.2 | 2026-10-15 | draft | `37fa8cc37f43e32a` `src/automation.md` | Explains the existing Vectors Action failure controls with exact source and hosted job |
| [Catalog maintenance guide](catalog.md) | 0.7 | 2026-10-15 | draft | `8aad602241e86dc6` `src/catalog.md` | Explains exact registry releases without source tags and retains tagged release roles |
| [Retained evidence decision walkthrough](replay-an-evidence-decision.md) | 0.5 | 2026-10-16 | draft | `6e8a10dd814f8e01` `src/replay-an-evidence-decision.md` | Links one reusable source-bound presentation packet without changing the replay method |
| [Retained-run browser](runs.md) | 0.1 | 2026-10-06 | draft | `6a2ac67797c7adf9` `src/runs.md` | Search, exact claim-result filters and complete static navigation over the existing Lab register; no aggregate run grade |
| [Published source routes](start.md) | 0.2.3 | 2026-10-15 | draft | `76f6a619c66b1f36` `data/catalog-sources.json` | Appends current Python guide source reviews while retaining all earlier recipe and Action pins |
| [Caller-declared APS and PriorSeal replay guide](replay-tools.md) | 0.1 | 2026-10-06 | draft | `94025818d44f6e6d` `src/replay-tools.md` | Links one complete v2 procedure, explicit caller declarations, hashes of files read at invocation and actual process outputs; historical results stay unchanged |
| [Historical report and diagnostic retained record](runs.md) | 0.1 | 2026-10-06 | draft | `892a154384a1c6d9` `experiments/w3c-report-replay-2026-10-06/report.json` | Original historical report outputs and separate diagnostic controls with maintained data-only accounting; no new native or independent-operator claim |
| [Test outcomes and evidence conclusions](evidence-test-meaning.md) | 0.1 | 2026-10-06 | draft | `d0b4380e2ea9f868` `src/evidence-test-meaning.md` | Worked hypothetical refund story with historical package pins, retained per-case data and a maintained Lab checking route |
| [Approved SQL illustration](approved-sql.md) | 0.1.0 | 2026-10-09 | illustration | `1bf0e167febeafe3` `src/approved-sql.md` | Checked supplied-record comparison; native audit pair and independent reader remain separate contributions |
| [Request and effect join cases](request-effect-join.md) | 0.1 | 2026-10-09 | proposed | `f7668c14559f2470` `src/request-effect-join.md` | Selected producer contract and separate pre-dispatch, post-commit and target-coverage cases |
| [Synthetic authority, report and observation controls](authority-effect-cases.md) | 0.1.0 | 2026-10-09 | \[synthetic controls\]{.label .synthetic controls} | `ee68331360373c87` `src/authority-effect-cases.md` | Authored supplied-record comparisons, source attribution and an installed-package gate; live effects, independent observation and outside operation remain separate |
| [Agent checkout authority-to-effect assessment](agent-checkout-assessment.md) | 0.1 | 2026-10-13 | proposed | `9f8a0a73bf650683` `src/agent-checkout-assessment.md` | Assessment class from shopper approval to payment, order and effect; public synthetic method, operator records stay private |

[HTML view](versions.html) | [Agent guide](llms.txt)
