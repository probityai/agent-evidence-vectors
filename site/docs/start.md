# Choose a component

Start with the task you need.

Vectors tests how a verifier behaves. Verify checks a supplied claim against evidence bytes.

A published release, a reviewed guide and a tested installation are different pins. Use the exact recipe and source named by the result you reproduce. The [version ledger](versions.md#component-versions) records release and source roles.

Install links keep the reviewed recipe. Download links select the recorded package release. Live badges can move beyond those pins. PePy counts PyPI and known mirrors; crate counters read crates.io. Downloads do not count people, deployments or adoption.

| Task | Project |
|----|----|
| Check artifact digests or evaluate admission policies | [Probity Admission](#admission) |
| Run an APS refund example with safe retries | [Probity APS refund example](#aps-refund-retries) |
| Check an artifact against a document's named digest | [Probity artifact digest check](#artifact-digest-check) |
| Choose a tool or inspect recorded claims and retained runs | [Agent Evidence Conformance Board](#atlas) |
| Run a checkout composition and replay its retained claims | [Checkout composition reference](#checkout-runner) |
| Sign and verify DSSE envelopes in Rust | [dsse](#dsse) |
| Read selected retained Inspect execution profiles | [Probity native Inspect reader](#inspect-native-reader) |
| Reject duplicate JSON keys and canonicalize in Rust | [jcs-admit](#jcs-admit) |
| Check published MintID trace records | [Probity MintID trace reader](#mintid-trace-records-v2) |
| Record file actions or check native delegation evidence | [Probity Observer](#observer) |
| Check an agent guard against replay and regression cases | [Probity Ratchet](#ratchet) |
| Test an agent on public fault and benign cases | [Probity Ratchet public cases](#ratchet-cases) |
| Test a verifier against conformance cases | [Agent Evidence Vectors](#vectors) |
| Install a pinned verifier and check an evidence claim | [Probity Verify](#verify) |
| Use shared definitions for agent evidence claims | [Probity Vocabulary](#vocabulary) |
| Check a selected run against retained witness anchors | [Probity witnessed run selection](#witnessed-run-selection) |

<a id="admission"></a>

## Probity Admission

Component ID: `admission`.

Provides a Python artifact-digest checker, admission policies for OPA, Kyverno and policy-controller, and a pre-call budget reservation API.

Draft. [Reviewed guide and source](https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/packages/admission/README.md)

Python digest checker: published release [py-v0.1.0](https://github.com/probityai/agent-evidence-admission/releases/tag/py-v0.1.0), source [`0004d2333a84`](https://github.com/probityai/agent-evidence-admission/tree/0004d2333a841c95658d4a9c75232f0913ca7141), read 2026-10-15. This release is the digest-check package. Admission policy and budget tasks retain their own source pins.

<a id="aps-refund-retries"></a>

## Probity APS refund example

Profile ID: `aps-refund-retries`. Component ID: `observer`.

Runs a local APS refund example that ties retries to approved actions and retains records for a separate reader.

Prototype. [Reviewed guide and source](https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/observer/docs/APS-REFUND-RETRIES.md)

<a id="artifact-digest-check"></a>

## Probity artifact digest check

Profile ID: `artifact-digest-check`. Component ID: `admission`.

Checks an artifact against digests named by a TEA document, CycloneDX SBOM or VEX, or in-toto statement.

Released. [Reviewed guide and source](https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/packages/admission/python/README.md)

<div>

<p class="distribution-title">

agent-evidence-admission / recorded package release 0.1.0
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/packages/admission/python/README.md#install">Install</a> <a href="https://pypi.org/project/agent-evidence-admission/0.1.0/#files">Download release files</a> <a href="https://pypi.org/project/agent-evidence-admission/0.1.0/">Registry release</a> <a href="https://pepy.tech/projects/agent-evidence-admission">Download statistics</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://pypi.org/project/agent-evidence-admission/"><img src="https://img.shields.io/pypi/v/agent-evidence-admission?label=PyPI" alt="Current pypi version of agent-evidence-admission" height="20" /></a> <a href="https://pepy.tech/projects/agent-evidence-admission"><img src="https://img.shields.io/pepy/dt/agent-evidence-admission?label=PyPI%20%2B%20mirrors" alt="Download statistics for agent-evidence-admission" height="20" /></a>
</p>

</div>

<a id="atlas"></a>

## Agent Evidence Conformance Board

Component ID: `atlas`.

Provides task-based project navigation, agent assurance documentation and an Open Evidence Lab run register.

Draft. [Reviewed guide and source](https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/site/README.md)

<a id="checkout-runner"></a>

## Checkout composition reference

Component ID: `checkout-runner`.

Runs a bounded synthetic checkout and refund composition as a CLI or Action, with separate decisions, attempts, effects and observations for offline replay.

Released. [Reviewed guide and source](https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/examples/checkout-runner/README.md)

Composition CLI and Action: source tag [0.2.0](https://github.com/probityai/agent-checkout-runner/tree/v0.2.0), source [`297b5b182bb4`](https://github.com/probityai/agent-checkout-runner/tree/297b5b182bb40605b62586eccbf93a9c68a4aee1), read 2026-10-15. A bounded synthetic composition reference. The source tag pins the CLI and Action, not a registry release or a merchant deployment.

<div>

<p class="distribution-title">

Composition CLI and Action
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/examples/checkout-runner/README.md#install">Install</a> <a href="https://github.com/probityai/agent-checkout-runner/blob/297b5b182bb40605b62586eccbf93a9c68a4aee1/README.md#run-it-in-your-own-ci">Use pinned Action</a> <a href="https://github.com/probityai/agent-checkout-runner/actions/workflows/ci.yml">Workflow runs</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://github.com/probityai/agent-checkout-runner/actions/workflows/ci.yml"><img src="https://github.com/probityai/agent-checkout-runner/actions/workflows/ci.yml/badge.svg" alt="Checkout runner run workflow status" height="20" /></a>
</p>

</div>

<a id="dsse"></a>

## dsse

Component ID: `dsse`.

Signs and verifies DSSE envelopes with explicit threshold and key handling.

Released. [Reviewed guide and source](https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/crates/dsse/README.md)

Rust crate: registry release [0.1.3](https://crates.io/crates/dsse/0.1.3), source [`5f1e4b5ffd61`](https://github.com/probityai/dsse/tree/5f1e4b5ffd61b6bae0f69b43766c493370004d29), read 2026-10-15. Signature verification checks bytes under caller-selected keys, not the truth of the payload.

<div>

<p class="distribution-title">

dsse / recorded package release 0.1.3
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/crates/dsse/README.md#quick-start">Install</a> <a href="https://crates.io/api/v1/crates/dsse/0.1.3/download">Download release files</a> <a href="https://crates.io/crates/dsse/0.1.3">Registry release</a> <a href="https://crates.io/crates/dsse">Download statistics</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://crates.io/crates/dsse"><img src="https://img.shields.io/crates/v/dsse?label=crates.io" alt="Current crates version of dsse" height="20" /></a> <a href="https://crates.io/crates/dsse"><img src="https://img.shields.io/crates/d/dsse?label=crate%20downloads" alt="Download statistics for dsse" height="20" /></a>
</p>

</div>

<a id="inspect-native-reader"></a>

## Probity native Inspect reader

Profile ID: `inspect-native-reader`. Component ID: `observer`.

Reads selected retained Inspect execution profiles offline, preserving errors and unstarted attempts. Inspect accepted the catalog entry, and the live Inspect extensions catalog lists it as of October 14, 2026.

Prototype. [Reviewed guide and source](https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/observer/docs/NATIVE-CONSUMER-CI.md)

<a id="jcs-admit"></a>

## jcs-admit

Component ID: `jcs-admit`.

Checks raw JSON input before producing its RFC 8785 canonical form.

Released. [Reviewed guide and source](https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/crates/jcs-admit/README.md)

Rust crate: registry release [0.1.2](https://crates.io/crates/jcs-admit/0.1.2), source [`d7e65f04bf13`](https://github.com/probityai/jcs-admit/tree/d7e65f04bf13873e6579a91aa111234866020389), read 2026-10-15. Canonicalization and raw-input admission are separate from envelope verification.

<div>

<p class="distribution-title">

jcs-admit / recorded package release 0.1.2
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/crates/jcs-admit/README.md#quick-start">Install</a> <a href="https://crates.io/api/v1/crates/jcs-admit/0.1.2/download">Download release files</a> <a href="https://crates.io/crates/jcs-admit/0.1.2">Registry release</a> <a href="https://crates.io/crates/jcs-admit">Download statistics</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://crates.io/crates/jcs-admit"><img src="https://img.shields.io/crates/v/jcs-admit?label=crates.io" alt="Current crates version of jcs-admit" height="20" /></a> <a href="https://crates.io/crates/jcs-admit"><img src="https://img.shields.io/crates/d/jcs-admit?label=crate%20downloads" alt="Download statistics for jcs-admit" height="20" /></a>
</p>

</div>

<a id="mintid-trace-records-v2"></a>

## Probity MintID trace reader

Profile ID: `mintid-trace-records-v2`. Component ID: `jcs-admit`.

Reads published MintID trace records after raw JSON admission and checks source-bound evidence and actor attribution.

Prototype. [Reviewed guide and source](https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/crates/jcs-admit/interop/mintid-trace-records-v2/README.md)

<a id="observer"></a>

## Probity Observer

Component ID: `observer`.

Records brokered file actions with signed packets and history, and reads selected native delegation evidence offline.

Prototype. [Reviewed guide and source](https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/observer/README.md)

Python package: registry release [0.0.1](https://pypi.org/project/agent-evidence-observer/0.0.1/), source [`c12869620f18`](https://github.com/probityai/agent-evidence-observer/tree/c12869620f1834ce566cd924ba95918c4dde52ce), read 2026-10-15. Root package release; separate integration profile wheels and source readers keep their own installation paths. The reviewed quick start remains a pinned source recipe.

<div>

<p class="distribution-title">

agent-evidence-observer / recorded package release 0.0.1
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/observer/README.md#quick-start">Install</a> <a href="https://pypi.org/project/agent-evidence-observer/0.0.1/#files">Download release files</a> <a href="https://pypi.org/project/agent-evidence-observer/0.0.1/">Registry release</a> <a href="https://pepy.tech/projects/agent-evidence-observer">Download statistics</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://pypi.org/project/agent-evidence-observer/"><img src="https://img.shields.io/pypi/v/agent-evidence-observer?label=PyPI" alt="Current pypi version of agent-evidence-observer" height="20" /></a> <a href="https://pepy.tech/projects/agent-evidence-observer"><img src="https://img.shields.io/pepy/dt/agent-evidence-observer?label=PyPI%20%2B%20mirrors" alt="Download statistics for agent-evidence-observer" height="20" /></a>
</p>

</div>

<a id="ratchet"></a>

## Probity Ratchet

Component ID: `ratchet`.

Provides a source-tagged agent guard harness, signed admission records and public regression cases.

Released. [Reviewed guide and source](https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/ratchet/README.md)

Harness source: source tag [0.1.2](https://github.com/probityai/probity/tree/probity-ratchet-v0.1.2), source [`e2daf77f75e9`](https://github.com/probityai/probity/tree/e2daf77f75e92aa961cf184084335b67aaae7581), read 2026-10-15. Annotated harness tag, peeled to its source commit. It is separate from the public case package.

<div>

<p class="distribution-title">

Harness source
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/ratchet/README.md#install">Install</a>
</p>

</div>

Public case suite: published release [0.2.0](https://github.com/probityai/probity/releases/tag/probity-ratchet-cases-v0.2.0), source [`b6504260db8a`](https://github.com/probityai/probity/tree/b6504260db8af7d3746e9ac87740430dd988e8d9), read 2026-10-15. The case package has its own release. All shipped splits are public.

<a id="ratchet-cases"></a>

## Probity Ratchet public cases

Profile ID: `ratchet-cases`. Component ID: `ratchet`.

Grades agent tasks in a simulated company on final state, with declared tool faults, traps and benign cases. All shipped splits are public.

Released. [Reviewed guide and source](https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/ratchet/probity-ratchet-cases/README.md)

<div>

<p class="distribution-title">

probity-ratchet-cases / recorded package release 0.2.0
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/ratchet/probity-ratchet-cases/README.md#install">Install</a> <a href="https://pypi.org/project/probity-ratchet-cases/0.2.0/#files">Download release files</a> <a href="https://pypi.org/project/probity-ratchet-cases/0.2.0/">Registry release</a> <a href="https://pepy.tech/projects/probity-ratchet-cases">Download statistics</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://pypi.org/project/probity-ratchet-cases/"><img src="https://img.shields.io/pypi/v/probity-ratchet-cases?label=PyPI" alt="Current pypi version of probity-ratchet-cases" height="20" /></a> <a href="https://pepy.tech/projects/probity-ratchet-cases"><img src="https://img.shields.io/pepy/dt/probity-ratchet-cases?label=PyPI%20%2B%20mirrors" alt="Download statistics for probity-ratchet-cases" height="20" /></a>
</p>

</div>

<a id="vectors"></a>

## Agent Evidence Vectors

Component ID: `vectors`.

Provides conformance cases and reference verifiers for selected agent evidence formats.

Released. [Reviewed guide and source](https://github.com/probityai/agent-evidence-vectors/blob/9e596fbff7bb29809d38319aebb56f2141923eb2/README.md)

Go verifier and Python harness: published release [0.18.1](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.18.1), source [`33d545104ff2`](https://github.com/probityai/agent-evidence-vectors/tree/33d545104ff2f8c124cff465c96c013eeb809156), read 2026-10-15. The reviewed guide also carries a 0.18.0 install recipe. Select the version required by your result.

<div>

<p class="distribution-title">

agent-evidence-vectors / recorded package release 0.18.1
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/agent-evidence-vectors/blob/9e596fbff7bb29809d38319aebb56f2141923eb2/README.md#try-it">Install</a> <a href="https://pypi.org/project/agent-evidence-vectors/0.18.1/#files">Download release files</a> <a href="https://pypi.org/project/agent-evidence-vectors/0.18.1/">Registry release</a> <a href="https://pepy.tech/projects/agent-evidence-vectors">Download statistics</a> <a href="https://github.com/probityai/agent-evidence-vectors/blob/9e596fbff7bb29809d38319aebb56f2141923eb2/docs/guides/runner.md#run-the-suite-in-ci">Use pinned Action</a> <a href="https://github.com/probityai/agent-evidence-vectors/actions/workflows/ci.yml">Workflow runs</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://pypi.org/project/agent-evidence-vectors/"><img src="https://img.shields.io/pypi/v/agent-evidence-vectors?label=PyPI" alt="Current pypi version of agent-evidence-vectors" height="20" /></a> <a href="https://pepy.tech/projects/agent-evidence-vectors"><img src="https://img.shields.io/pepy/dt/agent-evidence-vectors?label=PyPI%20%2B%20mirrors" alt="Download statistics for agent-evidence-vectors" height="20" /></a> <a href="https://github.com/probityai/agent-evidence-vectors/actions/workflows/ci.yml"><img src="https://github.com/probityai/agent-evidence-vectors/actions/workflows/ci.yml/badge.svg" alt="Vectors ci workflow status" height="20" /></a>
</p>

</div>

<a id="verify"></a>

## Probity Verify

Component ID: `verify`.

Checks supplied evidence bytes through claim-specific offline adapters. Its README links to source-pinned installation and checked task recipes.

Released. [Reviewed guide and source](https://github.com/probityai/probity/blob/08a27efd567a754ce72a4c789e23f28924f49754/packages/probity-verify/README.md)

Python package: registry release [0.1.1](https://pypi.org/project/probity-verify/0.1.1/), source [`db28cc76e5f5`](https://github.com/probityai/probity/tree/db28cc76e5f5aa6932d5122d9c6241ef7adb7fee), read 2026-10-15. The released wheel adds packaged sample inputs. The reviewed guide deliberately retains its earlier source recipe; historical 0.1.0 builder provenance remains separate.

<div>

<p class="distribution-title">

probity-verify / recorded package release 0.1.1
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/probity/blob/08a27efd567a754ce72a4c789e23f28924f49754/packages/probity-verify/README.md#quick-start">Install</a> <a href="https://pypi.org/project/probity-verify/0.1.1/#files">Download release files</a> <a href="https://pypi.org/project/probity-verify/0.1.1/">Registry release</a> <a href="https://pepy.tech/projects/probity-verify">Download statistics</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://pypi.org/project/probity-verify/"><img src="https://img.shields.io/pypi/v/probity-verify?label=PyPI" alt="Current pypi version of probity-verify" height="20" /></a> <a href="https://pepy.tech/projects/probity-verify"><img src="https://img.shields.io/pepy/dt/probity-verify?label=PyPI%20%2B%20mirrors" alt="Download statistics for probity-verify" height="20" /></a>
</p>

</div>

<a id="vocabulary"></a>

## Probity Vocabulary

Component ID: `vocabulary`.

Defines versioned terms and crosswalks for claims about agent execution.

Released. [Reviewed guide and source](https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/packages/vocabulary/README.md)

Python package: registry release [0.4.0](https://pypi.org/project/agent-evidence-vocabulary/0.4.0/), source [`59c93ac4529c`](https://github.com/probityai/agent-evidence-vocabulary/tree/59c93ac4529c1e8fdf6e7cdfff7a950740c873f3), read 2026-10-15. Python package carries the released registry and crosswalk data. The reviewed quick start still reads the independently tagged v0.4.0 raw registry.

<div>

<p class="distribution-title">

agent-evidence-vocabulary / recorded package release 0.4.0
</p>

<p class="distribution-actions">

<a href="https://github.com/probityai/agent-evidence/blob/44066a188c1b080b7c9bd5a73f6626c229baaa14/packages/vocabulary/README.md#quick-start">Install</a> <a href="https://pypi.org/project/agent-evidence-vocabulary/0.4.0/#files">Download release files</a> <a href="https://pypi.org/project/agent-evidence-vocabulary/0.4.0/">Registry release</a> <a href="https://pepy.tech/projects/agent-evidence-vocabulary">Download statistics</a>
</p>

<p class="distribution-badges">

Live registry and named workflow reports:<br /> <a href="https://pypi.org/project/agent-evidence-vocabulary/"><img src="https://img.shields.io/pypi/v/agent-evidence-vocabulary?label=PyPI" alt="Current pypi version of agent-evidence-vocabulary" height="20" /></a> <a href="https://pepy.tech/projects/agent-evidence-vocabulary"><img src="https://img.shields.io/pepy/dt/agent-evidence-vocabulary?label=PyPI%20%2B%20mirrors" alt="Download statistics for agent-evidence-vocabulary" height="20" /></a>
</p>

</div>

Vocabulary registry: published release [v0.4.0](https://github.com/probityai/agent-evidence-vocabulary/releases/tag/v0.4.0), source [`220a4f0a08b9`](https://github.com/probityai/agent-evidence-vocabulary/tree/220a4f0a08b90a555a430bb7d4334eb2617d05ba), read 2026-10-15. Terms and crosswalks are versioned independently of executable packages.

<a id="witnessed-run-selection"></a>

## Probity witnessed run selection

Profile ID: `witnessed-run-selection`. Component ID: `observer`.

Checks a supplied run against consumer-retained witness anchors, plan and control pins, and execution closure.

Prototype. [Reviewed guide and source](https://github.com/probityai/probity/blob/e2164379c19cf17a00356dfbdf625a998272ac58/packages/observer/docs/WITNESSED-RUN-SELECTION.md)

<a id="run-and-share-a-check"></a>

## Run and share a check

The [Open Evidence Lab](lab.md) holds replayable runs and accepts new results and corrections. For scripted lookups, use the [automation guide](automation.md).

For a combined CLI and Action example, use the [checkout composition reference](experiments.md#checkout-composition). It keeps decisions, attempts, effects and observations separate in a replayable synthetic bundle.

[HTML view](start.html) | [Agent guide](llms.txt)
