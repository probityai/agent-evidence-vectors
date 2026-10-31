# The rails against the automated governance maturity model

The CNCF Automated Governance Maturity Model gives an organization 65 checkboxes in four
categories, Policy, Evaluation, Enforcement and Audit, and grades it by the share it can
check. It scores an organization, never a tool. This page answers the question an
organization adopting these rails asks of it: which boxes do the rails in this repository
help you check, with which file, and which do they leave to you.

Source: `cncf/tag-security` at commit 5fb87f474808e02e7786d7c5548e65ffc1a6e29e, file
[community/resources/automated-governance-maturity-model/README.md](https://github.com/cncf/tag-security/blob/5fb87f474808e02e7786d7c5548e65ffc1a6e29e/community/resources/automated-governance-maturity-model/README.md).
The file last changed at commit f448c613447e030b264d82ebd2ebda73d2bca59b, and the
repository is archived.

Every item below is quoted from that file exactly, with two mechanical changes so this page
stays plain ASCII: the right single quotation mark is written as an apostrophe, and an item
the source wraps across two lines is joined with one space, which is how it renders. The
source's own spelling is kept, so two items read "consistency" and "demonstration" where
"consistently" and "demonstrate" are meant. Item V16 sits in a code span because it carries
an abbreviation the style gate of this repository refuses in prose written here, and the
code span marks it as quoted.

## How to read this page

Each item carries one of three marks.

- **served**: a file in this repository implements what the item describes, for the
  admission decision these rails make. The file is named.
- **partly served**: a file here does part of it, and the row says which part is left to
  the deployment.
- **not served**: nothing in this repository does it. An organization checks that box with
  something else or not at all.

`scripts/maturity-map-gate.py` holds this page to the repository and to the model. It fails
when a file or an identifier the page cites does not exist, when the counts below disagree
with the rows, and, given the model file, when any quoted item differs from the source or
any item of the source is missing here. Continuous integration fetches the model at the
commit above, checks its SHA-256, and runs the gate against it on every push.

| category | items | served | partly served | not served |
|---|---|---|---|---|
| Policy | 21 | 5 | 3 | 13 |
| Evaluation | 17 | 5 | 5 | 7 |
| Enforcement | 11 | 1 | 5 | 5 |
| Audit | 16 | 1 | 2 | 13 |
| all | 65 | 12 | 15 | 38 |

## The rails as policy enforcement points

The model's Enforcement category is written around the Policy Enforcement Point. Each rail
here is one: a policy document an admission controller loads, which admits or refuses a
Kubernetes Pod at creation on the adversarial-execution-evidence attestation its image
carries. The measured map for each rail says, per obligation, what the rail enforces.

| rail | enforcement point | document | response | measured map |
|---|---|---|---|---|
| Rego | sigstore policy-controller, or `opa eval` in a pipeline | `rego/execution_evidence.rego`, embedded verbatim in `policy-controller/clusterimagepolicy-adversarial-execution-evidence-soundness.yaml` by `policy-controller/gen_soundness_cip.py` | reject, or warn with `mode: warn` | `profiles/rego/PROFILE-MAP.json` |
| Kyverno JMESPath | Kyverno admission webhook | `kyverno/clusterpolicy-adversarial-execution-evidence.yaml`, with an audit sibling `kyverno/clusterpolicy-adversarial-execution-evidence-audit.yaml` and a freshness sibling `kyverno/clusterpolicy-adversarial-execution-evidence-freshness.yaml` | Enforce, or Audit with a PolicyReport entry | `profiles/kyverno-jmespath/PROFILE-MAP.json` |
| Kyverno CEL | Kyverno admission webhook | `kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml` | Deny, naming the failed validation | `profiles/kyverno-cel/PROFILE-MAP.json` |
| CUE | sigstore policy-controller | `policy-controller/clusterimagepolicy-adversarial-execution-evidence-cue.yaml` | reject, or warn | `profiles/cue/PROFILE-MAP.json` |

A fifth document, `policy-controller/clusterimagepolicy-adversarial-execution-evidence.yaml`,
is a shallow Rego policy for the same controller. It carries no measured map, so no row
below leans on it.

## Enforcement

All eleven items, each with a row.

| id | the model's text | mark | what serves it |
|---|---|---|---|
| E1 | "Policy Enforcement Points are distributed and appropriately placed to augment their respective workloads" | served | Each rail is an enforcement point inside the cluster that runs the workload, bound to Pod `CREATE` and `UPDATE` and to the image references it governs: `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::imageReferences`, `kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml::matchImageReferences`, `policy-controller/clusterimagepolicy-adversarial-execution-evidence-cue.yaml::mode: enforce`. Two admission controllers and four policy languages carry the same decision, so a cluster places the one it already runs. |
| E2 | "Controls are regularly evaluated for their ROI and reduced/removed if they add unnecessary complexity or overhead" | not served | Nothing here measures return on investment. |
| E3 | "Administrative and Technical controls work in harmony with each other" | partly served | The administrative decisions, which corpus and substrate a deployment trusts, which attack classes a run must have assessed, which results it admits and how old evidence may be, are a data document the technical control reads: `docs/CONSUMER-POLICY.md`, `rego/execution_evidence.rego::data.consumer`. An unpinned deployment is denied, and running unpinned is a declared act: `rego/execution_evidence.rego::allow_unpinned_anchors`. Who signs off on those values is left to the deployment. |
| E4 | "Systems or components are automatically taken out of commission if they are non-compliant for a period exceeding their compliance SLA" | not served | The rails decide at admission and never re-evaluate a running Pod: `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::background: false`. The freshness sibling refuses a new admission on evidence older than its window, `kyverno/clusterpolicy-adversarial-execution-evidence-freshness.yaml::168h`, and that stops no running workload. |
| E5 | "Policy enforcement supports the use of SLAs and SLOs for the recipients of any discrepancies as a part of automated response and notification policies" | not served | Nothing here notifies anyone. |
| E6 | "Policy enforcement is applied consistency across all environments (development, staging, production)" | partly served | One decision, four engines, measured against one oracle over one pinned corpus: `conformance/run_policy_conformance.py`. The three Kyverno documents are held to one condition set, `conformance/run_policy_conformance.py::_check_condition_parity`, and no rail may claim an obligation it fails a vector of: `scripts/profile-map-gate.py`. That is consistency across engines. Applying the same documents in every environment is the deployment's step. |
| E7 | "Enforcement responses are differentiated based on the type and severity of a violation" | partly served | The response is chosen per document: Enforce or Audit on the JMESPath rail, `kyverno/clusterpolicy-adversarial-execution-evidence-audit.yaml::failureAction: Audit`; reject or warn on policy-controller, `policy-controller/clusterimagepolicy-adversarial-execution-evidence-soundness.yaml::mode: warn`. The CEL rail's denial names the validation that failed, `kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml::message:`. No rail grades a violation by severity: under Enforce, every failed obligation is a denial. |
| E8 | "Policy Enforcement Points support self-healing or automated remediation/deploying compensating controls automatically" | not served | No rail remediates. The one mutation any rail makes rewrites an image reference to its digest form, `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::mutateDigest: true`, which pins what was checked and repairs nothing. |
| E9 | "Policy Enforcement logs are captured in an immutable log" | not served | The audit sibling writes a PolicyReport entry, which is a mutable Kubernetes resource. Nothing here writes to an append-only log. |
| E10 | "Policy Enforcement metrics are gathered and available for trending and analysis" | partly served | The audit sibling exists to measure how much of a fleet would be blocked before enforcing, one PolicyReport entry per Pod: `kyverno/clusterpolicy-adversarial-execution-evidence-audit.yaml::PolicyReport`. Collecting and trending those entries is the deployment's monitoring. |
| E11 | "Exceptions to Enforcement activities can be overridden only via a structured and codified exception process with a time-based expiration or renewal process enforced in code, appropriate sign-off, and organizational notification/awareness" | partly served | Three codified exception paths. A deployment declines a pin only through a named knob that excuses an absent value and never a mismatched one: `rego/execution_evidence.rego::allow_unpinned_scope`. An advisory held against a pinned engine carries a reason and an expiry, and the build fails once the expiry passes: `ENGINE-ADVISORIES.toml`, `scripts/engine-advisory-gate.py::expires`. A rail's declared divergence from the oracle is asserted for exact equality, so an exception that no longer reproduces fails the build: `conformance/run_policy_conformance.py::Declared divergence from the rego oracle`. The consumer knobs carry no expiry, and sign-off and notification are left to the deployment. |

## Evaluation

The model defines an evaluation as the check of one service against the assessment
requirements that apply to it. For these rails the service is the Pod and the requirements
are the obligations of the predicate, vendored as `registry/conditions.json`.

| id | the model's text | mark | what serves it |
|---|---|---|---|
| V1 | "Clear assessment requirements are defined based on technology-specific controls" | served | Each obligation the corpus cites is registered by id, `registry/conditions.json`, and each rail's disposition on it is measured and rendered: `PROFILE-REGISTRY.md`. |
| V2 | "Assessment requirements contain both configuration and behavioral elements" | served | Configuration: the statement must bind the catch policy and the network posture by digest, `rego/execution_evidence.rego::catchPolicy`. Behavior: every attack row records what was observed when the attack ran, and the result is recomputed from those rows, `rego/execution_evidence.rego::containmentObserved`. |
| V3 | "Services are automatically evaluated based on policy-driven assessment requirements prior to deployment approval" | served | This is the admission decision every rail makes: a Pod is admitted only after its image's evidence passes the rail. `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::failureAction: Enforce`. |
| V4 | "Policy conflicts are automatically detected and resolved within a reasonable time period" | partly served | A rail answering differently from the oracle without a declared reason fails the build, `conformance/run_policy_conformance.py`, and so does a Kyverno document whose conditions drift from its siblings, `conformance/run_policy_conformance.py::_check_condition_parity`. Resolving a conflict is a commit a person makes. |
| V8 | "Evaluation tooling integrates with pipelines" | served | The Rego rail runs as a pipeline step with the consumer data document, `docs/CONSUMER-POLICY.md::opa eval`, and this repository's own pipeline runs every rail over every vector: `../../.github/workflows/package-admission.yml`. |
| V13 | "It is always possible to identify whether the Evaluation of Policies is expected to be, or was manual vs automated" | partly served | For each obligation and each rail the map says enforced, approximated, or unreachable, so an obligation a rail cannot reach is named as one some other check has to cover: `profiles/rule-index.json`, `scripts/gen_profile_map.py`. |
| V14 | "Automated evaluation tools automatically ingest policies to determine applicability of assessment requirements" | partly served | The Rego rail reads the deployment's demanded classes from its data document to decide which attack classes a run must have assessed: `rego/execution_evidence.rego::demanded_classes`. The Kyverno and CUE rails take those values as literals edited into the document. |
| V15 | "Policy exceptions are tracked, reviewed, and risk-assessed on a periodic basis" | partly served | An advisory held against a pinned engine is re-read by its expiry date or the build fails: `ENGINE-ADVISORIES.toml`. The consumer opt-out knobs carry no review date. |
| V16 | "`Policy evaluation is performed within their defined SLAs and SLOs (i.e. the evaluation itself occurs within a given period/cadence)`" | partly served | Each Kyverno evaluation is bounded, and fails closed when the bound is hit: `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::webhookTimeoutSeconds: 30`, `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::failurePolicy: Fail`. There is no cadence, because the rails evaluate at admission only. |
| V17 | "Evaluations are improved over time using the scientific method, and not solely based on opinions" | served | Every disposition is measured by running the rail over the corpus, never typed: `scripts/gen_profile_map.py`. A rail that claims an obligation it fails a vector of is refused: `scripts/profile-map-gate.py`. Open adversarial findings against the rails are published with the ledger digest they came from: `docs/ADVERSARIAL-RATCHET.md`. |

Not served, quoted in full:

```text
V5   Evaluation results are versioned and accessible for historical analysis
V6   Evaluations include context regarding known threats and risks to prioritize policy violations
V7   Running services are automatically evaluated based on policy-driven assessment requirements no less frequently than daily
V9   Evaluation tooling integrates with IDEs
V10  Evaluation tooling integrates with ticketing systems
V11  Evaluation tooling integrates with meeting transcripts to provide feedback while ideas are still being discussed
V12  Evaluations are distinguished between short-term, temporary deviations and long-term deviations
```

## Policy

| id | the model's text | mark | what serves it |
|---|---|---|---|
| P8 | "Policies are informed by previous work (external or internal)" | served | Every policy file records where it came from, at which commit, with the SHA-256 of the source bytes: `PROVENANCE.md`. The obligations are the published predicate's, vendored with the corpus digest they were read at: `registry/conditions.json`. |
| P9 | "Policies are automatically distributed to relevant tooling across the organization, such as policy engines or assessment tools." | partly served | The Rego module is generated into the deployed policy-controller document, and the build refuses a copy that has drifted: `policy-controller/gen_soundness_cip.py`. The Kyverno and CUE documents are separate files held to the oracle by the conformance harness. Getting the documents into a cluster is the deployment's delivery pipeline. |
| P12 | "Policies include threat-informed controls for technology used by the business unit" | served | The rails admit a workload only on evidence of the attacks run against it, class by class, recomputed from the rows: `rego/execution_evidence.rego::assessedClasses`. The attack classes come from a published adversarial corpus pinned by package version, wheel hash and corpus digest: `../../.github/workflows/package-admission.yml::VECTORS_CORPUS_DIGEST`. |
| P14 | "Policies are updated based on changes in the threat landscape" | partly served | A new corpus release brings new attack vectors, and moving the pin re-runs every rail over them before the maps can be committed: `requirements-vectors.txt`, `../../.github/workflows/package-admission.yml::VECTORS_CORPUS_DIGEST`, `scripts/gen_profile_map.py`. Dependabot proposes each release as a pull request; deciding when to merge it is a person's call. |
| P15 | "Policies are updated based on changes in the business unit's risk appetite" | partly served | Risk appetite on the Rego rail is data, not code: the results a deployment admits and the age it tolerates are values in its data document, `docs/CONSUMER-POLICY.md`, `rego/execution_evidence.rego::max_evidence_age_hours`. On the other rails the same change is an edit to a literal. |
| P16 | "Policies are extensible or reusable for activities that have similar technology and risk profiles" | served | One policy serves every deployment, and what differs between them lives in the consumer data document: `docs/CONSUMER-POLICY.md`. |
| P17 | "Policies can be automatically ingested by evaluation tooling to inform enforcement and audit activities" | served | Each document is the engine's own format and is loaded by it as written: `kyverno/clusterpolicy-adversarial-execution-evidence.yaml`, `kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml`, `policy-controller/clusterimagepolicy-adversarial-execution-evidence-cue.yaml`, `rego/execution_evidence.rego`. The audit sibling feeds the same decision into audit reporting: `kyverno/clusterpolicy-adversarial-execution-evidence-audit.yaml`. |
| P18 | "Policies have scopes which are clearly defined and able to be automatically identified, given an asset" | served | Each document states its scope in the engine's match syntax, so given a Pod the engine decides whether the policy applies: `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::kinds:`, `kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml::matchConstraints`. |

Not served, quoted in full:

```text
P1   Decision making feedback-loops operate in cycles of less than two business-days
P2   A standard process is used to determine which standards, frameworks, regulations, and control catalogs are applicable for different business activities.
P3   Continuous improvement and proactive innovation is driven by a culture of experimentation and feedback
P4   Decision making is organized and accessible
P5   Decision making is data-driven; data points are understandable and usable to answer real-world questions
P6   Policies are consistently created and maintained using internal and external sources
P7   Policies are understandable, and do not contain superfluous information
P10  Policies are created based on rules or regulations applicable to the business unit's activities
P11  Policies are created based on risks defined by the business unit
P13  Policies are updated based on changes in the technical landscape
P19  Policies generate data which is evaluated and monitored against SLA and SLO thresholds
P20  Each Policy has exactly one owner, regardless of the number of responsible parties are involved with managing the Policy
P21  Roles are able to quickly identify their responsibilities for any and all Policies which fall into an individual's scope of work
```

## Audit

| id | the model's text | mark | what serves it |
|---|---|---|---|
| A4 | "Decisions and decision-making approaches are well documented and easy to understand" | partly served | The admission decision is documented where it is made: each knob and what its absence means, `docs/CONSUMER-POLICY.md`; each rule of the oracle, in its header, `rego/execution_evidence.rego`; each rail's per-obligation disposition, `PROFILE-REGISTRY.md`. The organization's other decisions are outside this repository. |
| A10 | "Audit Artifacts are gathered automatically during Runtime / Operational activities" | partly served | The audit sibling records a PolicyReport entry for every Pod it evaluates at admission: `kyverno/clusterpolicy-adversarial-execution-evidence-audit.yaml`. Nothing is recorded after admission. |
| A14 | "New assets are automatically identified as in-scope for audits" | served | A new Pod is in scope the moment it is created, with no registration step: the JMESPath rail matches every image, `kyverno/clusterpolicy-adversarial-execution-evidence.yaml::imageReferences`, and the CEL rail every image under the glob it governs, `kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml::matchImageReferences`. |

Not served, quoted in full:

```text
A1   Evidence is able to be queried and accessed quickly
A2   Evidence is accessible to and usable by non-technical audiences
A3   Artifacts can be easily identified as in- or out- of scope for a given Audit
A5   Changes to documentation are properly approved, versioned, released, and trained with limited overhead
A6   Governance changes can be easily traced to the author(s) and approver(s) of a given statement
A7   The company can demonstration cohesion between legal decisions (such as contracts) or technical decisions (such as adopting a given technology) and business decisions
A8   Company turnover does not substantially affect the outcomes of Audits
A9   Audit Artifacts are gathered automatically during CI/CD
A11  Audit Artifacts can be enriched with supplementary or supporting information as it becomes available
A12  Audit participants quickly and easily understand their role in an audit, and have access to and ownership of the corresponding data points for their scope of responsibilities
A13  Preparation for Audits is continuous and standard
A15  When questions are asked, if the data required to answer them is not available, gathering the new details is easy and standard practice
A16  Risk decisions are able to be explicitly connected to Business Decisions such that an Auditor can be confident that the decision was not made in isolation
```

## What the marks do not claim

A mark says what this repository does for the one decision it makes: whether a Pod's
evidence admits it. It says nothing about the organization around that decision, and the
model grades the organization. The trust ceiling in `README.md` applies to every served
row: the rails evaluate a statement the engine's key authority has already verified, and
no rail verifies an observation record's own signature.
