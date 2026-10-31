# The agent-evidence Action

The root `action.yml` runs this repository's admission checks in a workflow. Pin it to a release tag or, better, to the commit that tag names:

```yaml
- uses: probityai/agent-evidence@action-v0.1.0
  with:
    check: policy
    statement: evidence/run.statement.json
    pins: evidence/pins.json
```

A release of the Action is one fixed set of bytes. It pins every tool it installs by version and SHA-256 in [actions/admission/pins.json](../actions/admission/pins.json): the `agent-evidence-admission` wheel from PyPI and OPA from its GitHub release. The rules are the files under [packages/admission/rego](../packages/admission/rego) at the tagged commit. It runs on Linux and macOS runners, x64 and arm64; the checks below call it on all four.

## `check: policy`

Evaluates each statement against one admission rule set with OPA, in one call.

| input | meaning |
| --- | --- |
| `statement` | the statement paths, one per line |
| `rules` | `execution-evidence` (default), `agent-change-admission` or `verifier-isolation` |
| `pins` | a JSON data document holding your consumer pins |

The pins document carries the data key each rule set reads: `consumer` for `execution-evidence`, `change_admission_consumer` for `agent-change-admission`, `verifier_isolation_consumer` for `verifier-isolation`. [Consumer policy](../packages/admission/docs/CONSUMER-POLICY.md) lists the pins and what an absent value means. Without pins the rules refuse every statement that depends on one, so a workflow that has pinned nothing admits nothing.

The rules evaluate a statement whose envelope signature something else has already verified; they do not verify signatures. `agent-change-admission` and `verifier-isolation` say so by refusing until the pins declare `signature_verified_upstream: true`.

To admit the sample statement this repository ships:

```yaml
- uses: actions/checkout@v7
  with:
    repository: probityai/agent-evidence
    ref: action-v0.1.0
    path: agent-evidence
- run: |
    cat > pins.json <<'JSON'
    {"consumer": {
      "expected_corpus_digest": "cc1bdef2ffca96d86a636e5a9fb27a4a111836773e0dd1368d8de94f413979be",
      "expected_substrate_digest": "018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb",
      "demanded_classes": ["XA"]}}
    JSON
- uses: probityai/agent-evidence@action-v0.1.0
  with:
    check: policy
    statement: agent-evidence/packages/admission/samples/adversarial-execution-evidence.pass.statement.json
    pins: pins.json
```

## `check: digest`

Runs `agent-evidence-admission digest-check` once per artifact: each artifact must have a digest the document names.

| input | meaning |
| --- | --- |
| `document` | the in-toto statement, CycloneDX SBOM or TEA artifact that names the digests |
| `artifacts` | the artifact paths, one per line |

```yaml
- uses: probityai/agent-evidence@action-v0.1.0
  with:
    check: digest
    document: dist/provenance.statement.json
    artifacts: |
      dist/app.tar.gz
      dist/app.sbom.json
```

A match binds the document to the bytes. It does not verify a signature.

## Results

The step fails when any subject is refused, and writes a table of each subject, its decision and the reasons to the job summary. Two outputs carry the same answer for later steps: `result` is `admitted` or `refused`, and `refusals` is the count. A missing file, an unknown rule set or a tool that does not run fails the step as an error, never as a refusal. When a rule set refuses a statement without naming a reason, the Action says so in the reasons column instead of leaving it empty.

## Checks and releases

[.github/workflows/actions-admission.yml](../.github/workflows/actions-admission.yml) runs the Action's logic against every vector this repository holds for the three rule sets, then calls the Action as `uses: ./` on each pinned runner. A release tag is `action-v<version>`, the version in [actions/VERSION](../actions/VERSION); the release workflow re-runs those checks on the tagged commit. When a new `agent-evidence-admission` or OPA version is pinned, the tests fail until `pins.json` matches it, and the change ships as a new Action release.

## `check: coverage`

Checks that a CycloneDX BOM or SPDX 3 document accounts for every class a buyer requires. Each required class comes back `ASSESSED`, `INCOMPLETE`, `NOT-ASSESSED` (with the reason `unknown` or `withheld`), `COVERED-ELSEWHERE` (a CycloneDX BOM-Link or an SPDX import), or one of the refusals `MISSING`, `DOUBLE` (two entries select the class) and `NO-REASON` (not assessed, with neither a reason nor a covering reference). It reads the formats as published (CycloneDX 1.6 compositions, SPDX 3.0.1 relationship completeness) and the fields proposed in [CycloneDX/specification#1159](https://github.com/CycloneDX/specification/issues/1159) and [spdx/spdx-3-model#1105](https://github.com/spdx/spdx-3-model/issues/1105) when they are present. It needs no pinned tool: it runs from the tagged commit's own source.

| input | meaning |
| --- | --- |
| `document` | the CycloneDX JSON BOM or SPDX 3 JSON-LD document |
| `required` | a file listing the required classes: a JSON array, or an object with `required`, `cyclonedx` and `spdx` lists |

```yaml
- uses: probityai/agent-evidence@action-v0.1.0
  with:
    check: coverage
    document: sbom.cdx.json
    required: tender/required-classes.json
```

The same check runs as a command, `agent-evidence-admission coverage-check sbom.cdx.json --required tender/required-classes.json`, and its [positive and negative vectors](../packages/admission/python/vectors/coverage/manifest.json) are the conformance cases for it.
