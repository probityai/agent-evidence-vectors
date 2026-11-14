# Verified by Probity

The badge means one thing: a released conformance workflow executed the project's implementation against an identified corpus of agent-evidence-vectors, and the recorded result satisfies the corpus's published expectation. It is granted by the maintainers of this repository, never self-declared, and re-checked at every release of the corpus. A grant that no longer meets the evidence rule below blocks the release until it is fixed or withdrawn.

## What the badge claims

Four wordings exist, and only the first two carry the badge.

| Wording | What it rests on | Badge |
| --- | --- | --- |
| Applicant-originated conformance execution | The released reusable workflow ran the candidate in the applicant's own repository, and a separate trusted job signed what it measured | Yes |
| Independently replay-qualified | A registered replay environment, not controlled by the applicant, re-executed every covered member and recorded its own result | Yes |
| Recipient-attested record | A key the recipient registered signed the record | No |
| Independently witnessed assessment | A separate assessment on fresh or hidden cases | A different badge, not this one |

A public-corpus badge claims successful execution against the identified corpus and profile. It does not claim correctness beyond the covered members, resistance to an applicant's own administrators, or that an implementation could not have been written to echo the public expectations.

## Who grants it

The maintainers of this repository. A grant is one entry in [badge-grants.json](badge-grants.json), added by pull request with a link to the public thread where a maintainer of the project agrees to the listing. The entry records the project, its repository and repository id, its default branch, the basis of the grant, and the workflow provenance the grant rests on. Nobody can add a row by editing their own README.

## The evidence a badge needs

For a grant on the first basis, the receipt must show all of these:

- The job workflow reference is the registered reusable conformance workflow, pinned by a full commit SHA. A tag is rejected, including a protected tag, because present settings cannot prove a tag was never moved.
- That SHA is on the allowlist in the ledger, and the receipt was logged inside the SHA's activation interval, with no later suspension or revocation that reaches it.
- Both jobs ran on a GitHub-hosted runner, from an event the policy names. `pull_request_target`, `workflow_run` and inherited secrets are not allowed.
- The caller repository name and repository id match the registered project, the ref is the registered default branch, and the commit matches the receipt.
- Candidate execution was separated from signing. The execution job held no signing credential and ran the candidate in a locked sandbox. A second job, which ran no candidate code, authenticated the measurement bundle, recomputed every digest, derived the verdict itself, and only then requested the signing token.
- The receipt binds the candidate identity and its executable closure, the corpus, expectation and release-manifest digests, the command, the exit status, the output digest, the run identity, and the verdicts of the candidate and of the pinned reference.
- A missing, malformed or truncated output, a timeout, a crash or a closure mismatch is an execution error, never a pass.

For the replay-qualified basis, the replay environment must be registered in the ledger and its own replay record must be present. A signature from the recipient's own key alone never produces a badge: it establishes who signed, not what was executed.

## How it is re-checked

Every release of the corpus runs `scripts/badge-grants-gate.py`. It reads each active grant in the ledger and re-evaluates the recorded evidence against the current allowlist and revocation state, so a workflow SHA revoked after a grant was made fails the next release. A revocation says whether it only stops new grants, suspends later revalidation, or invalidates receipts from a stated time. The test in `scripts/badge-grants-gate-test.py` breaks each rule on a copy of a valid ledger and requires the gate to fail.

The gate re-checks the recorded claims. Verifying the receipt signature, the transparency-log entry and the measurement bundle belongs to the badge verifier that ships with the reusable workflow, and a grant is only added after that verifier accepts the receipt.

A withdrawn grant stays in the ledger with the date and the reason, and its badge comes off.

## The workflow

[conformance.yml](../.github/workflows/conformance.yml) is the reusable conformance workflow. It runs three jobs:

- `pin` reads the workflow's own commit from its OIDC token and runs nothing else.
- `execute` runs the candidate with `contents: read` only, so no OIDC token and no secret reaches it. Every call the harness makes to the candidate goes through a recording shim, which keeps each call's arguments (a file argument by its SHA-256), exit status and output in `transcript.json`. That transcript is the only thing the job hands on.
- `sign` runs no candidate code. It checks out this repository at the commit its own OIDC token names, never at an input. It fetches the transcript by the numeric artifact id, requires that artifact to belong to this run and the downloaded archive to match the digest GitHub recorded for it, and replays the transcript through the harness over the pinned corpus. A member the transcript does not answer fails. [conformance_receipt.py](../scripts/conformance_receipt.py) `sign-check` then recomputes the verdict and refuses to sign unless every pinned member was answered and conformed. Only then does `cosign sign-blob` request a certificate, whose identity is `conformance.yml` at that commit.

The receipt (`receipt.json` with `receipt.sigstore.json`) is published as the `aev-conformance-receipt` artifact. `conformance_receipt.py verify` is the badge verifier: it checks the signature, the certificate identity against the allowlist in [badge-grants.json](badge-grants.json), and every run claim in the certificate against the receipt.

[conformance-receipt-test.py](../scripts/conformance-receipt-test.py) blocks every release. It requires the signer or the verifier to refuse nine attempts: a substituted artifact, an altered case set, results injected from the execution job, a signature from any other workflow, a wrong repository or commit, a zero-count report, a stale-run replay, an unpinned profile and a wrong ref (a tag pin, a branch that is not the default, a forbidden event or a self-hosted runner). It also requires a genuine run to pass.

The two runtime corpora (`vectors-uncertain-effect`, `vectors-decision-client-failure-modes`) are not eligible: their evidence is the state of a counting endpoint, which a transcript cannot carry.

## Where it stands

The workflow ships in this release. No workflow SHA is on the allowlist until a maintainer adds the released commit, and the ledger holds no grants. [Used by](USED-BY.md) lists projects whose own CI runs or pins a corpus. That is use, not the badge.

## Get it

Call the workflow from your CI, pinned by full commit SHA, on `push` to your default branch, `schedule` or `workflow_dispatch`:

```yaml
jobs:
  conformance:
    permissions: { contents: read, actions: read, id-token: write }
    uses: probityai/agent-evidence-vectors/.github/workflows/conformance.yml@<full commit SHA>
    with:
      corpus: vectors-a2a-jcs-v01
      verifier: ./bin/my-verifier
      setup: make build   # optional
```

Keep the run public, then open a pull request that adds your entry to [badge-grants.json](badge-grants.json) with the run that produced your receipt.

## Paste it

After the grant, put the badge at the top of your README exactly as it appears at the top of [this repository's README](../README.md), and link it to your latest passing run so a reader can open the run the badge rests on:

```markdown
[![Verified by Probity](<badge image from the README>)](<link to your latest passing run>)
```

## Run it yourself

```bash
uv add agent-evidence-vectors==<release>
pip install agent-evidence-vectors==<release>
```

Use the release pinned in the [README](../README.md). The `probityai` command line that will run the same check is planned and not yet released; its install lines will be `uv add probityai` and `pip install probityai`.
