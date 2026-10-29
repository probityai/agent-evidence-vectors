# Checking an AI Act log after the fact

The CRA and AI Act table in [orcwg/cra-hub#364](https://github.com/orcwg/cra-hub/pull/364) has a row, "Recording what the system did", where nobody can check the logs independently. AI Act Articles 19(1) and 21(2) both say "to the extent such logs are under their control", and neither asks the holder to show that control. A faithful log and a revised one reach the authority looking the same.

This corpus gives that row a checker that runs today: [`vectors-anchored-chain`](../../vectors-anchored-chain/README.md).

## What it checks

The holder keeps a chain of signed records and, separately, an anchor over the chain head signed by a key the store does not hold. A later reader (a market surveillance authority, a deployer, an auditor) runs the verifier over the store and the anchor. The cases cover deleting, reordering, replaying and rolling back records that the system signed itself, where every signature still verifies. Signature-only checking passes those stores. The chain links and the anchor catch them.

## Run it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-anchored-chain
```

To judge your own verifier: `python3 vectors-anchored-chain/check_vectors.py --verifier './verifier'`. CI runs the corpus on every push (`vectors-anchored-chain/tests`).

## What it does not check

- Records written after the last anchor are not protected. A store cut back to before the first uncovered record looks like an honest store anchored at its head, and the corpus expects `verified` for it.
- It says the history was not revised against the anchor. It does not say the log was complete when it was written; that needs an observer outside the logged system.
- The anchor key has to be held by someone other than the log holder. If the holder keeps both, the check proves nothing.

## The other unchecked row

The row for open-weight models exempt under Article 53(2) has no checker yet. A profile of [artifact binding](../../spec/artifact-binding/v1.md) for model records (weights digest, copyright policy and training-content summary as required roles, with an absent role reported as `not-established`) is the planned shape.
