# Checking an AI Act log after the fact

The proposed CRA and AI Act table in [orcwg/cra-hub#364](https://github.com/orcwg/cra-hub/pull/364) has a meeting point, "Recording activity". AI Act Articles 19(1), 21(2) and 26(6) all apply "to the extent such logs are under their control", and they do not prescribe how a holder shows that logs are complete and unaltered. An outside check is possible where a reference to the logs was kept somewhere the holder does not control, such as a hash recorded with a third party. Those provisions do not require one.

This corpus tests one such construction today: [`vectors-anchored-chain`](../../corpora/vectors-anchored-chain/README.md). Other constructions can do the same job. Passing it is not compliance with either act.

## What it checks

The holder keeps a chain of signed records and, separately, an anchor over the chain head signed by a key the store does not hold. A later reader (a market surveillance authority, a deployer, an auditor) runs the verifier over the store and the anchor. The cases cover deleting, reordering, replaying and rolling back records that the system signed itself, where every signature still verifies. Signature-only checking passes those stores. The chain links and the anchor catch them.

## Run it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-anchored-chain
```

To judge your own verifier: `python3 corpora/vectors-anchored-chain/check_vectors.py --verifier './verifier'`. CI runs the corpus on every push (`corpora/vectors-anchored-chain/tests`).

## What it does not check

- Records written after the last anchor are not protected. A store cut back to before the first uncovered record looks like an honest store anchored at its head, and the corpus expects `verified` for it.
- It says the history was not revised against the anchor. It does not say the log was complete when it was written, that a logged event happened, or that it came before an external effect. A signature over a later export establishes none of those by itself. They need an observation from outside the logged system.
- The anchor key has to be held by someone other than the log holder. If the holder keeps both, a match does not show that the holder left the history unrevised.

## Open-weight models

The table's open-source meeting point covers open-weight models under Article 53(2). That has its own guide and checker: [Checking an open-weight model release](cra-ai-act-open-weight.md).
