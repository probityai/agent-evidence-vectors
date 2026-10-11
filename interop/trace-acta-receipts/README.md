# TRACE Acta receipt comparison

This repository runs its receipt-signature corpus against TRACE's Acta verifier.
The comparison runs here, so TRACE does not need our package in its CI.

The maintained [workflow](../../.github/workflows/trace-acta-receipts.yml) retrieves
`tools/acta_receipt_verifier.py` from public TRACE commit
`9cac83a86a54b869ab891ea7e76006342785c15c` and checks its exact SHA-256 before
execution. It uses this repository's locked dependencies and original corpus.
Every member runs with and without the issuer key windows. A missing answer,
wrong verdict, skipped window check or proposed extra rule fails the comparison.

Each run retains the original reader bytes, HTTP headers, source check, Python
version, harness output and per-member report. The job runs on relevant changes,
weekly and on manual request. It does not update the upstream verifier pin.

The [corpus contract](../../vectors-receipt-signature/README.md) states the
draft-03 rules and the limits of these synthetic cases. These checks establish
results for the selected source and inputs. They do not establish an upstream
merge, standards decision, independent operator or customer deployment.
