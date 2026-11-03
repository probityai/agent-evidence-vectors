# TRACE Acta receipt comparison

This repository runs its receipt-signature corpus against TRACE's Acta verifier.
The comparison runs here, so TRACE does not need our package in its CI.

The maintained [workflow](../../.github/workflows/trace-acta-receipts.yml) retrieves
`tools/acta_receipt_verifier.py` from public TRACE commit
`b938790f7f46d3a943c76a5360d2de60bb72112c` and checks its exact SHA-256 before
execution. It uses this repository's locked dependencies and original corpus.
Every member runs with and without the issuer key windows. A missing answer,
wrong verdict, skipped window check or proposed extra rule fails the comparison.
One member is recorded as an answer under another code: for an `issued_at` with no
time-zone designator the reader answers undecidable and names the code `malformed`,
where the corpus names `window_not_applicable`. `check_report.py` holds that answer
exactly, so a change in it, or any other failing member, fails the job.

Each run retains the original reader bytes, HTTP headers, source check, Python
version, harness output and per-member report. The job runs on relevant changes,
weekly and on manual request. It does not update the upstream verifier pin.

The [corpus contract](../../corpora/vectors-receipt-signature/README.md) states the
draft-03 rules and the limits of these synthetic cases. These checks establish
results for the selected source and inputs. They do not establish an upstream
merge, standards decision, independent operator or customer deployment.
