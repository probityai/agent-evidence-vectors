# Customer support action experiment

This runner checks a structured discount offer against company records and a selected approval snapshot.

It is for a support lead who needs a reason before an assistant makes a customer commitment. The report is synthetic. The experiment makes no evaluator request and sends no email.

## Run the selected source

Use the published full Git revisions selected for Verify and Vectors. Both checkouts must have those exact revisions and clean tracked files. Install Verify's locked environment before the offline run.

Run on Linux with Go installed. The selected Go reader refuses unsupported platforms.

```sh
python3 examples/customer-support-action/run.py \
  --verify-root /path/to/probity-verify \
  --verify-revision "$customer_support_verify_revision" \
  --verify-python /path/to/probity-verify/.venv/bin/python \
  --vectors-root /path/to/agent-evidence-vectors \
  --vectors-revision "$customer_support_vectors_revision" \
  --output "experiments/$customer_support_record_id"
```

The output directory must be new. The runner exports the exact Git trees to scratch directories. It records their byte hashes and refuses a checkout or runtime that uses another source. The Go reader builds from the exported Vectors source with one worker and network package lookup disabled.

Register a measured result only after its retained run completes. Keep failed and cancelled output unchanged. The runner's existence does not establish a passing measurement.

The [design decision](docs/architecture/DESIGN_DECISIONS.md) explains why corpus admission precedes every reader.

## What the readers check

The contract is `vectors-customer-support-action/CONTRACT.md` in the selected Vectors revision. It defines raw action, draft, customer, company policy, advisory report and approval artifacts. The consumer separately selects their byte hashes, rules, clock, manager identity and approval-use snapshot.

A routine eligible offer can proceed. An exception needs an exact selected approval for its request, recipient, plan, discount and draft bytes. Wrong recipients, changed drafts, expired grants and consumed approvals retain different failure reasons. Missing source selection and incomplete required checks cause review. Malformed input requires an explicit refusal, not reader silence.

Verify evaluates each member through its local support adapter. Vectors' Go reader derives the same bounded checks independently. Both use the public expected results. Probity operates both processes; a second implementation does not establish a separate operator or independent custody.

## What the run retains

The output carries the complete selected corpus, source hash manifests, actual command arguments, process exits and raw standard output and error. The Go output retains each member's verdict and mismatch findings. Verify's output retains each decision, reason and action permission.

The runner also creates portable ZIPs for routine and manager-approved offers. Each ZIP carries the case, selected policy, required artifact bytes and full decision. Replay occurs from a new working directory that contains only the carried ZIP. The full packet remains available beside the archive.

The additional controls change selected policy or company source bytes while preserving the valid offer. An unchanged APPROVE outcome must still carry different byte bindings. Reusing the old decision in either changed ZIP must refuse. Rebinding only the producer's source hash, while the consumer retains its earlier selection, must cause review.

These are finite comparisons of supplied records and authority snapshots. They do not authenticate the company or manager, atomically consume a grant, or prove a real email effect. A production boundary needs those separate mechanisms.
