# GovOps descriptor and decision IDs

Compare a gateway's raw descriptor with a saved authority record, or add a descriptor fingerprint at evidence ingestion. The optional reader keeps those routes separate.

The ingestion route returns a canonical descriptor digest, raw-input digest and the reported agent, call, attempt and target IDs. It verifies no grant. The decision route verifies an Ed25519 signature with a caller-configured authority key, then checks the capability ID, descriptor and each record binding. An issuer may assign an opaque capability ID or explicitly derive it from the descriptor. The gateway must copy that granted ID.

## Run it

You need Python, Rust and the pinned dependencies:

```sh
python -m pip install -r interop/govops-capability-id/requirements-check.txt
cargo build --locked --release --manifest-path interop/govops-capability-id/admission/Cargo.toml
python -m unittest discover -s interop/govops-capability-id -p test_reader.py
python interop/govops-capability-id/qualify.py \
  --admitter interop/govops-capability-id/admission/target/release/govops-jcs-admission \
  --installation interop/govops-capability-id/.build/installed
```

The qualification installs the Python API and console command, calls it from another directory and retains each native response in `report.json`. [The workflow](../../.github/workflows/ci.yml) (job `govops_capability_id`) repeats the installed comparison on both Python runtimes. All keys in the finite examples are public test keys.

## Use the API or CLI

```python
from pathlib import Path
from govops_ids import Admitter, evaluate, fingerprint

admitter = Admitter(Path("/absolute/path/to/govops-jcs-admission"))
descriptor = fingerprint(raw_descriptor_bytes, admitter)
result = evaluate(raw_request_bytes, admitter, trusted_keys, expected_authority)
```

Install `interop/govops-capability-id` into your environment to use `probity-govops-ids`. Pass `--admitter` and, for the decision route, `--trusted-key AUTHORITY=PUBLIC_KEY_HEX` and `--expected-authority AUTHORITY`. The command reads one request on stdin. It returns a JSON result and a failing exit status for refusals.

The request has `route`, `invocation` and optional `catalog_capability_id`. Invocation fields are `descriptor_text`, `capability_id`, `subject_id`, `runtime_agent_id`, `invocation_id`, `attempt_id` and `target_id`. A decision request also carries `decision`: `authority_id`, exact signed `raw` JSON text and `signature_hex`. That signed record contains the same binding fields plus `authority_id`, `decision_id`, `granted`, `id_binding`, `capability_id` and `descriptor_text`. Trust keys come from the caller, never the request.

## What stays distinct

[Pinned jcs-admit](source/jcs-admit/README.md) admits the original bytes before Python parses a value or hashes anything. Raw descriptors remain text inside records so duplicate names survive to admission. The default numeric policy is I-JSON with integers-only values; RFC canonicalization and ordinary I-JSON are explicit alternatives. Integers-only accepts integral values spelled with a decimal point. A raw-byte hash still distinguishes the original spellings.

Canonical descriptor identity does not normalize semantic aliases or Unicode normalization forms. A caller-supplied `alias_catalog` may record an equivalence label, but agreement there never rebinds a signed grant to another descriptor. A catalog entry, runtime agent, invocation, attempt and target are separate identifiers.

[Historical source pins](MANIFEST.json) preserve the earlier proposal at `12345bdf200614481411aee63d312a505978b4e0` exactly. Its original raw cases run through the new reader with an explicit public-key and binding adaptation. Historical verdicts stay in the report, including the prior float-spelling rule's difference from native admission. The original checker also runs separately. Its fixed PDP-minting and TRACE statements are historical proposal text, not upstream acceptance.

This comparison verifies saved-record syntax, signatures and bindings. Target effects remain `not-observed`. Kernel observation, host deployment, outside custody, issuer freshness, revocation and production key discovery are separate work.
