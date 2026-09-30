# ACP authorship ingress pair

Two envelopes exercise the handoff before an AI Change Provenance evaluator
reads `signed` authorship evidence. `valid.json` carries the AI Change
Authorship Statement in in-toto/attestation#602. `changed-operator.json` keeps
its signature but changes the operator in the decoded DSSE payload.

The producer is Python `cryptography`; the reader is the separately published
Rust `dsse` crate, pinned to 0.1.1. The public test key and expected head are
outside the envelopes. The reader verifies the exact payload bytes, then checks
the Statement type, predicate type, and subject and predicate head binding.

```sh
python3 vectors-acp-authorship/gen_vectors.py
cargo test --manifest-path vectors-acp-authorship/oracle/Cargo.toml
cargo run --quiet --manifest-path vectors-acp-authorship/oracle/Cargo.toml -- \
  vectors-acp-authorship/cases/valid.json
```

`changed-operator.json` returns exit 1. Neither envelope says who is trusted in
production. A consumer must pin that key separately. This pair does not test
ACP rule evaluation, account resolution, Sigstore identity, or the forge's
review history; `acp-evaluator-conformance` covers the later evaluation step.
