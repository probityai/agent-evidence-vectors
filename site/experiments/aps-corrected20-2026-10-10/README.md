# Corrected Agent Passport corpus: independent reader result

Probity wrote and operated a Python reader for APS/AEOESS's 20 public synthetic
Agent Passport cases. The unchanged [native report](report.json) records the
bounded diagnostic comparison. It does not import or call the APS SDK.

The corrected corpus is pinned to
`407ca2d5ad10c846860ad1b6faafc971ae9690e5`, SHA-256
`9fce76dbf13de9749a2ef52c8dedecce08e4874da0203b39a7d941eb479b5ac5`.
APS retains corpus authorship and Apache-2.0 licensing in [producer/](producer/README.md).
Probity retains its own reader and Lab record. This is separate from federation
membership, package adoption and live identity acceptance.

The source records four valid, fourteen invalid and two indeterminate SDK
observations. This reader returns four valid, eleven invalid, three
indeterminate and two unsupported outcomes. All diagnostic, resolver-request
and exposed-preimage comparisons agree. Three declared full-outcome differences
remain: `did-web-resolver-not-found`, `record-type-changed` and `version-changed`.
`PASS` describes that finite comparison; it does not make the verdicts identical.

Five upstream annotations remain separate: `did-web-resolver-not-found`,
`expired`, `not-yet-valid`, `record-type-changed` and `version-changed`. The
fixture's draft-04 note does not determine their assignments. They are not five
indeterminate source outcomes.

To replay the finite reader from this directory on Linux x86-64:

```sh
uv venv --python 3.14.7 .reader-venv
uv pip install --python .reader-venv/bin/python --require-hashes --only-binary :all: -r reader-requirements.txt
.reader-venv/bin/python -I -B read_corpus.py --fixture producer/agent-passport-vectors-v2.json --output replay.json
```

The reader supports the corpus's printable ASCII subset. Ed25519 checks use
cryptography 50.0.2/OpenSSL, so this is no independent cryptographic-backend or
general JCS qualification. Resolver answers and evaluation times are supplied;
historical authority, authenticated lookup and principal binding remain untested.
Public answers were exposed before implementation and execution.

The [original overall run](original-native-result.json) remains adverse. Both
selected SDK invocations failed before corpus evaluation at a 109-byte IPC
socket path. The [original locked dependency audit](npm-audit.json) records
three high entries and two advisories. Those failures do not erase the reader
result or become a whole-SDK qualification.

[Provenance](provenance.json), [source manifest](source-manifest.json) and the
[40-file selected original-source capsule](selected-source.zip) retain the
inputs, reader, two selected SDK closures, licenses, lockfiles and harness.
The capsule packages original bytes; its ZIP metadata is Atlas-created. Runtime
archives, installed dependencies and the complete provider archive are omitted.
The retained runtime inventories and hash requirements identify their sources.
No outside use of this reader, maintainer acceptance, live host adoption,
federation enrollment or commercial result is established.
