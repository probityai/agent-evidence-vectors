# Separate JEP Core 0.7 reader

This Probity implementation consumes the pinned JEP fixtures without importing
JEP's validator, reference adapter, BYOI runner or acceptance fixture. The
[protocol](PROTOCOL.md) was publicly committed before execution. It reports the
25 validation, four producer and eight acceptance assertions separately.

Run the exact commands in the protocol from the reader's published commit. The
output directory must not exist. `report.json` retains every fresh-process
request, stdout, stderr, exit status, result, read-only effect observation,
comparison, source pin and dependency version. A nonzero result means a failed
or incomplete comparison. Old outputs are never overwritten.

The adapter also accepts the standard `jep-byoi/1` stdin request/response exchange.
Validation refusals are JSON results and exit zero; an unsupported operation or
profile cannot pass the harness. Logs go to stderr. The test-only producer key
is deterministically derived from the SHA-256 of the ASCII string
`Probity JEP Core 0.7 test-only producer key`; it has no authority outside this
synthetic suite.

Acceptance records `(domain, who, id)` and canonical unsigned content in SQLite.
The synthetic effect is a committed row in the same transaction. A new adapter
process handles each delivery. The read-only probe observes rows, including when
acceptance state is synthetically unavailable; it never sums `effect_applied`
flags. These tests do not prove an external action, independent database custody,
power-loss durability or distributed failover.

The public expectations were read before implementation. Producer output is
checked by Probity's separate verifier, without the JEP reference cross-check.
Any later native JEP harness reproduction must disclose its own reuse. No host
CI adoption is established by this owned workflow.

Original suite files under `upstream/` are copied byte for byte at
`a87a395b54b5685fd22d6cc86d120058f1c8850d`. Their BSD license is retained there.

```sh
python -m pip install pytest==9.2.0 hypothesis==6.168.3
python -m pytest -q interop/jep-core07-reader/test_jep_reader.py
```
