# Choose a corpus reader

The manifest's `suite` selects the reader. Use the packaged Python route for a supported suite or build the Go CLI to judge a corpus directory.

From the repository root:

```sh
GOWORK=off go build -o aee-verify ./cmd/aee-verify
./aee-verify vectors
./aee-verify vectors-ai-agent-action
./aee-verify vectors-artifact-binding
./aee-verify vectors-dependency-selection
```

| Result | Exit |
| --- | --- |
| Every member matches its manifest | `0`, with counts by verdict |
| A member or corpus-level check fails | `1`, with findings |
| Missing, unreadable or unsupported suite | `2`, with the suite or read error |

The Go binary supports its [registered readers](../../corpora/registry.go), rather than every directory named `vectors-*`. In particular, the SCITT/COSE corpus retains its own checker; the binary refuses that suite and describes the missing reader.

The following Python routes describe the current source. A released wheel exposes its own set with `--list-corpora`.

| Current source Python route | Supported corpora |
| --- | --- |
| Packaged reference readers | `vectors`, `vectors-w3c-report`, `vectors-observed-effect`, `vectors-receipt-signature`, `vectors-agent-audit-record`, `vectors-anchored-chain`, `vectors-receipt-chain-end`, `vectors-identity-binding`, `vectors-authority-at-dispatch`, `vectors-approval-binding`, `vectors-dispatch-fence`, `vectors-aggregate-accounting`, `vectors-converted-argument-binding`, `vectors-chunked-export`, `vectors-done-contract`, `vectors-done-receipt`, `vectors-spoofed-tool-output`, `vectors-test-tampering`, `vectors-grader-isolation`, `vectors-done-probes`, `vectors-trace-anchor`, `vectors-mcp-owasp`, `vectors-a2a-jcs-v01`, `vectors-grade-floor`, `vectors-agent-change-admission`, `vectors-agentic-process-evidence`, `vectors-recorded`, `vectors-admission` |
| Named verifier required | `vectors-source-coverage` |
| Own external contract supported | `vectors`, `vectors-receipt-signature`, `vectors-anchored-chain`, `vectors-receipt-chain-end`, `vectors-identity-binding`, `vectors-authority-at-dispatch`, `vectors-approval-binding`, `vectors-dispatch-fence`, `vectors-aggregate-accounting`, `vectors-converted-argument-binding`, `vectors-chunked-export`, `vectors-trace-anchor`, `vectors-a2a-jcs-v01`, `vectors-grade-floor`, `vectors-agent-change-admission`, `vectors-agentic-process-evidence` and `vectors-admission` (the policy path in `AEE_CONSUMER_POLICY`, exit 0 exactly when admitted); source coverage uses its consumer contract |

`vectors-w3c-report`, `vectors-observed-effect`, `vectors-agent-audit-record`, `vectors-mcp-owasp` and the six done corpora (`vectors-done-contract`, `vectors-done-receipt`, `vectors-spoofed-tool-output`, `vectors-test-tampering`, `vectors-grader-isolation`, `vectors-done-probes`) refuse a named verifier. Their Python and Go readers read observation v3 and Done Receipt v2, derive every member's verdicts from its records, and are replayed member by member through probity-verify by `vectors-done-receipt/crosscheck_probity_verify.py`, which CI runs on every push. Other suites with no packaged reader exit `2` unless a named verifier supplies their external route. A named verifier runs over such a suite through the generic contract only when that contract can carry every member's expectation, as for `vectors-ai-agent-action` and `vectors-scitt-cose`; a suite whose members expect another verdict, such as `allow` or `malformed`, is refused by name with exit `2` and never scored, because no verifier could pass it through an exit status. `scripts/oracle-every-corpus-test.py` drives a verifier that answers every member as its manifest declares over each corpus and requires a clean run or a named refusal. Check each [corpus README](../guides/corpora.md) for its contract.

Two standalone tools have separate jobs: [vectors-anchor-stream/run_verifier.py](../../vectors-anchor-stream/run_verifier.py) measures a supplied `anchors_verify.py` implementation; [vectors-mcp-record-contract/check_run_record.py](../../vectors-mcp-record-contract/check_run_record.py) checks a run record you supply.

## The a2a-jcs-v01 contract

`vectors-a2a-jcs-v01` is a2aproject/a2a-tck's Agent Card canonicalization corpus, kept byte for byte and locked by commit and corpus digest in its [source-lock.json](../../vectors-a2a-jcs-v01/source-lock.json). Its MANIFEST names two targets, with the vector count of each under `targets`, and the harness scores one per run:

| Target | Function | Vectors |
| --- | --- | --- |
| `card-signing-input` (default) | the card without its top-level `signatures` member, canonicalized | every vector |
| `rfc8785` (`A2A_JCS_TARGET=rfc8785`) | one JSON value to RFC 8785 bytes | groups A3 to A6 |

The harness runs `<verifier> <target> <input.json>` once per vector. The input file holds the vector's JSON text: `input_raw` verbatim for a reject, `input` serialized for an accept, with every number written as the token the vector file holds, so an integer `-0` reaches the verifier as `-0`. The verifier answers on its last nonempty stdout line:

| Exit | Answer | Meaning |
| --- | --- | --- |
| `0` | `{"canonical_utf8_hex": "<hex>"}` | produced canonical bytes |
| `1` | anything | refused: the input has no canonical form |
| other, timeout, malformed | none | errored |

A MUST-ACCEPT vector passes on the expected bytes; other bytes are `diverged` and a refusal is `refused`. A MUST-REJECT vector passes on a refusal; bytes are `accepted`. The four rule-3 rejects present a card that still carries `signatures` as its own signing bytes, and pass when the recomputed bytes differ from them. The report has `rail: external`, the `target`, and `verifier.vectorsExecuted`, so the Action's summary applies unchanged. `python -m agent_evidence_vectors.a2ajcs` is the packaged reference implementation of the contract.

## Test a canonicalizer from Python

A project that writes or fixes an RFC 8785 canonicalizer can test it in process against the corpus the wheel ships, with no copy of the vectors in its own tree. Pin the package as a test dependency and parametrize a test with `a2ajcs.params()`:

```python
import pytest
from agent_evidence_vectors import a2ajcs

@pytest.mark.parametrize("vector", a2ajcs.params())
def test_rfc8785(vector):
    a2ajcs.assert_conforms(my_canonicalize, vector)
```

Each vector becomes one test whose id is the vector id, such as `test_rfc8785[A5-001]`. A failure names the vector, its clause and what went wrong, for example `A5-001 (RFC8785-3.2.2.3): diverged: got b'{"tolerance":1e-06}' want b'{"tolerance":0.000001}'`.

| Function | Returns |
| --- | --- |
| `vectors(target="rfc8785")` | the `Vector`s the target owns, in manifest order |
| `params(target="rfc8785")` | the same vectors as `pytest.param` objects with the vector ids; plain vectors when pytest is absent |
| `assert_conforms(fn, vector, *, text=False)` | `None`, or raises `AssertionError` naming the vector and clause |
| `failure(fn, vector, *, text=False)` | why `fn` fails the vector, or `None` |
| `check(fn, target="rfc8785", *, text=False)` | one line per failing vector; empty when `fn` conforms |

`fn` takes a parsed JSON value and returns `bytes`; raising any exception is a refusal. With `text=True` it gets the vector's JSON text instead, number tokens as the file spells them, for a canonicalizer that parses for itself. The `target` is one of the two in the table above: `rfc8785` for a plain canonicalizer, `card-signing-input` for one that also drops the card's top-level `signatures`. Each answer is scored by the same rules as the external contract, so `check` and a harness run give the same verdict. `vectors` first checks the corpus against its manifest and raises `ValueError` on a mismatch rather than testing against bytes nothing vouches for. The module's own `canonicalize` and `signing_input` pass every vector of both targets, and `scripts/a2a-jcs-rails-test.py` requires `json.dumps(value, sort_keys=True)` to fail exactly the ten vectors on UTF-16 key order, ECMAScript number spelling and NaN or Infinity.
