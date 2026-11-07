# Who can check an agent record

Whether an agent did what its record says comes down to one test: a party that distrusts the issuer checks the record offline, an observer the agent cannot reach produced it, and the check is held to a public corpus. Five designs face that test here. The rows are classes of design, not products. Every cell links to a corpus, a recorded run or the primary text of a standard, and [`scripts/vantage-grid-gate.py`](../../scripts/vantage-grid-gate.py) fails the build when a link goes missing or stops resolving.

## The grid

<!-- vantage-grid:begin -->
| Design class | Verifiable offline by a party that distrusts the issuer | Produced by an observer the agent cannot reach | Passing a public corpus | Meets all three |
| --- | --- | --- | --- | --- |
| Self-held signed session record | Signature only. A DSSE signature binds the bytes to a key ([DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/b531b787bb3e5f0c3e1c19cee84da1c5d569b061/protocol.md)); the issuer holds that key and chose the bytes. | No. The runtime under observation writes and signs it. A second key the runtime mints can re-attest altered content and every signature still verifies ([`srr-c-3`](../../corpora/vectors-self-reported-record/README.md#the-five-attacks-and-where-each-one-went)). | A corpus exists for verifiers of this class: [`vectors-self-reported-record`](../../corpora/vectors-self-reported-record/README.md) refuses the records a signature-only check accepts. | No |
| Vendor dashboard verify button | No. The verdict comes from the issuer's service, and a relying party accepts a verdict only from a Verifier it trusts ([RFC 9334, section 7.1](https://www.rfc-editor.org/rfc/rfc9334.html#section-7.1)). | No. One party holds the record and computes the verdict ([RFC 9334, section 7.1](https://www.rfc-editor.org/rfc/rfc9334.html#section-7.1)). | No. A corpus run invokes a command the reader holds once per vector ([verifier contract](verifier-contract.md#invocation-and-output)); a hosted button offers no such command. | No |
| Observability trace | No. The OTLP `Span` message defines no signature field ([`trace.proto`](https://github.com/open-telemetry/opentelemetry-proto/blob/169f2f2c7c1550c364d5eecb05d1b6163a011b06/opentelemetry/proto/trace/v1/trace.proto#L89-L308)). | No. Instrumentation runs inside the code it reports on: "Each signal provides a mechanism for software to describe itself" ([OpenTelemetry overview](https://github.com/open-telemetry/opentelemetry-specification/blob/a847b4eadd3392bd48a32500629736191f82c823/specification/overview.md?plain=1#L54)). | No. With no signed field there is nothing for a corpus to refuse ([`trace.proto`](https://github.com/open-telemetry/opentelemetry-proto/blob/169f2f2c7c1550c364d5eecb05d1b6163a011b06/opentelemetry/proto/trace/v1/trace.proto#L89-L308)). | No |
| Transparency-log receipt | For registration. A Receipt "is universally verifiable without online access to the TS" ([RFC 9943, section 4](https://www.rfc-editor.org/rfc/rfc9943.html#section-4)); the reader trusts the log's key, not the issuer. | No. The log records what the issuer submits: "Transparency does not prevent dishonest or compromised Issuers" ([RFC 9943, section 4](https://www.rfc-editor.org/rfc/rfc9943.html#section-4)). | Yes. [`sigstore-conformance`](https://github.com/sigstore/sigstore-conformance/tree/9688d7c97e84e58ca448c4f1dfbe8109adc99a34) tests Sigstore clients, and [`vectors-scitt-cose`](../../corpora/vectors-scitt-cose/README.md) tests the COSE carriage around an agent record. | No |
| Independent observer with a public corpus | Yes. The verifier is a pinned wheel that installs and replays with no network ([air-gap guide](../guides/airgap-enclave.md)); [our run of release 0.35.0](../runs/vantage-grid-0.35.0.md) replayed with every network route closed. | Yes, and the verifier checks it. A record that claims a `below-observed` vantage with a commitment key the observed party signs with is refused, and the consumer anchors the observer's key out of band ([observed-effect predicate](../../spec/predicates/observed-effect.md#what-a-self-observing-party-can-still-forge)). | Yes. [`vectors-observed-effect`](../../corpora/vectors-observed-effect/README.md) behaved as declared in [our run](../runs/vantage-grid-0.35.0.md), and [a reader this repository did not write](../runs/observed-effect-verdict-words.md) rejected every reject member. | Yes |
<!-- vantage-grid:end -->

## What the last row reports, does not prove, and needs no trust in

| Reports | Does not prove | Needs no trust in |
| --- | --- | --- |
| What changed inside a declared path scope, from the vantage the record names, with the gaps the observer disclosed. | That the observer's key belongs to the observer you think it does. Anchor that key out of band, as you would any signer ([observed-effect predicate](../../spec/predicates/observed-effect.md#what-a-self-observing-party-can-still-forge)). | The agent, its operator, the issuer's service, or this repository's hosting: the wheel, the corpora and the signed digest list check offline ([release verification](release-verification.md)). |

## Run it yourself

```sh
uvx agent-evidence-vectors==0.35.0 --corpus vectors-observed-effect
uvx agent-evidence-vectors==0.35.0 --corpus vectors-self-reported-record
```

Each prints `verdict: every member behaves as MANIFEST.json declares` when the reference reader agrees with the corpus. The [verifier contract](verifier-contract.md) covers scoring your own verifier.
