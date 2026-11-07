# Offline replay of release 0.35.0

The run behind the last row of [the vantage grid](../reference/vantage-grid.md), on 2026-11-05.

## What ran

The published wheel `agent_evidence_vectors-0.35.0-py3-none-any.whl`, SHA-256 `2ba211c12cdf296639e9e14a48464d2d084a51a58b1022a173eb5db90caab876` as PyPI lists it, through its packaged reference reader. The wheel was fetched once, then every replay ran with uv in offline mode and every HTTP and HTTPS proxy variable pointed at a closed local port, so any fetch would have failed the run:

```sh
export UV_OFFLINE=1 http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 \
  HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9
uvx --offline agent-evidence-vectors==0.35.0 --corpus <corpus>
```

## Results

Each line is the run's own output, copied verbatim. Every command in this table exited 0.

| Corpus | Output |
| --- | --- |
| `vectors` | `totals: 288 vectors, 288 pass, 0 fail` |
| `vectors-observed-effect` | `members: 80`, `verdict: every member behaves as MANIFEST.json declares` |
| `vectors-self-reported-record` | `members: 11`, `verdict: every member behaves as MANIFEST.json declares` |
| `vectors-anchored-chain` | `anchored-record-chain/v1: reference reader answered 14 of 14 cases, 0 disagreements` |

The member counts are those of release 0.35.0. A later release can change them; its manifest is the source.

## A named verifier over the SCITT/COSE carriage corpus

The same release also ran `vectors-scitt-cose` through the Go reference verifier `aee-verify` built from tag `v0.35.0` (`go install github.com/probityai/agent-evidence-vectors/cmd/aee-verify@v0.35.0`, Go 1.26.3), on a Hetzner box, on 2026-11-06. This run needed the network to build the verifier, so it is not part of the offline replay above:

```sh
uvx agent-evidence-vectors==0.35.0 --corpus vectors-scitt-cose --verifier "aee-verify -validity-only -json"
```

| Corpus | Output | Exit |
| --- | --- | --- |
| `vectors-scitt-cose` | `totals: 27 vectors, 0 pass, 27 fail, 4 suite-level refusal(s); 17 of 27 conform, 17 reason-parity mismatch(es)` and `verifier: aee-verify -validity-only -json ran on 27 of 27 vectors` | 1 |

`aee-verify` reads Adversarial Execution Evidence statements, not COSE_Sign1 messages, so it answered every member `invalid`. The manifest holds 17 reject, 6 accept and 4 indeterminate members: the 17 conform on verdict only, and none of them on the failure code, hence the 17 reason-parity mismatches; the 6 accept members fail and the 4 indeterminate families are refused. A verifier that refuses everything scores no passes, which is what the accept twins are for. The verdict for this corpus belongs to a verifier that reads COSE.
