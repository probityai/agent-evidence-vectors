# CCS draft-10 reader (corpus v1.4.0)

This package reads the CCS v1.4.0 conformance corpus with a reader written from draft-correctover-ccs-10, and records where the draft and the corpus disagree, byte for byte. It does not import, copy or consult the corpus's reference checker.

## Run

From the repository root, in an environment with the pinned dependencies and a Rust toolchain:

```bash
python -m pip install -r interop/ccs-draft10-reader/requirements.txt
python -m pytest -q interop/ccs-draft10-reader/test_ccs_reader.py
```

The test builds the jcs-admit check crate, runs the reader over [fixtures/ccs-v1.4.0/](fixtures/ccs-v1.4.0/) twice (PYTHONHASHSEED 0 and 1) and requires every output to equal [results/](results/) byte for byte, with these digests:

```text
003b4889329eb3ad81f409b1bae201002f41add9120f9d6c8c2a5486f5ed463c  cases.jsonl
6b4c890ba445e3be8eecbbc831b0a88ac7ca6b48f3de5076400679d4b902aa3b  summary.json
0e660e944ba914a61a3cd2fcc1b7543b77233ae347de3257f7e84824e8f94005  controls.json
```

To run the reader alone: `JCS_ADMIT=<built jcs-admit-check> python -I interop/ccs-draft10-reader/ccs_spec_reader.py interop/ccs-draft10-reader/fixtures/ccs-v1.4.0 <out-dir>`. CI runs the same test in [ccs-draft10-reader.yml](../../.github/workflows/ccs-draft10-reader.yml).

## What ran

The reader ([ccs_spec_reader.py](ccs_spec_reader.py)) was written from the text of draft-correctover-ccs-10. The corpus's reference checker was never opened. The expected answers in each case's `expected.json` were visible to the author. Canonical bytes come from `agent_evidence_vectors.a2ajcs` in agent-evidence-vectors 0.18.1, and on every call the [jcs-admit check](jcs-admit-check/) produces the same bytes again with jcs-admit 0.1.0; any difference stops the run. Ed25519 verification uses cryptography 50.0.2. The corpus is DSHCorrectover/ccs-conformance-vectors at commit `c848faeade7a2ad9d211cf065e0e1ef415b4a3e7`, whose `vectors/v1.4.0-conformance` tree is `5da3c1520b5a78b342c4c60f0f1e93f2ddf6bd6e`, the same tree as at `effff90f231d11bb3be93d3d0d0792f36934cc78`. [box_job.sh](box_job.sh) cloned that commit on a Hetzner box and ran the reader twice, with PYTHONHASHSEED 0 and 1; both runs printed byte-identical outputs ([results/box-run-steps.txt](results/box-run-steps.txt)). The manifest lists 66 cases and 66 are on disk. [infer_constructions.py](infer_constructions.py) tests which preimage each corpus digest uses and wrote [results/constructions.json](results/constructions.json).

Every check in `cases.jsonl` names the draft section it comes from, and reports SILENT where the draft says nothing a case depends on. Reading A applies everything the draft states, literally. Reading B is VERIFIED as section 7.2 defines it (the signature over every signed field, against the embedded key), plus every semantic rule the draft states that a case can be tested on.

## Findings

**The signed bytes.** Draft-10 as written verifies 0 of 73 receipt signatures. Section 4.2 signs fields 1 to 21 and encodes the signature as 128 lowercase hex characters; the corpus signs 29 members and encodes the signature in base64. Adding the key fields of section 7.2 item 3 to the signed set still verifies 0 of 73. Signing every member except `signature`, a rule the draft does not state, verifies 69 of 73 and reproduces the corpus's `signing-input` bytes for 73 of 73. The four that fail are the signature-negative cases (04, 07a missing public_key, 07a missing signature, 09c).

**Reading A.** Read literally, draft-10 refuses all 66 cases, including the 6 the corpus marks valid. Every one of the 69 L1 receipts lacks the MUST field `receipt` (field 7), and every one fails the stated formats for trace_id, issuer, audience, nonce and signature, which refuses 01, 02 and 03. The three L2 behavior cases marked valid (06a, 06b, 06c) carry a `receipt_type` the draft does not define, and are refused because their signatures fail the section 4.2 reading.

**Reading B.** Reading B agrees with the corpus on 37 of 66 cases. Of the 29 disagreements, recounted from `results/cases.jsonl`:

- 1 is the draft deciding the other way on a case marked valid: 02 carries the verdict `block`, read as deny, with a non-empty `response_hash`, which the section 4.2 lifecycle forbids for a deny.
- 7 are the draft allowing what the corpus refuses: 10a, a sequence gap, which section 6.8 ("monotonically increasing") allows; four 07a cases that drop a field section 4.1 marks SHOULD (max_clock_skew, response_hash, runtime_context_hash, sequence); and 08b and 08d, which compare `timestamp` with `issued_at`, two values sections 6.9 and 12.2 do not relate.
- 21 rest on a rule the draft does not state, or on a construction the corpus does not carry or does not follow: 05b, 06d, nine 07a cases (args_digest, deployment_mode, latency_us, public_key_fingerprint, receipt_version, rule_version, signing_algorithm, tool_call_id, verifier_source_class; section 7.2 item 3 requires the key fields to be signed when present, not to be present), 07b, 07c, 09a (see D6), 10b to 10e (see D13), 11a (no request Command is carried), 11b (see D3) and 11c (no configuration is carried).

## Disagreements proven on the bytes

| | Draft-10 says | The corpus does |
|---|---|---|
| D1 | Sections 4.2 and 7.2: fields 1 to 21 (plus the key fields), signature in hex | Signs every member except `signature`, in base64 |
| D2 | Section 4.2 lifecycle: a deny carries an empty `response_hash` | 02 is valid with verdict `block` and a non-empty `response_hash` |
| D3 | Section 6.5: `params_hash` is SHA-256 of the sorted, compact arguments | `params_hash` is SHA-256(JCS{tool, param_keys}) in 31 of 32 receipts (11b is the planted mismatch); the section 6.5 value sits in `args_digest` in 32 of 32 |
| D4 | Section 13.1: `params_hash` detects changed arguments | Changing `customer_id` in 01-allow leaves `params_hash` at `f516269c...`; only `args_digest` moves |
| D5 | Section 6.4: `action` is `ccs:tool-invoke:{tool}:{sha256(params)}` | 0 of 32 receipts use that form |
| D6 | Section 7.2 item 2: the fingerprint is the full SHA-256 of the key | The first 8 bytes, in 64 of 66 receipts |
| D7 | Sections 6.1, 6.2 and 6.3: request, response and runtime hashes carry a `sha256:` prefix | No prefix; the response value matches in 31 of 32 once the prefix is ignored |
| D8 | Sections 4.1 and 4.5: the verdict is allow, deny or escalate | `block` appears (02, 04, 05d) |
| D9 | Section 6.8: sequence is monotonically increasing | 10a refuses a gap |
| D10 | Section 4.1: max_clock_skew, response_hash, runtime_context_hash and sequence are SHOULD | Refused when absent |
| D11 | Sections 6.9 and 12.2: freshness reads issued_at and expires_at | 08b and 08d refuse on timestamp skew |
| D12 | No L2 behavior receipt | Four receipts carry `receipt_type` |
| D13 | Section 11.2 names `previous_receipt_hash` without its preimage | The previous digest is SHA-256 of the predecessor's signing input in 4 of 5 hops (10e is planted) |
| D14 | Section 6.9 checks against local time | No evaluation instant is pinned, and every receipt has expired at real local time (most carry `expires_at` 1750089600, June 2025); the reader evaluates at `verified_at` and records that it does |

## Controls

Four mutations of 01-allow are all refused by reading B: a flipped signature byte, a changed signed field, a substituted embedded key, and an added member. Under the relaxed-signature pairing, each case refused for its signature is read again with that check removed. Two flip to valid, so the signature is their only ground (07a missing public_key, 09c). Two keep a second ground: 04-tampered (a block verdict with a non-empty `response_hash`) and 07a missing signature (a missing MUST field).

## Classification

In the terms of criterion 8 of the group's intake criteria v2, this is an implementation written from the specification. It shares no verification code with the reference checker. The expected answers were visible to its author. It was run by the same operator who ran the 2026-10-11 known-answer replay of this corpus.

## Attribution

The files under [fixtures/ccs-v1.4.0/](fixtures/ccs-v1.4.0/) are the CCS v1.4.0 conformance vectors by Guigui Wang (Correctover), [DSHCorrectover/ccs-conformance-vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors) at commit `c848faeade7a2ad9d211cf065e0e1ef415b4a3e7`, tree `vectors/v1.4.0-conformance`. They are kept byte for byte under CC0 1.0, with the upstream [LICENSE](fixtures/ccs-v1.4.0/LICENSE.upstream). [INPUTS.json](INPUTS.json) pins each file's SHA-256 and upstream path, and the tests check each file against the corpus's own `manifest.json`. The reader, tests and results are this repository's, under its Apache-2.0 license.
