# Output contract

## Command

From the repository root, with the locked development environment:

```bash
uv sync --locked --extra dev
uv run python interop/aae-verdict-binding-v1/run_binding.py --output-dir /tmp/aae-binding-attempt
uv run python interop/aae-verdict-binding-v1/check_report.py /tmp/aae-binding-attempt/report.json
```

The run prints one line on success or on a recorded difference:

```text
aae-verdict-binding: 26/26 vectors reproduced, 7/7 cases as declared, report /tmp/aae-binding-attempt/report.json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every pin held, all 26 vectors reproduced and every case produced its declared outcome. A fresh `report.json` exists. |
| 1 | Every pin held and a fresh `report.json` exists, but at least one vector or case produced a different outcome. |
| 2 | Malformed input, a failed file pin, an unpinned key, an existing output directory, or an output failure. This invocation wrote no report. |

## Fresh output directory

`--output-dir` must not exist; the runner creates it (its parent must exist) and refuses an existing directory even when empty. The report is written to `report.json.tmp` and renamed, so a reader never sees a partial report. A report left by an earlier invocation is never read, changed or counted.

## Pins

`INPUTS.json` holds:

- `source`: repository, tag `v1.4.0`, commit `531f880155ea1ce993a7ca74137b12c255d5b2ee`, license and attribution.
- `files`: the path, SHA-256, byte count and role of every file under `fixtures/` and `cases/`, with the upstream path for each retained vector, `LICENSE` and `NOTICE`. A file that differs from its pin, a pinned file that is missing, and a file present but not pinned each exit 2 before any evaluation.
- `trust_keys`: `did:web:example.com:registry` bound to Ed25519 public key `9d53a7a4431e299b0ceb950ccbd5bd6f4845cdd9c7bd38e1c9e4e26490f8f90e` (upstream `testkeys/issuer-test-key-1.json`). It is the only authority key any ratification vector's mandate names.
- `untrusted_keys_seen`: `did:web:example.com:stranger` with key `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`, which signs vector 23 and is never trusted.
- `evidence_keys`: the observed-effect observer key `4f2a59edc8367deb40047ce83ee7f5ce711a57d93abbda9d1ce8588c56a3ce88`, this repository's fixed test key.

Key rule: a ratification is evaluated only when every authority key its mandate names equals the pinned key for that DID, and an evidence record is checked only under the pinned observer key. Any other key exits 2.

## Report fields

| Field | Content |
|---|---|
| `profile` | `aev.aae-verdict-binding.v1` |
| `source`, `input_sha256`, `trust_keys`, `evidence_keys` | Copied from the checked pins. |
| `code_sha256` | SHA-256 of each package module and of `vectors-observed-effect/check_vectors.py`. |
| `vectors_total`, `vectors_reproduced`, `vectors[]` | Per vector: `file`, `id`, `kernel` and a `checks` map of booleans (`verdict` or `status`, `core_digest`, `grant_index`, `ratifies`, `authority`, `trace`, `kernel_version`, `domain_tags`, `key_order_independent`, or `caller_error` for vectors 24 and 25), and `reproduced`. |
| `cases_total`, `cases_as_declared`, `cases[]` | Per case: `name`, `role` (`case` or `control`), `declared`, `produced`, `matches_declaration` and the full `result`. |
| `not_established` | `execution`, `outcome`, `completeness_of_the_decision_set`, `freshness_at_presentation`, `production_identity_of_any_key`, `revocation_state`, `independent_custody`. |

## Per-case claims and their closed values

| Claim | Values |
|---|---|
| `authorization.core_digest_recomputed` | `true`, `false` |
| `authorization.verdict` | `PERMIT`, `DENY`, `PENDING`: what the issuer asserted at issuance |
| `authorization.ratification.status` | `NOT_REQUESTED`, `RATIFIED`, `REJECTED`, `CALLER_ERROR` |
| `binding.status` | `MATCH`, `MISMATCH`, `ABSENT` |
| `evidence.verifier_verdict` | `valid`, `invalid`, `malformed`, `absent` |
| `execution.status` | `CLAIMED_BY_BOUND_RECORD`, `UNKNOWN` |
| `completeness.status` | `NOT_ESTABLISHED` |

`result` also carries `binding.cited` (the evidence record's `predicate.authorityDigest`), `binding.verdict_record_digest`, `evidence.codes`, a `reason` for execution and completeness, and for a ratification its `decision`, `authority`, `core_digest` or caller-error `code`. Reasons are diagnostic and never compared.
