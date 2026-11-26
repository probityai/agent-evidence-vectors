# Model preservation vectors

Cases for `model-preservation/v1`: the two signed records that keep a model checkable
after its publisher, its hub or its hosted service has gone, and the decision a verifier
must reach on each. The expected decision and reason for every case are in
`MANIFEST.json`.

**The reference record** lists a digest for every file of a model. It is the OpenSSF
model-signing v1.0 statement (an in-toto Statement v1 with predicate type
`https://model_signing/signature/v1.0`, whose subject digest is the SHA-256 over every
resource digest in name order), signed in a DSSE envelope by the endpoint that fetched the
model. The endpoint adds a `fetch` member saying where it fetched the model, at which
revision and when; a v1.0 verifier ignores that member. The model card and the licence text
are files of the model, so they are listed like the weights. With the record, a copy
recovered from anyone, including a party nobody trusts, is checked without trusting them.

**The swap record** says that a service replaced one model with another. It names the old
model (by digest where there is one, by service and observation date where there is not),
the new model as the statement's subject, the digest of the test set and the verdict of
the run, and is signed by whoever made the swap. Its predicate type is
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/model-swap`.

Both records come from the reference record (T0) and the hosted-service sections of the
model preservation draft in `open-source-ecosystem/ai-model-sovereignty`
(`PRESERVATION.md`). Each record gets a match, a tampered digest and a wrong signer, and
the cases below add the rules a reader of either record gets wrong.

| Case | Record | Expected | Reason |
| --- | --- | --- | --- |
| reference-copy-matches | reference | verified | copy_matches_record |
| reference-copy-file-tampered | reference | mismatch | file_digest_mismatch |
| reference-copy-file-missing | reference | mismatch | file_missing |
| reference-copy-extra-file | reference | mismatch | file_not_in_record |
| reference-record-digest-tampered | reference | rejected | signature_invalid |
| reference-wrong-signer | reference | rejected | signer_not_trusted |
| reference-wrong-signer-names-trusted-keyid | reference | rejected | signature_invalid |
| reference-root-digest-inconsistent | reference | rejected | root_digest_inconsistent |
| reference-gated-pointer-matches | reference | verified | copy_matches_record |
| reference-gated-pointer-mismatch | reference | mismatch | file_digest_mismatch |
| reference-recorded-after-withdrawal | reference | not_established | record_after_withdrawal |
| reference-record-is-a-swap-record | reference | rejected | unexpected_predicate_type |
| swap-passed | swap | verified | swap_passed |
| swap-passed-hosted-old-model | swap | verified | swap_passed_old_model_unproven |
| swap-failed-test | swap | failed | swap_failed_test |
| swap-verdict-tampered | swap | rejected | signature_invalid |
| swap-wrong-signer | swap | rejected | signer_not_trusted |
| swap-signed-by-another-trusted-party | swap | rejected | signer_not_swapper |
| swap-deployed-model-differs | swap | mismatch | deployed_model_not_swapped_in |
| swap-test-set-not-required | swap | mismatch | test_set_not_required |
| swap-old-model-not-identified | swap | not_established | old_model_not_identified |

Five cases carry the points a reader tends to get wrong:

- **A digest rewritten to fit a bad copy.** `reference-record-digest-tampered` pairs a copy
  with altered weights and a record whose weights digest was changed to match it after
  signing. A reader that compares the copy with the record before it checks the signature
  reports a match.
- **Gated weights.** The hub hides a gated file's SHA-256 until access is granted, but shows
  the git id of the file's large-file pointer, which fixes the SHA-256 and the size.
  `reference-gated-pointer-matches` records the weights by that id (algorithm
  `git-lfs-pointer`, this corpus's extension; model-signing v1.0 lists SHA-256 only), and
  the reader rebuilds the pointer from the copy to compare it.
- **A record made too late.** A copy rescued later can only be checked against a record
  made before the model went. `reference-recorded-after-withdrawal` is not established,
  never verified.
- **A failed swap is evidence, not an error.** `swap-failed-test` is a well-formed record of
  a worse model swapped in; the verifier reports `failed` with the swapper on record.
- **Behaviour is not identity.** A run against a hosted service shows how it behaves, never
  which model answered. `swap-passed-hosted-old-model` passes with the reason
  `swap_passed_old_model_unproven`, so model identity is reported apart from the verdict.

## Check order

The reader names the first check that fails. For both records: a signature names a
trusted keyid (`signer_not_trusted`); it verifies over the DSSE pre-authentication
encoding (`signature_invalid`); the payload type, statement type and predicate type are
the ones the case asks about (`unexpected_predicate_type`). For a reference record: the
subject digest is consistent with the resources (`root_digest_inconsistent`); the record
predates the withdrawal the case names (`record_after_withdrawal`); the copy's file set is
the record's (`file_missing`, `file_not_in_record`); every file has its digest
(`file_digest_mismatch`). For a swap record: the signer is the swapper
(`signer_not_swapper`); the old model is identified (`old_model_not_identified`); the test
set is the required one (`test_set_not_required`); the subject is the deployed model
(`deployed_model_not_swapped_in`); the verdict is pass (`swap_failed_test`). A record
missing a member these checks read is `rejected` with `malformed_record`.

## What a case holds

- `case.json`: `kind` (`reference` or `swap`), the record file, the keys the verifier
  trusts (`keyid`, the SHA-256 of the raw Ed25519 key, with the party it belongs to); for a
  reference record the copy's files (`copy`, a model path to the file in this directory)
  and, where the model was withdrawn, `withdrawnAt`; for a swap record the test set the
  requirement names (`requiredTestSet`) and the digest of the model now deployed
  (`deployed`).
- `record.dsse.json`: the DSSE envelope. A model-signing deployment stores it inside a
  Sigstore bundle; the vectors carry the envelope alone and sign with a private key, one of
  the signing methods model-signing supports.
- `copy-*`: the copy's files, a few bytes each, standing for a real model's files.

Keys are Ed25519 seeds derived from published labels in `gen_vectors.py`, so anyone can
rebuild every signature. They are test keys and protect nothing.

## Running it

```sh
agent-evidence-vectors --corpus vectors-model-preservation
python3 corpora/vectors-model-preservation/check_vectors.py
python3 corpora/vectors-model-preservation/check_vectors.py --verifier "your-verifier"
```

The external-verifier contract: `<verifier> <case-dir>/case.json --json` prints one JSON
object carrying `decision` and `reason`, and exits 0 for `verified`, 1 for `failed`, 2 for
`mismatch`, 3 for `rejected` and 4 for `not_established`.

In CI, the Action runs the same cases against your verifier:

```yaml
- uses: probityai/agent-evidence-vectors@<release tag>
  with:
    corpus: vectors-model-preservation
    verifier: your-verifier
```

Regenerate with `python3 corpora/vectors-model-preservation/gen_vectors.py`; the tests in
`tests/` check that regeneration is byte-identical and that switching off any one rule
changes at least one verdict.
