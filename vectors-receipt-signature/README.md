# Signed decision receipts: signature conformance suite

Conformance vectors for verifiers of signed decision receipts in the envelope
shape of `draft-farley-acta-signed-receipts-03`, vendored at
`spec-vendored/draft-farley-acta-signed-receipts-03.txt` and pinned by digest in
`MANIFEST.json`. Every member is one receipt. What a member asks is whether a
verifier holding an external key set reaches the right verdict on it, in the
cases where the receipt looks well formed and the answer still has to be a
refusal.

The members and their expected outcomes are in `INDEX.md`, which the generator
writes from the manifest.

## Where the members come from

The `signature-input-drift` and `superseded-key` cases were written by
giskard09 for this corpus, each as a reject and its conformant twin, and are
taken from `giskard09/argentum-core` at commit
`541ce84b4f970c1dd3d9e53f2a4562dbbc354e46`
(`examples/conformance/farley-receipt-signature`, Apache-2.0).
`superseded-key` is the stale-external-key case. `gen_vectors.py` does not copy
those files: it derives the same test keys from the same public recipe and
signs the same payloads. Ed25519 signing is deterministic, and the build refuses
unless each file hashes to the digest recorded upstream. The manifest's `origin`
block records the commit, the upstream file names and those digests.

The other members are this corpus's own. They cover the two edges of a key's
validity window, and three further rules of Section 6.6: no pre-hash before
signing, the envelope rule applied to an envelope, and no signature member in
the signed object, not even as null.

## Two key sets, two passes

A verifier is judged on every member twice:

| pass | key set | what it is |
|---|---|---|
| with windows | `keys/jwks.json` | upstream's key set: two Ed25519 keys, each with a `valid_from` and one with a `valid_until` |
| without windows | `keys/jwks-no-window.json` | the same keys with `valid_from` and `valid_until` removed |

The key is never read from the receipt (Section 9.5). The two passes make the
expected verdict a property of the receipt and the key set it was presented
with, not of what a verifier says about itself.

## How a SHOULD is graded

Section 9.2 of draft-03 says "Verifiers SHOULD check key validity windows when
available." A member whose only defect is the window therefore tests a SHOULD,
and it is `indeterminate` rather than `reject`:

- given the windows, a verifier that rejects it with
  `key_outside_validity_window` honours Section 9.2 and passes;
- given the windows, a verifier that accepts it is reported by name as not
  honouring Section 9.2. That is not a failure, and it is counted apart from the
  passes, so a verifier that skips the check cannot print the same totals as one
  that implements it;
- without the windows, it must be accepted. A verifier that rejects it there, or
  rejects it with a different code, fails.

Each such member carries `expected` (the verdict when the SHOULD is honoured),
`expectedIfNotHonoured` and `expectedWithoutWindows`. The boundary member at
exactly `valid_until` is graded the same way: draft-03 does not say whether the
end of the window is inside it, and a verifier that treats the end as inside
lands in the not-honouring line.

The draft's next revision makes the check a MUST, and places `valid_from`
inside the window and `valid_until` outside it (Section 5.5 of
`draft-farley-acta-signed-receipts-04`, open as VeritasActa/drafts#3). It is not
on the datatracker yet. When it is, these members become reject members and the
not-honouring line becomes a failure.

## Verifier contract

A verifier runs once per member per pass:

```
<verifier command> <path to the receipt>
```

with the environment variable `AEV_RECEIPT_JWKS` set to the absolute path of
that pass's key set. It answers in two places, which must agree:

- **exit status**: `0` valid, `1` invalid, `2` undecidable (the check could not
  run: no key for the `kid`, an unsupported algorithm, a malformed receipt).
  Any other status is not an answer;
- **the last non-empty line of stdout**: one JSON object,
  `{"verdict": "valid" | "invalid" | "undecidable", "code": <string or null>}`.
  `code` is null on `valid` and names the reason otherwise.

The codes this corpus expects are listed in the manifest's `codeRegistry`:
`signature_invalid`, `key_outside_validity_window` and
`signature_in_signing_input`. A verifier with its own vocabulary maps it in its
adapter. `tools/veritasacta-verify.py` is the adapter for `@veritasacta/verify`,
and it maps that package's `invalid_signature` to `signature_invalid`.

A member counts as executed only when both of its invocations started, exited
and answered. The harness reports the executed count beside the totals and
fails a run in which the verifier did not answer every member.

## Running it

```
aee-verify vectors-receipt-signature/                    # the corpus judges itself, from the repository root
python3 gen_vectors.py                                   # regenerate, byte-identically
python3 gen_vectors.py --check                           # refuse a tree the generator does not emit
agent-evidence-vectors --corpus vectors-receipt-signature --verifier '<your verifier>'
agent-evidence-vectors --corpus vectors-receipt-signature \
    --verifier 'python3 vectors-receipt-signature/tools/veritasacta-verify.py'
```

## Observed runs

Runs of a third-party verifier through the contract above, recorded with the
date and the exact version.

### @veritasacta/verify 0.10.19, 25 September 2026

Run through `tools/veritasacta-verify.py` (`--jwks <key set> --mode receipt
--json`) on Node.js 24.19.0, with the packaged harness at the commit that added
this section. The verifier answered every member in both passes.

| member | kind | with windows | without windows | graded |
|---|---|---|---|---|
| `ve116653dd041dda0` (signature-input-drift reject) | reject | invalid `signature_invalid` | invalid `signature_invalid` | pass |
| `v4f9fe96e52a39bfb` (its twin) | accept | valid | valid | pass |
| `vc4b43c5739979581` (superseded-key reject) | indeterminate | valid | valid | not honouring Section 9.2 |
| `vea8370fb85e1b4b1` (its twin) | accept | valid | valid | pass |
| `v4ec9fa36ae77ce07` (before `valid_from`) | indeterminate | valid | valid | not honouring Section 9.2 |
| `vbc25ef71da0567f9` (at `valid_until`) | indeterminate | valid | valid | not honouring Section 9.2 |
| `vb19450def8dcc5cd` (at `valid_from`) | accept | valid | valid | pass |
| `v0340fed8ef07e072` (pre-hashed signature) | reject | invalid `signature_invalid` | invalid `signature_invalid` | pass |
| `vad088133176d7114` (its twin) | accept | valid | valid | pass |
| `v1adc0db0267a742b` (flat rule on an envelope) | reject | invalid `signature_invalid` | invalid `signature_invalid` | pass |
| `vaafe541bbd74c320` (its twin) | accept | valid | valid | pass |
| `v5397adb77c3e6754` (`"signature": null` in the payload) | reject | valid | valid | **fail** |
| `v03377fbbac6d12f8` (its twin) | accept | valid | valid | pass |

Two findings. The receipt JWKS path of this release does not read `valid_from`
or `valid_until`, so every window member is accepted with the windows present:
that is the gap giskard09 reported, and under draft-03 it is graded as not
honouring a SHOULD rather than as a failure. And it accepts a receipt whose
payload carries `"signature": null` and whose signature was made over the
canonical bytes of that payload. Section 6.6 says the canonicalized object MUST
NOT contain a signature member, null included, so that acceptance is a failure
under a MUST.
