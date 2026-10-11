# Signed decision receipts: signature conformance suite

Conformance vectors for verifiers of signed decision receipts in the envelope
shape of `draft-farley-acta-signed-receipts-03`, vendored at
`spec-vendored/draft-farley-acta-signed-receipts-03.txt` and pinned by digest in
`MANIFEST.json`. Every member is one receipt, and some present it in a context:
after the receipts of a chain, and against the issuer's commitment to that
chain. What a member asks is whether a verifier holding an external key set
reaches the right verdict on it, in the cases where the receipt looks well
formed and the answer still has to be a refusal, and in the cases where the
draft's answer is the gap.

The members and their expected outcomes are in `INDEX.md`, which the generator
writes from the manifest.

## Where the members come from

Three upstream families are lifted byte for byte, each Apache-2.0:

| family | written by | upstream |
|---|---|---|
| `signature-input-drift`, `superseded-key` | giskard09, for this corpus | `giskard09/argentum-core` at `541ce84b4f970c1dd3d9e53f2a4562dbbc354e46`, `examples/conformance/farley-receipt-signature` |
| `signing-input`: the Section 6.6 member null, the empty string and a string, and the twin without it | tomjwxf, from this corpus's null-member case | `ScopeBlind/agent-governance-testvectors` at `56801e37a0c9e668626959a267ac8cfa02e8c27d`, `verifier-vectors/signing-input` (pull request 28) |
| `revocation` and `timeliness` | astrogilda, for that suite | the same commit, `verifier-vectors/revocation` and `verifier-vectors/timeliness` (pull request 27) |

`superseded-key` is the stale-external-key case. `gen_vectors.py` does not copy
any of these files: it derives the same test keys from the same public recipes
and signs the same payloads. Ed25519 signing is deterministic, and the build
refuses unless each file, and each upstream key set, hashes to the digest
recorded upstream. The manifest's `origins` list records each commit, path,
author, upstream file name and digest. Carrying the two suites' cases in one
corpus means one command runs both, and a verifier's answer on a lifted file is
an answer on the upstream bytes.

The other members are this corpus's own. They cover the two edges of a key's
validity window, three further rules of Section 6.6 (no pre-hash before signing,
the envelope rule applied to an envelope, no signature member in the signed
object, not even as null), and the Section 6.7 link of a receipt presented at a
chain position: the timeliness receipt after the receipt its link names, and
after one it does not.

## Two key sets, two passes

A verifier is judged on every member twice:

| pass | key set | what it is |
|---|---|---|
| with windows | `keys/jwks.json` | every upstream key set in one: five Ed25519 keys, four with a window and one with a `revoked_at` |
| without windows | `keys/jwks-no-window.json` | the same keys with `valid_from`, `valid_until` and `revoked_at` removed |

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

## How a gap is graded

Some questions the draft does not decide, and the manifest's `gaps` list states
them with the rule proposed to close each, for the draft's next revision:

- `RS-G-001`: was the key revoked before the receipt was issued? No revision
  defines key revocation, so a receipt signed inside its key's window and after
  the key's `revoked_at` verifies.
- `RS-G-002`: was the receipt issued after a commitment its issuer recorded
  where the issuer cannot rewrite it? Section 9.7 defines the commitment to a
  chain's count and terminal hash, and no rule reads when it was recorded.

A `gap` member is one whose verdict the draft decides and whose decision is the
gap. Each carries the draft's verdicts (`expected`, `expectedWithoutWindows`)
and the closing rule's (`expectedIfGapClosed`,
`expectedIfGapClosedWithoutWindows`):

- a verifier that answers the draft's verdicts in both passes passes;
- one that answers the closing rule's verdicts in both passes is reported by
  name as closing the gap, and is not failed;
- any other answer fails, a mixture of the two included. The commitment rule
  refuses its member in both passes, since the commitment is not key metadata,
  so a verifier that applies it only when the key set carries windows fails.

Both reference rails recompute every column: each member with the gaps open
and again with every gap closed, and closing a gap must move no member but the
gap members. So the proposed rules are shown to refuse what they are for and to
leave every twin valid.

## Verifier contract

A verifier runs once per member per pass:

```
<verifier command> <path to the receipt>
```

with the environment variable `AEV_RECEIPT_JWKS` set to the absolute path of
that pass's key set. For a member with a context, `AEV_RECEIPT_CONTEXT` is set
to the absolute path of a JSON file:

```
{"chain": ["<absolute path>", ...],
 "commitment": "<absolute path>",
 "commitmentLoggedAt": "<RFC 3339 time>"}
```

`chain` lists the receipts before this one, first to last; the receipt is at
position `len(chain) + 1`. `commitment` and `commitmentLoggedAt` are present
together or not at all. For a member without a context the variable is unset.
A verifier that ignores a chain it was handed fails the member whose chain its
link does not name. It answers in two places, which must agree:

- **exit status**: `0` valid, `1` invalid, `2` undecidable (the check could not
  run: no key for the `kid`, an unsupported algorithm, a malformed receipt).
  Any other status is not an answer;
- **the last non-empty line of stdout**: one JSON object,
  `{"verdict": "valid" | "invalid" | "undecidable", "code": <string or null>}`.
  `code` is null on `valid` and names the reason otherwise.

The codes this corpus expects are listed in the manifest's `codeRegistry`. A
verifier with its own vocabulary maps it in its adapter.
`tools/veritasacta-verify.py` is the adapter for `@veritasacta/verify`: it maps
that package's `invalid_signature` to `signature_invalid`, and for a member with
a context it hands the chain and the receipt to the package's own
`--replay-chain`, whose chain-break count decides `chain_link_mismatch`.

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
