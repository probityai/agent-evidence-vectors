# Admission corpus

The corpus in [`../vectors`](../vectors) judges whether an Adversarial Execution
Evidence statement is valid and which evidence tier each row derives. It never
judges the answer a relying party acts on: whether the statement is ADMITTED
under that party's own policy. A verifier could pass every member there and
still print a pass for a statement nothing independent stands behind. This
corpus judges that answer.

Each member is a pair: one statement and one consumer policy. The member
requires an admission answer and names the policy conditions that decide it.
[`INDEX.md`](INDEX.md) lists every member with its case in words.

## What it catches

- **A pass with no policy at all.** A verifier handed a statement and no
  consumer policy has admitted nothing: no observation key is pinned, so no
  substrate row is attested, and no anchor is compared. It must not report
  success.
- **A pass on the observation key alone.** The specification requires the
  consumer to pin the corpus, the substrate and the classes it demands. A
  consumer that pins none of them, and declines none of them by name, has not
  made an admission decision.
- **A renamed, redated subject.** The observer's records bind the subject's
  sha256 digest, and not its name or the statement's `issuedAt`. A party
  holding only the envelope key can rename the subject and move the date and
  every record still verifies. The subject is matched by the digest the
  consumer supplies for the artifact it is deploying, and a bound on the run's
  time is evaluated against the `armedAt` an arming record carries.
- **A fail result reported as admitted.** Validity and attestation say the
  evidence is sound. They do not say the subject passed.
- **A published test key.** A record that verifies under a key whose seed is
  public says only that someone ran the recipe. It is not admitted unless the
  consumer declines that refusal by name, which a demonstration may do and a
  deployment should not.
- **Artifact-only evidence.** A clean row that is not a live substrate
  interception is the producer's own account. It is not admitted unless the
  consumer declines that obligation by name.

## The external-verifier contract

A verifier is invoked as `<cmd> <statement-file>` with the consumer policy's
path in the environment variable `AEE_CONSUMER_POLICY`.

- Exit 0 means ADMITTED, 1 means not admitted, 2 means the verifier could not
  answer. Any other exit status is not an answer.
- The last line of stdout is one JSON object carrying `admitted` (a boolean
  that agrees with the exit status) and `policyCodes` (a list of strings, empty
  when admitted).

`admitted` is normative. `policyCodes` is measured: the codes are the reference
verifier's vocabulary, compared as a set, and a different code for the same
member is a reason-parity datum rather than a failure.

## The policy document

```json
{
  "substrateObservationKeys": [{"keyid": "<hint>", "publicKeyHex": "<64-hex ed25519 public key>"}],
  "expectedCorpusDigest": "<64-hex>",
  "expectedSubstrateDigest": "<64-hex>",
  "expectedSubjectDigest": "<64-hex, the sha256 of the artifact being admitted>",
  "allowUnpinnedAnchors": false,
  "demandedClasses": ["<class>"],
  "allowUnpinnedScope": false,
  "acceptedResults": ["pass"],
  "admitUninterceptedCleanRows": false,
  "maxIssuanceLagSeconds": 86400,
  "allowPublishedTestKeys": false
}
```

| member | absent means | a verifier refuses with |
|---|---|---|
| `substrateObservationKeys` | no key: every substrate row is unattested | `substrate-row-unattested` |
| `expectedCorpusDigest`, `expectedSubstrateDigest`, `expectedSubjectDigest` | not admitted, unless `allowUnpinnedAnchors` is `true` | `corpus-anchor-unpinned`, `substrate-anchor-unpinned`, `subject-anchor-unpinned`; a pin that differs is `*-anchor-mismatch` |
| `allowUnpinnedAnchors` | the three anchors are required | declines an ABSENT anchor only, never a mismatched one |
| `demandedClasses` | not admitted, unless `allowUnpinnedScope` is `true` | `scope-unpinned`; a demanded class the run did not assess is `demanded-class-unassessed` |
| `allowUnpinnedScope` | the demand is required | declines an absent demand only |
| `acceptedResults` | `["pass"]` | `result-not-accepted`; a list other than `["pass"]` or `["pass", "pass_indirect"]` is `accepted-results-malformed` |
| `admitUninterceptedCleanRows` | the row rule holds: every clean row is `basis: substrate` and `method: intercepted` | `clean-row-unintercepted`; a widened threshold that does not say `true` or `false` here is `row-gate-undeclared`, and `true` under a `pass`-only threshold is `row-gate-decline-unreachable` |
| `allowPublishedTestKeys` | an observation key whose seed a conformance suite publishes refuses admission | `observation-key-published`; every key in this corpus is one, so every policy pinning one declines the refusal by name except the member that tests it |
| `maxIssuanceLagSeconds` | no bound | `issuance-lag-exceeded` when `issuedAt` is more than this after any verified arming record's `armedAt`; `observed-instant-absent` when no arming record verifies under a pinned key |

The same knobs, with the same absent-input defaults, are the ones
[agent-evidence-admission](https://github.com/probityai/agent-evidence-admission)
takes in its consumer data document, so a policy pinned for an offline check
and for a cluster says the same thing in both places.

## Readers

`aee-verify vectors-admission` judges the corpus with the Go reference verifier,
and `agent-evidence-vectors --corpus vectors-admission` with the Python one. A
third-party verifier runs through the contract above with
`agent-evidence-vectors --corpus vectors-admission --verifier '<cmd>'`.

## Regenerating

`python3 gen_vectors.py` writes every file here from the members of
`../vectors`, and `python3 gen_vectors.py --check` refuses a tree that differs.
Each condition in `MANIFEST.json` carries the sentence it rests on, and the
generator and both readers refuse a manifest whose sentence is no longer in
the file it cites.
