# Verify a record offline

Follow this page to check an agent evidence record on a machine with no network and no account. You need the record, a key set you chose, and the files in [offline-verify/](offline-verify/). Nothing on this page calls home: the verifier reads bytes from disk, prints a decision, and stops.

The record format is the Adversarial Execution Evidence statement, an in-toto Statement whose predicate type is `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`. The verifier is the released `agent-evidence-verify` 0.5.1 from PyPI, pinned by hash.

## What you need

| Machine | Needs |
| --- | --- |
| Connected machine, once | Python 3.12 or newer with pip, the same operating system and CPU architecture as the offline machine |
| Offline machine | Python 3.12 or newer with its `venv` module, and `sha256sum` |

The connected machine only downloads. Everything that decides runs on the offline machine.

## 1. Download on the connected machine

Copy the [offline-verify/](offline-verify/) folder from this repository at the release tag you trust, then run [connected.sh](offline-verify/connected.sh) inside it. Its two working steps:

```sh
python3 -m pip download --require-hashes --only-binary=:all: --dest wheels -r requirements.txt
(cd records && sha256sum -c ../SHA256SUMS)
```

[requirements.txt](offline-verify/requirements.txt) pins `agent-evidence-verify==0.5.1` and its five dependencies, each with every published SHA-256, so pip refuses any wheel whose hash it does not list. The script also fetches eight example records from the `v0.36.3` tag of this repository into `records/` and checks them against [SHA256SUMS](offline-verify/SHA256SUMS). To check your own record instead, put it in `records/` and add its line to `SHA256SUMS`.

## 2. Move the folder

Carry the folder, now holding `wheels/` and `records/`, across by your own transfer process. Send the SHA-256 of the tarball by a second channel so a swapped copy cannot carry its own matching digest.

## 3. Verify on the offline machine

Run [offline.sh](offline-verify/offline.sh). Its steps:

```sh
python3 -m venv venv
venv/bin/pip install --no-index --find-links wheels --require-hashes -r requirements.txt
python3 make_case.py --out pinned --keys keys.json records/*.json
python3 make_case.py --out unpinned records/*.json
for c in pinned/*.case.json unpinned/*.case.json; do venv/bin/agent-evidence-verify "$c" --policy "$(dirname "$c")/policy.json" --artifact-root records --json > "${c%.case.json}.out.json"; done
venv/bin/python summary.py pinned unpinned || echo "summary exit $?"
```

`--no-index` stops pip from reaching any package index, and `--require-hashes` stops it installing anything the lock does not name. [make_case.py](offline-verify/make_case.py) uses the standard library only. It writes one case file per record, naming the record by path, length and SHA-256, and one policy file that holds your key set. The `pinned` run uses [keys.json](offline-verify/keys.json); the `unpinned` run pins no key, which is what a party holding only the record can check.

[summary.py](offline-verify/summary.py) prints one line per record and exits 1 when any record carries a verdict code you did not allow with `--allow CODE`. Use that exit status as your gate.

## The key set

A key set is a JSON file in the shape the [verifier contract](../reference/verifier-contract.md) defines:

```json
{"substrateObservationKeys": [{"keyid": "<sha256 of the raw key, hex>", "publicKeyHex": "<32-byte Ed25519 public key, hex>"}]}
```

The keys are those of the observers you accept: the components that watched the agent from outside its reach and signed what they saw. Get them out of band, from a party and a channel you already trust, and never from the record. The record's `keyid` is a lookup hint and the verifier never takes a key from it.

The [keys.json](offline-verify/keys.json) in this folder holds the corpus's published test key (derivation in [vectors/keys/README.md](../../vectors/keys/README.md)). Anyone can sign with it, so a clean verdict under it shows the mechanics and nothing about who observed. Never put it in a production key set. The Go verifier's admission stage refuses it as `observation-key-published`; the Python verifier on this page does not, so keeping it out is your key set's job.

## Reading the output

Each `*.out.json` is one decision. The fields that matter:

| Field | Meaning |
| --- | --- |
| `decision` | `supported` when the statement verifies, `contradicted` when it does not |
| `checks[0].verdict` | `valid` or `invalid` |
| `checks[0].verdict_code` | One of the seven codes below, or `null` for a clean report |
| `checks[0].codes` | The detailed failure codes, in detection order; the first decides the verdict code |
| `checks[0].result` | For a valid statement only: the run's own result (`pass`, `fail`, `pass_indirect` and so on), recomputed from the rows |
| `checks[0].tiers` | For a valid statement only: `attested`, `unattested` or `declared` per row under your key set |

A `supported` decision says the record is sound. It does not say the agent passed: read `result` for that.

## Verdict codes

The closed list lives in [receipt-verdict-codes.json](../reference/receipt-verdict-codes.json), and the [verifier contract](../reference/verifier-contract.md#receipt-verdict-codes) maps every detailed code to one of them. A code your verifier version does not classify is refused, never read as a pass.

| Verdict code | Kind | What it tells you | Example record |
| --- | --- | --- | --- |
| none (`null`) | clean | Valid, and every substrate row is attested under a key in your set | `vfcb846afff2d6979` with `keys.json` |
| `MALFORMED` | failure | Unreadable, a broken shape rule, or a signed root that commits to records the document no longer carries | `v577011f7dd9a08fe` |
| `LEAF_HASH_MISMATCH` | failure | Carried bytes do not hash to the digest stated or pinned for them: the document was edited | `v02fd1bc1d7916002` |
| `PROOF_BROKEN` | failure | A record's hash does not reach the signed batch root | `v28b0cf874ea02de1` |
| `CLAIM_NOT_BOUND` | failure | A readable claim disagrees with the sealed record behind it, or cites none that can carry it | `v131478f1be775746` |
| `SUMMARY_MISMATCH` | failure | The summary disagrees with the record's own rows | `vcb23d2c4509c9daf` |
| `NOT_PUBLICLY_VERIFIABLE` | limit | Valid, but a substrate row is not attested under your keys: the document alone cannot show who observed it | `v550c91df0d36a218`, and `vfcb846afff2d6979` without a key |
| `NOT_RECONSTRUCTIBLE` | limit | Valid, but the rows rest on no sealed observation record, so the claims cannot be tied back to hashes | `v9cc570167acf4ae8` |

A limit is not a pass. Allow one with `--allow` only when your use of the record can live with what it says the record cannot show.

## The recorded run

[TRANSCRIPT.txt](offline-verify/TRANSCRIPT.txt) is a run of exactly these files on 2026-11-10 (Python 3.12, x86-64): [connected.sh](offline-verify/connected.sh) in a `python:3.12-slim` container, then [offline.sh](offline-verify/offline.sh) in a fresh container started with `--network none`, whose only interface was `lo` and whose probe of the package index failed with no route. [scripts/offline-verify-run.sh](../../scripts/offline-verify-run.sh) reproduces it. The summary it printed:

```text
pinned v02fd1bc1d7916002 contradicted invalid LEAF_HASH_MISMATCH corpus-digest-mismatch None -
pinned v131478f1be775746 contradicted invalid CLAIM_NOT_BOUND refs-empty,interception-record-orphaned None -
pinned v28b0cf874ea02de1 contradicted invalid PROOF_BROKEN batch-root-mismatch None -
pinned v550c91df0d36a218 supported valid NOT_PUBLICLY_VERIFIABLE - fail unattested
pinned v577011f7dd9a08fe contradicted invalid MALFORMED batch-root-orphaned None -
pinned v9cc570167acf4ae8 supported valid NOT_RECONSTRUCTIBLE - pass_indirect declared
pinned vcb23d2c4509c9daf contradicted invalid SUMMARY_MISMATCH result-recompute-mismatch None -
pinned vfcb846afff2d6979 supported valid None - pass attested
unpinned vfcb846afff2d6979 supported valid NOT_PUBLICLY_VERIFIABLE - pass unattested
```

The last two lines are one record. With the key pinned its row is attested and the report is clean; with no key the same bytes verify but nobody can say who observed them.

Three more recordings of the same files, each in a container started with `--network none` and each printing the same eight verdicts, sit beside it, so the page holds on the other interpreter and CPU architecture a stranger is likely to have: [TRANSCRIPT-py312-aarch64.txt](offline-verify/TRANSCRIPT-py312-aarch64.txt) (Python 3.12, arm64), [TRANSCRIPT-py313-aarch64.txt](offline-verify/TRANSCRIPT-py313-aarch64.txt) (Python 3.13, arm64) and [TRANSCRIPT-py313-x86_64.txt](offline-verify/TRANSCRIPT-py313-x86_64.txt) (Python 3.13, x86-64). Each header names the machine, the image digest, the Python it ran and the digest of the page folder, and the page test refuses a transcript whose folder digest is not the folder's current one. Make one with `IMAGE=python:3.13-slim sh scripts/offline-verify-run.sh`.

## Pin the verifier in your CI

Commit `requirements.txt`, `make_case.py` and `summary.py` from this folder at a release tag, and your key set, then run the check on every record your build produces or receives:

```yaml
jobs:
  verify-records:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install --require-hashes -r evidence/requirements.txt
      - run: python evidence/make_case.py --out cases --keys evidence/keys.json records/*.json
      - run: for c in cases/*.case.json; do agent-evidence-verify "$c" --policy cases/policy.json --artifact-root records --json > "${c%.case.json}.out.json"; done
      - run: python evidence/summary.py cases
```

To replay the conformance corpus against a verifier of your own in the same workflow, add the [GitHub Action](runner.md), pinned to a tag.

Let Dependabot propose each new verifier release as a pull request your CI tests, so a pin never goes stale and never moves without a green run. Add to `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: /evidence
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

A new verdict code, or a code moved between verdict codes, ships as a minor release, never a patch, so a bump that can turn your gate red says so in its version.

## What an offline check establishes

| An offline check establishes | It does not establish | It needs no trust in |
| --- | --- | --- |
| The bytes are a well-formed statement of predicate version 0.7, read under the strict I-JSON profile | That a key in your set belongs to the party you think: that is your key set's provenance | The agent that was observed |
| Every carried observation record hashes into the signed batch root, with none added, removed or duplicated | That the observer saw everything the agent did, beyond the coverage the record declares and the verifier checks | The party that handed you the record, for every row attested under your keys: altering it breaks a hash, the root or a signature |
| The stated result equals the result recomputed from the rows | That the record is the latest one, or that no other record was withheld: offline means no log, no revocation list and no freshness check | Any network, service, account or licence |
| Each substrate row's covering records are signed by a key in your set, or the row is reported `unattested` | That `issuedAt` is the true time: it is what the signer wrote | The issuer being online, or still existing |
| A claim that disagrees with its sealed record is caught and named | That the verifier wheel is sound: the hash pin proves these are the published bytes, and whether to trust that release is your decision | |

To check the release itself, the signed digest list and its timestamp proofs, follow [Release verification](../reference/release-verification.md). To carry the whole corpus and verifier into an air-gapped enclave as one signed bundle, use the [enclave guide](airgap-enclave.md).
