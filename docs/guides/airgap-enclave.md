# Run the verifier inside an enclave with no network

This is the one-page brief for a security or authorizing officer who must approve software that crosses into an air-gapped enclave. The offline bundle holds the pinned verifier, every shipped conformance corpus and the maintainer's signed digest list. Installing and running it needs no network, no package index, no licence server and no account.

## What is in the bundle

| Path | Content |
| --- | --- |
| `requirements.lock` | The exact release of `agent-evidence-vectors` and the SHA-256 of its wheel. The verifier has no runtime dependencies, so nothing else is fetched. |
| `wheels/` | The wheel, downloaded with `pip download --require-hashes`. It is pure Python, so one wheel serves every platform. |
| `corpora/` | The same corpora the wheel carries, unpacked so a reviewer can read them without installing. |
| `release/` | The signed digest list, the public key and the timestamp proofs of the release. |
| `SHA256SUMS`, `install.sh` | A digest for every file above, and the installer that checks them before it runs pip. |

## Steps

On the connected build host, with Python and pip:

1. Write the lock: `python3 scripts/airgap-bundle.py lock --version X.Y.Z --out requirements.lock`.
2. Check out the matching release tag, then build: `python3 scripts/airgap-bundle.py build --lock requirements.lock --out aev-airgap-X.Y.Z --release-dir release --tar`.
3. Move `aev-airgap-X.Y.Z.tar.gz` through your transfer process. Send the line in `aev-airgap-X.Y.Z.tar.gz.sha256` by a second channel, so a swapped tarball cannot carry its own matching digest.

Inside the enclave, with Python and its `venv` module:

1. Check the tarball against the digest that arrived separately, then unpack it.
2. Run `sh install.sh`. It checks `SHA256SUMS`, builds a fresh virtual environment, installs with `--no-index --find-links wheels --require-hashes`, and replays the default corpus.
3. Confirm the maintainer's signature on the digest list with a `cosign` binary you already trust: `cosign verify-blob --key release/cosign.pub --signature release/CORPUS-DIGESTS.txt.sig --insecure-ignore-tlog=true release/CORPUS-DIGESTS.txt`. [Release verification](../reference/release-verification.md) explains each proof.

## What an approver can rely on

- Any changed, missing or added file stops the install before pip runs. The wheel is then installed only if its hash equals the one in the lock.
- The installer never contacts a network. The tests build a bundle and install it with every network route pointed at a closed port, so a stray fetch fails the test.
- The verifier writes a local JSON report and nothing else. Nothing leaves the enclave.

## What it does not cover

- The Python interpreter and the `cosign` binary are not in the bundle. Bring in builds your enclave already trusts.
- A hash proves the bytes are the release's bytes. Whether to trust that release is your decision, and the key beside the corpus must still be selected through your own trust process.
- The bundle verifies conformance of a verifier against the corpora. It does not scan your agents or prove a particular run happened.
