# APS and PriorSeal source replay

This is Probity's October 1 reproduction of the pinned Frequency review adapter. It checks that the adapter read the APS owner fixtures at their declared commit, that PriorSeal's copy matches all 17 declared fixture files, and that a fresh run gives the recorded claim results. It also retains failed runs for a changed copy, missing owner, omitted owner argument and stale report.

The verifier here is the [Frequency review adapter](https://github.com/altrudev/Frequency-Federation-Review/tree/4162622af24c94efb843f53aa27940ffd1256ad6/capsules/aps-priorseal-v0.1), executed without modification. This reproduction is distinct from [Probity's earlier independent E2 checker](https://github.com/probityai/agent-evidence-vectors/tree/00f5acab880bffc5ee8fe124f3a015d3ed970514/interop/aps-priorseal-e2-2026-09-30), which did not exercise the PriorSeal signature checks. The two results answer different questions.

## Inputs and result

| Input | Revision or SHA-256 |
| --- | --- |
| Frequency review capsule | `4162622af24c94efb843f53aa27940ffd1256ad6` |
| Adapter `verify.mjs` | `5f5cc203c921ecd576b81ee5d22063d39efc3ec74cc0b3aa75d1e41916e5cad3` |
| Adapter lockfile | `2ca396b3f9b357f5a79e3c6ff7d6dbd9d33ee179c5132792608a8e330e014c7a` |
| APS owner fixtures | `aeoess/agent-passport-system@948f99b85343bef2c6fa677c8543965caacfc087` |
| PriorSeal copied fixtures and observations | `imokokok/PriorSeal@d749d2691c3e6be139de4020e7b27cdafca2c428` |
| Owner and copy manifest | `2bf365bc9124ecfc943d5be86c34e8e0cacd51a5929b8d0c906e633a017231f9` |

The clean run produced 14 `ESTABLISHED`, 3 `CONTRADICTED` and 5 `NOT_ESTABLISHED` claims. The three contradictions are the expired decision's validity at the fixed reference time and the over-limit observation's exact-call and cap checks. The five unresolved claims cover live-chain execution, decision single use, live currency enforcement, an independently operated witness and production adoption. The declared positive and over-limit observations are producer fixtures. The adapter's Ed25519 and EIP-712 signature checks validate bytes against its preselected public test keys. They do not establish the real-world identity or custody of those keys, a chain effect, or independent observation.

Changing a copied fixture byte exits 1 without a report. An absent owner root exits 1 without a report; omitting `--aps-owner` exits 2. A failed run does not remove a report already at the output path. The replay therefore accepts a result only if the process exits zero **and** the output path was absent before the run and exists afterward.

## Run from clean checkouts

Use Node.js 20 or later, npm and Git. From this repository's root:

```sh
set -eu
replay_dir=$(mktemp -d)
git clone https://github.com/altrudev/Frequency-Federation-Review.git "$replay_dir/capsule"
git -C "$replay_dir/capsule" checkout --detach 4162622af24c94efb843f53aa27940ffd1256ad6
git clone https://github.com/aeoess/agent-passport-system.git "$replay_dir/aps"
git -C "$replay_dir/aps" checkout --detach 948f99b85343bef2c6fa677c8543965caacfc087
git clone https://github.com/imokokok/PriorSeal.git "$replay_dir/priorseal"
git -C "$replay_dir/priorseal" checkout --detach d749d2691c3e6be139de4020e7b27cdafca2c428
(cd "$replay_dir/capsule/capsules/aps-priorseal-v0.1/adapter" && npm ci --ignore-scripts --no-audit --no-fund)
node experiments/aps-priorseal-source-replay/run.mjs \
  --runner https://github.com/OWNER/REPOSITORY \
  "$replay_dir/capsule" \
  "$replay_dir/aps" \
  "$replay_dir/priorseal" \
  "$replay_dir/result"
```

`result` must not exist before the command. `run.mjs` checks the Git revisions, adapter and lockfile, manifests, payment inputs and producer report by digest before it starts the adapter. It runs the adapter self-test and five cases, then checks all 22 claim states and writes `clean.json`, `receipt.json` and the stale-output control in the new output directory. The failed controls create no new report. Keep the generated directory out of Git; the public package contains no copied third-party implementation, fixtures or full adapter report.

`recorded.json` contains the SHA-256 of one locally generated report. The adapter includes a generation time, so a fresh run's report digest changes; the replay compares claim results and case outcomes, not that historical digest. The runner pins the adapter source and lockfile, while the documented `npm ci` installs dependencies. It does not independently attest the installed `node_modules` tree or Node runtime bytes.

The dedicated GitHub workflow repeats this procedure with Node 20 when this experiment changes. It retains Probity's `receipt.json` and a separate run-contract record as CI artifacts; the source checkouts and full generated adapter report stay within that job.

## Pinned run contract

The [Frequency review wrapper at `b12879d`](https://github.com/altrudev/Frequency-Federation-Review/blob/b12879d5878991d9c3ed260d06ee11716eb99d33/capsules/aps-priorseal-v0.1/run-pinned.sh) is a separate execution path from the adapter replay above. `check-run-contract.mjs` pins the wrapper bytes and runs it against the same pinned producer checkouts with stubbed `npm` and `node` commands. In three controls, a failed Node command, a failed dependency install and a successful command that writes no report, the wrapper exits zero, records zero and prints `PASS` without a report. Probity rejects each as a usable run because there is no fresh report. The record includes the injected exits and observed wrapper behavior. No adapter assertion or producer claim is evaluated by these stubs.

To reproduce from the repository root, use the APS and PriorSeal checkouts from the command above:

```sh
git clone https://github.com/altrudev/Frequency-Federation-Review.git "$replay_dir/review-wrapper"
git -C "$replay_dir/review-wrapper" checkout --detach b12879d5878991d9c3ed260d06ee11716eb99d33
node experiments/aps-priorseal-source-replay/check-run-contract.mjs \
  --runner https://github.com/OWNER/REPOSITORY \
  "$replay_dir/review-wrapper" \
  "$replay_dir/aps" \
  "$replay_dir/priorseal" \
  "$replay_dir/contract-result"
```

The output directory must be new. This control describes the pinned wrapper only. The main replay invokes the adapter directly and requires a zero exit and a newly written report before it accepts any result.

## Caller declaration and current records

Replace `https://github.com/OWNER/REPOSITORY` with your caller identity in both commands.
Put exactly one `--runner` option before the four path arguments.
The identity must contain 1 to 512 UTF-8 bytes, without outer whitespace, control characters or line separators.
The tools refuse missing, repeated or unknown options before they inspect source checkouts or create output.
They do not infer the caller from a publisher, Git origin, environment or earlier record.

New outputs use `probity.aps-priorseal-source-replay/v2` or `probity.aps-priorseal-run-contract/v2`.
`scope.runner` contains `identity` and `source: "caller-declared"`.
This is your declaration, not proof of an authenticated identity or independent operator.
`harness.files` retains the SHA-256 of the entrypoint and `runner.mjs` helper files read at invocation.
These hashes bind local source bytes at invocation. They do not authenticate their publisher or attest the runtime.
The replay also checks and records the unchanged `recorded.json` baseline digest.
Historical records keep their original schemas and bytes.

Each case also retains the child command, actual exit, signal, and raw stdout/stderr before assertions.
The record binds those files by size and SHA-256. Each `process.files[].path` is relative to the record's directory.
The replay retains its adapter self-test the same way.
The tools mark a spawn or capture error incomplete and refuse a successful record.
The public CI artifact keeps `result/receipt.json` and `contract-result/record.json` with their sibling process logs.
Curated control records and their streams stay under `caller-controls/public-results/`, preserving their relative layout.
The control ledger's stream paths are relative to its own directory.
`caller-controls/public-artifact-manifest.json` uses `probity.aps-priorseal-public-artifact/v1`.
Its `base_directory: "public-results"` is relative to the manifest's parent; every `files[].path` is relative to that base.
The manifest binds each selected regular file by size and SHA-256. The pinned uploader explicitly includes these bounded hidden paths.
Full adapter reports and third-party checkouts remain within that job's bounded technical review.
The public artifact copies only checked regular files. It follows no test links into producer checkouts.

The wrapper record and stdout use `meetsRunContract`.
It is true only when the wrapper exits zero, its retained exit is zero, and a previously absent report path exists afterward.
It does not mean that Probity admitted a result or that the report is valid.
The supplied wrapper controls all lack a fresh report, so this predicate is false.

## Use copied tools outside an Atlas checkout

Select one published 40-character Atlas commit and retain that selection.
Download `runner.mjs` beside the entrypoint from that same commit.
For `run.mjs`, also download the unchanged `recorded.json` data file from that commit.
Retain and verify the source hashes before invocation against the source you selected.
The baseline data must have SHA-256 `4d94934e711610fba6d8156752ed91f55788b3c10aeab697ad166a3825cbf65a`.
The copied files need no Atlas Git checkout, local package install or optional import helper.
Both commands use the same pinned producer checkouts described above.

```sh
set -eu
# Set atlas_revision to the published commit you selected.
copied_tools=$(mktemp -d)
for file in run.mjs check-run-contract.mjs runner.mjs recorded.json; do
  curl --fail --location \
    "https://raw.githubusercontent.com/probityai/agent-evidence-atlas/$atlas_revision/experiments/aps-priorseal-source-replay/$file" \
    --output "$copied_tools/$file"
done
(cd "$copied_tools" && sha256sum run.mjs check-run-contract.mjs runner.mjs recorded.json)
node "$copied_tools/check-run-contract.mjs" \
  --runner https://github.com/OWNER/REPOSITORY \
  "$replay_dir/review-wrapper" "$replay_dir/aps" "$replay_dir/priorseal" \
  "$replay_dir/copied-contract-result"
node "$copied_tools/run.mjs" \
  --runner https://github.com/OWNER/REPOSITORY \
  "$replay_dir/capsule" "$replay_dir/aps" "$replay_dir/priorseal" \
  "$replay_dir/copied-replay-result"
```

Printing hashes retains a byte identity. Compare them with your selected trusted source before execution.
These commands do not authenticate an arbitrary copied tool merely because it prints a hash.

## Limits and next decisions

This is a local technical review of public producer fixtures, with the Frequency adapter's expected claims visible before the run. It is not answer-blind, an independent second verifier, the federation's formal pilot, mutation adequacy, commercial use, approval to publish a formal result, outside-operator custody or host-project adoption. A formal run needs its separately confirmed scope. The planned authenticity and decision-binding mutations need discriminating fixtures and a separate adequacy decision. An actual action/effect pilot needs an externally selected trust policy, live observation and a consumer decision bound to the observed bytes.

The capsule's [review-only notice](https://github.com/altrudev/Frequency-Federation-Review/blob/4162622af24c94efb843f53aa27940ffd1256ad6/REVIEW-ONLY-NOTICE.md) permits technical review and reproducibility assessment, but withholds commercial incorporation and redistribution of modified or derivative Frequency implementations. This runner invokes that repository by reference. It copies none of its implementation or fixtures and makes no partnership or endorsement claim. The APS fixtures are from an Apache-2.0 repository; PriorSeal's repository uses MIT. Their own notices govern their bytes.

## External runs of the run-contract vector

- Agent Errata (`piiiico`, an AI agent operated by Hakon Amdal) ran `check-run-contract.mjs` at `89250120`
  unmodified on a GitHub-hosted runner, against the wrapper `run-pinned.sh` at `b12879d5`. All three
  injected-failure cases matched the vector: the wrapper exits 0, records 0 and prints `PASS` with no report.
  The artifact is retained on [run 37404021921](https://github.com/piiiico/agent-errata/actions/runs/37404021921),
  and the full record is [atlas#43](https://github.com/probityai/agent-evidence/issues/31). It covers that
  wrapper revision only, not the corrected runner at `cf738909`.
