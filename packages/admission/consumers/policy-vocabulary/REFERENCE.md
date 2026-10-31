# Host-selected report publication

This consumer lets a receiving project decide whether to publish a retained model report or admit its model quality. It installs a separately selected reader, authenticates the original packet, and repeats the decision without a model runtime.

The checked-in host selection binds Observer commit `62f5d0c6fbd785259db2d5c8076dd844b53a0593`, nine source files at full commits, the source contract, the builder, four packet commitments and the complete original archive. The archive comes from an immutable Atlas commit. An Actions download token is unnecessary.

## Run the receiving project's gate

Use Linux, Python 3.12 or later, Git and Python's `venv` module. The standalone download command uses `SIGALRM`; run it in the main thread with no other active alarm timer. The host owns its Python interpreter, installed build tools, repository checkout and selection file.

Pin this consumer to a reviewed commit before execution. Install the selected build tools in a private host environment:

```bash
python3 -I -m venv host-tools
host-tools/bin/python -I -m pip install --only-binary=:all: --require-hashes \
  -r consumers/policy-vocabulary/build-tools.lock
git clone https://github.com/probityai/agent-evidence-observer.git observer-selected
git -C observer-selected checkout --detach 62f5d0c6fbd785259db2d5c8076dd844b53a0593
host-tools/bin/python -I -B consumers/policy-vocabulary/consumer.py install observer-selected reader-installation
host-tools/bin/python -I -B consumers/policy-vocabulary/consumer.py download original-native.zip
host-tools/bin/python -I -B consumers/policy-vocabulary/consumer.py evaluate \
  reader-installation original-native.zip report-decision --purpose publication
```

The last command publishes only this report's scope. Apply the distinct model-quality gate before admitting that model configuration:

```bash
host-tools/bin/python -I -B consumers/policy-vocabulary/consumer.py evaluate \
  reader-installation original-native.zip quality-decision --purpose model-quality
```

| purpose | selected original result | exit code |
| --- | --- | --- |
| publication | `publish-scoped-report` | 0 |
| model-quality | `hold-quality`; all eight rows fail the host's quality rule | 1 |
| any effect | `hold-no-effect-authorization` | no effect command exists |

All 128 attempts finished. All outputs meet their format and schema. Quality still fails: the broad-schema control gets 4/64 answers correct; the shared vocabulary gets 18/64. The host demands all sixteen answers and all eight pairs in every row. These two token caps return the same outputs, so they are not independent samples.

## Place the gate in another project

Copy this reviewed consumer directory and its checked-in selection into the receiving project's repository. Adapt [the complete job](../../../../.github/workflows/package-admission.yml) to the host's CI. Put the `evaluate --purpose publication` command before the report publication step. Let its nonzero exit stop publication. Use `--purpose model-quality` before an admission step; the selected original must stop that step.

The packet's convenience pins do not change the host's selection. The authenticated archive is held in one bounded buffer before extraction. Paths, member population and regular files are checked. Reader execution uses a fresh private copy of selected installed sources. Candidate helpers, cached bytecode and Python startup files cannot choose the reader code. The source hashes do not authenticate the host's Python binary or operating system.

The private library and Python site each contain at most 128 entries. The installation receipt is at most 65,536 bytes. The reader namespace contains exactly the selected flat files. Each installed source is at most 1,048,576 bytes. The host checks the opened input's regular file type and bounds its read. It refuses excess entries, nested directories, pipes and larger inputs before import. Review these host limits with any future consumer selection.

This repository's job runs on relevant changes, manual dispatch and a weekly schedule. A green check confirms the selected report's publication scope and expected quality refusal. It does not authorize model quality or an effect. This is a first-party consumer placement; outside adoption and independent custody remain separate.

## Replace or upgrade a selection

Review a new source contract, its full source commits, builder, complete archive and four packet commitments against primary records. Record the reviewed changes in the receiving project's `host-selection.json`. The quality rule stays all sixteen answers and all eight pairs per row.

Build into a new installation directory. Run `verify_native.py` against the host's selected packet to check the original's expected decisions, repeat, mutations and fresh replacement. That verifier fixes this original's population and weak-quality result; a new experiment needs a reviewed verifier for its declared result. Do not change the old verifier until the new population and expected decisions are reviewed. Keep both selections and their receipts until the new installation passes. Change the host's CI pin through normal review, then remove the old installation.

```bash
host-tools/bin/python -I -B consumers/policy-vocabulary/test_consumer.py
host-tools/bin/python -I -B consumers/policy-vocabulary/verify_native.py \
  --observer-checkout observer-selected --archive original-native.zip --output host-checks
```

The native check uses two fresh installed readers, repeats the original, refuses changed source, archive, terminal, candidate helper and installed code, and checks an executable poisoned bytecode control. A fresh replacement restores the selected decision. It also checks unselected directories, symlinks and CLI failure propagation. The host reader makes zero model calls and executes zero effects. Original model resources and this host's replay resources have separate fields.
