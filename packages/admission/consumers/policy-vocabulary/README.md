# Host-selected report publication

Decide whether to publish a retained model report and whether its model meets your quality rule. This guide is for CI owners who need to repeat those decisions without a model runtime.

A report can be fit to publish even when its answers fail. Every output in the selected report meets the format and schema. The answers still fail the host's quality rule.

| Check on the selected report | Decision | Exit code |
| --- | --- | --- |
| Publish the report within its stated scope | `publish-scoped-report` | 0 |
| Admit the model configuration | `hold-quality` | 1 |
| Authorize a tool action | `hold-no-effect-authorization` | No effect command exists |

All 128 attempts finished. The broad-schema control gets 4/64 answers correct; the shared vocabulary gets 18/64. All eight rows fail the host's quality rule. The [reference](REFERENCE.md) keeps the exact rule, source selection and limits.

## Run the receiving project's gate

Pin this consumer to reviewed commit `bbff435d11a7c0ec9bc0e8e65e6d8fc40c10b671`. Run from that repository's root on Linux with Python 3.12 or later, Git and Python's `venv` module. Run the download in the main thread with no other active alarm timer.

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

The last command returns `publish-scoped-report` for this selected archive. Run the separate quality check before an admission step:

```bash
host-tools/bin/python -I -B consumers/policy-vocabulary/consumer.py evaluate \
  reader-installation original-native.zip quality-decision --purpose model-quality
```

That command returns `hold-quality` and exits 1. A valid report format does not admit model quality or authorize an effect.

This is a first-party consumer placement. Its CI check covers the selected publication decision and expected quality refusal. Outside adoption and independent custody remain separate.

| Next task | Exact instructions and contract |
| --- | --- |
| Check the source selection, archive and host limits | [Full reference](REFERENCE.md) |
| <a name="place-the-gate-in-another-project"></a>Put the gate before a publication or admission step | [Place the gate in another project](REFERENCE.md#place-the-gate-in-another-project) |
| <a name="replace-or-upgrade-a-selection"></a>Review a new report or reader | [Replace or upgrade a selection](REFERENCE.md#replace-or-upgrade-a-selection) |
