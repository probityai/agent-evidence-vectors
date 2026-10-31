# Harness Watch import

Bring saved publisher rows into a pinned evidence bundle, then hand token
arithmetic to [Probity Verify](https://github.com/probityai/probity-verify).
The installed API and CLI preserve source versions, original row bytes,
per-field lineage and the publisher's platform labels.

[source-pins.json](source-pins.json) selects the original
[Harness Watch](https://github.com/piiiico/agent-errata/tree/e9a247004c84aa505e8df0dbfc5fbbdae5924298/studies/S003/watch)
population, baseline, definitions and reader revisions. Fetch those exact
files rather than copying the upstream implementation into this repository.

```sh
python -m pip install .
python fetch_sources.py --output .build/upstream
probity-watch-import .build/upstream --sources source-pins.json \
  --output .build/import
```

The source manifest is consumer-held input. Each file's length, SHA-256 and
Git blob identity are checked before row parsing. Raw JSON admission rejects
duplicate keys, non-scalar strings, non-finite numbers and oversized input.
Source pins describe selected bytes; the host establishes publisher identity
and capture provenance.

Instruction arms compare token membership. Symlink arms compare occurrence
counts, while retaining the publisher's order-sensitive comparison separately.
Reordered tokens stay visible in raw rows and get their own result. Missing
baseline fields retain a visibility gap. Tool counts and platform changes
remain separate from instruction membership.

The output contains exact raw rows, an import report, field pointers and
candidate consumer policies for Verify's operand-lineage adapter. Verify
support covers arithmetic over importer-derived token projections. The host's
capture evidence establishes execution and effects. The original platform
change and unpinned tokenizer/runtime dependencies remain in the bundle.

The publisher's [planted selftest](https://github.com/piiiico/agent-errata/issues/7)
keeps that classification. `forced` alone means a requested measurement;
it does not classify a run as a selftest.

To qualify installed readers against the retained source pins:

```sh
python -m pip install -r requirements-check.txt
python fetch_sources.py --verify-source --output .build/verify-source
python -m pip install --no-build-isolation --target .build/installation .
python -m pip install --no-build-isolation --target .build/verify-installation \
  .build/verify-source
PROBITY_VERIFY_ROOT="$PWD/.build/verify-installation" python test_import.py
python qualify.py --input-root .build/upstream \
  --installation .build/installation \
  --verify-installation .build/verify-installation
```

Qualification keeps the original population and synthetic mutation controls
separate. The native workflow retains raw rows, candidate policies, actual
reader output and source/runtime receipts. Installations and upstream source
implementation bytes remain fetchable through the manifest.
