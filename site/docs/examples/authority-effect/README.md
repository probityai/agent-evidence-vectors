# Keep authorization, execution reports and observations separate

Run the same supplied records through a signed-intent reader and an installed
coverage reader. The report keeps each conclusion separate. A matching target
cannot turn a missing observation into proof that an action ran.

```sh
uv sync --frozen --group dev --no-editable --python 3.14.7
bash scripts/run-gate.sh
```

The gate builds a wheel, installs that wheel, checks every packaged control and
retains the child stdout, stderr and exit. It also runs the installed Verify
reader through Vectors' external-process contract for selected text coverage.

Read one immutable case with a separately selected policy:

```sh
.venv/bin/probity-authority-effect-cases read authority_effect/fixtures/cases/matching-supplied-records.json --policy authority_effect/fixtures/policy.json
```

The [input contract](docs/INPUT-CONTRACT.md) defines every field and conclusion.
The [source map](docs/SOURCE-MAP.md) credits the submissions that motivated the
controls. Qualification results belong to the retained run, not this recipe.
The [literal-decision control](docs/FREQUENCY-CONTROL.md) separately covers the
complete supplied-claim table and refuses non-Boolean decision inputs. It compares
an observation with the requested effect; required post-refusal state stays separate.

The [PriorSeal control](controls/priorseal-tampered-intent.mjs) runs from the
pinned producer checkout. Copy it to `lab-tampered-intent-control.mjs`, use the
producer's locked dependencies with lifecycle scripts disabled, and run
`node lab-tampered-intent-control.mjs`. It checks the unchanged positive fixture
and a changed synthetic intent through both supplied reader paths.

Probity owns this synthetic reader and its controls. The records use public test
keys and supplied times, reports and observations. They establish no live
dispatch, independent observation, trusted time or commercial use.
