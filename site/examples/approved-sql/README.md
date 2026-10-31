# Approved SQL example

This reader compares an approval, an application record, a database audit projection, and a later state observation.
It is for people who want to test whether those records agree before connecting a native export.

Use the locked development tools. The reader itself has no external dependencies.

```sh
uv sync --frozen --group dev
.venv/bin/python -m sql_illustration.check fixtures/matching-commit-later-change.json
```

The output includes `"result": "recorded_commit_matches"` and `"later_state": "supplied_state_differs"`.
That is the useful distinction: a later change does not erase an earlier matching execution record.

Version 0.1.0. The 17 fixtures are author-created examples. This source does not invoke Tadpole or a database.
The reader compares supplied records. It does not authenticate them or prove that an audit export is complete.

| Read next | Content |
|---|---|
| [Input contract](docs/INPUT-CONTRACT.md) | Fields, exact comparisons, outputs, and native input needed |
| [Source map](SOURCE-MAP.md) | Cho's case, pinned Tadpole source, and the actual native boundaries |
| [Design decisions](docs/architecture/DESIGN_DECISIONS.md) | Why SQL bytes, outcome, and later state stay separate |
| [Join the case](https://github.com/probityai/agent-evidence/issues/24) | Bring a native pair, another reader, or a check to keep |

## Other readers

`ogasurfproject-jpg` wrote a second reader from the input contract and the 16 fixture inputs alone, without
this reader, its tests or the manifest:
[`horizon-shield@5037ecf8`, `workers/hs-ledger/nenrin/approved-sql-reader-v0/`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/5037ecf8a2195f2f17f1b47ca3d2b5f49ea0a0e0/workers/hs-ledger/nenrin/approved-sql-reader-v0)
(`reader.py` sha256 `fc87a6ec...0fa0b86`, Python standard library only).
We ran it over the fixtures on 2026-10-23 with CPython 3.13.15. Against the manifest:

| Measure | Agreement |
| --- | --- |
| Exit code | 16 of 16 |
| `result` string, exactly | 4 of 16; the contract named only two results then, so the rest are the reader's own |
| Partition | Consistent: no two fixtures this reader separates fall in one manifest result |
| `later_state` | 15 of 16; it says `changed` where this reader says `supplied_state_differs` |

Its two contract gaps, a literal reading that accepts `approval.granted: false` and a missing application
record, are now closed in the [input contract](docs/INPUT-CONTRACT.md), which lists every result.
The 17th fixture, `approval-not-granted-no-audit-match.json`, pins the one difference the new text exposed:
`approval.granted: false` and no matching audit record in a complete, matching scope. The contract checks the
join first, so it gives `no_match_in_declared_complete_scope`; the clean-room reader gives `approval_not_granted`.
Both exit 1.

`ogasurfproject-jpg` then moved the reader to the contract's result names, check order and `later_state` values in
[`horizon-shield@156d0db1`](https://github.com/ogasurfproject-jpg/horizon-shield/tree/156d0db10074ab44547832dbd415469d7666c95f/workers/hs-ledger/nenrin/approved-sql-reader-v0)
(`reader.py` sha256 `507238d9...`). He wrote it after seeing the manifest, so it is not clean-room, and
`5037ecf8` stays the clean-room reader. We ran it over the 17 fixtures on 2026-10-24 with CPython 3.13.15:
17 of 17 exit codes, `result` strings and `later_state` values.
Run either from this directory:

```sh
for f in fixtures/*.json; do [ "$(basename $f)" = manifest.json ] || { python3 <path>/reader.py "$f" > /dev/null; echo "$(basename $f) $?"; }; done
```

Cho HyunJong (`hangum`) supplied the case in [the Lab thread](https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247269344).
We own this illustration's fields and code. The producer owns its export semantics.
