# Corpus and methods section for the v0.1 reporting-format paper

This directory holds the corpus section offered for the paper proposed on the
public-agent-conformance list
([2026Oct/0005](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0005.html)),
with the commands that recount every number in it. The v0.1 text is a draft of
that community group, not a W3C standard. The LaTeX form of the section is
[`corpus-section.tex`](corpus-section.tex).

## 1. Pinned inputs

Three populations are cited. They are counted separately and never added together.

| | A. Emitted report, 272 records | B. Report corpus, 235 members | C. Section 10 selection, 165 members |
| --- | --- | --- | --- |
| What it is | a v0.1 report the reference emitter wrote from the AEE vector corpus | the conformance corpus `vectors-w3c-report` that section 10 of v0.1 points at | the members of B a v0.1 implementation must judge: subjectType `report`, every requirement `agreed` |
| Producer | `agent-evidence-vectors` 0.12.0, source commit `2f3aee40a454df6de0f571d119f057d7dbb8dd67` | `agent-evidence-vectors` 0.17.4, tag commit `99b47c56b5e81760e1eadfc874949d56bca8d522` | as B |
| Package hash | wheel `agent_evidence_vectors-0.12.0-py3-none-any.whl`, sha256 `cb346a41f715029f8e68542150560b08a71ac23eb7660eaa411aea4fd2ec1f59` (PyPI) | corpusDigest `f00d4443f14881b4102693da0b73ecc7524b7410aec25fe9dbef077e7f73f1fe`, listed in the signed `release/CORPUS-DIGESTS.txt` of v0.17.4 | as B |
| Checker and configuration | reference rail, suite `vectors`, predicateType `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`; CPython 3.14.3, Linux x86_64 | Python reader `agent_evidence_vectors.w3creport`, with Go and Rust readers held to the same verdicts by a parity gate | as B |
| Command | `uvx agent-evidence-vectors==0.12.0 --emit-w3c-report report.json` | `uvx agent-evidence-vectors==0.17.4 --corpus vectors-w3c-report` | `python3 -I recount.py selection MANIFEST.json` |
| Output hash | `report.json` `37288d8dfc01f56cb5ef553232258dc596928bc962e2309e0c7dc09ae588baf2`; `conformance-report.json` `ee349e66697a2f4f95dd8223fd261810f99f5f2807e03bde03c9a9f57359529d`; `RUN.json` `00007b271fd027a5c952c17a8100190b8af360929f906936be352bb806c97448` | `MANIFEST.json` at v0.17.4 `de9a261d55e995fac3783b71fef90eaedb04790e5b4db849fbe01d4645f7a873` | as B |
| Where the bytes are | [`vectors-w3c-report/observed/aee-v0.12.0/`](https://github.com/probityai/agent-evidence-vectors/tree/v0.13.0/vectors-w3c-report/observed/aee-v0.12.0) at tag v0.13.0 (0.12.0 ran it; 0.13.0 was the first release to publish it) | [v0.17.4](https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.17.4) | as B |
| Case statuses | report states: 239 fail, 31 pass, 2 inconclusive. By fixture kind: 209 reject to fail, 30 accept to fail, 31 accept to pass, 2 indeterminate to inconclusive. Every record carries annotation `harness-status: PASS`. The conformance report beside it: 272 vectors, 272 pass, 0 fail, 272 conform, and `no external verifier supplied; using the reference rail` | 169 report, 44 agent-run-metrics, 22 llm-context-discovery | 83 reject, 82 accept |
| Code authorship | corpus, emitter and reference rail: Sankalp Gilda | corpus and the three readers: Sankalp Gilda | as B |
| Operators | Sankalp Gilda (runs of 24 and 25 September 2026, both recorded in `RUN.json`); Nicolás Rocchia re-ran the same command on another machine and got byte-identical `report.json` and `conformance-report.json` ([2026Sep/0089](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0089.html)) | Sankalp Gilda | Sankalp Gilda; the selection was posted in [2026Oct/0022](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0022.html) |
| Claim ceiling | the published bytes are what the pinned release produces, on two machines and by two operators. It is the same code run twice. It does not show that the reference reader is right, and it says nothing about any agent's safety | the corpus is judged as declared by readers that one person wrote | as B |

What the 239 are. A record's state is the v0.1 state the emitter mapped from the
fixture it replayed: a reject fixture is built to be refused, so its record reads
fail, and 30 accept fixtures declare a result of fail (27) or degraded (3). The
239 are fixture report states. They are not failed executions, not incidents
and not product defects; the conformance report over the same 272 fixtures counts
272 passing executions. A count of fail records without its outcome type
changes what the number means.

Other producers are kept in their own rows and are not pooled with A, B or C:
EATF-MultiRoot (Anton Sokolov: 48 run checks, 44 controls from 192 mutants, 12
of them resting on the code-to-check mapping; re-runs by Roel Schuurkes and
Nicolás Rocchia, 2026Oct/0060 to 0062 and 0076), disensor (Nicolás Rocchia: 70
declarations, 61 controls; re-run by Roel Schuurkes, 2026Oct/0063 to 0065),
Assay (Roel Schuurkes: the conservative report, 2026Oct/0016 and 0024) and the
AgentAvow implementations Kenne Ives offered (2026Oct/0010). Each producer's
numbers, operators and limits belong to its own section.

Recount A from the tagged files:

```bash
B=https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.13.0/vectors-w3c-report/observed/aee-v0.12.0
curl -sSfO $B/report.json && curl -sSfO $B/conformance-report.json
python3 -I recount.py report report.json conformance-report.json
```

Recount B and C:

```bash
curl -sSfo MANIFEST.json https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.17.4/vectors-w3c-report/MANIFEST.json
python3 -I recount.py selection MANIFEST.json
```

The later corpus at v0.18.1 has 269 members. It is a different population and
none of the numbers above is projected onto it.

## 2. Section text

**Corpus.** The section reports three populations, kept apart because each
answers a different question. The first is a report the reference emitter wrote
in the v0.1 format from the AEE vector corpus: `agent-evidence-vectors` 0.12.0
(source commit 2f3aee4, wheel sha256 cb346a41...), run with
`uvx agent-evidence-vectors==0.12.0 --emit-w3c-report report.json`. It holds
272 per-check records: 239 fail, 31 pass and 2 inconclusive, with the roll-up's
negative-capable field reading shown-by-run. These states describe fixtures,
not executions. Of the 239, 209 are reject fixtures, built to be refused, and 30
are accept fixtures whose declared result is fail or degraded. Every record also
carries the harness annotation PASS, and the conformance report written in the
same run counts 272 vectors, 272 passing and 0 failing, with no external
verifier supplied. The same 272 fixtures thus carry 239 negative report states
and 272 successful conformance executions. A fail count reported without its
outcome type would read as 239 failures, and it is not.

**Reproduction.** The report was run twice by its author (24 and 25 September
2026) with identical bytes, and once by a second operator, Nicolás Rocchia, on
another machine with CPython 3.13.7 and an empty package cache, who obtained
byte-identical report.json and conformance-report.json (sha256 37288d8d... and
ee349e66...). This establishes that the published files are what the pinned
release produces. It is the same code run by two operators; it does not show
that the reference reader judges the format correctly.

**Conformance corpus.** Section 10 of v0.1 points at the `vectors-w3c-report`
corpus at `agent-evidence-vectors` 0.17.4, whose corpusDigest f00d4443... is
listed in the release's signed CORPUS-DIGESTS.txt. It has 235 members: 169 of
subjectType report, 44 for the run-metrics draft and 22 for the
context-discovery draft. The selection section 10 names, members of subjectType
report whose requirements are all agreed, is 165 members: 83 to reject under a
named row and 82 to accept. The corpus, its three readers (Python, Go, Rust,
held to one verdict per member by a parity gate) and the selection have one
author.

**Claim ceiling.** These results show that the v0.1 format can carry a 272-record
report whose bytes reproduce across machines and operators, and that a
235-member corpus exercises its rejection table. They do not show that any
reader other than the author's agrees, that the format is complete, or anything
about the safety of an agent. A reader written by someone else, run at the same
corpusDigest, is the open test.

**One-variable claim-downgrade experiment (run by the corpus author).** v0.1
prescribes three outcomes when an evidence link behind a claim is weakened:
refuse (rows 11 to 14, the 5.4 conditions), read as unchecked when a reference
does not resolve (section 3), and leave a control's binding unread when either
side does not declare it (5.4, with O7 open). We built three accepted base
reports: a fail record with other-verdict and discrimination demonstrated by one
evidence object of two digest-referenced observations; an all-pass run naming a
failed control under the run's checker and constraint set; and an all-pass run
naming a prior discriminating run. We then changed one evidence link at a time,
22 cases in all, re-sealing the roll-up and check-set binding each time so that
the link was the only variable, and ran the Python reader of
`agent-evidence-vectors` 0.18.1 (wheel sha256 3953c8ab...) with and without a
resolution store, and the Rust reader of the same tag in its report mode, which
resolves nothing. Each refusal the text prescribes fired under one named row
when the store was supplied: 13 of 22 cases. Two of those 13 (a mismatched
observation digest, and a resolved body under the cited digest whose verdict no
longer differs) were refused only by the reader holding the store; the reader
without it, and the Rust reader, accepted them. In 5 cases the text prescribes a
weaker claim (a reference that does not resolve, twice; a control with no
binding on either side, twice; a prior run whose reference cannot be obtained),
and every reader's output was byte-identical to its output on the verified base.
The format has no field in which a reader reports that a claim stands
unchecked or unbound, so a consumer cannot tell those five from a verified
claim. This was run by the author of both readers, who also built the bases;
it shows what these two readers do, not what a reader written by someone else
does, and the 22 cases are constructed, not drawn from producers' reports.

## 3. The experiment

[`claim-downgrade/`](claim-downgrade/) holds the script, the box runner and the
results. Run it from a checkout of this directory:

```bash
bash claim-downgrade/run.sh
```

`run.sh` installs `agent-evidence-vectors==0.18.1` under its PyPI sha256
(`3953c8ab3c48f3e8b6d1779c2eafacb997f0336555ea0e1e6a83056fe2c5755f`), builds
`readers/w3c-report-rs` from tag v0.18.1 with `--locked`, runs the 22 cases and
prints the sha256 of `results.json`. The recorded run is in
[`claim-downgrade/results.json`](claim-downgrade/results.json) (sha256
`695e664deab4b36bd6794b1d101780bdbced6d1e3af9a7f15ebad9855ee930b5`), made on
2026-10-13 with CPython 3.13.15 on Linux x86_64; the Rust binary built from
v0.18.1 (commit `33d545104ff2f8c124cff465c96c013eeb809156`) had sha256
`bd89ad2fbe7d704d5c67689523c52203bb92c011f9e4b067c400ad1ca7a7e383` on four
separate builds. A later run of the script exactly as committed here wrote the
same `results.json` bytes.

| Base | Case | Variable changed | v0.1 says | Python, store supplied | Python, no store; Rust | Claim status | Output same as base |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | 0 | none | 3 line 1 | accept | accept | verified | (base) |
| B1 | 1 | reader holds no store | 3 line 3 | accept | accept | unchecked | yes |
| B1 | 2 | observation digest differs from resolved bytes | 3 line 2 | W3C-R-020 | accept | refused | no |
| B1 | 3 | one observation does not resolve | 3 line 3 | accept | accept | unchecked | yes |
| B1 | 4 | discrimination cites a missing evidence id | row 11 | W3C-R-011 | W3C-R-011 | refused | no |
| B1 | 5 | discrimination cites no evidence | row 11 | W3C-R-011 | W3C-R-011 | refused | no |
| B1 | 6 | a referenced observation carries no digest | row 14 | W3C-R-026 | W3C-R-026 | refused | no |
| B1 | 7 | evidence leaves the checker unpinned | 1.3 | W3C-R-024 | W3C-R-024 | refused | no |
| B1 | 8 | evidence changed slot is the checker | row 12 | W3C-R-012 | W3C-R-012 | refused | no |
| B1 | 9 | resolved body no longer differs in verdict | row 13 | W3C-R-021, W3C-R-025 | accept | refused | no |
| B2 | 0 | none | 5.4 | accept | accept | verified | (base) |
| B2 | 1 | control checker differs from the run's | 5.4 | W3C-R-029 | W3C-R-029 | refused | no |
| B2 | 2 | control constraint set differs | 5.4 | W3C-R-029 | W3C-R-029 | refused | no |
| B2 | 3 | control declares no binding | 5.4, O7 | accept | accept | unbound | yes |
| B2 | 4 | run declares no binding | 5.4, O7 | accept | accept | unbound | yes |
| B2 | 5 | control state inconclusive | 5.4 | W3C-R-013 | W3C-R-013 | refused | no |
| B2 | 6 | control names an undeclared check | 5.4 | W3C-R-013 | W3C-R-013 | refused | no |
| B2 | 7 | control carries another operator | none | accept | accept | verified | yes |
| B3 | 0 | none | 5.4, 3 line 3 | accept | accept | unchecked | (base) |
| B3 | 1 | prior-run reference has no leaf count | 3.1 | W3C-R-015 | W3C-R-015 | refused | no |
| B3 | 2 | prior-run digest matches nothing obtainable | 5.4, 3 line 3 | accept | accept | unchecked | yes |
| B3 | 3 | prior run names undeclared checks | 5.4 | W3C-R-014 | W3C-R-014 | refused | no |

The claim-status column is computed by the script from the reading table; no
reader prints it, which is the finding. B2 case 7 is the negative control: v0.1
binds no operator, so nothing should change, and nothing did. The `W3C-R-`
identifiers are the corpus's requirement identifiers; `vectors-w3c-report/MANIFEST.json`
binds each to its v0.1 sentence by digest.
