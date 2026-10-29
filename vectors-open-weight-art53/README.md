# Open-weight release vectors (AI Act Article 53(2))

Cases for `open-weight-art53/v1`: a model release record and the decision a checker must reach on
whether the record evidences the conditions of Article 53(2) of Regulation (EU) 2024/1689. The
article lifts the obligations of Article 53(1), points (a) and (b), from providers of models "released
under a free and open-source licence that allows for the access, usage, modification, and
distribution of the model, and whose parameters, including the weights, the information on the model
architecture, and the information on model usage, are made publicly available", and adds that "this
exception shall not apply to general-purpose AI models with systemic risks". It gives the row of the
[CRA and AI Act table](https://github.com/orcwg/cra-hub/pull/364) that had no test a third party could
run one. This is a check of what a record carries, not legal advice and not a finding about any
real model.

Three answers: `exempt` (every condition is evidenced), `not-exempt` (the record shows a condition
failing) and `not-established` (the record is silent, so nothing can be said). Silence never passes.

| Case | Expected | Reason |
| --- | --- | --- |
| exempt-open-release | exempt | all_conditions_evidenced |
| exempt-attribution-licence | exempt | all_conditions_evidenced |
| exempt-without-copyright-policy | exempt | all_conditions_evidenced |
| exempt-systemic-presumption-rebutted | exempt | all_conditions_evidenced |
| noncommercial-licence | not-exempt | licence_restricts_use |
| licence-not-recognised | not-established | licence_not_recognised |
| weights-private | not-exempt | weights_not_public |
| weights-gated | not-established | weights_access_gated |
| weights-without-digest | not-established | weights_not_digest_bound |
| architecture-missing | not-established | architecture_not_evidenced |
| usage-information-missing | not-established | usage_information_not_evidenced |
| monetised-by-personal-data | not-exempt | monetised_release |
| monetisation-not-stated | not-established | monetisation_not_stated |
| systemic-risk-presumed | not-exempt | systemic_risk_presumed |
| systemic-risk-designated | not-exempt | systemic_risk_designated |
| training-compute-not-stated | not-established | training_compute_not_stated |

Three cases carry the points a reader tends to get wrong:

- **An exempt provider is not free of Article 53(1)(c) and (d).** `exempt-without-copyright-policy`
  is exempt, and the answer reports that the copyright policy and the training-content summary are
  absent, because the exemption names only points (a) and (b).
- **Open weights alone do not qualify.** `systemic-risk-presumed` releases everything and fails on
  training compute above 10^25 operations (Article 51(2)); a recorded Commission decision that the
  model is not systemic is the only thing that clears it.
- **A gated download is not established.** `weights-gated` is neither exempt nor refused: whether a
  sign-in wall is "publicly available" is a question for the authority, so the checker says what it
  cannot establish.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-open-weight-art53
```

To check your own release record (a JSON file shaped like `cases/exempt-open-release/release.json`):

```sh
python3 -m agent_evidence_vectors.openweight release.json
python3 -m agent_evidence_vectors.openweight release.json --require-exempt   # exit 1 unless exempt
```

To judge your own checker: a verifier takes `case.json --json`, prints one JSON object carrying
`decision` and `reason`, and exits 0 when it answered.

```sh
agent-evidence-vectors --corpus vectors-open-weight-art53 --verifier './verifier'
```

The checks run in a fixed order (licence, weights, architecture, usage, monetisation, systemic
risk), `not-exempt` outranks `not-established`, and the first finding of the winning class names the
reason. Regenerate the cases with `python3 vectors-open-weight-art53/gen_vectors.py`.

The reader never fetches a URL and never judges a licence in law: it checks an SPDX identifier
against a pinned list, that locators are `https`, that weights carry a SHA-256, and a stated training
compute. A consumer who holds a different list of recognised licences replaces the constants in
`openweight.py`. Source text of the Article and Recital 103: `docs/guides/cra-ai-act-open-weight.md`.
