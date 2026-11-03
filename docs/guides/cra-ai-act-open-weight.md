# Checking an open-weight model release against AI Act Article 53(2)

The proposed CRA and AI Act table in [orcwg/cra-hub#364](https://github.com/orcwg/cra-hub/pull/364) has an open-source meeting point. For a provider of an open-weight general-purpose AI model, Article 53(2) lifts Article 53(1)(a) and (b) but not (c) and (d), and it does not reach models with systemic risks. Whether a release qualifies depends on what was released: a free and open-source licence, public weights, public architecture and usage information, and a model that does not have systemic risks. A claim about public bytes can be tested against a record of those bytes.

This corpus tests such a record today: [`vectors-open-weight-art53`](../../corpora/vectors-open-weight-art53/README.md). It is a check of what a release record carries. It is not legal advice, and it reaches no conclusion about any real model.

## What the Article says

EU AI Act, Article 53(2): "The obligations set out in paragraph 1, points (a) and (b), shall not apply to providers of AI models that are released under a free and open-source licence that allows for the access, usage, modification, and distribution of the model, and whose parameters, including the weights, the information on the model architecture, and the information on model usage, are made publicly available. This exception shall not apply to general-purpose AI models with systemic risks."

Points (a) and (b) are the technical documentation for the AI Office and the information for downstream providers. Points (c) and (d), the copyright policy and the public training-content summary, are not exempted. Two other texts bound the exemption: Article 51(2) presumes high impact capabilities above 10^25 floating point operations of training compute, and Recital 103 withholds the exceptions from AI components provided against a price or otherwise monetised, including through personal data used for reasons other than exclusively improving security, compatibility or interoperability, with an exception for transactions between microenterprises.

## What it checks

A provider (or a reviewer, or an integrator) writes a small JSON record of public locators for a release. The checker reads six conditions and answers `exempt`, `not-exempt` or `not-established`:

| Condition | What the record must carry |
| --- | --- |
| licence | an SPDX identifier on the pinned open list, none of the restricted ones (non-commercial, no-derivatives) |
| weights | `access: public`, an `https` locator and a SHA-256 over the weights |
| architecture | an `https` locator |
| usage | an `https` locator |
| monetisation | an explicit empty list of monetisation conditions |
| systemic risk | stated training compute at or below 10^25, no Commission designation, or a recorded Commission decision that the model is not systemic |

Silence never passes. A missing field is `not-established`, a visible failure is `not-exempt`, and a failure outranks a gap. The answer also reports whether the record carries the copyright policy and the training summary, because the exemption leaves them in force.

## Run it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-open-weight-art53
python3 -m agent_evidence_vectors.openweight release.json --require-exempt
```

The first command runs the packaged cases through the reference reader. The second judges your own record and exits 1 unless it is `exempt`, so it works as a CI step in the repository that publishes the model. A record looks like `corpora/vectors-open-weight-art53/cases/exempt-open-release/release.json`. To judge another checker: `agent-evidence-vectors --corpus vectors-open-weight-art53 --verifier './verifier'`.

## What it does not check

- It fetches nothing. A locator that returns 404, or weights whose bytes differ from the digest, are for a second tool; the record binds the digest so that tool has something to compare.
- It does not decide that a licence is free and open-source in law. It compares an identifier with a pinned list, and the list is a parameter a consumer replaces with its own.
- It does not decide that a model is a general-purpose model or that it has systemic risk. That is the Commission's. The checker reads the compute the provider states and the Commission decisions the provider records.
- A gated download is reported `not-established`: whether a sign-in wall is "publicly available" is for the authority.
- It does not decide who the provider is, or whether CRA steward duties or the AI Act Article 2(12) exclusion apply. Those turn on the actor and the product.
- The text of the Article above was compared with the [Official Journal text of Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) on 2 November 2026.

## Recording activity

The table's recording meeting point has its own guide: [Checking an AI Act log after the fact](cra-ai-act-logs.md).
