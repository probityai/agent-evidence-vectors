# Checking an open-weight model release against AI Act Article 53(2)

The CRA and AI Act table in [orcwg/cra-hub#364](https://github.com/orcwg/cra-hub/pull/364) has a row for open-weight models exempt under Article 53(2) where nobody can check the provider's claim. The exemption is a claim about a release: a licence, weights, architecture and usage information that are public, and a model that is not classed as having systemic risk. A claim about public bytes can be tested against a record of those bytes.

This corpus gives that row a checker that runs today: [`vectors-open-weight-art53`](../../vectors-open-weight-art53/README.md). It is a check of what a release record carries. It is not legal advice, and it reaches no conclusion about any real model.

## What the Article says

EU AI Act, Article 53(2): "The obligations set out in paragraph 1, points (a) and (b), shall not apply to providers of AI models that are released under a free and open-source licence that allows for the access, usage, modification, and distribution of the model, and whose parameters, including the weights, the information on the model architecture, and the information on model usage, are made publicly available. This exception shall not apply to general-purpose AI models with systemic risks."

Points (a) and (b) are the technical documentation for the AI Office and the information for downstream providers. Points (c) and (d), the copyright policy and the public training-content summary, are not exempted. Two other texts bound the exemption: Article 51(2) presumes high impact capabilities above 10^25 floating point operations of training compute, and Recital 103 withholds the exceptions from a release monetised through conditions such as personal data collected for reasons other than security, compatibility or interoperability.

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

The first command runs the packaged cases through the reference reader. The second judges your own record and exits 1 unless it is `exempt`, so it works as a CI step in the repository that publishes the model. A record looks like `vectors-open-weight-art53/cases/exempt-open-release/release.json`. To judge another checker: `agent-evidence-vectors --corpus vectors-open-weight-art53 --verifier './verifier'`.

## What it does not check

- It fetches nothing. A locator that returns 404, or weights whose bytes differ from the digest, are for a second tool; the record binds the digest so that tool has something to compare.
- It does not decide that a licence is free and open-source in law. It compares an identifier with a pinned list, and the list is a parameter a consumer replaces with its own.
- It does not decide that a model is a general-purpose model or that it has systemic risk. That is the Commission's. The checker reads the compute the provider states and the Commission decisions the provider records.
- A gated download is reported `not-established`: whether a sign-in wall is "publicly available" is for the authority.
- The text of the Article above was read from a reproduction of the Official Journal text; confirm it against EUR-Lex before quoting it in a filing.

## The other row

The logs row of the same table has its own guide: [Checking an AI Act log after the fact](cra-ai-act-logs.md).
