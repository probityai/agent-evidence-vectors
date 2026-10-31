# agent-evidence-vocabulary

[![PyPI](https://img.shields.io/pypi/v/agent-evidence-vocabulary.svg)](https://pypi.org/project/agent-evidence-vocabulary/)
[![Downloads (PePy)](https://static.pepy.tech/badge/agent-evidence-vocabulary)](https://pepy.tech/projects/agent-evidence-vocabulary)

A closed, versioned vocabulary for claims about an agent's execution: what it attempted, what the
system beneath it observed or refused, how directly and from what vantage the claim was obtained,
and how much of a population the claim covers.

It's for anyone who writes a predicate, a verifier or an evidence format for agents and needs each
term to mean one thing across vendors, including teams who want to map their own fields onto it.

Install the Python package: `pip install agent-evidence-vocabulary==0.8.0`.

agent-evidence is the open record format. The `probityai` command checks and grades records against it: `pip install probityai==0.1.0`.

## Quick start

Pin the registry at a release and check its digest:

```bash
curl -fsSLO https://raw.githubusercontent.com/probityai/agent-evidence/agent-evidence-vocabulary-v0.8.0/packages/vocabulary/vocabulary.yaml
echo "76233ba8924cebdf053f0449ce023186805156aedca4121b9b156bd747a411b4  vocabulary.yaml" | sha256sum -c
```

Then read a term:

```bash
pip install PyYAML==6.0.3
python3 -c 'import yaml; v = yaml.safe_load(open("vocabulary.yaml")); print(v["evidence_dimensions"]["observation_vantage"]["values"])'
```

It prints `['substrate', 'artifact']`. Every term carries a definition, its allowed values and a
lifecycle status.

To map your own system's fields onto the vocabulary, copy
[`crosswalk/TEMPLATE.yaml`](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/crosswalk/TEMPLATE.yaml)
and run `python3 scripts/validate_crosswalks.py` before opening a pull request.

## Status

Release v0.8.0, tagged October 26, 2026. It adds open verdict classes, a criticality for each term, the `registryDigest` a record carries, and a resolvable URI for each term. The registry file is CC0-1.0, and the rest of the
repository is Apache-2.0. Every term starts as proposed and is promoted only when an independent
system emits it; the rules are in
[GOVERNANCE.md](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/GOVERNANCE.md).
The first crosswalk came from an independent implementation of the Adversarial Execution Evidence
predicate, in
[pull request 2](https://github.com/probityai/agent-evidence-vocabulary/pull/2).

## Documentation

| page | read it for |
| --- | --- |
| [Start a project](https://github.com/new?template_name=evidence-starter&template_owner=probityai) | a template with the evidence packages pinned and the conformance Action in CI |
| <a name="why-this-exists"></a><a name="files"></a><a name="companion-project"></a>[About the vocabulary](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/docs/ABOUT.md) | why it exists, what each file is for, and how the term set was chosen |
| [vocabulary.yaml](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/vocabulary.yaml) | the registry itself |
| [OpenCRE links](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/docs/OPENCRE.md) | which terms link to which OpenCRE requirement, how closely, and why the rest have no link |
| [Agent change admission predicate](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/docs/predicates/agent-change-admission-v1.md) | the signed decision that admits or rejects a change to an agent's harness, and how to verify it |
| [Done verification terms](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/docs/done-verification.md) | the eight terms for deciding that an agent's work is done from outside the agent, each with its check, and the crosswalks to Claude Code goals, Codex goals and in-toto 604 |
| [Incident response terms](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/docs/incident-response.md) | the eleven terms for telling a decision, an action, an effect and a restart apart after an incident, each with its check, and the crosswalks to NIST, AWS, OWASP and AIIR |
| [Releasing](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/docs/RELEASING.md) | how a version is cut, tagged and checked |
| [GOVERNANCE.md](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/GOVERNANCE.md) and [CONTRIBUTING.md](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/CONTRIBUTING.md) | the promotion rules, and how to file a crosswalk |
| [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) | the predicate specification and conformance vectors this vocabulary describes |
