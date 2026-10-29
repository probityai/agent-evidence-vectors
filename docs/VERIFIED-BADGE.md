# Verified by Probity

The badge means one thing: the project's CI runs a released agent-evidence-vectors corpus end to end and the run passes. It is granted by the maintainers of this repository, never self-declared, and re-checked at every release of the corpus. A badge that no longer matches a passing run is withdrawn.

## Get it

Run the [GitHub Action](https://github.com/probityai/agent-evidence-vectors/blob/main/action.yml) or the released package in your CI, then open an issue or pull request on [probityai/agent-evidence](https://github.com/probityai/agent-evidence) with a link to a passing run. When we have read that run, we add you to [Used by](USED-BY.md) and confirm the badge.

## Paste it

```markdown
[![Verified by Probity](https://raw.githubusercontent.com/probityai/agent-evidence/main/assets/verified-by-probity.svg)](https://github.com/probityai/probity)
Verified by Probity (github.com/probityai/probity): <link to your latest passing run>
```

Link the second line to your live result page, so a reader can open the run the badge rests on.

## Run it yourself

```bash
uv add agent-evidence-vectors==0.25.0
pip install agent-evidence-vectors==0.25.0
```

The `probityai` command line that will run the same check is planned and not yet released; its install lines will be `uv add probityai` and `pip install probityai`.
