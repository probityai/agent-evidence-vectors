# Probity Atlas

<a name="independent-evidence-for-ai-agent-actions"></a>

Find a Probity tool, inspect retained runs, or compare agent assurance mechanisms.

[Choose a project](https://probityai.github.io/agent-evidence-atlas/start.html) for evidence terms, conformance tests, observation, verification or admission policy. The [Open Evidence Lab](https://probityai.github.io/agent-evidence-atlas/lab.html) holds replayable runs and accepts results and corrections.

## Quick start

Read a retained run locally. Python 3.11 or later:

```sh
git clone https://github.com/probityai/agent-evidence/tree/main/site && cd agent-evidence-atlas
git checkout 3109ae4be7dca77594fa7ddba8565d7feb261cf9
python3 tools/check_lab.py --list
python3 tools/check_lab.py --record E6-observer-admission --json
```

The checker validates artifact hashes and measured fields before emitting the record. To re-read the ledger's external sources, run `python3 tools/rederive.py`.

## Docs

| Page | Read it for |
| --- | --- |
| [Start a project](https://github.com/new?template_name=evidence-starter&template_owner=probityai) | A template with the packages pinned and the conformance Action in CI |
| [Choose a project](https://probityai.github.io/agent-evidence-atlas/start.html) | A tool for your task and its pinned quickstart |
| [Assurance atlas](https://probityai.github.io/agent-evidence-atlas/atlas.html) | Mechanisms, projects and evidence boundaries |
| [Open Evidence Lab](https://probityai.github.io/agent-evidence-atlas/lab.html) | Retained runs, submissions and corrections |
| [Claim status](https://probityai.github.io/agent-evidence-atlas/status.html) | What stands, on what evidence, and the open cells |
| [Automation](https://probityai.github.io/agent-evidence-atlas/automation.html) | Catalog lookups and run records |
| [Claim ledger](CLAIMS.md) | Sources and re-derive commands |
| <a name="what-is-here"></a><a name="release-rule"></a><a name="re-derive-and-build"></a>[Repository guide](https://probityai.github.io/agent-evidence-atlas/repository.html) | Files, checks and release rules |

<a name="the-public-code-the-framework-uses"></a><a name="status"></a>Project names, source pins and statuses live in [data/catalog.json](data/catalog.json). The build emits [llms.txt](llms.txt), the public catalog and a readable Markdown mirror of each page. Each artifact keeps its release state in [data/versions.toml](data/versions.toml).

<a name="author"></a>Created by Sankalp Gilda. The paper behind the framework is *Three Jobs, Not One* ([Zenodo](https://doi.org/10.5281/zenodo.21935891)).
