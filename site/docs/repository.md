# Working in the repository

The files, the release rule, and the commands that re-derive and build the site

The files in the repository, the rule for releasing an artifact, and the commands that re-derive the claims and build this site.

<a id="what-is-here"></a>

## What is here

| path | what it is |
|----|----|
| `data/atlas.toml` | The atlas as data: the layers, the named projects and standards with their measured sizes, the mechanisms classified by who writes their record, and the seams between layers. Every atlas fact is written here and only here. |
| `CLAIMS.md` | The claim ledger. |
| `tools/rederive.py` | Re-derives every automatable row of the claim ledger and prints the recorded and the current value side by side. |
| `data/versions.toml` | The version ledger: every artifact, its version, date and status. The build adds the SHA-256 of each artifact's source. |
| `src/lab.md`, `data/lab-register.json` | The Open Evidence Lab protocol, intake/correction routes and retained run register. |
| `data/catalog.json`, `data/catalog-sources.json` | Reviewed project identities, tasks and pinned README sources. |
| `tools/discovery.py`, `tools/discoverability/` | Task navigation and machine indexes used by the site build. |
| `src/pilot.md` | The proposed APS and PriorSeal pilot status, acceptance gates and open decisions; separate from measured Lab records. |
| `tools/check_lab.py` | Checks register artifact hashes and measured-field bindings before the site builds. Whether a claim means what it says, and whether anyone independent ran it, is still reviewed by hand. |
| `tools/build.py`, `tools/template.html`, `assets/site.css` | The site build: HTML and readable Markdown from the same expanded source, failing on any pandoc warning. |
| `tools/gen_atlas.py`, `templates/atlas.md.in` | Renders the atlas page from `data/atlas.toml`. |
| `tools/markdown_mirrors.py` | Preserves visible page content, code and stable fragments in readable Markdown. |
| `tools/check_links.py` | Checks HTML and generated Markdown links and anchors and, with `--external`, every external URL. |
| `docs/` | The built site, for GitHub Pages to serve from this directory. |

<a id="release-rule"></a>

## Release rule

Each artifact has its own release contract, and an artifact is added here when it passes that contract, not before. The version ledger lists every artifact of the framework; one that has not passed yet is shown there as held. The experiment draft retains the local PEER pilot, an immutable APS/PriorSeal fixture record, a source-pinned AGT transcript-byte result, and the public observer declaration-to-admission demo with its original CI bundle and replay controls. Separately reproduced below-agent observation and independent history remain registered designs without a qualifying result. The essay, runnable verifier demonstration and twelve-month series plan remain held.

<a id="re-derive-and-build"></a>

## Re-derive and build

``` sh
python3 -m pip install -r requirements/discoverability.txt
python3 tools/rederive.py            # recorded vs current value for every automatable claim; no credentials
python3 tools/rederive.py --strict   # exit 1 if any value moved or could not be read
python3 tools/gen_atlas.py           # render the atlas page from data/atlas.toml into src/atlas.md
python3 tools/build.py               # build docs/ (pandoc 3.x); any pandoc warning fails the build
python3 tools/build.py --check       # fail if docs/ differs from what the sources give
python3 tools/check_links.py --external
```

[Maintain the catalog](catalog.md) to add a project. The same build emits the task page, `catalog.json`, `llms.txt` and `sitemap.xml`; retained runs keep their own register.

Each built page has a sibling `.md` URL. The HTML header advertises it with `rel="alternate"` and points to the agent guide with `rel="describedby"`. The guide links to Markdown pages. Links between built pages use their Markdown mirrors; pinned source URLs and retained downloads keep their original targets. The link checker renders each mirror before checking its destinations and anchors.

Current component navigation uses the reviewed README pins in the catalog. Historical source rows, Lab records and retained experiment bytes keep their original pins and scopes.

A read that fails is printed as `UNREAD` with its reason and is never counted as unchanged. GitHub's unauthenticated API allows 60 requests an hour, which covers one run; set `GITHUB_TOKEN` to raise the limit.

The `observer-admission` CI job checks the original pinned observer demo and the retained signed bundle on every push and pull request. Reproduce it using the E6 commands in `src/experiments.md`. It requires the exact source blobs, Python 3.12.14 and cryptography 46.0.7, and refuses changed authority, signed-claim tampering and a second admission. The result remains an author-produced same-operator PEER/artifact fixture.

The [Open Evidence Lab](lab.md) accepts pinned run submissions through the repository's evidence-run issue form and corrections through the evidence-correction form. Its initial E6 record retains the fixture's limits. Host-project CI dependence and independently operated witnesses are separate evidence claims; listing a record supplies no membership or endorsement. Run `python3 tools/check_lab.py` to check its local integrity and measured-field bindings.

[HTML view](repository.html) | [Agent guide](llms.txt)
