# Maintain the project catalog

Edit `data/catalog.json`, then run the site build. It generates the task page, public JSON, llms.txt and sitemap.

<a id="add-an-entry"></a>

## Add an entry

- Add a repository record with its public path and pinned README commit.
- Give the component a stable `id`, a task and a short summary. Link its repositories.
- Add a profile when a specific adapter or integration needs its own entry.
- Review the source and publication fields. Add its status source to `CLAIMS.md` and `data/catalog-sources.json`.

Components may share repositories or span several of them. Rename the display label without changing the ID. Retain an old ID when retiring a project.

Use public metadata in this file; planning notes belong in a private workspace. The schema owns field shape; `tools/discoverability/catalog.py` checks names, references, destinations and source pins. The build projects reviewed public fields.

<a id="check-the-update"></a>

## Check the update

``` sh
python3 -m pip install -r requirements/discoverability-test.txt
python3 -m pytest -q tools/discoverability/test_catalog.py tests/test_discovery.py
python3 tools/build.py
python3 tools/build.py --check
python3 tools/check_links.py
python3 tools/check_lab.py
```

For a rename or retirement, validate with the previous catalog too:

``` sh
python3 tools/discoverability/catalog.py validate data/catalog.json --previous tools/discoverability/catalog.seed.json
```

<a id="import-a-reviewed-catalog"></a>

## Import a reviewed catalog

Keep the current catalog as the baseline. Import the reviewed public fields with stable IDs and publication gates, then validate against that baseline. Review its pinned README sources and retain their earlier rows in `data/catalog-sources.json`.

Run the native build and compare `docs/catalog.json` with the reviewed public projection. They should contain the same repositories, components and profiles. Update the C rows in `CLAIMS.md` and the catalog revision in `data/versions.toml` with the source capture.

Leave planning fields out of the import. Generate the pages and indexes from the catalog; the source history retains the earlier pins.

For a source refresh, give each component quickstart the same reviewed README pin as its owning repository. Append source history; keep earlier reviews. Current navigation does not update historical Lab claims or experiment objects.

<a id="record-versions-without-duplicating-release-numbers"></a>

## Record versions without duplicating release numbers

`data/atlas.toml` owns the existing artifact release values and their re-derive readers. A `component_release` row in `data/versions.toml` names that artifact with `artifact_ref`, then adds the catalog component, repository, exact tag, peeled source commit, read date and scope. The build refuses a tag that no longer matches its artifact version. Update the identity when its release changes.

For an artifact absent from the assurance atlas, keep its version in that ledger row. Use a separate row for each independently versioned artifact. Ratchet's harness source tag and public case package release are separate records. `kind = "source-tag"` never becomes a published package release.

A package published directly to a registry can use `kind = "registry-release"` with its exact `registry`, `package`, `version` and source `commit`. It has no `tag` or `version_prefix`: the version link opens the actual registry release. This records a package publication without inventing a GitHub release or tag. Keep a separate source-tag or data release row when it has a different role.

The task page and version ledger render those same rows. Catalog JSON retains its stable schema and identities; the Markdown version ledger is linked from `llms.txt`. Reviewed guides describe recipes. A tested installation needs its exact source, environment, command and retained output. Historical results and citation snapshots keep their recorded pins when current navigation changes.

<a id="bind-package-actions-to-their-artifact"></a>

## Bind package actions to their artifact

The same release row can record a `registry`, `package` and `install_anchor`. Use `profile` when the package serves a specific task, such as the digest checker or Ratchet cases. The build checks that the package belongs to that task and refuses registry controls on a source tag. Catalog JSON keeps its existing schema.

The package version comes from the release value. `version_prefix` records an actual release namespace: Admission's GitHub tag starts with `py-v`, while its PyPI package version does not. The build removes only that recorded prefix and refuses a mismatch. It does not maintain a second version number.

Install buttons open the task's reviewed guide at its named heading. File links select the recorded package release. Registry and download badges are live and can describe a newer registry state. PePy includes PyPI and known mirrors; crate download counters read crates.io. Neither counter measures users or adoption.

An `action_guide` selects an immutable guide URL and heading from the retained source reviews. The build binds it to its owning repository; a README refresh cannot silently move that Action recipe. A `workflow` and `workflow_name` identify one workflow file and name its live status. That report describes the named workflow, not a product-wide result or the installation shown by a pinned guide.

Keep project navigation in the catalog and measured runs in the Lab register.

Integration profiles link the reviewed reader guide. Record upstream listing acceptance and live documentation publication separately in `CLAIMS.md`; the profile status describes the tool.

[HTML view](catalog.html) | [Agent guide](llms.txt)
