"""Render task navigation and machine indexes for the existing site build.

The reviewed catalog supplies project names, tasks and source pins. This module
adds site destinations; it does not read or modify the Lab register.
"""

from __future__ import annotations

import html
import json
import re
import tomllib
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote
from xml.sax.saxutils import escape

from discoverability import catalog

ROOT = Path(__file__).resolve().parent.parent
BASE_URL = "https://probityai.github.io/agent-evidence-atlas/"
PAGE_NAME = re.compile(r"[a-z][a-z0-9-]*\Z")
SITE_LINKS = (
    ("start", "Choose a project", "Tools grouped by the task you need."),
    ("automation", "Automation", "Read the catalog and pinned run records."),
    ("lab", "Open Evidence Lab", "Retained runs, submissions and corrections."),
    ("runs", "Find a retained run", "Search recorded claims, declared roles, limits and original evidence."),
    ("atlas", "Assurance atlas", "Projects, mechanisms and evidence boundaries."),
    ("experiments", "Experiments", "Pinned procedures and recorded results."),
    ("replay-an-evidence-decision", "Replay an evidence decision", "A retained admission and its state-preserving refusals."),
    ("replay-tools", "Run the APS and PriorSeal replay", "Declare the caller and retain pinned sources, process logs and results."),
    ("evidence-test-meaning", "Interpret a green test suite", "Separate test outcomes, record validity and action results using retained artifacts."),
    ("claims", "Claim ledger", "Sources and re-derive commands."),
    ("versions", "Versions and source pins", "Published releases, reviewed guides and historical result pins."),
    ("repository", "Repository guide", "Sources, checks and the site build."),
)


def load_public(root: Path = ROOT) -> dict[str, Any]:
    """Load and project reviewed catalog records for a site build.

    Parameters
    ----------
    root : pathlib.Path
        Repository containing ``data/catalog.json``.

    Returns
    -------
    dict[str, Any]
        Validated public fields from :func:`catalog.public_projection`.
        Editing notes, extensions and unreviewed records are absent.

    Raises
    ------
    catalog.CatalogError
        If catalog shape, references, public text or source pins are invalid.
    OSError
        If the catalog cannot be read.
    """
    data = catalog.load_catalog(root / "data/catalog.json")
    baseline = catalog.load_catalog(root / "tools/discoverability/catalog.seed.json")
    public = catalog.public_projection(catalog.validate_catalog(data, baseline))
    sources = json.loads(
        (root / "data/catalog-sources.json").read_text(encoding="ascii")
    )
    check_source_bindings(public, sources)
    return public


def check_source_bindings(
    public: dict[str, Any], sources: list[dict[str, str]]
) -> None:
    """Bind public repository pins to their reviewed README capture records.

    Parameters
    ----------
    public : dict[str, Any]
        Validated catalog projection.
    sources : list of dict of str to str
        Reviewed source URLs, commits and Git blob digests. These are source
        identities, not measurements of tool performance.

    Raises
    ------
    catalog.CatalogError
        If source URLs repeat or a published repository lacks its matching pin.
    """
    index = {row["url"]: row for row in sources}
    if len(index) != len(sources):
        catalog.fail("Catalog source URL is repeated")
    for repository in public["repositories"]:
        source = index.get(repository["source"]["url"])
        if source is None or source["commit"] != repository["source"]["commit"]:
            catalog.fail(f"Catalog source pin is unreviewed: {repository['id']}")


def project_entries(public: dict[str, Any]) -> list[dict[str, Any]]:
    """Return components and integration profiles in stable identity order."""
    return sorted([*public["components"], *public["profiles"]], key=lambda r: r["id"])


def project_url(record: dict[str, Any], public: dict[str, Any]) -> str:
    """Choose a reviewed guide, falling back to the owning repository."""
    repositories = {row["id"]: row for row in public["repositories"]}
    return cast(
        str, record.get("docs_url", repositories[record["repositories"][0]]["url"])
    )


def component_versions(public: dict[str, Any], root: Path = ROOT) -> list[dict[str, str]]:
    """Read component releases and source tags from the existing version ledger.

    A component can contain separately versioned artifacts. A harness source tag
    must not acquire the release number of a case package in the same repository.
    The recorded commit is the peeled source commit, not an annotated tag object.
    """
    data = tomllib.loads((root / "data/versions.toml").read_text(encoding="utf-8"))
    atlas = tomllib.loads((root / "data/atlas.toml").read_text(encoding="utf-8"))
    artifacts = {row["name"]: row for row in atlas["artifact"]}
    components = {row["id"]: row for row in public["components"]}
    repositories = {row["id"]: row for row in public["repositories"]}
    sources = json.loads((root / "data/catalog-sources.json").read_text(encoding="utf-8"))
    result: dict[tuple[str, str], dict[str, str]] = {}
    for authored in data.get("component_release", []):
        row = resolve_component_version(authored, artifacts)
        version = checked_component_version(row, components, repositories)
        check_distribution_binding(version, public)
        check_action_source(version, repositories, sources)
        key = (row["component"], row["artifact"])
        if key in result:
            catalog.fail("Component version artifact is repeated")
        result[key] = version
    return [result[key] for key in sorted(result)]


def resolve_component_version(row: dict[str, str], artifacts: dict[str, Any]) -> dict[str, str]:
    """Keep an existing artifact record as the sole authored release version."""
    row = row.copy()
    if "artifact_ref" in row:
        artifact = artifacts.get(row.pop("artifact_ref"))
        if artifact is None or "version" in row:
            catalog.fail("Component version must use one known artifact version source")
        row["version"] = artifact["version"]
        if row.get("kind") != "registry-release" and row.get("tag") not in {row["version"], f"v{row['version']}"}:
            catalog.fail("Component version tag does not match its artifact version")
    return row


def checked_component_version(
    row: dict[str, str],
    components: dict[str, Any],
    repositories: dict[str, Any],
) -> dict[str, str]:
    """Refuse unknown identities and unsafe authored fields before rendering."""
    check_component_version_fields(row)
    component = components.get(row["component"])
    repository = repositories.get(row["repository"])
    if component is None or repository is None or row["repository"] not in component["repositories"]:
        catalog.fail("Component version repository does not belong to its component")
    if row["kind"] == "registry-release":
        url = registry_links(row)["registry"]
    else:
        route = "releases/tag" if row["kind"] == "release" else "tree"
        url = f"{repository['url']}/{route}/{row['tag']}"
    return {**row, "display_name": component["display_name"],
            "url": url,
            "source_url": f"{repository['url']}/tree/{row['commit']}"}


def check_component_version_fields(row: dict[str, str]) -> None:
    """Check the ledger field set, source identity, date and authored text."""
    fields = {"component", "repository", "artifact", "kind", "version", "commit", "read", "note"}
    registry_release = row.get("kind") == "registry-release"
    if not registry_release:
        fields.add("tag")
    optional = {"registry", "package", "version_prefix", "profile", "install_anchor", "action_guide", "workflow", "workflow_name"}
    if not fields <= set(row) <= fields | optional or any(not isinstance(value, str) for value in row.values()):
        catalog.fail("Component version fields are invalid")
    if row["kind"] not in {"release", "source-tag", "registry-release"}:
        catalog.fail("Component version kind is invalid")
    if registry_release and ("registry" not in row or "version_prefix" in row):
        catalog.fail("Registry release needs an exact registry package version")
    if re.fullmatch(r"[0-9a-f]{40}", row["commit"]) is None or (not registry_release and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", row["tag"]) is None):
        if registry_release:
            catalog.fail("Component version needs a full source commit")
        catalog.fail("Component version needs a full source commit and a safe tag")
    try:
        date.fromisoformat(row["read"])
    except ValueError:
        catalog.fail("Component version read date is invalid")
    for field in ("artifact", "version", "note"):
        catalog.check_public_text(row[field])
    check_distribution_fields(row)


def check_distribution_fields(row: dict[str, str]) -> None:
    """Check optional distribution metadata without permitting arbitrary URLs."""
    if {"registry", "package", "version_prefix", "profile"} & set(row):
        if not {"registry", "package", "install_anchor"} <= set(row) or row["registry"] not in {"pypi", "crates"}:
            catalog.fail("Distribution needs a known registry, package and install anchor")
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", row["package"]) is None or row["kind"] not in {"release", "registry-release"}:
            catalog.fail("Distribution needs a released package identity")
        package_version(row)
    if "install_anchor" in row and re.fullmatch(r"[a-z0-9][a-z0-9-]*", row["install_anchor"]) is None:
        catalog.fail("Distribution install anchor is invalid")
    if "action_guide" in row:
        match = re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/blob/[0-9a-f]{40}/([A-Za-z0-9._/-]+)#[a-z0-9][a-z0-9-]*", row["action_guide"])
        if match is None or any(part in {".", "..", ""} for part in match[1].split("/")):
            catalog.fail("Action guide needs a safe pinned source and heading")
    if {"workflow", "workflow_name"} & set(row):
        if not {"workflow", "workflow_name"} <= set(row) or re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", row["workflow"]) is None:
            catalog.fail("Workflow needs a named workflow file")
        catalog.check_public_text(row["workflow_name"])


def package_version(row: dict[str, str]) -> str:
    """Remove only an explicitly recorded release namespace, without a new number."""
    prefix = row.get("version_prefix", "")
    version = row["version"]
    if "version_prefix" in row and (not prefix or not version.startswith(prefix)):
        catalog.fail("Package version prefix does not match the recorded release")
    version = version[len(prefix):]
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)", version) is None:
        catalog.fail("Distribution needs an exact package version")
    return version


def check_distribution_binding(row: dict[str, str], public: dict[str, Any]) -> None:
    """Bind a registry package and install recipe to the owning public task."""
    entries = {entry["id"]: entry for entry in project_entries(public)}
    target = entries.get(row.get("profile", row["component"]))
    if target is None or target.get("component", target["id"]) != row["component"]:
        catalog.fail("Distribution profile does not belong to its component")
    if "registry" in row and row["package"] not in target.get("packages", []):
        catalog.fail("Distribution package does not belong to its task")


def check_action_source(
    row: dict[str, str], repositories: dict[str, Any], sources: list[dict[str, Any]]
) -> None:
    """Require an independently reviewed guide, even after a README pin changes."""
    if "action_guide" not in row:
        return
    repository = repositories[row["repository"]]
    url = row["action_guide"].partition("#")[0]
    if not url.startswith(repository["url"] + "/blob/"):
        catalog.fail("Action guide does not belong to its repository")
    if not any(source["url"] == url and "https://github.com/" + source["repository"] == repository["url"] for source in sources):
        catalog.fail("Action guide needs a retained source review")


def registry_links(row: dict[str, str]) -> dict[str, str]:
    """Derive registry routes from the existing release value and package identity."""
    name = row["package"]
    version = quote(package_version(row), safe="")
    if row["registry"] == "pypi":
        current = f"https://pypi.org/project/{name}/"
        return {"registry": f"{current}{version}/", "download": f"{current}{version}/#files",
                "statistics": f"https://pepy.tech/projects/{name}", "current": current,
                "version_badge": f"https://img.shields.io/pypi/v/{name}?label=PyPI",
                "download_badge": f"https://img.shields.io/pepy/dt/{name}?label=PyPI%20%2B%20mirrors"}
    current = f"https://crates.io/crates/{name}"
    return {"registry": f"{current}/{version}",
            "download": f"https://crates.io/api/v1/crates/{name}/{version}/download",
            "statistics": current, "current": current,
            "version_badge": f"https://img.shields.io/crates/v/{name}?label=crates.io",
            "download_badge": f"https://img.shields.io/crates/d/{name}?label=crate%20downloads"}


def distribution_markup(row: dict[str, str], public: dict[str, Any]) -> str:
    """Render useful actions and live metrics while keeping recipe pins separate."""
    if not {"registry", "install_anchor", "action_guide", "workflow"} & set(row):
        return ""
    entries = {entry["id"]: entry for entry in project_entries(public)}
    target = entries[row.get("profile", row["component"])]
    repository = next(repo for repo in public["repositories"] if repo["id"] == row["repository"])
    actions = []
    badges = []
    title = row["artifact"]
    if "install_anchor" in row:
        actions.append(("Install", target["docs_url"] + "#" + row["install_anchor"]))
    if "registry" in row:
        links = registry_links(row)
        title = f"{row['package']} / recorded package release {package_version(row)}"
        actions.extend((label, links[key]) for label, key in [
            ("Download release files", "download"), ("Registry release", "registry"), ("Download statistics", "statistics")
        ])
        badges.extend((links[key], links[destination], label) for key, destination, label in [
            ("version_badge", "current", f"Current {row['registry']} version of {row['package']}"),
            ("download_badge", "statistics", f"Download statistics for {row['package']}")
        ])
    if "action_guide" in row:
        actions.append(("Use pinned Action", row["action_guide"]))
    if "workflow" in row:
        workflow = f"{repository['url']}/actions/workflows/{row['workflow']}"
        actions.append(("Workflow runs", workflow))
        badges.append((workflow + "/badge.svg", workflow, row["workflow_name"] + " workflow status"))
    links_html = "\n".join(f'<a href="{html.escape(url)}">{html.escape(label)}</a>' for label, url in actions)
    badge_html = "\n".join(
        f'<a href="{html.escape(url)}"><img src="{html.escape(source)}" alt="{html.escape(label)}" height="20" /></a>'
        for source, url, label in badges
    )
    return (f'<div class="distribution">\n<p class="distribution-title">{html.escape(title)}</p>\n'
            f'<p class="distribution-actions">\n{links_html}\n</p>\n'
            + (f'<p class="distribution-badges">Live registry and named workflow reports:<br />\n{badge_html}\n</p>\n' if badges else "")
            + "</div>")


def component_publication_role(version: dict[str, str]) -> str:
    """Name the recorded publication without inventing a source tag."""
    return {"release": "Published release", "source-tag": "Source tag",
            "registry-release": "Registry release"}[version["kind"]]


def component_version_line(version: dict[str, str]) -> str:
    """Name publication and source identity without claiming an install result."""
    role = component_publication_role(version)
    return (f"{version['artifact']}: {role.lower()} [{version['version']}]({version['url']}), "
            f"source [`{version['commit'][:12]}`]({version['source_url']}), read {version['read']}. "
            f"{version['note']}")


def start_markdown(
    public: dict[str, Any], versions: list[dict[str, str]] | None = None
) -> str:
    """Build a task table and short project entries from projected fields.

    Parameters
    ----------
    public : dict[str, Any]
        Output of :func:`load_public` or ``catalog.public_projection``.

    Returns
    -------
    str
        Markdown for ``start.html``. Stable IDs own fragment anchors, so a
        display-name change leaves existing project links usable.
    """
    rows = [
        "---",
        'title: "Choose a component"',
        'subtitle: "Start with the task you need."',
        'description: "Find Probity tools for evidence terms, conformance tests, observation, verification and workload admission."',
        "---",
        "",
        "Vectors tests how a verifier behaves. Verify checks a supplied claim against evidence bytes.",
        "",
        "A published release, a reviewed guide and a tested installation are different pins. "
        "Use the exact recipe and source named by the result you reproduce. "
        "The [version ledger](versions.html#component-versions) records release and source roles.",
        "",
        "Install links keep the reviewed recipe. Download links select the recorded package release. "
        "Live badges can move beyond those pins. PePy counts PyPI and known mirrors; crate counters read crates.io. "
        "Downloads do not count people, deployments or adoption.",
        "",
        "| Task | Project |",
        "| --- | --- |",
    ]
    entries = project_entries(public)
    for record in entries:
        rows.append(
            f"| {record['task']} | [{record['display_name']}](#{record['id']}) |"
        )
    for record in entries:
        rows.extend(
            [
                "",
                f"## {record['display_name']} {{#{record['id']}}}",
                "",
                (
                    f"Profile ID: `{record['id']}`. Component ID: `{record['component']}`."
                    if "component" in record
                    else f"Component ID: `{record['id']}`."
                ),
                "",
                record["summary"],
                "",
                f"{record['status'].capitalize()}. [Reviewed guide and source]({project_url(record, public)})",
            ]
        )
        for version in versions or []:
            if version["component"] == record["id"]:
                rows.extend(["", component_version_line(version)])
            if version.get("profile", version["component"]) == record["id"]:
                if markup := distribution_markup(version, public):
                    rows.extend(["", markup])
    rows.extend(
        [
            "",
            "## Run and share a check",
            "",
            "The [Open Evidence Lab](lab.html) holds replayable runs and accepts new results and corrections. For scripted lookups, use the [automation guide](automation.html).",
            "",
            "For a combined CLI and Action example, use the [checkout composition reference](experiments.html#checkout-composition). It keeps decisions, attempts, effects and observations separate in a replayable synthetic bundle.",
            "",
        ]
    )
    return "\n".join(rows)


def llms_index(public: dict[str, Any], pages: set[str]) -> str:
    """Render an index whose site links name pages in the current build.

    Parameters
    ----------
    public : dict[str, Any]
        Validated, projected catalog records.
    pages : set[str]
        Page stems that the build will publish.

    Returns
    -------
    str
        ASCII Markdown index. Each project destination retains its reviewed
        source pin; page links use the site's canonical base URL.
    """
    rows = [
        "# Probity AI",
        "",
        "> Tools and run records for checking claims about agent actions.",
        "",
        "## Guides",
        "",
    ]
    for stem, label, summary in SITE_LINKS:
        if stem in pages:
            rows.append(f"- [{label}]({BASE_URL}{stem}.md): {summary}")
    rows.extend(["", "## Projects", ""])
    for record in project_entries(public):
        identity = (
            f"Profile ID: `{record['id']}`. Component ID: `{record['component']}`."
            if "component" in record
            else f"Component ID: `{record['id']}`."
        )
        rows.append(
            f"- [{record['display_name']}]({project_url(record, public)}): {identity} {record['summary']}"
        )
    rows.extend(
        [
            "",
            "## Data",
            "",
            f"- [Project catalog]({BASE_URL}catalog.json): Stable project IDs, tasks and pinned README sources.",
        ]
    )
    if "lab" in pages:
        rows.append(
            f"- [Lab register]({BASE_URL}lab/register.json): Retained artifacts, results and review state."
        )
    return "\n".join(rows) + "\n"


def sitemap(pages: Iterable[str]) -> str:
    """Render canonical page URLs without a fabricated modification time.

    Parameters
    ----------
    pages : iterable of str
        Built page stems. Order and repetition do not change the output.

    Returns
    -------
    str
        Sitemap XML with the home page's canonical directory URL.

    Raises
    ------
    ValueError
        If a page stem could change a URL or XML element.
    """
    stems = sorted(set(pages))
    if any(PAGE_NAME.fullmatch(stem) is None for stem in stems):
        catalog.fail("Sitemap page must be a plain page stem")
    rows = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for stem in stems:
        url = BASE_URL if stem == "index" else f"{BASE_URL}{stem}.html"
        rows.append(f"  <url><loc>{escape(url)}</loc></url>")
    rows.append("</urlset>")
    return "\n".join(rows) + "\n"


def site_assets(public: dict[str, Any], pages: set[str]) -> dict[str, str]:
    """Return the machine-readable files emitted by the existing site build."""
    return {
        "catalog.json": json.dumps(public, indent=2, sort_keys=True, ensure_ascii=True)
        + "\n",
        "llms.txt": llms_index(public, pages),
        "sitemap.xml": sitemap(pages),
    }
