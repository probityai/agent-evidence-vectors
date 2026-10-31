"""Validate project records and build reviewed public navigation.

The checked-in schema owns record shape. The semantic pass checks references,
public URLs and source pins. Renderers project named fields only: private notes
and extensions never become public prose.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import SplitResult, urlsplit

from jsonschema import Draft202012Validator

LOGGER = logging.getLogger(__name__)
HERE = Path(__file__).resolve().parent
COLLECTIONS = ("repositories", "components", "profiles")
TEXT_FIELDS = ("display_name", "summary", "task", "status")
FORBIDDEN = re.compile(
    r"gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9]+",
    re.IGNORECASE,
)
SAFE_TEXT = re.compile(r"[A-Za-z0-9 .,:;()'/-]+\Z")
SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]+\Z")
# A project's README may live in an approved repository other than the one that
# names the project: a package moved into a monorepo keeps its record and its ID.
SOURCE_README = re.compile(
    r"https://github\.com/(?P<repository>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r"/blob/(?P<commit>[0-9a-f]{40})/(?:[A-Za-z0-9._-]+/)*README\.md"
)


class CatalogError(ValueError):
    """A catalog cannot be safely used for public navigation."""


def fail(message: str) -> None:
    """Log a precise refusal and raise the same message.

    Parameters
    ----------
    message : str
        Diagnostic for a build log. Generated navigation omits diagnostics.

    Raises
    ------
    CatalogError
        Always; the exception and logged message agree.
    """
    LOGGER.error(message)
    raise CatalogError(message)


def unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Decode an object while refusing repeated JSON members."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"Repeated JSON member: {key}")
        result[key] = value
    return result


def load_catalog(path: Path) -> dict[str, Any]:
    """Read local JSON without accepting duplicate object members.

    Parameters
    ----------
    path : pathlib.Path
        Local input. The loader performs no network fetch.

    Returns
    -------
    dict[str, Any]
        Parsed object to pass to validate_catalog before rendering.

    Raises
    ------
    CatalogError
        For malformed JSON, repeated members or a non-object root.
    OSError
        If the local file cannot be read.
    """
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_members
        )
    except UnicodeDecodeError:
        fail("Catalog must be UTF-8 JSON")
    except json.JSONDecodeError as error:
        fail(f"Invalid JSON at line {error.lineno}, column {error.colno}")
    if not isinstance(data, dict):
        fail("Catalog root must be an object")
    return cast(dict[str, Any], data)


def is_published(record: dict[str, Any]) -> bool:
    """Return whether the record passed the explicit publication gate.

    Parameters
    ----------
    record : dict[str, Any]
        Schema-valid record with publication and reviewed fields.

    Returns
    -------
    bool
        True for reviewed public records. Held, draft, private and unreviewed
        records are absent from generated navigation.
    """
    return record["publication"] == "public" and record["reviewed"] is True


def records_by_id(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index stable IDs and reject ambiguous IDs or aliases.

    Parameters
    ----------
    data : dict[str, Any]
        Schema-valid catalog. All record kinds share one naming namespace.

    Returns
    -------
    dict[str, dict[str, Any]]
        Canonical IDs only; aliases remain a catalog editing aid.
    """
    index: dict[str, dict[str, Any]] = {}
    occupied: set[str] = set()
    for collection in COLLECTIONS:
        for record in data[collection]:
            for name in [record["id"], *record["aliases"]]:
                if name in occupied:
                    fail(f"Duplicate ID or alias: {name}")
                occupied.add(name)
            index[record["id"]] = record
    return index


def check_url(url: str, approved: set[str]) -> None:
    """Refuse links outside approved public repository and Pages paths.

    Parameters
    ----------
    url : str
        Canonical HTTPS URL. Credentials, query strings, encoded paths,
        traversal and Markdown punctuation are refused.
    approved : set[str]
        Explicit approved repository names, each owned by probityai.

    Raises
    ------
    CatalogError
        If the link changes rendering or points outside the approval set.
    """
    parsed = parse_public_url(url)
    parts = parsed.path.strip("/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        fail("Public URL contains an unsafe path segment")
    owner_repo = "/".join(parts[:2])
    if parsed.netloc == "probityai.github.io":
        owner_repo = f"probityai/{parts[0]}"
    if owner_repo not in approved:
        fail("Public URL does not belong to an approved repository")


def parse_public_url(url: str) -> SplitResult:
    """Parse a canonical public URL without normalizing away hostile controls."""
    if not url.isascii() or any(character.isspace() for character in url):
        fail("Public URL must have a plain repository path")
    try:
        parsed = urlsplit(url)
    except ValueError:
        fail("Public URL must use an approved HTTPS host")
    if parsed.scheme != "https" or parsed.netloc not in {
        "github.com",
        "probityai.github.io",
    }:
        fail("Public URL must use an approved HTTPS host")
    if parsed.query or parsed.fragment or not SAFE_PATH.fullmatch(parsed.path):
        fail("Public URL must have a plain repository path")
    return parsed


def check_public_text(value: str) -> None:
    """Check authored plain text before interpolating it into Markdown."""
    if FORBIDDEN.search(value):
        fail("Public text contains a forbidden identity or credential")
    if (
        not SAFE_TEXT.fullmatch(value)
        or "https:" in value.lower()
        or "http:" in value.lower()
    ):
        fail("Public text must be plain ASCII without embedded links")


def check_public_record(record: dict[str, Any], approved: set[str]) -> None:
    """Check public fields; notes and extensions are opaque and never rendered."""
    if record["publication"] != "public":
        return
    check_public_text(record["id"])
    for field in TEXT_FIELDS:
        check_public_text(record[field])
    for package in record.get("packages", []):
        check_public_text(package)
    check_record_urls(record, approved)


def check_record_urls(record: dict[str, Any], approved: set[str]) -> None:
    """Validate link fields without examining opaque editing metadata."""
    for field in ("url", "docs_url"):
        if field in record:
            check_url(record[field], approved)


def check_reference(
    record: dict[str, Any],
    target_id: str,
    expected: set[str],
    index: dict[str, dict[str, Any]],
    kinds: dict[str, str],
) -> None:
    """Check target type and prevent published records referencing hidden ones."""
    if target_id not in index:
        fail(f"Dangling reference: {record['id']} -> {target_id}")
    if kinds[target_id] not in expected:
        fail(f"Wrong reference kind: {record['id']} -> {target_id}")
    if is_published(record) and not is_published(index[target_id]):
        fail(f"Published record references a hidden record: {record['id']}")


def check_record_edges(
    record: dict[str, Any],
    collection: str,
    index: dict[str, dict[str, Any]],
    kinds: dict[str, str],
) -> None:
    """Check multi-repository components and explicit integration relationships."""
    for repository_id in record.get("repositories", []):
        check_reference(record, repository_id, {"repositories"}, index, kinds)
    if collection == "profiles":
        check_reference(record, record["component"], {"components"}, index, kinds)
    for relationship in record.get("relationships", []):
        if record["publication"] == "public":
            check_public_text(relationship["kind"])
        check_reference(
            record, relationship["target"], {"components", "profiles"}, index, kinds
        )


def check_repository(record: dict[str, Any], approved: set[str]) -> None:
    """Bind public repository metadata to its own pinned README source."""
    if record["publication"] != "public":
        return
    identity_matches = record["url"] == f"https://github.com/{record['full_name']}"
    if record["full_name"] not in approved or not identity_matches:
        fail("Public repository identity does not match its approval")
    source = record["source"]
    match = SOURCE_README.fullmatch(source["url"])
    if (
        match is None
        or match["repository"] not in approved
        or match["commit"] != source["commit"]
        or source["repository"] != record["id"]
    ):
        fail("Public repository source must pin its own README commit")


def validate_catalog(
    data: dict[str, Any], previous: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Validate a catalog and return an independent copy.

    Parameters
    ----------
    data : dict[str, Any]
        Complete catalog. Unknown core fields are refused; extensions and
        private_notes are allowed JSON and omitted from every public output.
    previous : dict[str, Any] or None
        Previous catalog, when checking an update. Stable IDs must remain
        present in their original record kind; retire records instead of
        silently dropping them.

    Returns
    -------
    dict[str, Any]
        Deep copy of the valid catalog. Input is never mutated.

    Raises
    ------
    CatalogError
        For structural errors, ambiguous names, broken references, unsafe
        public fields or inconsistent public source pins.

    Notes
    -----
    JSON Schema owns shape and enums. Cross-record integrity and repository URL
    membership need this semantic pass; schema validation alone is insufficient.
    """
    schema = json.loads((HERE / "catalog.schema.json").read_text(encoding="ascii"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(data), key=lambda e: str(e.json_path)
    )
    if errors:
        fail(f"Schema violation at {errors[0].json_path}: {errors[0].message}")
    index = records_by_id(data)
    kinds = {
        r["id"]: collection for collection in COLLECTIONS for r in data[collection]
    }
    approved = set(data["approved_repositories"])
    check_catalog_records(data, approved, index, kinds)
    for repository in data["repositories"]:
        check_repository(repository, approved)
    if previous is not None:
        check_evolution(data, validate_catalog(previous))
    return copy.deepcopy(data)


def check_catalog_records(
    data: dict[str, Any],
    approved: set[str],
    index: dict[str, dict[str, Any]],
    kinds: dict[str, str],
) -> None:
    """Validate records and typed edges across all catalog collections."""
    for collection in COLLECTIONS:
        for record in data[collection]:
            check_public_record(record, approved)
            check_record_edges(record, collection, index, kinds)


def check_evolution(current: dict[str, Any], previous: dict[str, Any]) -> None:
    """Retain stable identities and record kinds across catalog updates."""
    for collection in COLLECTIONS:
        present = {record["id"] for record in current[collection]}
        for record in previous[collection]:
            if record["id"] not in present:
                fail(f"Stable ID removed or changed kind: {record['id']}")


def public_projection(data: dict[str, Any]) -> dict[str, Any]:
    """Project reviewed public fields without notes, aliases or extensions.

    Parameters
    ----------
    data : dict[str, Any]
        Complete catalog, validated inside this function.

    Returns
    -------
    dict[str, Any]
        Public records in canonical order. Extension fields never acquire a
        public effect without an explicit renderer code change.
    """
    checked = validate_catalog(data)
    fields = (
        "id",
        "display_name",
        "summary",
        "task",
        "status",
        "url",
        "docs_url",
        "repositories",
        "component",
        "packages",
        "source",
        "relationships",
    )
    result: dict[str, Any] = {"schema_version": checked["schema_version"]}
    for collection in COLLECTIONS:
        result[collection] = [
            {field: record[field] for field in fields if field in record}
            for record in sorted(checked[collection], key=lambda r: r["id"])
            if is_published(record)
        ]
        normalize_public_records(result[collection])
    return result


def normalize_public_records(records: list[dict[str, Any]]) -> None:
    """Sort set-like fields to make equivalent input orderings byte-identical."""
    for record in records:
        for field in ("repositories", "packages"):
            if field in record:
                record[field].sort()
        if "relationships" in record:
            record["relationships"].sort(
                key=lambda edge: (edge["kind"], edge["target"])
            )


def render_navigation(data: dict[str, Any]) -> dict[str, str]:
    """Build a task table, LLM index and public JSON without writing files.

    Parameters
    ----------
    data : dict[str, Any]
        Catalog to validate and project.

    Returns
    -------
    dict[str, str]
        TASKS.md, llms.txt and catalog.public.json content. Stable IDs determine output
        order, independent of input ordering or timestamps.
    """
    public = public_projection(data)
    repositories = {r["id"]: r for r in public["repositories"]}
    table = [
        "# Find a tool for your task",
        "",
        "| Task | Project | Catalog ID | Status |",
        "| --- | --- | --- | --- |",
    ]
    llms = [
        "# Probity public projects",
        "",
        "Choose a project by task. Follow its README for commands and limitations.",
        "",
        "## Projects",
        "",
    ]
    for component in [*public["components"], *public["profiles"]]:
        repo = repositories[component["repositories"][0]]
        url = component.get("docs_url", repo["url"])
        name = component["display_name"]
        table.append(
            f"| {component['task']} | [{name}]({url}) | `{component['id']}` | {component['status']} |"
        )
        llms.append(
            f"- [{name}]({url}): Catalog ID: `{component['id']}`. {component['summary']} Status: {component['status']}."
        )
    return {
        "TASKS.md": "\n".join(table) + "\n",
        "llms.txt": "\n".join(llms) + "\n",
        "catalog.public.json": json.dumps(
            public, indent=2, sort_keys=True, ensure_ascii=True
        )
        + "\n",
    }


def check_destination(destination: Path) -> None:
    """Refuse links and non-regular files before writing generated output."""
    if destination.is_symlink():
        fail("Output file must be a regular file")
    if not destination.exists():
        return
    if not destination.is_file() or destination.stat().st_nlink != 1:
        fail("Output file must be an unshared regular file")


def write_outputs(output: Path, contents: dict[str, str]) -> None:
    """Write to a dedicated directory without following output symlinks.

    Parameters
    ----------
    output : pathlib.Path
        Directory dedicated to generated navigation. It must not contain
        unrelated files; symlink directories and existing symlink files fail.
    contents : dict[str, str]
        Fixed output names from render_navigation.

    Raises
    ------
    CatalogError
        For a symlink ancestor or an unrelated existing directory member.
    OSError
        For local filesystem errors.
    """
    check_output_contents(contents)
    check_output_directory(output, set(contents))
    for name in contents:
        check_destination(output / name)
    output.mkdir(parents=True, exist_ok=True)
    for name, content in contents.items():
        (output / name).write_text(content, encoding="ascii")


def check_output_contents(contents: dict[str, str]) -> None:
    """Refuse path injection and non-ASCII output before writing any file."""
    allowed_names = {"TASKS.md", "llms.txt", "catalog.public.json"}
    if set(contents) - allowed_names:
        fail("Output filenames must be recognized generated artifacts")
    if not all(content.isascii() for content in contents.values()):
        fail("Output content must be ASCII")


def check_output_directory(output: Path, names: set[str]) -> None:
    """Check ancestors and refuse a directory holding unrelated files."""
    ancestors = [output.absolute(), *output.absolute().parents]
    if any(path.is_symlink() for path in ancestors):
        fail("Output directory must not use symlinks")
    if output.exists():
        if not output.is_dir():
            fail("Output directory must be a directory")
        existing = {path.name for path in output.iterdir()}
        if existing - names:
            fail("Output directory contains unrelated files")


def main(argv: list[str] | None = None) -> int:
    """Validate or build locally; exit two on refused or unreadable input.

    Parameters
    ----------
    argv : list[str] or None
        Arguments, or None for process arguments. validate performs no writes.
        build requires a dedicated output directory.

    Returns
    -------
    int
        Zero on success. argparse exits two on a refused operation.
    """
    parser = argparse.ArgumentParser(
        description="Build navigation from reviewed public records."
    )
    parser.add_argument("command", choices=("validate", "build"))
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args(argv)
    try:
        data = load_catalog(args.catalog)
        validate_catalog(
            data, load_catalog(args.previous) if args.previous is not None else None
        )
        if args.command == "build":
            if args.output is None:
                fail("build requires --output")
            write_outputs(args.output, render_navigation(data))
    except (CatalogError, OSError) as error:
        parser.exit(2, f"Catalog refused: {error}\n")
    print("Catalog validated" if args.command == "validate" else "Navigation built")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
