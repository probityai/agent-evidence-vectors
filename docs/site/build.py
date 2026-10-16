#!/usr/bin/env python3
"""Publish the repository's guides, reference pages and tracked corpus data.

Usage:
    python3 docs/site/build.py --out _site
"""

from __future__ import annotations

import argparse
import html
import json
import posixpath
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from xml.etree.ElementTree import Element, SubElement, tostring

import markdown
from markdown.extensions import Extension
from markdown.treeprocessors import Treeprocessor

SUMMARY = "Build the static site the Pages workflow publishes."
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REPO_URL = "https://github.com/probityai/agent-evidence-vectors"
SITE_URL = "https://probityai.github.io/agent-evidence-vectors"
DOC_SECTIONS = ("guides", "reference", "research")
MANIFEST_NAME = "MANIFEST.json"
CODES_GO = REPO_ROOT / "aee" / "codes.go"
CITATION = REPO_ROOT / "CITATION.cff"
STYLE = (Path(__file__).resolve().parent / "style.css").read_text(encoding="utf-8")

# The same shape scripts/code-contract-gate.py reads, so a constant this page
# would miss is a constant that gate would miss too.
CONST_RE = re.compile(r'^Code[A-Za-z0-9]+\s+Code\s*=\s*"([a-z0-9-]+)"')


def corpus_dirs() -> list[Path]:
    """Every directory carrying a manifest, sorted by name, none skipped."""
    found = sorted(p.parent for p in REPO_ROOT.glob(f"*/{MANIFEST_NAME}"))
    if not found:
        raise SystemExit(f"FAIL: no {MANIFEST_NAME} found under {REPO_ROOT}")
    return found


def read_manifest(directory: Path) -> dict[str, object]:
    with (directory / MANIFEST_NAME).open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict) or not isinstance(loaded.get("vectors"), list):
        raise SystemExit(f"FAIL: {directory.name}/{MANIFEST_NAME} carries no vectors list")
    return loaded


def release_tag() -> str:
    for line in CITATION.read_text(encoding="utf-8").splitlines():
        if line.startswith("version:"):
            return "v" + line.split(":", 1)[1].strip()
    raise SystemExit("FAIL: CITATION.cff carries no version line")


def failure_codes() -> list[tuple[str, list[str]]]:
    """The code constants of aee/codes.go, grouped under the comment that
    introduces each const block: the comment lines directly above ``const (``
    joined, cut at the end of their first sentence."""
    groups: list[tuple[str, list[str]]] = []
    comment: list[str] = []
    in_block = False
    for raw in CODES_GO.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if in_block:
            if line == ")":
                in_block = False
            else:
                const = CONST_RE.match(line)
                if const:
                    groups[-1][1].append(const.group(1))
            continue
        if line.startswith("//"):
            comment.append(line[2:].strip())
        elif line.startswith("const ("):
            in_block = True
            groups.append((first_sentence(" ".join(comment)) or "Codes", []))
            comment = []
        else:
            comment = []
    if not any(codes for _, codes in groups):
        raise SystemExit("FAIL: aee/codes.go yielded no code constants")
    return groups


def first_sentence(text: str) -> str:
    """Up to the first period that ends a sentence; ``0.7`` is not one."""
    match = re.search(r"\.(?:\s|$)", text)
    return (text[: match.start()] if match else text).strip()


def published_routes() -> dict[Path, Path]:
    """Map tracked Markdown sources to their published HTML routes.

    Returns
    -------
    dict of pathlib.Path to pathlib.Path
        Repository-relative source paths and site-relative output paths.
        New pages in ``DOC_SECTIONS`` join the site without another route list.
        Predicate aliases are added separately by :func:`predicate_pages`.
    """
    routes = {
        Path("README.md"): Path("start.html"),
        Path("RUNS.md"): Path("runs.html"),
        Path("DISTRIBUTION.md"): Path("distribution.html"),
        Path("spec/predicates/REGISTRY.md"): Path("predicate/index.html"),
        Path("spec/predicates/observed-effect.md"): Path("predicate/v1/observed-effect.html"),
    }
    for section in DOC_SECTIONS:
        for source in sorted((REPO_ROOT / "docs" / section).rglob("*.md")):
            relative = source.relative_to(REPO_ROOT)
            routes[relative] = relative.relative_to("docs").with_suffix(".html")
    return routes


def relative_route(target: Path, current: Path) -> str:
    """Locate a published page from another page's output directory.

    Parameters
    ----------
    target, current : pathlib.Path
        Site-relative output paths, including their HTML filenames.

    Returns
    -------
    str
        A POSIX URL path that works at either predicate alias depth.
    """
    return posixpath.relpath(target.as_posix(), current.parent.as_posix())


def repository_target(value: str, source: Path) -> Path:
    """Resolve a link against its Markdown source and keep it inside the repo.

    Parameters
    ----------
    value : str
        The URL path, without a query or fragment. Percent escapes are decoded
        before checking parent traversal and symlink destinations.
    source : pathlib.Path
        The Markdown file containing the link.

    Returns
    -------
    pathlib.Path
        The resolved repository-relative target.

    Raises
    ------
    ValueError
        If the link escapes ``REPO_ROOT`` or its target does not exist.
    """
    decoded = unquote(value)
    parent = REPO_ROOT if decoded.startswith("/") else source.parent
    target = (parent / decoded.lstrip("/")).resolve()
    root = REPO_ROOT.resolve()
    if not target.is_relative_to(root):
        raise ValueError(f"Markdown link escapes repository: {value!r}")
    relative = target.relative_to(root)
    if not target.exists():
        raise ValueError(f"Markdown link target is missing: {relative.as_posix()!r}")
    return relative


def repository_url(target: Path) -> str:
    """Return the GitHub file or directory URL for an unpublished repo asset.

    Parameters
    ----------
    target : pathlib.Path
        A validated repository-relative path from :func:`repository_target`.

    Returns
    -------
    str
        The current repository URL, with spaces and URL punctuation escaped.

    Raises
    ------
    ValueError
        If a guide, reference or research Markdown target has no site route.
    """
    if target.suffix == ".md" and target.parts[:2] in {
        ("docs", section) for section in DOC_SECTIONS
    }:
        raise ValueError(f"Published document has no route: {target.as_posix()!r}")
    kind = "tree" if (REPO_ROOT / target).is_dir() else "blob"
    return f"{REPO_URL}/{kind}/main/{quote(target.as_posix(), safe='/')}"


def resolve_link(value: str, source: Path, output: Path, routes: Mapping[Path, Path]) -> str:
    """Rewrite a Markdown link while retaining its query and fragment.

    Parameters
    ----------
    value : str
        The parsed Markdown link destination.
    source : pathlib.Path
        The source Markdown file, used for relative path resolution.
    output : pathlib.Path
        The site-relative HTML page receiving the rendered link.
    routes : mapping of pathlib.Path to pathlib.Path
        Published source-to-output routes from :func:`published_routes`.

    Returns
    -------
    str
        A relative site route, a GitHub fallback, or the unchanged external or
        fragment-only URL. Code examples are not processed as links.

    Raises
    ------
    ValueError
        If the source-relative target escapes the repo or a published document
        is absent from ``routes``.
    """
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or not parts.path:
        return value
    target = repository_target(parts.path, source)
    destination = routes.get(target)
    resolved = (
        quote(relative_route(destination, output), safe="/")
        if destination is not None
        else repository_url(target)
    )
    return urlunsplit(("", "", resolved, parts.query, parts.fragment))


class SourceLinks(Treeprocessor):
    """Resolve parsed links without rewriting code blocks or raw HTML anchors."""

    def __init__(
        self, md: markdown.Markdown, source: Path, output: Path, routes: Mapping[Path, Path]
    ) -> None:
        super().__init__(md)
        self.source = source
        self.output = output
        self.routes = routes

    def run(self, root: Element) -> Element:
        """Rewrite anchor destinations after Markdown has parsed inline text.

        Parameters
        ----------
        root : xml.etree.ElementTree.Element
            The parsed Markdown tree.

        Returns
        -------
        xml.etree.ElementTree.Element
            The tree with site-aware links and unchanged heading identifiers.
        """
        for anchor in root.iter("a"):
            href = anchor.get("href")
            if href is not None:
                anchor.set("href", resolve_link(href, self.source, self.output, self.routes))
        for image in root.iter("img"):
            value = image.get("src")
            if value is not None:
                resolved = resolve_link(value, self.source, self.output, self.routes)
                image.set(
                    "src", resolved.replace(f"{REPO_URL}/blob/main/", f"{REPO_URL}/raw/main/")
                )
        return root


class SourceLinkExtension(Extension):
    """Attach source and output routes to the Markdown renderer."""

    def __init__(self, source: Path, output: Path, routes: Mapping[Path, Path]) -> None:
        super().__init__()
        self.source = source
        self.output = output
        self.routes = routes

    def extendMarkdown(self, md: markdown.Markdown) -> None:
        """Register :class:`SourceLinks` after inline links and headings exist.

        Parameters
        ----------
        md : markdown.Markdown
            The renderer building one published page.
        """
        processor = SourceLinks(md, self.source, self.output, self.routes)
        md.treeprocessors.register(processor, "repository-links", 1)


def render_markdown(
    path: Path, output: Path | None = None, routes: Mapping[Path, Path] | None = None
) -> str:
    """Render a source page with heading IDs and source-relative links.

    Parameters
    ----------
    path : pathlib.Path
        The Markdown source file.
    output : pathlib.Path, optional
        The site's output route. By default, use the route registered for the
        source, or ``index.html`` when rendering an unpublished document.
    routes : mapping of pathlib.Path to pathlib.Path, optional
        The publication map. Defaults to :func:`published_routes`.

    Returns
    -------
    str
        HTML containing the source's text, heading IDs and resolved links.
    """
    selected = published_routes() if routes is None else routes
    relative = path.resolve().relative_to(REPO_ROOT.resolve())
    destination = output if output is not None else selected.get(relative, Path("index.html"))
    extension = SourceLinkExtension(path.resolve(), destination, selected)
    return markdown.markdown(
        path.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "toc", extension],
    )


def page(title: str, body: str, tag: str, output: Path = Path("index.html")) -> str:
    nav = " | ".join(
        f'<a href="{html.escape(href)}">{label}</a>'
        for href, label in (
            (relative_route(Path("start.html"), output), "Start"),
            (relative_route(Path("index.html"), output), "Corpora"),
            (relative_route(Path("runs.html"), output), "Runs"),
            (relative_route(Path("distribution.html"), output), "Releases"),
            (relative_route(Path("codes.html"), output), "Codes"),
            (REPO_URL, "Repository"),
        )
    )
    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n<style>\n{STYLE}</style>\n</head>\n<body>\n"
        '<header><p class="site">agent-evidence-vectors '
        f'<span class="tag">{html.escape(tag)}</span></p>'
        f"<nav>{nav}</nav></header>\n<main>\n{body}\n</main>\n"
        "<footer><p>Built from tracked repository files.</p></footer>\n</body>\n</html>\n"
    )


def index_body(tag: str) -> str:
    rows = []
    for directory in corpus_dirs():
        manifest = read_manifest(directory)
        vectors = manifest["vectors"]
        assert isinstance(vectors, list)
        suite = html.escape(str(manifest.get("suite", "")))
        digest = html.escape(str(manifest.get("corpusDigest", "")))
        counts = manifest.get("counts")
        split = (
            ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
            if isinstance(counts, dict)
            else ""
        )
        rows.append(
            f'<tr><td><a href="{REPO_URL}/tree/main/{directory.name}">'
            f"<code>{directory.name}/</code></a></td>"
            f'<td><code>{suite}</code></td><td class="num">{len(vectors)}</td>'
            f'<td>{html.escape(split)}</td><td><code class="digest">{digest}</code></td></tr>'
        )
    return (
        "<h1>Conformance corpora</h1>\n"
        "<p>One row per corpus directory in the repository, read from each directory's "
        "<code>MANIFEST.json</code> when this page was built. The count is the length of the "
        "manifest's vector list; the split is its <code>counts</code> member; the digest is its "
        f"<code>corpusDigest</code>. The signed list of the same digests is "
        f'<a href="{REPO_URL}/blob/main/release/CORPUS-DIGESTS.txt">'
        "release/CORPUS-DIGESTS.txt</a>.</p>\n"
        "<table><thead><tr><th>Directory</th><th>Suite</th><th>Vectors</th><th>Split</th>"
        "<th>corpusDigest</th></tr></thead><tbody>\n" + "\n".join(rows) + "\n</tbody></table>\n"
        f"<p>Tag: <code>{html.escape(tag)}</code>, read from <code>CITATION.cff</code>. "
        f'<a href="distribution.html">Distribution</a> says how to cite and verify a release; '
        f'<a href="runs.html">Independent runs</a> records outside runs in their authors\' words; '
        '<a href="codes.html">Failure codes</a> lists the closed code set the reference '
        "verifier emits.</p>\n"
    )


def codes_body() -> str:
    sections = []
    for heading, codes in failure_codes():
        items = "\n".join(f"<li><code>{html.escape(c)}</code></li>" for c in codes)
        sections.append(f'<h2>{html.escape(heading)}</h2>\n<ul class="codes">\n{items}\n</ul>')
    return (
        "<h1>Failure codes</h1>\n"
        f'<p>Every code constant in <a href="{REPO_URL}/blob/main/aee/codes.go">'
        "<code>aee/codes.go</code></a>, grouped under the heading its const block sits under, "
        "read at build time. The codes are this "
        "suite's closed set, compared as a set by the harness; message text carries nothing. "
        "<code>scripts/code-contract-gate.py</code> holds the corpus and both first-party rails "
        "to this set.</p>\n" + "\n".join(sections)
    )


PREDICATE_REGISTRY = REPO_ROOT / "spec" / "predicates" / "REGISTRY.md"

# Every type URI under this host's /predicate/ prefix, read from the tracked
# registry rather than typed here: a URI present in a signed payload and absent
# from the registry is meant to fail review, and a second list in this file would
# be the place that silently disagreed.
PREDICATE_PATH_RE = re.compile(r"^### `predicate/(v\d+)/([a-z0-9-]+)`$", re.MULTILINE)


def predicate_uris() -> list[tuple[str, str]]:
    """The (version, name) pair of every registered type URI, in registry order."""
    found = PREDICATE_PATH_RE.findall(PREDICATE_REGISTRY.read_text(encoding="utf-8"))
    if not found:
        raise SystemExit(f"FAIL: {PREDICATE_REGISTRY} registers no predicate type URI")
    return [(version, name) for version, name in found]


# A "Defined here" entry names its normative document on a `- Document:` line.
DEFINED_SECTION_RE = re.compile(r"^## Defined here$(.*?)^## ", re.MULTILINE | re.DOTALL)
DOCUMENT_RE = re.compile(
    r"^### `predicate/(v\d+)/([a-z0-9-]+)`$\s*^- Document: `([^`]+)`$", re.MULTILINE
)


def defined_documents() -> dict[tuple[str, str], Path]:
    """The normative document of every type URI the registry says is defined here.

    Read from the registry for the same reason the URI list is: the page a type
    URI serves is decided in one tracked file. An entry under "Defined here"
    that names no document, or names one that is not tracked, fails the build
    rather than falling back to the registration page, because serving the
    registry where a definition was promised is the 404 in a quieter form.
    """
    text = PREDICATE_REGISTRY.read_text(encoding="utf-8")
    section = DEFINED_SECTION_RE.search(text)
    if section is None:
        raise SystemExit(f"FAIL: {PREDICATE_REGISTRY} has no 'Defined here' section")
    names = PREDICATE_PATH_RE.findall(section.group(1))
    docs = {(v, n): REPO_ROOT / rel for v, n, rel in DOCUMENT_RE.findall(section.group(1))}
    for key in names:
        if key not in docs or not docs[key].is_file():
            raise SystemExit(
                f"FAIL: predicate/{key[0]}/{key[1]} is defined here and names no document"
            )
    return docs


def document_title(path: Path) -> str:
    """The document's own first heading, without the registry's prefix."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            heading = line[2:].strip()
            if heading.startswith("Predicate type: "):
                return heading.removeprefix("Predicate type: ") + " predicate"
            return heading
    raise SystemExit(f"FAIL: {path} has no first-level heading")


def predicate_pages(tag: str, routes: Mapping[Path, Path] | None = None) -> dict[Path, str]:
    """One page per registered type URI, plus the registry at the prefix itself.

    A type URI has no file extension, and the two ways a static host can resolve
    one are a sibling `<name>.html` and a child `<name>/index.html`. Both serve
    the same source document with navigation relative to their own directory.

    The page a type URI serves is its normative document where this repository
    has one, and the registry entry where it does not. The registry says which is
    which, and it says so on the page, so nobody reads a registration as a field
    definition.
    """
    selected = published_routes() if routes is None else routes
    prefix = Path("predicate/index.html")
    registry = render_markdown(PREDICATE_REGISTRY, prefix, selected)
    uris = predicate_uris()
    defined = defined_documents()
    pages: dict[Path, str] = {prefix: page("Predicate types", registry, tag, prefix)}
    for version, name in uris:
        document = defined.get((version, name))
        if document is not None:
            source = document
            title = document_title(document)
        else:
            source = PREDICATE_REGISTRY
            title = f"{name} ({version}), registered"
        for relative in (
            Path("predicate") / version / f"{name}.html",
            Path("predicate") / version / name / "index.html",
        ):
            body = render_markdown(source, relative, selected)
            pages[relative] = page(title, body, tag, relative)
    return pages


def markdown_pages(tag: str, routes: Mapping[Path, Path]) -> dict[Path, str]:
    """Render every published Markdown source except predicate aliases.

    Parameters
    ----------
    tag : str
        The release tag displayed in the site header.
    routes : mapping of pathlib.Path to pathlib.Path
        The source-to-output map from :func:`published_routes`.

    Returns
    -------
    dict of pathlib.Path to str
        Complete pages for the start, runs, distribution and companion routes.
    """
    pages = {}
    for relative, output in routes.items():
        if relative.parts[:2] == ("spec", "predicates"):
            continue
        source = REPO_ROOT / relative
        heading = re.search(r"^# (.+)$", source.read_text(encoding="utf-8"), re.MULTILINE)
        title = heading.group(1) if heading is not None else source.stem
        body = render_markdown(source, output, routes)
        pages[output] = page(title, body, tag, output)
    return pages


def canonical_route(path: Path) -> str | None:
    """Choose one discovery URL for each published document.

    Parameters
    ----------
    path : pathlib.Path
        A site-relative HTML output path.

    Returns
    -------
    str or None
        An HTML route, the predicate prefix, or the registered extensionless
        predicate URI. A predicate's directory alias returns ``None``.
    """
    if path.parts[0] != "predicate":
        return path.as_posix()
    if path.name != "index.html":
        return path.with_suffix("").as_posix()
    return "predicate/" if len(path.parts) == 2 else None


def sitemap(paths: Iterable[Path]) -> bytes:
    """Build a deterministic sitemap without duplicate predicate aliases.

    Parameters
    ----------
    paths : iterable of pathlib.Path
        All HTML output routes produced by the site build.

    Returns
    -------
    bytes
        UTF-8 XML containing sorted canonical URLs. No build clock or derived
        modification date is added.
    """
    routes = {canonical_route(path) for path in paths} - {None}
    root = Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")
    for route in sorted(str(route) for route in routes):
        entry = SubElement(root, "url")
        SubElement(entry, "loc").text = f"{SITE_URL}/{quote(route, safe='/')}"
    return bytes(tostring(root, encoding="utf-8", xml_declaration=True))


def write_discovery(out: Path, paths: Iterable[Path]) -> None:
    """Serve the reviewed agent guide unchanged and list canonical pages.

    Parameters
    ----------
    out : pathlib.Path
        The site output directory.
    paths : iterable of pathlib.Path
        Published HTML routes passed to :func:`sitemap`.

    Raises
    ------
    ValueError
        If the tracked ``llms.txt`` contains non-ASCII text.
    """
    guide = (REPO_ROOT / "llms.txt").read_bytes()
    try:
        guide.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("llms.txt must contain ASCII text") from error
    (out / "llms.txt").write_bytes(guide)
    (out / "sitemap.xml").write_bytes(sitemap(paths))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=SUMMARY)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    tag = release_tag()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    routes = published_routes()
    pages = {
        Path("index.html"): page("agent-evidence-vectors", index_body(tag), tag),
        Path("codes.html"): page("Failure codes", codes_body(), tag),
    }
    pages.update(markdown_pages(tag, routes))
    pages.update(predicate_pages(tag, routes))
    for relative, rendered in pages.items():
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
    write_discovery(out, pages)
    (out / ".nojekyll").write_text("", encoding="utf-8")
    print(f"wrote {len(pages)} pages to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
