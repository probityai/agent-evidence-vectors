#!/usr/bin/env python3
"""Build the static site the Pages workflow publishes.

Every figure on the page is read from the repository at build time and none is
typed here: the per-corpus size comes from each corpus's MANIFEST.json, the
release tag from CITATION.cff, the failure-code union from aee/codes.go, and the
independent-runs and distribution pages are the tracked RUNS.md and
DISTRIBUTION.md rendered as they stand. The page carries no script and loads
nothing from anywhere else, so what a reader sees is what this build wrote.

Usage:
    python3 docs/site/build.py --out _site
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

import markdown

SUMMARY = "Build the static site the Pages workflow publishes."
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# The CURRENT owner path. The former one 301-redirects, so a link written to it
# still resolves and is still wrong: it publishes a spelling that is no longer
# this repository's, on every page of the site, and a redirect is not a name.
REPO_URL = "https://github.com/probityai/agent-evidence-vectors"
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


def render_markdown(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(
        r"\]\((?!https?://|#)([^)]+)\)",
        lambda m: f"]({REPO_URL}/blob/main/{m.group(1)})",
        text,
    )
    return markdown.markdown(text, extensions=["tables", "fenced_code"])


def page(title: str, body: str, tag: str) -> str:
    nav = " | ".join(
        f'<a href="{href}">{label}</a>'
        for href, label in (
            ("index.html", "Corpora"),
            ("runs.html", "Independent runs"),
            ("distribution.html", "Distribution"),
            ("codes.html", "Failure codes"),
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
        "<footer><p>Built from the repository at publish time. Every figure on these pages is "
        "read from a tracked file, never typed into the site.</p></footer>\n</body>\n</html>\n"
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
PREDICATE_DOC = REPO_ROOT / "spec" / "predicates" / "observed-effect.md"

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


def predicate_pages(tag: str) -> dict[Path, str]:
    """One page per registered type URI, plus the registry at the prefix itself.

    A type URI has no file extension, and the two ways a static host can resolve
    one are a sibling `<name>.html` and a child `<name>/index.html`. Which of
    them a host prefers is the host's business, so BOTH are written with the same
    bytes: the URI then cannot 404 under either routing, and a 404 on a type URI
    is indistinguishable to a verifier from a type that was withdrawn.

    The page a type URI serves is its normative document where this repository
    has one, and the registry entry where it does not. The registry says which is
    which, and it says so on the page, so nobody reads a registration as a field
    definition.
    """
    registry = render_markdown(PREDICATE_REGISTRY)
    pages: dict[Path, str] = {Path("predicate/index.html"): page("Predicate types", registry, tag)}
    for version, name in predicate_uris():
        if name == "observed-effect":
            body = render_markdown(PREDICATE_DOC)
            title = "Observed Effect predicate"
        else:
            body = registry
            title = f"{name} ({version}), registered"
        rendered = page(title, body, tag)
        pages[Path("predicate") / version / f"{name}.html"] = rendered
        pages[Path("predicate") / version / name / "index.html"] = rendered
    return pages


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=SUMMARY)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    tag = release_tag()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    pages = {
        "index.html": ("agent-evidence-vectors", index_body(tag)),
        "runs.html": ("Independent runs", render_markdown(REPO_ROOT / "RUNS.md")),
        "distribution.html": ("Distribution", render_markdown(REPO_ROOT / "DISTRIBUTION.md")),
        "codes.html": ("Failure codes", codes_body()),
    }
    for name, (title, body) in pages.items():
        (out / name).write_text(page(title, body, tag), encoding="utf-8")
    for relative, rendered in predicate_pages(tag).items():
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    written = len(pages) + len(predicate_pages(tag))
    print(f"wrote {written} pages to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
