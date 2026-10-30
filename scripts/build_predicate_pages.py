"""Build the predicate type pages under pages/ from their specification files.

    python3 scripts/build_predicate_pages.py --spec-dir DIR --commit SHA

Each type URI under https://w3id.org/agent-evidence/predicate/v1/ redirects to
https://probityai.github.io/agent-evidence/predicate/v1/<name>/, the Pages site of
this repository, and the page there is its specification rendered to HTML. DIR
holds the specification files (spec/predicates/ of agent-evidence-vectors at
SHA). The build needs pandoc 3.3 and writes pages/; CI does not run it. CI checks
the published bytes instead (scripts/check_predicate_pages.py), because a page
must not change by accident once a signed statement carries its URI.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "pages"
TYPE_BASE = "https://w3id.org/agent-evidence/predicate/v1/"
SPEC_REPO = "https://github.com/probityai/agent-evidence-vectors"
# The predicates this site defines, by URI name, and the specification file of each.
PREDICATES = {"done-contract": "done-contract.md", "done-receipt": "done-receipt.md"}
STYLE = """:root{color-scheme:light dark;--page:#f6f8fb;--surface:#fff;--ink:#14202e;--body:#33404f;\
--link:#1f4fd1;--rule:#cfd8e3;font-family:system-ui,sans-serif;color:var(--ink);background:var(--page)}
@media (prefers-color-scheme:dark){:root{--page:#10151b;--surface:#18202a;--ink:#e8edf3;--body:#c3ccd6;\
--link:#8fb0ff;--rule:#2c3846}}
*{box-sizing:border-box}body{margin:0;font:400 1rem/1.6 system-ui,sans-serif;background:var(--page)}
.shell{max-width:52rem;margin-inline:auto;padding-inline:16px}
header,footer{padding-block:1.25rem}header a{font-weight:700;color:var(--ink);text-decoration:none}
footer{border-top:1px solid var(--rule);color:var(--body);font-size:.9375rem;margin-top:3rem}
a{color:var(--link)}p,li,td{color:var(--body)}h1{line-height:1.2}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:.875em}code{overflow-wrap:anywhere}
pre{background:var(--surface);border:1px solid var(--rule);border-radius:6px;padding:1rem;overflow-x:auto}
blockquote{margin:1rem 0;padding:.25rem 1rem;border-left:4px solid var(--rule);background:var(--surface)}
table{border-collapse:collapse;display:block;overflow-x:auto}
th,td{border:1px solid var(--rule);padding:.4rem .6rem;text-align:left;vertical-align:top}"""


def _page(title: str, canonical: str, description: str, body: str, footer: str, head: str = "") -> str:
    """One page. ``head`` is extra markup for the end of <head>, each element on its own line."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
<link rel="canonical" href="{canonical}">{head}
<style>
{STYLE}
</style>
</head>
<body>
<header class="shell"><a href="https://github.com/probityai/agent-evidence">Agent Evidence</a></header>
<main class="shell">
{body}
</main>
<footer><div class="shell">{footer}</div></footer>
</body>
</html>
"""


def _render(markdown: str, commit: str) -> str:
    # A link to a sibling specification becomes a link to that file at the pinned commit.
    markdown = re.sub(r"\]\(([a-z0-9-]+\.md)\)",
                      lambda m: f"]({SPEC_REPO}/blob/{commit}/spec/predicates/{m[1]})", markdown)
    return subprocess.run(["pandoc", "-f", "gfm", "-t", "html5", "--wrap=none"], input=markdown,
                          capture_output=True, text=True, check=True).stdout


def build(spec_dir: Path, commit: str) -> dict[str, str]:
    """Write every page and return the SHA-256 of each predicate page by name."""
    digests = {}
    rows = []
    for name, filename in PREDICATES.items():
        source = (spec_dir / filename).read_text(encoding="utf-8")
        title = source.splitlines()[0].removeprefix("# ").strip()
        uri = TYPE_BASE + name
        if f"Type URI: {uri}" not in source:
            raise SystemExit(f"{filename} does not declare the type URI {uri}")
        source_url = f"{SPEC_REPO}/blob/{commit}/spec/predicates/{filename}"
        source_sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        footer = (f'Built from <a href="{source_url}">spec/predicates/{filename}</a> '
                  f"(SHA-256 <code>{source_sha}</code>). The type URI is <code>{uri}</code>; it does "
                  "not change once a signed statement carries it.")
        page = _page(title, uri, f"Type URI, schema and rules of the {title.split(': ')[-1]} in-toto "
                     "predicate.", _render(source, commit), footer)
        out = PAGES / "predicate" / "v1" / name / "index.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(page, encoding="utf-8")
        digests[name] = hashlib.sha256(page.encode("utf-8")).hexdigest()
        rows.append(f'<li><a href="{name}/"><code>{uri}</code></a>: {html.escape(title)}</li>')
    listing = ("<h1>Predicate types, version 1</h1>\n<p>Each type URI below is a persistent identifier "
               "that redirects to its page here.</p>\n<ul>\n" + "\n".join(rows) + "\n</ul>")
    (PAGES / "predicate" / "v1" / "index.html").write_text(
        _page("Agent Evidence predicate types", TYPE_BASE, "The in-toto predicate types of Agent Evidence.",
              listing, "Agent Evidence predicate types."), encoding="utf-8")
    (PAGES / "index.html").write_text(
        _page("Agent Evidence", "https://w3id.org/agent-evidence/", "Persistent identifiers of Agent Evidence.",
              '<h1>Agent Evidence</h1>\n<p>The pages behind the persistent identifiers under '
              '<code>https://w3id.org/agent-evidence/</code>.</p>\n<ul>\n<li><a href="predicate/v1/">'
              "Predicate types, version 1</a></li>\n</ul>",
              '<a href="https://github.com/probityai/agent-evidence">probityai/agent-evidence</a>'),
        encoding="utf-8")
    (PAGES / "predicate" / "v1" / "PAGES.sha256").write_text(
        "".join(f"{digests[n]}  {n}\n" for n in sorted(digests)), encoding="utf-8")
    return digests


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").partition("\n")[0])
    parser.add_argument("--spec-dir", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    for name, digest in sorted(build(args.spec_dir, args.commit).items()):
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
