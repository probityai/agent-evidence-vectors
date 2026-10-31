"""Build the vocabulary term pages under pages/vocab/v1/ from the registry index.

    python3 scripts/build_vocabulary_pages.py          # write the pages
    python3 scripts/build_vocabulary_pages.py --check  # fail when they are stale

Every term URI https://w3id.org/agent-evidence/vocab/v1/<term> redirects to
https://probityai.github.io/agent-evidence/vocab/v1/<term>/, and every registered
value is an anchor (#<value>) on its term's page. The input is
packages/vocabulary/registry.json, which gen_registry_index.py generates from
vocabulary.yaml. The build also publishes the exact vocabulary.yaml bytes at
vocab/v1/registry/sha256-<hex>.yaml, the address a record's registryDigest
names. A published registry copy is never removed, because older records name
it. Never edit pages/vocab/ by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "packages" / "vocabulary"
OUT = ROOT / "pages" / "vocab" / "v1"
PAGES_BASE = "https://probityai.github.io/agent-evidence/vocab/v1/"
_SPEC = importlib.util.spec_from_file_location("build_predicate_pages", ROOT / "scripts" / "build_predicate_pages.py")
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("cannot load scripts/build_predicate_pages.py")
_predicate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_predicate)
SOURCE_URL = "https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/vocabulary.yaml"
CONTEXT = {"skos": "http://www.w3.org/2004/02/skos/core#", "owl": "http://www.w3.org/2002/07/owl#",
           "rdfs": "http://www.w3.org/2000/01/rdf-schema#"}


def _jsonld(data: dict) -> str:
    """``data`` as a JSON-LD script element; ``<\\/`` keeps a definition from closing the element."""
    text = json.dumps({"@context": CONTEXT, **data}, indent=1, sort_keys=True, ensure_ascii=False)
    return '\n<script type="application/ld+json">\n' + text.replace("</", "<\\/") + "\n</script>"


def term_graph(name: str, term: dict, base: str, children: dict) -> dict:
    """The SKOS description of one term: a concept in the scheme. A registered value is a value OF the term,
    not a narrower kind of it, so it is tied to the term by rdfs:isDefinedBy and never by skos:narrower."""
    values = [{"@id": f"{term['uri']}#{value}", "@type": "skos:Concept", "skos:notation": value,
               "rdfs:isDefinedBy": {"@id": term["uri"]}, "skos:inScheme": {"@id": base},
                 **({"skos:definition": term["value_definitions"][value]}
                    if value in term["value_definitions"] else {})}
                for value in term["values"] or []]
    values += [{"@id": child["uri"], "@type": "skos:Concept", "skos:notation": code,
                "rdfs:isDefinedBy": {"@id": term["uri"]}, "skos:broader": {"@id": f"{term['uri']}#{child['parent']}"},
                "skos:inScheme": {"@id": base}}
               for code, child in sorted(children.items())]
    graph = {"@id": term["uri"], "@type": "skos:Concept", "skos:notation": name, "skos:prefLabel": name,
             "skos:definition": term["definition"], "skos:inScheme": {"@id": base},
             "skos:topConceptOf": {"@id": base}}
    return {"@graph": [graph, *values]}


def _term_page(name: str, term: dict, base: str, children: dict) -> str:
    e = html.escape
    parts = [f"<h1><code>{e(name)}</code></h1>",
             f'<p>Term URI: <a href="{term["uri"]}">{term["uri"]}</a></p>',
             f"<p>Section: <code>{e(term['section'])}</code>. Criticality: <code>{e(term['criticality'])}</code>.</p>",
             f"<p>{e(term['definition'])}</p>"]
    if term["values"]:
        parts.append("<h2>Registered values</h2>\n<ul>")
        for value in term["values"]:
            meaning = term["value_definitions"].get(value)
            tail = f": {e(meaning)}" if meaning else ""
            parts.append(f'<li id="{e(value)}"><code>{term["uri"]}#{e(value)}</code>{tail}</li>')
        parts.append("</ul>")
    if children:
        parts.append("<h2>Registered verdict classes</h2>\n<ul>")
        for code, child in sorted(children.items()):
            parts.append(f'<li id="{e(code)}"><code>{e(child["uri"])}</code>, parent <code>{e(child["parent"])}</code></li>')
        parts.append("</ul>")
    footer = (f'Generated from <a href="{SOURCE_URL}">vocabulary.yaml</a>. This page describes the current '
              "registry. A record is read against the registry its registryDigest names, named on "
              f'<a href="{PAGES_BASE}">the term listing</a>. The term URI does not change once a signed record carries it.')
    return _predicate._page(f"{name}: Agent Evidence vocabulary", term["uri"],
                            f"The {name} term of the Agent Evidence vocabulary.", "\n".join(parts), footer,
                            _jsonld(term_graph(name, term, base, children)))


def render(index: dict) -> dict[str, str]:
    """Every generated page, by path relative to pages/vocab/v1/."""
    base = index["term_uri_base"]
    children = index["verdict_classes"]["children"]
    parent_term = index["verdict_classes"]["parent_term"]
    pages = {}
    rows = []
    for name in sorted(index["terms"]):
        term = index["terms"][name]
        pages[f"{name}/index.html"] = _term_page(name, term, base, children if name == parent_term else {})
        rows.append(f'<li><a href="{name}/"><code>{term["uri"]}</code></a> ({html.escape(term["criticality"])})</li>')
    digest = index["source_sha256"]
    listing = (f"<h1>Vocabulary terms, version 1</h1>\n<p>Registry version {html.escape(index['version'])}, "
               f'registryDigest <a href="registry/sha256-{digest}.yaml"><code>{digest}</code></a>.</p>\n'
               "<ul>\n" + "\n".join(rows) + "\n</ul>")
    scheme = {"@id": base, "@type": "skos:ConceptScheme", "skos:prefLabel": "Agent Evidence vocabulary",
              "owl:versionInfo": index["version"], "rdfs:seeAlso": {"@id": f"{PAGES_BASE}registry/sha256-{digest}.yaml"},
              "skos:hasTopConcept": [{"@id": index["terms"][name]["uri"]} for name in sorted(index["terms"])]}
    pages["index.html"] = _predicate._page("Agent Evidence vocabulary terms", base,
                                           "The terms of the Agent Evidence vocabulary.", listing,
                                           "Agent Evidence vocabulary terms.", _jsonld(scheme))
    return pages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").partition("\n")[0])
    parser.add_argument("--check", action="store_true", help="fail when the pages are stale")
    args = parser.parse_args(argv)
    index = json.loads((PACKAGE / "registry.json").read_text(encoding="utf-8"))
    source = (PACKAGE / "vocabulary.yaml").read_bytes()
    if hashlib.sha256(source).hexdigest() != index["source_sha256"]:
        print("registry.json is stale: run packages/vocabulary/scripts/gen_registry_index.py", file=sys.stderr)
        return 1
    pages = render(index)
    copy = f"registry/sha256-{index['source_sha256']}.yaml"
    stale = [p for p, text in pages.items() if not (OUT / p).is_file() or (OUT / p).read_text(encoding="utf-8") != text]
    expected = set(pages) | {copy}
    extra = [str(p.relative_to(OUT)) for p in OUT.rglob("index.html")] if OUT.is_dir() else []
    extra = sorted(set(extra) - expected)
    if args.check:
        if not (OUT / copy).is_file() or (OUT / copy).read_bytes() != source:
            stale.append(copy)
        for failure in stale + [f"{p}: no longer generated" for p in extra]:
            print(f"pages/vocab/v1/{failure} is stale: run scripts/build_vocabulary_pages.py", file=sys.stderr)
        if stale or extra:
            return 1
        print(f"vocabulary pages ok ({len(pages)} pages)")
        return 0
    if extra:
        # A term URI, once published, stays resolvable: older records carry it.
        for path in extra:
            print(f"pages/vocab/v1/{path}: an issued term lost its page; keep the term (deprecated) instead",
                  file=sys.stderr)
        return 1
    for path, text in pages.items():
        (OUT / path).parent.mkdir(parents=True, exist_ok=True)
        (OUT / path).write_text(text, encoding="utf-8")
    (OUT / copy).parent.mkdir(parents=True, exist_ok=True)
    (OUT / copy).write_bytes(source)
    print(f"wrote {len(pages)} pages and {copy}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
