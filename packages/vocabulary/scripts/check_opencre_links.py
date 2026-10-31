#!/usr/bin/env python3
"""Hold the OpenCRE links in vocabulary.yaml to the one shape OpenCRE can import.

OpenCRE's preferred way to link a standard is self-maintaining: the standard
carries a hyperlink to each Common Requirement it states, and OpenCRE's importer
reads the standard's own source and extracts those hyperlinks. Its existing
importers match `(https://www\\.)?opencre.org/cre/(?P<cre>\\d+-\\d+)` anywhere in
the text. So every such URL in vocabulary.yaml is a link OpenCRE would import,
wherever it sits, comments included. That makes the file's text the contract,
and this script holds it.

What it requires:

- A term links to OpenCRE only through an `opencre` list on the term itself.
  Each item is a mapping with exactly `cre`, `match` and `basis`. `cre` is the
  full `https://www.opencre.org/cre/NNN-NNN` URL. `match` is `exact`,
  `structural` or `partial`, read from the registry's own crosswalk_match_types.
  `basis` is one line saying what the term and the requirement share.
- No CRE appears twice on one term.
- Every opencre.org/cre/ URL in the raw text is one of those declared links,
  counted. A URL in a comment or a definition would be imported as a link
  nobody declared, so it is refused.
- `opencre` appears only on a term under one of the validator's term sections.
- docs/OPENCRE.md carries the same (term, CRE, match, basis) rows as the
  registry, no more and no fewer, and names every live term without a link in
  its second table, so the page a reviewer reads cannot drift from the file
  OpenCRE imports.

With `--live` it also asks opencre.org for each linked CRE and requires the id
to resolve to a CRE. That is a network call made on purpose: whether an id
exists is a fact about the live catalogue, and only the catalogue can settle it.

Exit 0 every link holds, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_VOCAB = _ROOT / "vocabulary.yaml"
_DOC = _ROOT / "docs" / "OPENCRE.md"
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"

#: The only spelling a link may take. Anchored at both ends, so a bare id, a
#: missing `www.`, plain http, a trailing path or a query string all fail.
CRE_URL = re.compile(r"^https://www\.opencre\.org/cre/(?P<id>\d{3}-\d{3})$")

#: What OpenCRE's importer would extract from the raw text. Deliberately looser
#: than CRE_URL, so a malformed URL that still imports is counted and refused.
IMPORTABLE = re.compile(r"opencre\.org/cre/(?P<id>\d+-\d+)")

#: The match types a link may declare. no_mapping and non_equivalent_similar_label
#: describe the absence of a link, so a link carrying one contradicts itself.
LINK_MATCHES = ("exact", "structural", "partial")

LINK_KEYS = frozenset({"cre", "match", "basis"})

#: A row of the link table in docs/OPENCRE.md: | `section.term` | [NNN-NNN](url) name | match | basis |
DOC_ROW = re.compile(
    r"^\|\s*`(?P<term>[a-z_]+\.[a-z_]+)`\s*\|\s*\[(?P<id>\d{3}-\d{3})\]"
    r"\((?P<url>[^)]+)\)[^|]*\|\s*(?P<match>[a-z_]+)\s*\|\s*(?P<basis>[^|]*?)\s*\|\s*$"
)

#: A row of the no-link table: | `section.term` | why no CRE fits |
DOC_UNLINKED = re.compile(r"^\|\s*`(?P<term>[a-z_]+\.[a-z_]+)`\s*\|\s*(?P<why>[^\[|][^|]*?)\s*\|\s*$")


def _term_sections() -> tuple[str, ...] | None:
    """The validator's term sections, so the two scripts cannot disagree."""
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return tuple(module.TERM_SECTIONS)


def declared_links(registry: dict, sections: tuple[str, ...], errors: list[str]) -> list[tuple[str, str, str, str]]:
    """Every (section.term, cre id, match, basis) the registry declares, refusing bad shapes."""
    match_types = registry.get("crosswalk_match_types")
    if not isinstance(match_types, dict):
        errors.append("vocabulary.yaml has no crosswalk_match_types mapping to read match values from")
        return []
    allowed = [m for m in LINK_MATCHES if m in match_types]
    links: list[tuple[str, str, str, str]] = []
    for section in sections:
        block = registry.get(section) or {}
        if not isinstance(block, dict):
            continue
        for term, entry in block.items():
            if not isinstance(entry, dict) or "opencre" not in entry:
                continue
            links.extend(_term_links(f"{section}.{term}", entry["opencre"], allowed, errors))
    return links


def _term_links(name: str, items, allowed: list[str], errors: list[str]) -> list[tuple[str, str, str, str]]:
    if not isinstance(items, list) or not items:
        errors.append(f"{name}: opencre must be a non-empty list of links (got {type(items).__name__})")
        return []
    links: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        where = f"{name}: opencre[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{where} must be a mapping with cre, match and basis (got {type(item).__name__})")
            continue
        keys = set(item)
        if keys != LINK_KEYS:
            missing = sorted(LINK_KEYS - keys)
            extra = sorted(keys - LINK_KEYS)
            errors.append(f"{where} must carry exactly cre, match and basis (missing {missing}, unexpected {extra})")
            continue
        cre = item["cre"]
        found = CRE_URL.match(cre) if isinstance(cre, str) else None
        if found is None:
            errors.append(
                f"{where}: cre {cre!r} is not a full https://www.opencre.org/cre/NNN-NNN URL, "
                f"the form OpenCRE's importer reads"
            )
            continue
        if item["match"] not in allowed:
            errors.append(f"{where}: match {item['match']!r} is not one of {allowed}")
            continue
        basis = item["basis"]
        if not isinstance(basis, str) or not basis.strip() or "\n" in basis.strip():
            errors.append(f"{where}: basis must be one non-empty line saying what the term and the requirement share")
            continue
        cre_id = found.group("id")
        if cre_id in seen:
            errors.append(f"{where}: CRE {cre_id} is linked twice from this term")
            continue
        seen.add(cre_id)
        links.append((name, cre_id, item["match"], basis.strip()))
    return links


def stray_keys(node, sections: tuple[str, ...], errors: list[str], path: str = "") -> None:
    """Refuse an `opencre` key anywhere but directly on a term in a term section."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if key == "opencre":
                parts = here.split(".")
                if not (len(parts) == 3 and parts[0] in sections):
                    errors.append(f"{here}: an opencre list belongs only on a term under {list(sections)}")
            stray_keys(value, sections, errors, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            stray_keys(value, sections, errors, f"{path}[{index}]")


def stray_urls(text: str, links: list[tuple[str, str, str, str]], errors: list[str]) -> None:
    """Every importable URL in the raw text must be a declared link, counted."""
    in_text: dict[str, int] = {}
    for found in IMPORTABLE.finditer(text):
        in_text[found.group("id")] = in_text.get(found.group("id"), 0) + 1
    declared: dict[str, int] = {}
    for _, cre_id, _, _ in links:
        declared[cre_id] = declared.get(cre_id, 0) + 1
    for cre_id in sorted(set(in_text) | set(declared)):
        if in_text.get(cre_id, 0) != declared.get(cre_id, 0):
            errors.append(
                f"opencre.org/cre/{cre_id} appears {in_text.get(cre_id, 0)} time(s) in the text and is declared "
                f"{declared.get(cre_id, 0)} time(s); OpenCRE imports every occurrence, so each must be a declared link"
            )


def doc_rows(doc: str, links: list[tuple[str, str, str, str]], terms: set[str], errors: list[str]) -> None:
    """docs/OPENCRE.md lists exactly the declared links, and every other live term as unlinked."""
    rows, unlinked = [], []
    for line in doc.splitlines():
        found = DOC_ROW.match(line)
        if found is not None:
            expected = f"https://www.opencre.org/cre/{found.group('id')}"
            if found.group("url") != expected:
                errors.append(f"docs/OPENCRE.md: the row for {found.group('term')} links {found.group('url')}, "
                              f"not {expected}")
            rows.append((found.group("term"), found.group("id"), found.group("match"), found.group("basis")))
            continue
        found = DOC_UNLINKED.match(line)
        if found is not None and found.group("term") in terms:
            unlinked.append(found.group("term"))
    for row in sorted(set(links) - set(rows)):
        errors.append(f"docs/OPENCRE.md has no row for {row[0]} -> {row[1]} ({row[2]}) with the registry's basis")
    for row in sorted(set(rows) - set(links)):
        errors.append(f"docs/OPENCRE.md lists {row[0]} -> {row[1]} ({row[2]}) with a basis vocabulary.yaml "
                      f"does not declare")
    linked = {row[0] for row in links}
    for term in sorted(terms - linked - set(unlinked)):
        errors.append(f"docs/OPENCRE.md does not say why {term} has no CRE")
    for term in sorted(set(unlinked) & linked):
        errors.append(f"docs/OPENCRE.md lists {term} as having no CRE, and vocabulary.yaml links it")


def check(text: str, doc: str, sections: tuple[str, ...]) -> tuple[list[str], list[tuple[str, str, str, str]]]:
    """All findings for one registry text and one docs page."""
    errors: list[str] = []
    try:
        registry = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"vocabulary.yaml is not valid YAML: {exc}"], []
    if not isinstance(registry, dict):
        return ["vocabulary.yaml is not a mapping"], []
    links = declared_links(registry, sections, errors)
    stray_keys(registry, sections, errors)
    stray_urls(text, links, errors)
    terms = {f"{section}.{term}" for section in sections
             for term in (registry.get(section) or {}) if isinstance(registry.get(section), dict)}
    doc_rows(doc, links, terms, errors)
    return errors, links


def resolve(cre_id: str) -> tuple[bool | None, str]:
    """(True, name) when opencre.org returns the CRE, (False, why) when it answers otherwise,
    (None, why) when it could not be asked."""
    url = f"https://www.opencre.org/rest/v1/id/{cre_id}"
    # opencre.org answers urllib's default User-Agent with 403, so the request
    # names itself. Only a 404 says the id is unknown; any other refusal says the
    # catalogue was not asked, and is never read as a finding about the link.
    request = urllib.request.Request(url, headers={"User-Agent": "agent-evidence-vocabulary-check"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, f"HTTP 404 from {url}"
        return None, f"HTTP {exc.code} from {url}"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return None, f"{url} could not be read ({exc})"
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict) or data.get("id") != cre_id or data.get("doctype") != "CRE":
        return False, f"{url} did not return CRE {cre_id}"
    return True, str(data.get("name"))


def main(argv: list[str]) -> int:
    live = "--live" in argv
    sections = _term_sections()
    if not sections:
        print("check_opencre_links: REFUSED -- the validator's term sections could not be read; "
              "nothing was checked.", file=sys.stderr)
        return 2
    try:
        text = _VOCAB.read_text(encoding="utf-8")
        doc = _DOC.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"check_opencre_links: REFUSED -- {exc}; nothing was checked.", file=sys.stderr)
        return 2
    errors, links = check(text, doc, sections)
    unreachable = []
    if live and not errors:
        for cre_id in sorted({link[1] for link in links}):
            ok, detail = resolve(cre_id)
            if ok is None:
                unreachable.append(detail)
            elif ok:
                print(f"{cre_id} resolves: {detail}")
            else:
                errors.append(f"CRE {cre_id}: {detail}")
    for line in errors:
        print(f"FAIL: {line}", file=sys.stderr)
    for line in unreachable:
        print(f"NOT CHECKED: {line}", file=sys.stderr)
    terms = len({link[0] for link in links})
    print(f"check_opencre_links: {len(links)} link(s) on {terms} term(s), {len(errors)} finding(s)"
          + (", live" if live else ", offline"))
    if errors:
        return 1
    return 2 if unreachable else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
