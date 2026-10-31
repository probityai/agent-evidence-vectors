"""Emit readable Markdown for the same expanded public pages as the HTML build."""

from __future__ import annotations

import html
import json
import re
import subprocess
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def pandoc(text: str, reader: str, writer: str) -> str:
    """Convert a document, refusing every warning as the HTML build does."""
    result = subprocess.run(
        ["pandoc", f"--from={reader}", f"--to={writer}", "--wrap=none", "--fail-if-warnings"],
        input=text, capture_output=True, text=True, check=False,
    )
    if result.returncode or result.stderr.strip():
        raise ValueError(f"Markdown conversion failed or warned: {result.stderr.strip()}")
    return result.stdout


def markdown_target(url: str, built: set[str], base_url: str) -> str:
    """Link built site pages to their mirrors without changing external URLs."""
    own = url.startswith(base_url)
    target = url[len(base_url):] if own else url
    parts = urlsplit(target)
    if not own and (parts.scheme or parts.netloc or parts.path.startswith("/")):
        return url
    if parts.path == "" and own and "index" in built:
        path = "index.md"
    elif parts.path.endswith(".html") and parts.path[:-5] in built:
        path = parts.path[:-5] + ".md"
    else:
        return url
    return urlunsplit(("", "", path, parts.query, parts.fragment))


def clean_node(node: Any, built: set[str], base_url: str) -> Any:
    """Keep content, links, code and stable anchors; omit presentation classes."""
    if isinstance(node, list):
        result = []
        for item in node:
            cleaned = clean_node(item, built, base_url)
            if isinstance(cleaned, dict) and "_replacement_blocks" in cleaned:
                result.extend(cleaned["_replacement_blocks"])
            else:
                result.append(cleaned)
        return result
    if not isinstance(node, dict):
        return node
    result = {key: clean_node(value, built, base_url) for key, value in node.items()}
    kind = result.get("t")
    if kind == "Link":
        result["c"][2][0] = markdown_target(result["c"][2][0], built, base_url)
    elif kind == "LineBreak":
        return {"t": "RawInline", "c": ["html", "<br />"]}
    elif kind == "LineBlock":
        inlines = []
        for position, line in enumerate(result["c"]):
            if position:
                inlines.append({"t": "RawInline", "c": ["html", "<br />"]})
            inlines.extend(line)
        return {"t": "Para", "c": inlines}
    elif kind == "DefinitionList":
        # GFM has no definition-list syntax. Its writer would insert a
        # two-space line ending between each term and its first definition.
        # Use an explicit visible break without touching literal code bytes.
        blocks = []
        for term, definitions in result["c"]:
            for position, definition in enumerate(definitions):
                if position == 0:
                    label = term + [{"t": "RawInline", "c": ["html", "<br />"]}]
                    if definition and definition[0]["t"] in {"Para", "Plain"}:
                        blocks.append({"t": "Para", "c": label + definition[0]["c"]})
                        blocks.extend(definition[1:])
                    else:
                        blocks.append({"t": "Para", "c": label})
                        blocks.extend(definition)
                else:
                    blocks.extend(definition)
        return {"_replacement_blocks": blocks}
    elif kind in {"Span", "Div"}:
        result["c"][0] = [result["c"][0][0], [], []]
    elif kind == "Header":
        identifier = result["c"][1][0]
        if identifier:
            # GFM drops custom heading IDs. Keep the actual HTML fragment as an
            # explicit anchor instead of guessing a new fragment from its label.
            anchor = {"t": "RawBlock", "c": ["html", f'<a id="{html.escape(identifier, quote=True)}"></a>']}
            result["c"][1] = ["", [], []]
            return {"_replacement_blocks": [anchor, result]}
    return result


def metadata_inlines(value: dict[str, Any]) -> list[dict[str, Any]]:
    if value["t"] == "MetaInlines":
        return value["c"]
    if value["t"] == "MetaString":
        return [{"t": "Str", "c": value["c"]}]
    raise ValueError("Page title, subtitle and status must contain inline text")


def render(text: str, stem: str, built: set[str], base_url: str) -> str:
    """Render resolved source with its visible title, status and source links."""
    if re.search(r"^<!-- include: .* -->$", text, re.MULTILINE):
        raise ValueError("Markdown source has an unresolved include")
    document = json.loads(pandoc(text, "markdown-smart", "json"))
    metadata = document["meta"]
    prefix: list[dict[str, Any]] = []
    if "title" in metadata:
        prefix.append({"t": "Header", "c": [1, ["", [], []], metadata_inlines(metadata["title"])]})
    for name in ["subtitle", "status"]:
        if name in metadata:
            prefix.append({"t": "Para", "c": metadata_inlines(metadata[name])})
    # Only the fields visible in the HTML header enter the mirror. Metadata
    # used by a source author for another purpose does not become public text.
    document["meta"] = {}
    document["blocks"] = clean_node(prefix + document["blocks"], built, base_url)
    body = pandoc(json.dumps(document, ensure_ascii=True), "json", "gfm")
    return body.rstrip() + f"\n\n[HTML view]({stem}.html) | [Agent guide](llms.txt)\n"
