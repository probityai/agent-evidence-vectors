"""Escape page descriptions and optional previews bound to published local images."""

from __future__ import annotations

import html
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

import markdown_mirrors

IMAGE_PATH = re.compile(r"assets/[a-z0-9][a-z0-9.-]*\.png\Z")


def plain(metadata: dict[str, Any], key: str) -> str:
    """Read a required, bounded plain-text Pandoc metadata field."""
    value = metadata.get(key, {})
    if value.get("t") == "MetaString":
        text = value["c"]
    elif value.get("t") == "MetaInlines":
        chunks = []
        for node in value["c"]:
            if node["t"] == "Str":
                chunks.append(node["c"])
            elif node["t"] == "Space":
                chunks.append(" ")
            else:
                raise ValueError(f"{key} must contain plain text")
        text = "".join(chunks)
    else:
        raise ValueError(f"{key} must contain plain text")
    if not text.strip() or len(text) > 512 or any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in text
    ):
        raise ValueError(f"{key} must contain bounded, nonempty text without controls")
    return text


def render(
    text: str, root: Path, published: dict[str, str], base_url: str,
    canonical: str, site_name: str,
) -> str:
    """Return escaped description and optional social-preview tags.

    ``published`` maps destinations to source paths selected by the build's
    COPIES declaration for this page. A preview cannot publish an unrelated
    file or refer to an image that the build will omit.
    """
    document = json.loads(markdown_mirrors.pandoc(text, "markdown-smart", "json"))
    metadata = document["meta"]
    description = plain(metadata, "description") if "description" in metadata else None
    values = []
    if description is not None:
        values.append(("name", "description", description))
    fields = {"social_image", "social_image_alt"} & metadata.keys()
    if not fields:
        return tags(values)
    if len(fields) != 2:
        raise ValueError("social_image and social_image_alt must be supplied together")
    image = plain(metadata, "social_image")
    if not IMAGE_PATH.fullmatch(image) or image not in published:
        raise ValueError("social_image must name a PNG declared for this page in COPIES")
    source = Path(published[image])
    if source.is_absolute() or ".." in source.parts:
        raise ValueError("social image source must stay in the repository")
    asset = root / source
    components = [root.joinpath(*source.parts[:length]) for length in range(1, len(source.parts) + 1)]
    if any(path.is_symlink() for path in components) or not asset.is_file():
        raise ValueError("social image source must be a regular file without symlinks")
    if not asset.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("social image source must have a PNG signature")
    title = plain(metadata, "title")
    alt = plain(metadata, "social_image_alt")
    values = [
        *values,
        ("property", "og:type", "website"),
        ("property", "og:site_name", site_name),
        ("property", "og:url", canonical),
        ("property", "og:title", title),
        ("property", "og:image", base_url + image),
        ("property", "og:image:alt", alt),
        ("name", "twitter:card", "summary_large_image"),
        ("name", "twitter:title", title),
        ("name", "twitter:image", base_url + image),
        ("name", "twitter:image:alt", alt),
    ]
    if description is not None:
        values.extend([
            ("property", "og:description", description),
            ("name", "twitter:description", description),
        ])
    return tags(values)


def tags(values: list[tuple[str, str, str]]) -> str:
    """Escape every attribute value before it reaches Pandoc's HTML template."""
    return "\n".join(
        f'  <meta {kind}="{key}" content="{html.escape(value, quote=True)}" />'
        for kind, key, value in values
    )
