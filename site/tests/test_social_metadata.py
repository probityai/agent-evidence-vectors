"""Refuse unsafe preview metadata and inspect the actual published tags."""

import base64
import json
import struct
from html.parser import HTMLParser
from pathlib import Path

import pytest

import social_metadata
import build

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://probityai.github.io/agent-evidence-atlas/"
IMAGE = "assets/admission-social.png"
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aFZ0AAAAASUVORK5CYII="
)


class Head(HTMLParser):
    def __init__(self):
        super().__init__()
        self.meta = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            self.meta.append(dict(attrs))
        elif tag == "link":
            self.links.append(dict(attrs))


def source(**overrides):
    fields = {
        "title": 'Decision "quoted" & clear',
        "description": "Inspect recorded bytes.",
        "social_image": IMAGE,
        "social_image_alt": 'A "quoted" caption & a literal < sign',
    }
    fields.update(overrides)
    return "---\n" + "\n".join(
        f"{key}: {json.dumps(value)}" for key, value in fields.items()
    ) + "\n---\n\nBody.\n"


@pytest.fixture
def asset(tmp_path):
    path = tmp_path / IMAGE
    path.parent.mkdir()
    path.write_bytes(PNG)
    return tmp_path


def render(text, root, published=None):
    return social_metadata.render(
        text, root, {IMAGE: IMAGE} if published is None else published,
        BASE, BASE + "guide.html", "Probity AI",
    )


def test_quoted_attributes_are_literal_text_and_urls_are_canonical(asset):
    tags = render(source(), asset)
    head = Head()
    head.feed(tags)
    assert len(head.meta) == 13
    assert all(set(tag) in ({"property", "content"}, {"name", "content"}) for tag in head.meta)
    values = {tag.get("property", tag.get("name")): tag["content"] for tag in head.meta}
    assert values["og:title"] == 'Decision "quoted" & clear'
    assert values["og:image:alt"] == 'A "quoted" caption & a literal < sign'
    assert values["twitter:image:alt"] == values["og:image:alt"]
    assert values["og:url"] == BASE + "guide.html"
    assert values["og:image"] == values["twitter:image"] == BASE + IMAGE
    assert values["twitter:card"] == "summary_large_image"
    assert "&quot;" in tags and "&amp;" in tags and "&lt;" in tags


def test_ordinary_page_description_uses_the_same_escaped_path(asset):
    text = '---\ntitle: "Guide"\ndescription: \'A "quote" data-extra="literal" & < sign\'\n---\n'
    head = Head()
    head.feed(render(text, asset))
    assert head.meta == [{"name": "description", "content": 'A "quote" data-extra="literal" & < sign'}]


def test_hostile_quotes_stay_text_through_the_actual_pandoc_template(tmp_path):
    caption = 'A "quote" data-extra="literal" & a < sign'
    document = tmp_path / "guide.md"
    document.write_text(source(
        description=caption, social_image_alt=caption,
        headmetadata='<meta name="injected" content="wrong" />',
    ))
    dest = tmp_path / "replay-an-evidence-decision.html"
    build.render(document, dest, {"index", "replay-an-evidence-decision"})
    head = Head()
    head.feed(dest.read_text())
    assert not any(tag.get("name") == "injected" or "data-extra" in tag for tag in head.meta)
    values = {tag.get("property", tag.get("name")): tag.get("content") for tag in head.meta}
    assert values["description"] == values["og:description"] == caption
    assert values["og:image:alt"] == values["twitter:image:alt"] == caption


def test_no_social_fields_omit_preview_and_description_is_optional(asset):
    assert render('---\ntitle: "Ordinary page"\n---\n', asset) == ""
    text = source().replace('description: "Inspect recorded bytes."\n', "")
    assert "og:description" not in render(text, asset)


@pytest.mark.parametrize("missing", ["social_image", "social_image_alt"])
def test_partial_preview_refuses(asset, missing):
    text = "\n".join(line for line in source().splitlines() if not line.startswith(missing + ":"))
    with pytest.raises(ValueError, match="supplied together"):
        render(text, asset)


@pytest.mark.parametrize("image", [
    "../private.png", "/assets/image.png", "https://example.org/image.png",
    "assets/../image.png", "assets/image.png?query=1", "assets/image.png#fragment",
    "assets/image.svg", 'assets/image.png" data-extra="changed', "assets/unlisted.png",
])
def test_unpublished_or_nonlocal_image_refuses(asset, image):
    with pytest.raises(ValueError, match="PNG declared"):
        render(source(social_image=image), asset)


@pytest.mark.parametrize("key,value", [
    ("social_image_alt", "*formatted*"), ("social_image_alt", "<img src=x>"),
    ("social_image_alt", "[link](https://example.org)"),
    ("title", {"nested": "value"}), ("description", ["list"]),
    ("social_image_alt", ""), ("social_image_alt", "x" * 513),
])
def test_markup_or_nontext_preview_fields_refuse(asset, key, value):
    with pytest.raises(ValueError, match="plain text|bounded"):
        render(source(**{key: value}), asset)


@pytest.mark.parametrize("text", ["\x00", "\x7f", "\u202e", "\ud800"])
def test_control_characters_refuse(text):
    with pytest.raises(ValueError, match="without controls"):
        social_metadata.plain({"alt": {"t": "MetaString", "c": text}}, "alt")


def test_plain_string_metadata_and_space_nodes_are_supported():
    assert social_metadata.plain({"alt": {"t": "MetaString", "c": "a & b"}}, "alt") == "a & b"
    assert social_metadata.plain({"alt": {"t": "MetaInlines", "c": [
        {"t": "Str", "c": "a"}, {"t": "Space"}, {"t": "Str", "c": "b"},
    ]}}, "alt") == "a b"


@pytest.mark.parametrize("binding", ["../outside.png", "/outside.png"])
def test_copy_source_cannot_leave_repository(asset, binding):
    with pytest.raises(ValueError, match="stay in the repository"):
        render(source(), asset, {IMAGE: binding})


def test_missing_symlink_and_wrong_format_sources_refuse(asset):
    image = asset / IMAGE
    image.unlink()
    with pytest.raises(ValueError, match="regular file"):
        render(source(), asset)
    elsewhere = asset / "elsewhere.png"
    elsewhere.write_bytes(PNG)
    image.symlink_to(elsewhere)
    with pytest.raises(ValueError, match="without symlinks"):
        render(source(), asset)
    image.unlink()
    image.write_text("<svg></svg>")
    with pytest.raises(ValueError, match="PNG signature"):
        render(source(), asset)


def test_mapped_checkout_root_is_allowed_but_asset_directory_symlink_refuses(asset):
    mapped = asset.parent / "mapped-checkout"
    mapped.symlink_to(asset, target_is_directory=True)
    assert 'property="og:image"' in render(source(), mapped)
    (asset / "assets").rename(asset / "image-sources")
    (asset / "assets").symlink_to(asset / "image-sources", target_is_directory=True)
    with pytest.raises(ValueError, match="without symlinks"):
        render(source(), asset)


def test_served_article_binds_preview_to_source_asset_and_canonical_page():
    page = ROOT / "docs/replay-an-evidence-decision.html"
    head = Head()
    head.feed(page.read_text())
    values = {tag.get("property", tag.get("name")): tag.get("content") for tag in head.meta}
    canonical = next(link["href"] for link in head.links if link.get("rel") == "canonical")
    assert values["og:url"] == canonical == BASE + page.name
    assert values["og:image"] == values["twitter:image"] == BASE + IMAGE
    assert values["og:image:alt"] == values["twitter:image:alt"]
    assert "same-operator PEER fixture" in values["og:image:alt"]
    asset = (ROOT / IMAGE).read_bytes()
    assert (ROOT / "docs" / IMAGE).read_bytes() == asset
    assert asset[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", asset[16:24]) == (1200, 630)
    assert any(link.get("rel") == "alternate" and link["href"] == BASE + "replay-an-evidence-decision.md" for link in head.links)
