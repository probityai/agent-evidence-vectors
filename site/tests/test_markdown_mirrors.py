"""Exercise retrieved Markdown as a consumer and refuse broken public routes."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import check_links
import markdown_mirrors as mirrors

BASE = check_links.BASE_URL


def test_consumer_gets_visible_content_stable_fragments_and_original_code(tmp_path):
    source = '''---
title: "Public guide"
subtitle: "Use the actual record"
status: "Draft"
private_notes: "PRIVATE SENTINEL"
---

## Renamed task {#stable-task}

[Task](start.html?mode=read#stable-task) [Lab](https://probityai.github.io/agent-evidence-atlas/lab.html#retained)
[Outside](https://example.org/start.html) [Bytes](lab/original.json)

```sh
printf '%s' '<!-- include: literal-example -->'
```
'''
    rendered = mirrors.render(source, "start", {"start", "lab"}, BASE)
    assert "# Public guide" in rendered
    assert "Use the actual record" in rendered and "Draft" in rendered
    assert "PRIVATE SENTINEL" not in rendered
    assert "<div>" not in rendered
    assert "printf '%s' '<!-- include: literal-example -->'" in rendered
    target = tmp_path / "start.md"
    target.write_text(rendered)
    consumed = check_links.parse(target)
    assert "stable-task" in consumed.ids
    assert "start.md?mode=read#stable-task" in consumed.links
    assert "lab.md#retained" in consumed.links
    assert "https://example.org/start.html" in consumed.links
    assert "lab/original.json" in consumed.links
    assert "start.html" in consumed.links  # Reader can return to the HTML view.


@pytest.mark.parametrize("url,expected", [
    (BASE, "index.md"),
    ("#fragment", "#fragment"),
    ("mailto:owner@example.org", "mailto:owner@example.org"),
    ("/start.html", "/start.html"),
    ("https://probityai.github.io/other/start.html", "https://probityai.github.io/other/start.html"),
    ("missing.html", "missing.html"),
    ("lab/object.html", "lab/object.html"),
])
def test_unbuilt_or_external_destinations_keep_their_identity(url, expected):
    assert mirrors.markdown_target(url, {"index", "start"}, BASE) == expected


def test_unresolved_source_include_is_refused():
    with pytest.raises(ValueError, match="unresolved include"):
        mirrors.render("<!-- include: secrets.md -->", "start", {"start"}, BASE)


def test_nontext_visible_metadata_is_refused():
    with pytest.raises(ValueError, match="inline text"):
        mirrors.render("---\ntitle:\n  secret: unexpected\n---\nBody", "start", {"start"}, BASE)


@pytest.mark.parametrize("code,warning", [(1, "bad input"), (0, "unexpected warning")])
def test_conversion_never_treats_failure_or_warning_as_public_content(monkeypatch, code, warning):
    monkeypatch.setattr(mirrors.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=code, stderr=warning, stdout="untrustworthy output"))
    with pytest.raises(ValueError, match="conversion failed or warned"):
        mirrors.render("Body", "start", {"start"}, BASE)


def test_rendered_mirror_links_are_checked_including_absolute_anchors_and_queries(monkeypatch, tmp_path, capsys):
    (tmp_path / "start.md").write_text(mirrors.render(
        "## Task {#task}\n\n[Local](start.html?view=read#task)", "start", {"start"}, BASE))
    (tmp_path / "start.html").write_text('<a id="task"></a>')
    (tmp_path / "llms.txt").write_text("guide")
    monkeypatch.setattr(check_links, "DOCS", tmp_path)
    assert check_links.main() == 0
    (tmp_path / "start.md").write_text(f"[Broken]({BASE}start.html#absent)")
    assert check_links.main() == 1
    assert "missing anchor" in capsys.readouterr().out


@pytest.mark.parametrize("link", ["../private.md", "missing.md", "start.md#absent"])
def test_broken_or_escaped_retrieval_link_cannot_pass(monkeypatch, tmp_path, link):
    (tmp_path / "start.md").write_text(f"[Broken]({link})")
    (tmp_path.parent / "private.md").write_text("out-of-site sentinel")
    monkeypatch.setattr(check_links, "DOCS", tmp_path)
    assert check_links.main() == 1


def test_markdown_link_parser_refuses_a_converter_warning(monkeypatch, tmp_path):
    page = tmp_path / "start.md"
    page.write_text("guide")
    monkeypatch.setattr(check_links.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=0, stderr="warning", stdout=""))
    with pytest.raises(ValueError, match="Cannot parse Markdown"):
        check_links.parse(page)


def test_actual_public_projection_is_used_for_every_discovery_surface():
    import json
    import discovery
    from discoverability import catalog

    root = Path(__file__).resolve().parent.parent
    source = catalog.load_catalog(root / "data/catalog.json")
    source["private_notes"] = "PRIVATE SENTINEL"
    source["components"][0]["extensions"] = {"private": "PRIVATE SENTINEL"}
    public = catalog.public_projection(source)
    assert public == discovery.load_public(root)
    start = mirrors.render(discovery.start_markdown(public), "start", {"start"}, BASE)
    surfaces = start + json.dumps(discovery.site_assets(public, {"start"}))
    assert "PRIVATE SENTINEL" not in surfaces
    for component in public["components"]:
        assert component["display_name"] in start


def test_visible_breaks_survive_without_changing_fenced_code_trailing_bytes():
    import json

    literal = "literal trailing spaces  \nnext line"
    source = ("First line  \nSecond line\n\nTerm\n: Its definition\n\n"
              "| Retained first claim\n| Retained second claim\n\n```text\n" + literal + "\n```\n")
    rendered = mirrors.render(source, "start", {"start"}, BASE)
    html = mirrors.pandoc(rendered, "gfm", "html5")
    assert "First line<br />" in html
    assert "Second line" in html
    assert "Term<br />Its definition" in html
    assert "Retained first claim<br />Retained second claim" in html
    consumed = json.loads(mirrors.pandoc(rendered, "gfm", "json"))
    code = [block["c"][1] for block in consumed["blocks"] if block["t"] == "CodeBlock"]
    assert code == [literal]
    # Presentation breaks no longer introduce trailing whitespace. Literal
    # code keeps its original two spaces; stripping lines would corrupt it.
    assert [line for line in rendered.splitlines() if line.endswith(" ")] == ["literal trailing spaces  "]
