"""Check public navigation, stable links and build-owned machine indexes."""

from __future__ import annotations

import copy
import importlib.util
import json
import logging
import random
import subprocess
import sys
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import discovery
import pytest
from discoverability import catalog
from hypothesis import given
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def public() -> dict[str, Any]:
    """Read the actual reviewed catalog used by the site build."""
    return discovery.load_public(ROOT)


def refuse(operation: Any, message: str, caplog: pytest.LogCaptureFixture) -> None:
    """Require the same bounded error for a caller and the build log."""
    with (
        caplog.at_level(logging.ERROR),
        pytest.raises(catalog.CatalogError) as caught,
    ):
        operation()
    assert str(caught.value) == message
    assert caplog.messages == [message]


class TestStartMarkdown:
    class TestPassingCases:
        def test_each_project_has_a_stable_destination(
            self, public: dict[str, Any]
        ) -> None:
            page = discovery.start_markdown(public)
            for record in discovery.project_entries(public):
                assert f"](#{record['id']})" in page
                assert f"{{#{record['id']}}}" in page
                assert discovery.project_url(record, public) in page
                assert f"ID: `{record['id']}`" in page
                if "component" in record:
                    assert f"Component ID: `{record['component']}`" in page
            assert (
                "Vectors tests how a verifier behaves. Verify checks a supplied claim"
                in page
            )
            assert page.isascii()

        def test_new_project_needs_no_generator_edit(
            self, public: dict[str, Any]
        ) -> None:
            entry = copy.deepcopy(public["components"][0])
            entry.update(
                id="new-reader", display_name="New reader", task="Check a new record"
            )
            public["components"].append(entry)
            page = discovery.start_markdown(public)
            assert "[New reader](#new-reader)" in page
            assert "## New reader {#new-reader}" in page

        def test_profile_has_its_own_entry(self, public: dict[str, Any]) -> None:
            entry = copy.deepcopy(public["components"][0])
            entry.update(
                id="new-profile", display_name="New profile", component=entry["id"]
            )
            public["profiles"].append(entry)
            assert "[New profile](#new-profile)" in discovery.start_markdown(public)

        def test_rename_preserves_fragment(self, public: dict[str, Any]) -> None:
            public["components"][0]["display_name"] = "Changed label"
            page = discovery.start_markdown(public)
            assert "## Changed label {#admission}" in page
            assert "Component ID: `admission`." in page

        @given(st.integers(min_value=0, max_value=2**32 - 1))
        def test_input_order_does_not_change_navigation(self, seed: int) -> None:
            public = discovery.load_public(ROOT)
            expected = discovery.start_markdown(public)
            random.Random(seed).shuffle(public["components"])
            assert discovery.start_markdown(public) == expected

    class TestFailingCases:
        def test_removing_a_baseline_identity_is_refused(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            data = catalog.load_catalog(ROOT / "data/catalog.json")
            data["components"] = [
                row for row in data["components"] if row["id"] != "atlas"
            ]
            (tmp_path / "data").mkdir()
            (tmp_path / "tools/discoverability").mkdir(parents=True)
            (tmp_path / "data/catalog.json").write_text(
                json.dumps(data), encoding="ascii"
            )
            baseline = ROOT / "tools/discoverability/catalog.seed.json"
            (tmp_path / "tools/discoverability/catalog.seed.json").write_bytes(
                baseline.read_bytes()
            )
            refuse(
                lambda: discovery.load_public(tmp_path),
                "Stable ID removed or changed kind: atlas",
                caplog,
            )


class TestSourceBindings:
    class TestPassingCases:
        def test_actual_sources_bind(self, public: dict[str, Any]) -> None:
            sources = json.loads((ROOT / "data/catalog-sources.json").read_text())
            discovery.check_source_bindings(public, sources)

    class TestFailingCases:
        def test_new_pin_needs_its_source_review(
            self, public: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            sources = json.loads((ROOT / "data/catalog-sources.json").read_text())
            public["repositories"][0]["source"]["commit"] = "f" * 40
            refuse(
                lambda: discovery.check_source_bindings(public, sources),
                "Catalog source pin is unreviewed: repo-admission",
                caplog,
            )

        def test_duplicate_source_cannot_shadow_a_review(
            self, public: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            sources = json.loads((ROOT / "data/catalog-sources.json").read_text())
            sources.append(copy.deepcopy(sources[0]))
            refuse(
                lambda: discovery.check_source_bindings(public, sources),
                "Catalog source URL is repeated",
                caplog,
            )


class TestLlmsIndex:
    class TestPassingCases:
        def test_only_built_site_destinations_are_linked(
            self, public: dict[str, Any]
        ) -> None:
            index = discovery.llms_index(public, {"start", "claims"})
            assert f"{discovery.BASE_URL}start.md" in index
            assert f"{discovery.BASE_URL}claims.md" in index
            assert f"{discovery.BASE_URL}lab.md" not in index
            assert f"{discovery.BASE_URL}lab/register.json" not in index
            assert f"{discovery.BASE_URL}catalog.json" in index

        def test_lab_and_project_pins_are_available(
            self, public: dict[str, Any]
        ) -> None:
            index = discovery.llms_index(public, {"lab"})
            assert f"{discovery.BASE_URL}lab/register.json" in index
            for record in discovery.project_entries(public):
                assert discovery.project_url(record, public) in index
                assert f"ID: `{record['id']}`" in index
                if "component" in record:
                    assert f"Component ID: `{record['component']}`" in index

        def test_asset_json_is_the_same_projection(
            self, public: dict[str, Any]
        ) -> None:
            assets = discovery.site_assets(public, {"index", "start"})
            assert set(assets) == {"catalog.json", "llms.txt", "sitemap.xml"}
            assert json.loads(assets["catalog.json"]) == public
            assert all(value.isascii() for value in assets.values())

    class TestFailingCases:
        def test_unreviewed_fields_never_enter_assets(self) -> None:
            data = catalog.load_catalog(ROOT / "data/catalog.json")
            data["private_notes"] = "PRIVATE SENTINEL"
            data["components"][0]["extensions"] = {"secret": "PRIVATE SENTINEL"}
            public = catalog.public_projection(data)
            rendered = json.dumps(discovery.site_assets(public, {"index", "start"}))
            assert "PRIVATE SENTINEL" not in rendered


class TestSitemap:
    class TestPassingCases:
        def test_each_built_page_uses_its_canonical_url(self) -> None:
            xml = discovery.sitemap({"index", "start", "lab"})
            tree = ElementTree.fromstring(xml)
            urls = {
                element.text
                for element in tree.iter(
                    "{http://www.sitemaps.org/schemas/sitemap/0.9}loc"
                )
            }
            assert urls == {
                discovery.BASE_URL,
                discovery.BASE_URL + "start.html",
                discovery.BASE_URL + "lab.html",
            }
            assert "lastmod" not in xml

        @given(
            st.lists(st.sampled_from(["index", "start", "lab", "claims"]), max_size=20)
        )
        def test_order_and_duplicates_do_not_change_output(
            self, pages: list[str]
        ) -> None:
            assert discovery.sitemap(pages) == discovery.sitemap(sorted(set(pages)))

    class TestFailingCases:
        @pytest.mark.parametrize(
            "stem",
            [
                "",
                "../index",
                "start.html",
                "<page>",
                "page/other",
                "page%20name",
                "page\n",
            ],
        )
        def test_unsafe_page_stem_is_refused(
            self, stem: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            refuse(
                lambda: discovery.sitemap([stem]),
                "Sitemap page must be a plain page stem",
                caplog,
            )


class TestBuildIndexes:
    class TestPassingCases:
        def test_existing_build_is_deterministic(self) -> None:
            result = subprocess.run(
                [sys.executable, "tools/build.py", "--check"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert result.stdout == "docs/ matches its sources\n"
            assert (ROOT / "llms.txt").read_bytes() == (
                ROOT / "docs/llms.txt"
            ).read_bytes()

        def test_published_catalog_preserves_project_identities(
            self, public: dict[str, Any]
        ) -> None:
            assert json.loads((ROOT / "docs/catalog.json").read_text()) == public

    class TestFailingCases:
        def test_stale_root_index_is_refused_without_a_write(
            self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
        ) -> None:
            # The subprocess reads an isolated copy of the small build entry.
            # Its generated tree is held fixed; only the root index is stale.
            script = ROOT / "tools/build.py"
            monkeypatch.syspath_prepend(str(ROOT / "tools"))
            spec = importlib.util.spec_from_file_location("site_build", script)
            assert spec is not None and spec.loader is not None
            build = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(build)
            monkeypatch.setattr(build, "ROOT", tmp_path)
            monkeypatch.setattr(build, "OUT", tmp_path / "docs")
            build.OUT.mkdir()
            (tmp_path / "llms.txt").write_text("stale\n", encoding="ascii")

            def held_build(out: Path) -> None:
                out.mkdir()
                (out / "llms.txt").write_text("fresh\n", encoding="ascii")

            monkeypatch.setattr(build, "build", held_build)
            monkeypatch.setattr(build, "same_tree", lambda _a, _b: True)
            monkeypatch.setattr(sys, "argv", ["build.py", "--check"])
            assert build.main() == 1
            assert (tmp_path / "llms.txt").read_text() == "stale\n"
