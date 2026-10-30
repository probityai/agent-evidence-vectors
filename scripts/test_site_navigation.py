"""Check published routes, source-relative links and predicate document retention."""

from __future__ import annotations

import importlib.util
import json
import re
import string
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urljoin, urlsplit
from xml.etree.ElementTree import fromstring

import markdown
import pytest
from hypothesis import given
from hypothesis import strategies as st

SOURCE_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "vectors_site_build", SOURCE_ROOT / "docs/site/build.py"
)
assert SPEC is not None and SPEC.loader is not None
site = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(site)

COMPANIONS = (
    "guides/runner",
    "guides/corpora",
    "guides/report-run",
    "reference/corpus-readers",
    "reference/verifier-contract",
    "reference/maintenance",
    "reference/witness-attestor",
    "reference/layout",
    "reference/citing",
    "reference/release-verification",
    "research/external-records",
    "research/independence",
    "research/corpus-measurements",
)
PREDICATES = (
    ("v1", "observed-effect"),
    ("v1", "uncertain-effect"),
    ("v1", "evaluation-claim"),
    ("v1", "self-reported-record"),
    ("v1", "kernel-substrate"),
    ("v2", "kernel-substrate"),
    ("v2", "launch-chain"),
    ("v1", "agent-audit-record"),
    ("v1", "govops-trace-record"),
    ("v1", "peer-verification"),
    ("v1", "incident-action-authorization"),
    ("v1", "revocation-sweep"),
    ("v1", "re-enable-decision"),
    ("v1", "joint-authority"),
    ("v1", "revocation-boundary"),
    ("v1", "evidence-scope-disclosure"),
    ("v1", "launch-chain"),
    ("v1", "ml-bom"),
    ("v1", "quotation-fidelity"),
    ("v1", "scorecard-verdict"),
    ("v1", "security-verdict"),
    ("v1", "signed-evidence"),
    ("v1", "static-scan-verdict"),
    ("v1", "substrate-integrity"),
    ("v1", "sut-provenance"),
    ("v2", "a2a-mesh-scorecard"),
    ("v2", "mesh-quiescence"),
)
EXPECTED_HTML = (
    {Path(f"{relative}.html") for relative in COMPANIONS}
    | {
        Path(name)
        for name in (
            "start.html",
            "index.html",
            "runs.html",
            "distribution.html",
            "codes.html",
            "predicate/index.html",
        )
    }
    | {
        Path(f"predicate/{version}/{name}{suffix}")
        for version, name in PREDICATES
        for suffix in (".html", "/index.html")
    }
)
SEGMENT = st.text(alphabet=string.ascii_letters + string.digits + "_-", min_size=1, max_size=12)
URL_PART = st.text(alphabet=string.ascii_letters + string.digits + "-_%+", max_size=20)


class HtmlView(HTMLParser):
    """Collect rendered links, identifiers and text inside the main document."""

    def __init__(self, document: str) -> None:
        super().__init__()
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.text: list[str] = []
        self.in_main = False
        self.feed(document)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "main":
            self.in_main = True
        identifier = values.get("id", values.get("name"))
        if identifier is not None:
            self.ids.add(str(identifier))
        if tag == "a" and values.get("href") is not None:
            self.links.append(str(values["href"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "main":
            self.in_main = False

    def handle_data(self, data: str) -> None:
        if self.in_main:
            self.text.append(data)


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Build a small complete site source with the real predicate documents."""
    for relative in COMPANIONS:
        target = tmp_path / "docs" / f"{relative}.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# Companion\n\n## Run cases\n", encoding="ascii")
    files = {
        "README.md": (
            '# Start\n\n<a name="legacy-pipeline"></a>\n\n'
            "[Runner](docs/guides/runner.md#run-cases)\n"
        ),
        "RUNS.md": "# Independent runs\n",
        "DISTRIBUTION.md": "# Distribution\n",
        "CITATION.cff": "version: 0.15.0\n",
        "llms.txt": "# Probity Vectors\n\n[Start](start.html)\n",
        "aee/codes.go": '// Validity.\nconst (\nCodeSample Code = "sample-code"\n)\n',
        "vectors/MANIFEST.json": json.dumps(
            {"suite": "sample-suite", "vectors": ["sample"], "counts": {"accept": 1}}
        ),
    }
    for relative, text in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="ascii")
    for relative in (
        "spec/predicates/REGISTRY.md",
        "spec/predicates/observed-effect.md",
        "vectors-uncertain-effect/README.md",
        "spec/predicates/evaluation-claim.md",
        "spec/self-reported-record/v1.md",
        "spec/predicates/peer-verification.md",
        "spec/predicates/incident-action-authorization.md",
        "spec/predicates/revocation-sweep.md",
        "spec/predicates/re-enable-decision.md",
        "spec/predicates/joint-authority.md",
        "spec/predicates/revocation-boundary.md",
        "profiles/restoration-evidence.md",
        "spec/predicates/adversarial-execution-evidence.md",
        "spec/schemas/observed-effect-code-digest-v0.5.schema.json",
        "spec/schemas/observed-effect-invocation-binding-v0.9.schema.json",
        "packaging/agent_evidence_vectors/verdict_evidence/README.md",
        "packaging/agent_evidence_vectors/claim_record/README.md",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((SOURCE_ROOT / relative).read_bytes())
    monkeypatch.setattr(site, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(site, "CITATION", tmp_path / "CITATION.cff")
    monkeypatch.setattr(site, "CODES_GO", tmp_path / "aee/codes.go")
    monkeypatch.setattr(site, "PREDICATE_REGISTRY", tmp_path / "spec/predicates/REGISTRY.md")
    return tmp_path


@pytest.fixture
def built_site(repository: Path, tmp_path: Path) -> Path:
    """Render the complete repository fixture for one behavior check."""
    output = tmp_path / "published"
    site.main(["--out", str(output)])
    return output


class TestLinkResolution:
    class TestPassingCases:
        @pytest.mark.parametrize(
            ("value", "expected"),
            [
                ("../reference/verifier-contract.md", "../reference/verifier-contract.html"),
                (
                    "../reference/verifier-contract.md?mode=raw#comparison-rules",
                    "../reference/verifier-contract.html?mode=raw#comparison-rules",
                ),
                ("../../README.md#legacy-pipeline", "../start.html#legacy-pipeline"),
                ("../../RUNS.md", "../runs.html"),
                ("/docs/reference/verifier-contract.md", "../reference/verifier-contract.html"),
                ("#run-cases", "#run-cases"),
                ("?mode=raw#run-cases", "?mode=raw#run-cases"),
                ("https://example.org/a.md?x=1#part", "https://example.org/a.md?x=1#part"),
                ("//example.org/a.md", "//example.org/a.md"),
                ("mailto:reader@example.org", "mailto:reader@example.org"),
            ],
        )
        def test_known_destinations(self, repository: Path, value: str, expected: str) -> None:
            assert (
                site.resolve_link(
                    value,
                    repository / "docs/guides/runner.md",
                    Path("guides/runner.html"),
                    site.published_routes(),
                )
                == expected
            )

        @given(
            depth=st.integers(min_value=0, max_value=5),
            name=SEGMENT,
            query=URL_PART,
            fragment=URL_PART,
        )
        def test_nested_links_reach_the_selected_route(
            self, depth: int, name: str, query: str, fragment: str
        ) -> None:
            with TemporaryDirectory() as directory, pytest.MonkeyPatch.context() as patch:
                root = Path(directory)
                patch.setattr(site, "REPO_ROOT", root)
                nested = Path(*(["section"] * depth))
                source = root / "docs/guides" / nested / "current.md"
                output = Path("guides") / nested / "current.html"
                target = Path("docs/reference") / f"{name}.md"
                (root / target).parent.mkdir(parents=True)
                (root / target).write_text("# Target\n", encoding="ascii")
                routes = {target: Path("reference") / f"{name}.html"}
                value = "../" * (depth + 1) + f"reference/{name}.md?{query}#{fragment}"
                resolved = site.resolve_link(value, source, output, routes)
                absolute = urlsplit(urljoin(f"https://example.org/{output.as_posix()}", resolved))
                assert absolute.path == f"/reference/{name}.html"
                assert absolute.query == query
                assert absolute.fragment == fragment

        def test_repository_assets_keep_query_fragment_and_escaped_name(
            self, repository: Path
        ) -> None:
            asset = repository / "spec/name with space.json"
            asset.write_text("{}", encoding="ascii")
            result = site.resolve_link(
                "../../spec/name%20with%20space.json?raw=1#L2",
                repository / "docs/guides/runner.md",
                Path("guides/runner.html"),
                site.published_routes(),
            )
            assert result == f"{site.REPO_URL}/blob/main/spec/name%20with%20space.json?raw=1#L2"

        def test_directory_assets_use_github_tree(self, repository: Path) -> None:
            result = site.resolve_link(
                "../../vectors/",
                repository / "docs/guides/runner.md",
                Path("guides/runner.html"),
                site.published_routes(),
            )
            assert result == f"{site.REPO_URL}/tree/main/vectors"

    class TestFailingCases:
        @pytest.mark.parametrize(
            "value", ["../../../outside.md", "%2e%2e/%2e%2e/%2e%2e/outside.md"]
        )
        def test_parent_traversal_is_refused(self, repository: Path, value: str) -> None:
            expected = f"Markdown link escapes repository: {value!r}"
            with pytest.raises(ValueError, match=re.escape(expected)):
                site.resolve_link(
                    value,
                    repository / "docs/guides/runner.md",
                    Path("guides/runner.html"),
                    site.published_routes(),
                )

        def test_symlink_escape_is_refused(self, repository: Path, tmp_path: Path) -> None:
            (repository / "escape").symlink_to(tmp_path.parent)
            value = "../../escape/outside.md"
            with pytest.raises(
                ValueError, match=re.escape(f"Markdown link escapes repository: {value!r}")
            ):
                site.resolve_link(
                    value,
                    repository / "docs/guides/runner.md",
                    Path("guides/runner.html"),
                    site.published_routes(),
                )

        def test_document_cannot_fall_back_to_an_unpublished_route(self, repository: Path) -> None:
            expected = "Published document has no route: 'docs/guides/runner.md'"
            with pytest.raises(ValueError, match=re.escape(expected)):
                site.resolve_link(
                    "runner.md",
                    repository / "docs/guides/current.md",
                    Path("guides/current.html"),
                    {},
                )

        def test_missing_asset_cannot_become_a_github_link(self, repository: Path) -> None:
            expected = "Markdown link target is missing: 'spec/missing.json'"
            with pytest.raises(ValueError, match=re.escape(expected)):
                site.resolve_link(
                    "../../spec/missing.json",
                    repository / "docs/guides/runner.md",
                    Path("guides/runner.html"),
                    site.published_routes(),
                )


class TestSiteNavigation:
    class TestPassingCases:
        def test_companion_routes_and_existing_routes_are_published(self, built_site: Path) -> None:
            assert {
                path.relative_to(built_site) for path in built_site.rglob("*.html")
            } == EXPECTED_HTML

        @pytest.mark.parametrize("relative", sorted(EXPECTED_HTML))
        def test_navigation_reaches_root_pages(self, built_site: Path, relative: Path) -> None:
            view = HtmlView((built_site / relative).read_text(encoding="utf-8"))
            for href in view.links[:5]:
                assert (built_site / relative.parent / href).resolve().is_file()

        @pytest.mark.parametrize(
            ("relative", "identifier"),
            [
                ("start.html", "legacy-pipeline"),
                ("guides/runner.html", "run-cases"),
            ],
        )
        def test_legacy_and_heading_anchors(
            self, built_site: Path, relative: str, identifier: str
        ) -> None:
            assert identifier in HtmlView((built_site / relative).read_text()).ids

        def test_heading_and_reference_links_render_without_touching_code(
            self, repository: Path
        ) -> None:
            source = repository / "docs/guides/runner.md"
            source.write_text(
                "# Run cases\n\n[Contract][contract]\n\n"
                "[contract]: ../reference/verifier-contract.md#comparison-rules\n\n"
                "```markdown\n[example](../../../outside.md)\n```\n",
                encoding="ascii",
            )
            body = site.render_markdown(source)
            assert 'id="run-cases"' in body
            assert 'href="../reference/verifier-contract.html#comparison-rules"' in body
            assert "[example](../../../outside.md)" in body

        @pytest.mark.parametrize(("version", "name"), PREDICATES)
        def test_registered_predicate_routes_keep_their_document_bodies(
            self, repository: Path, version: str, name: str
        ) -> None:
            pages = site.predicate_pages("v0.15.0")
            source = site.defined_documents().get((version, name), site.PREDICATE_REGISTRY)
            original = markdown.markdown(source.read_text(), extensions=["tables", "fenced_code"])
            expected = " ".join(HtmlView(f"<main>{original}</main>").text).split()
            for relative in (
                Path(f"predicate/{version}/{name}.html"),
                Path(f"predicate/{version}/{name}/index.html"),
            ):
                assert " ".join(HtmlView(pages[relative]).text).split() == expected

        def test_new_nested_document_gets_a_route(self, repository: Path) -> None:
            source = repository / "docs/guides/advanced/replay.md"
            source.parent.mkdir()
            source.write_text("# Replay\n", encoding="ascii")
            assert site.published_routes()[Path("docs/guides/advanced/replay.md")] == Path(
                "guides/advanced/replay.html"
            )

        def test_llms_is_served_byte_for_byte(self, repository: Path, built_site: Path) -> None:
            assert (built_site / "llms.txt").read_bytes() == (repository / "llms.txt").read_bytes()
            assert (built_site / "llms.txt").read_bytes().isascii()

        def test_sitemap_is_deterministic(
            self, repository: Path, built_site: Path, tmp_path: Path
        ) -> None:
            second = tmp_path / "second"
            site.main(["--out", str(second)])
            assert (built_site / "sitemap.xml").read_bytes() == (
                second / "sitemap.xml"
            ).read_bytes()

        @pytest.mark.parametrize(
            ("relative", "present"),
            [
                ("start.html", True),
                ("predicate/v1/observed-effect", True),
                ("predicate/v1/observed-effect.html", False),
                ("predicate/v1/observed-effect/index.html", False),
            ],
        )
        def test_sitemap_uses_canonical_uris(
            self, built_site: Path, relative: str, present: bool
        ) -> None:
            root = fromstring((built_site / "sitemap.xml").read_bytes())
            namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            urls = [node.text for node in root.findall("s:url/s:loc", namespace)]
            assert (f"{site.SITE_URL}/{relative}" in urls) is present

        def test_sitemap_has_unique_urls_and_no_clock(self, built_site: Path) -> None:
            root = fromstring((built_site / "sitemap.xml").read_bytes())
            namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            urls = [node.text for node in root.findall("s:url/s:loc", namespace)]
            assert len(urls) == len(set(urls)) == 46
            assert root.find("s:url/s:lastmod", namespace) is None

        def test_local_image_loads_repository_bytes(self, repository: Path) -> None:
            target = repository / "docs/assets/icon.svg"
            target.parent.mkdir()
            target.write_text('<svg xmlns="http://www.w3.org/2000/svg"/>', encoding="ascii")
            source = repository / "docs/guides/runner.md"
            source.write_text("# Runner\n\n![Icon](../assets/icon.svg)\n", encoding="ascii")
            body = site.render_markdown(source)
            assert f'src="{site.REPO_URL}/raw/main/docs/assets/icon.svg"' in body

    class TestFailingCases:
        def test_missing_published_link_stops_the_build(
            self, repository: Path, tmp_path: Path
        ) -> None:
            (repository / "README.md").write_text(
                "# Start\n\n[Missing](docs/reference/missing.md)\n", encoding="ascii"
            )
            expected = "Markdown link target is missing: 'docs/reference/missing.md'"
            with pytest.raises(ValueError, match=re.escape(expected)):
                site.main(["--out", str(tmp_path / "published")])

        def test_empty_predicate_registry_stops_the_build(self, repository: Path) -> None:
            site.PREDICATE_REGISTRY.write_text("# Empty\n", encoding="ascii")
            expected = f"FAIL: {site.PREDICATE_REGISTRY} registers no predicate type URI"
            with pytest.raises(SystemExit, match=re.escape(expected)):
                site.predicate_pages("v0.15.0")

        def test_defined_type_without_its_document_stops_the_build(self, repository: Path) -> None:
            (repository / "spec/self-reported-record/v1.md").unlink()
            expected = (
                "FAIL: predicate/v1/self-reported-record is defined here and names no document"
            )
            with pytest.raises(SystemExit, match=re.escape(expected)):
                site.predicate_pages("v0.15.0")

        def test_non_ascii_llms_stops_the_build(self, repository: Path, tmp_path: Path) -> None:
            (repository / "llms.txt").write_bytes(b"# Guide\n\xff\n")
            with pytest.raises(ValueError, match="llms.txt must contain ASCII text"):
                site.main(["--out", str(tmp_path / "published")])
