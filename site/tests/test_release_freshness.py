"""Pin the checks that keep release versions, star counts and their ledger rows current.

A release the page calls current must be read from one place, re-read weekly, and quoted by
the claim ledger as the page shows it; a star refresh must rewrite only the entries that
carry a count, and move each quoted count's read time with it.
"""
import re
import tomllib
from pathlib import Path

import pytest

import build
import discovery
import gen_atlas
import refresh_stars
import rederive

ROOT = Path(__file__).resolve().parents[1]
DATA = tomllib.loads((ROOT / "data/atlas.toml").read_text(encoding="utf-8"))
CLAIMS = (ROOT / "CLAIMS.md").read_text(encoding="utf-8")
CADENCE = tomllib.loads((ROOT / "data/claim_cadence.toml").read_text(encoding="utf-8"))["cadence"]


class TestComponentVersionRoles:
    @pytest.fixture
    def public(self):
        return discovery.load_public(ROOT)

    def test_task_page_and_ledger_use_the_same_release_identities(self, public):
        versions = discovery.component_versions(public)
        task = discovery.start_markdown(public, versions)
        ledger = build.versions_markdown({"start", "versions"}, versions)
        for version in versions:
            assert version["url"] in task and version["url"] in ledger
            assert version["source_url"] in task and version["source_url"] in ledger
        assert "Repeat a tested installation" in ledger
        assert "Cite or replay a result" in ledger

    def test_harness_tag_does_not_inherit_its_case_package_version(self, public):
        versions = [v for v in discovery.component_versions(public) if v["component"] == "ratchet"]
        assert {v["kind"] for v in versions} == {"source-tag", "release"}
        assert len({v["version"] for v in versions}) == len(versions)
        tag = next(v for v in versions if v["kind"] == "source-tag")
        assert "source tag" in discovery.component_version_line(tag)
        assert "published release" not in discovery.component_version_line(tag)

    def test_a_release_change_requires_its_tag_identity_to_change(self):
        ledger = tomllib.loads((ROOT / "data/versions.toml").read_text())
        row = next(v for v in ledger["component_release"] if "artifact_ref" in v and v["kind"] in {"release", "source-tag"})
        artifacts = {a["name"]: a.copy() for a in DATA["artifact"]}
        artifacts[row["artifact_ref"]]["version"] = "99.0.0"
        with pytest.raises(discovery.catalog.CatalogError, match="tag does not match"):
            discovery.resolve_component_version(row, artifacts)

    @pytest.mark.parametrize("component", ["jcs-admit", "dsse"])
    def test_registry_artifact_version_needs_no_invented_tag(self, public, component):
        ledger = tomllib.loads((ROOT / "data/versions.toml").read_text())
        row = next(v for v in ledger["component_release"] if v["component"] == component)
        artifacts = {a["name"]: a for a in DATA["artifact"]}
        resolved = discovery.resolve_component_version(row, artifacts)
        assert resolved["kind"] == "registry-release" and "tag" not in resolved
        assert resolved["version"] == artifacts[row["artifact_ref"]]["version"]
        actual = next(v for v in discovery.component_versions(public) if v["component"] == component)
        assert actual["version"] == resolved["version"] and actual["commit"] == row["commit"]
        assert actual["url"] == f"https://crates.io/crates/{component}/{resolved['version']}"

    @pytest.mark.parametrize("component", ["jcs-admit", "dsse"])
    @pytest.mark.parametrize("change, remove, message", [
        ({"tag": "v99.0.0"}, (), "fields are invalid"),
        ({}, ("commit",), "fields are invalid"),
        ({}, ("registry",), "exact registry package version"),
        ({"repository": "repo-observer"}, (), "does not belong"),
    ])
    def test_registry_artifact_preserves_identity_refusals(self, public, component, change, remove, message):
        row = next(v for v in discovery.component_versions(public) if v["component"] == component).copy()
        for field in ("display_name", "url", "source_url", *remove):
            row.pop(field, None)
        row.update(change)
        with pytest.raises(discovery.catalog.CatalogError, match=message):
            discovery.checked_component_version(row,
                {r["id"]: r for r in public["components"]},
                {r["id"]: r for r in public["repositories"]})

    @pytest.mark.parametrize("component", ["jcs-admit", "dsse"])
    def test_registry_source_error_does_not_request_a_forbidden_tag(self, public, component):
        row = next(v for v in discovery.component_versions(public) if v["component"] == component).copy()
        for field in ("display_name", "url", "source_url"):
            row.pop(field)
        row["commit"] = "abcd"
        with pytest.raises(discovery.catalog.CatalogError, match="full source commit") as error:
            discovery.checked_component_version(row,
                {r["id"]: r for r in public["components"]},
                {r["id"]: r for r in public["repositories"]})
        assert "tag" not in str(error.value).lower()

    @pytest.mark.parametrize("kind", ["release", "source-tag"])
    def test_tagged_source_error_preserves_the_exact_supported_message(self, public, kind):
        row = next(v for v in discovery.component_versions(public) if v["kind"] == kind).copy()
        for field in ("display_name", "url", "source_url"):
            row.pop(field)
        row["commit"] = "abcd"
        with pytest.raises(discovery.catalog.CatalogError) as error:
            discovery.checked_component_version(row,
                {r["id"]: r for r in public["components"]},
                {r["id"]: r for r in public["repositories"]})
        assert str(error.value) == "Component version needs a full source commit and a safe tag"

    @pytest.mark.parametrize("change", [
        {"artifact_ref": "unknown-artifact"},
        {"version": "99.0.0"},
    ])
    def test_an_existing_release_cannot_get_another_version_source(self, change):
        ledger = tomllib.loads((ROOT / "data/versions.toml").read_text())
        row = next(v.copy() for v in ledger["component_release"] if "artifact_ref" in v)
        row.update(change)
        artifacts = {a["name"]: a for a in DATA["artifact"]}
        with pytest.raises(discovery.catalog.CatalogError, match="one known artifact"):
            discovery.resolve_component_version(row, artifacts)

    @pytest.mark.parametrize("change, message", [
        ({"repository": "repo-observer"}, "does not belong"),
        ({"component": "not-published"}, "does not belong"),
        ({"kind": "tested-install"}, "kind is invalid"),
        ({"commit": "abcd"}, "full source commit"),
        ({"tag": "v1.0/../../private"}, "safe tag"),
        ({"read": "2026-02-30"}, "date is invalid"),
        ({"artifact": "[injected](https://example.org)"}, "plain ASCII"),
        ({"note": "ghp_credential"}, "forbidden identity"),
        ({"unknown": "extra field"}, "fields are invalid"),
        ({"version": 1}, "fields are invalid"),
    ])
    def test_unsafe_or_unbound_version_metadata_is_refused(self, public, change, message):
        row = discovery.component_versions(public)[0].copy()
        for field in ("display_name", "url", "source_url"):
            row.pop(field)
        row.update(change)
        with pytest.raises(discovery.catalog.CatalogError, match=message):
            discovery.checked_component_version(
                row,
                {r["id"]: r for r in public["components"]},
                {r["id"]: r for r in public["repositories"]},
            )

    def test_duplicate_artifacts_are_refused(self, public, tmp_path):
        data = tmp_path / "data"
        data.mkdir()
        (data / "atlas.toml").write_bytes((ROOT / "data/atlas.toml").read_bytes())
        (data / "catalog-sources.json").write_bytes((ROOT / "data/catalog-sources.json").read_bytes())
        source = (ROOT / "data/versions.toml").read_text()
        repeated = source.split("[[component_release]]")[1]
        (data / "versions.toml").write_text(source + "\n[[component_release]]" + repeated)
        with pytest.raises(discovery.catalog.CatalogError, match="artifact is repeated"):
            discovery.component_versions(public, tmp_path)

SAMPLE = '''[meta]
stars_read = "2026-10-01 07:04:40 UTC"

[[entry]]
name = "One"
repo = "example/one"
stars = 10
[[entry]]
name = "A standard"
url = "https://example.org/standard"
[[corpus]]
dir = "pinned"
repo = "example/elsewhere"
commit = "0123456789abcdef0123456789abcdef01234567"
'''
SAMPLE_CLAIMS = (
    "| A-01 | One: 10 stars | GitHub API | stars 2026-10-01 07:04:40 | rederive | attention |\n"
    "| A-02 | A release read 2026-10-01 07:04:40 | tags | 2026-10-01 07:04:40 | rederive | none |\n"
)


class TestCurrentReleaseCadence:
    def test_the_ledger_has_no_release_row_that_can_outlive_its_release(self):
        assert build.release_cadence_violations(CLAIMS, CADENCE) == []

    @pytest.mark.parametrize("cadence", [30, "none", None])
    def test_a_current_release_row_needs_a_weekly_cadence(self, cadence):
        claims = "| A-38 | Current releases: tool v1.0 | tags | 2026-10-14 | rederive | none |\n"
        bad = build.release_cadence_violations(claims, {} if cadence is None else {"A-38": cadence})
        assert len(bad) == 1 and bad[0].startswith("A-38 ")

    def test_a_latest_release_row_is_held_to_the_same_rule(self):
        claims = "| C-99 | The latest release is 2.0 | PyPI | 2026-10-14 | read it | none |\n"
        assert build.release_cadence_violations(claims, {"C-99": "none"})

    def test_a_version_pinned_by_number_may_never_expire(self):
        claims = "| A-60 | Release v0.18.1 carries 1,197 members | manifest | 2026-10-13 | count | pinned |\n"
        assert build.release_cadence_violations(claims, {"A-60": "none"}) == []


class TestArtifactVersions:
    def test_every_artifact_shows_the_version_rederive_reads(self):
        gen_atlas.check_artifact_versions(DATA["artifact"])
        rows = {cid: recorded for cid, recorded, _ in rederive.artifact_release_rows()}
        assert rows == {f"A-38 {a['name']}": a["version"] for a in DATA["artifact"]}

    def test_the_ledger_row_quotes_every_version_the_page_shows(self):
        a38 = next(line for line in CLAIMS.splitlines() if line.startswith("| A-38 |"))
        for a in DATA["artifact"]:
            assert a["version"] in a38, a["name"]

    @pytest.mark.parametrize("change, message", [
        ({"release": "0.1.1 on crates.io", "version": "0.1.2"}, "does not show version"),
        ({"version_from": "github:example/x"}, "version_from must start"),
        ({"version": None}, "no version"),
    ])
    def test_an_artifact_that_disagrees_with_itself_is_refused(self, change, message):
        artifact = {"name": "x", "release": "0.1.2 on crates.io", "version": "0.1.2", "version_from": "crate:x"}
        artifact.update(change)
        artifact = {k: v for k, v in artifact.items() if v is not None}
        with pytest.raises(SystemExit, match=message):
            gen_atlas.check_artifact_versions([artifact])

    def test_only_pull_request_contributions_get_a_state_row(self):
        rows = [cid for cid, _, _ in rederive.contribution_state_rows()]
        pulls = [c for c in DATA["contribution"] if re.match(r"https://github\.com/.+/pull/[0-9]+$", c["url"])]
        assert rows == [f"A-39 {c['where']}" for c in pulls]


class TestStarRefresh:
    def test_a_corpus_repo_is_not_counted_as_a_star_entry(self):
        assert refresh_stars.entry_counts(SAMPLE) == [("example/one", 10)]

    def test_blocks_split_the_file_losslessly(self):
        assert "".join(refresh_stars.blocks(SAMPLE)) == SAMPLE

    def test_rewrite_moves_counts_and_their_read_time_only(self):
        text, claims, changed = refresh_stars.rewrite(SAMPLE, SAMPLE_CLAIMS, {"example/one": 12},
                                                      "2026-10-14 23:00 UTC")
        assert "stars = 12" in text and 'repo = "example/elsewhere"' in text
        assert 'stars_read = "2026-10-14 23:00 UTC"' in text
        assert changed == 1
        first, second = claims.splitlines()
        assert first == "| A-01 | One: 12 stars | GitHub API | stars 2026-10-14 23:00 | rederive | attention |"
        assert second == SAMPLE_CLAIMS.splitlines()[1]

    def test_an_entry_with_a_repo_and_no_count_is_refused(self):
        broken = SAMPLE.replace("stars = 10\n", "")
        with pytest.raises(refresh_stars.RefreshError):
            refresh_stars.entry_counts(broken)

    def test_the_real_data_file_refreshes(self):
        found = refresh_stars.entry_counts((ROOT / "data/atlas.toml").read_text(encoding="utf-8"))
        assert len(found) == sum(1 for e in DATA["entry"] if "repo" in e) > 0

    def test_main_writes_nothing_when_a_read_fails(self, monkeypatch, tmp_path):
        data, claims = tmp_path / "atlas.toml", tmp_path / "CLAIMS.md"
        data.write_text(SAMPLE, encoding="utf-8")
        claims.write_text(SAMPLE_CLAIMS, encoding="utf-8")
        monkeypatch.setattr(refresh_stars, "DATA", data)
        monkeypatch.setattr(refresh_stars, "CLAIMS", claims)

        def fail(repo):
            raise OSError("offline")

        assert refresh_stars.main([], reader=fail) == 2
        assert data.read_text(encoding="utf-8") == SAMPLE
        assert claims.read_text(encoding="utf-8") == SAMPLE_CLAIMS
