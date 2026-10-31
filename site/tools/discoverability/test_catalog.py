"""Exercise publication, catalog growth and deterministic rendering."""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any

import catalog
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st


@pytest.fixture
def seed() -> dict[str, Any]:
    """Return a fresh approved public snapshot for each test."""
    return catalog.load_catalog(Path(__file__).with_name("catalog.seed.json"))


def assert_refused(
    data: dict[str, Any], message: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Check that callers and build logs receive the same refusal."""
    with caplog.at_level(logging.ERROR), pytest.raises(catalog.CatalogError) as caught:
        catalog.validate_catalog(data)
    assert str(caught.value) == message
    assert message in caplog.messages


class TestValidateCatalog:
    class TestPassingCases:
        def test_seed_and_schema_agree(self, seed: dict[str, Any]) -> None:
            checked = catalog.validate_catalog(seed)
            assert checked == seed
            checked["components"][0]["summary"] = "Changed"
            assert checked != seed

        def test_component_can_span_repositories(self, seed: dict[str, Any]) -> None:
            seed["components"][0]["repositories"].append(seed["repositories"][1]["id"])
            assert catalog.validate_catalog(seed)["components"][0]["repositories"] == [
                "repo-vocabulary",
                "repo-vectors",
            ]

        def test_rename_and_retire_keep_the_id(self, seed: dict[str, Any]) -> None:
            record = seed["components"][0]
            stable_id = record["id"]
            record.update(
                display_name="Vocabulary registry",
                aliases=["former-vocabulary"],
                status="retired",
            )
            output = catalog.public_projection(seed)
            found = next(
                item for item in output["components"] if item["id"] == stable_id
            )
            assert found["display_name"] == "Vocabulary registry"
            assert found["status"] == "retired"

        def test_new_repository_and_profile_need_no_code_change(
            self, seed: dict[str, Any]
        ) -> None:
            repository = copy.deepcopy(seed["repositories"][0])
            repository.update(
                id="repo-new-format",
                full_name="probityai/new-format",
                url="https://github.com/probityai/new-format",
            )
            repository["source"].update(
                repository=repository["id"],
                url=f"{repository['url']}/blob/{repository['source']['commit']}/README.md",
            )
            seed["approved_repositories"].append(repository["full_name"])
            seed["repositories"].append(repository)
            profile = copy.deepcopy(seed["components"][0])
            profile.update(
                id="new-format-profile",
                component="vocabulary",
                repositories=[repository["id"]],
                docs_url=repository["source"]["url"],
            )
            seed["profiles"].append(profile)
            assert (
                catalog.public_projection(seed)["profiles"][0]["id"]
                == "new-format-profile"
            )

        @pytest.mark.parametrize("publication", ["private", "draft", "held"])
        def test_hidden_records_are_absent(
            self, seed: dict[str, Any], publication: str
        ) -> None:
            private = copy.deepcopy(seed["components"][0])
            private.update(
                id="internal-sentinel",
                publication=publication,
                display_name="SECRET SENTINEL",
                summary="https://example.invalid/private",
            )
            seed["components"].append(private)
            text = json.dumps(catalog.render_navigation(seed))
            assert "SECRET SENTINEL" not in text
            assert "internal-sentinel" not in text
            assert "example.invalid" not in text

        def test_unreviewed_public_record_is_absent(self, seed: dict[str, Any]) -> None:
            seed["components"][0]["reviewed"] = False
            assert (
                "Probity Vocabulary" not in catalog.render_navigation(seed)["TASKS.md"]
            )

    class TestFailingCases:
        def test_duplicate_id(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][1]["id"] = "vocabulary"
            assert_refused(seed, "Duplicate ID or alias: vocabulary", caplog)

        def test_alias_collision(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["aliases"] = ["vectors"]
            assert_refused(seed, "Duplicate ID or alias: vectors", caplog)

        def test_dangling_reference(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["repositories"] = ["missing"]
            assert_refused(seed, "Dangling reference: vocabulary -> missing", caplog)

        def test_wrong_kind(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["repositories"] = ["vectors"]
            assert_refused(seed, "Wrong reference kind: vocabulary -> vectors", caplog)

        def test_hidden_reference(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["repositories"][0]["publication"] = "private"
            assert_refused(
                seed, "Published record references a hidden record: vocabulary", caplog
            )

        def test_promotion_rechecks_public_text(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            record = seed["components"][0]
            record.update(publication="private", summary="ghp_secret123")
            catalog.validate_catalog(seed)
            record["publication"] = "public"
            assert_refused(
                seed, "Public text contains a forbidden identity or credential", caplog
            )

        def test_source_pin_cannot_point_to_another_repository(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["repositories"][0]["source"]["repository"] = "repo-vectors"
            assert_refused(
                seed, "Public repository source must pin its own README commit", caplog
            )

        @pytest.mark.parametrize(
            "text",
            ["ghp_secret123", "github_pat_secret123"],
        )
        def test_forbidden_text(
            self, seed: dict[str, Any], text: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["summary"] = text
            assert_refused(
                seed, "Public text contains a forbidden identity or credential", caplog
            )

        @pytest.mark.parametrize(
            "text",
            [
                "a | injected",
                "[bad](javascript:evil)",
                "<script>",
                "line\nbreak",
                "https://github.com/probityai/dsse",
                "\u00e9",
            ],
        )
        def test_markdown_and_non_ascii(
            self, seed: dict[str, Any], text: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["summary"] = text
            assert_refused(
                seed, "Public text must be plain ASCII without embedded links", caplog
            )

        @pytest.mark.parametrize(
            "url",
            [
                "https://example.invalid",
                "https://github.com/private-owner/private-project",
                "https://github.com/probityai/private-project",
                "https://github.com@evil.example/probityai/dsse",
                "https://github.com/probityai/dsse?token=secret",
                "https://github.com/probityai/dsse/%2e%2e/private",
                "https://github.com/probityai/dsse/../private",
                "https://github.com/probityai/dsse)\n<script>",
            ],
        )
        def test_bad_urls(
            self, seed: dict[str, Any], url: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["docs_url"] = url
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.validate_catalog(seed)
            assert str(caught.value) in {
                "Public URL must use an approved HTTPS host",
                "Public URL must have a plain repository path",
                "Public URL contains an unsafe path segment",
                "Public URL does not belong to an approved repository",
            }
            assert str(caught.value) in caplog.messages

        def test_unknown_core_field(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["marketing_claim"] = "Unsupported"
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.validate_catalog(seed)
            assert str(caught.value).startswith("Schema violation at $.components[0]:")
            assert str(caught.value) in caplog.messages


class TestRenderNavigation:
    class TestPassingCases:
        @given(st.permutations(tuple(range(8))))
        @settings(max_examples=25)
        def test_order_is_irrelevant(self, order: tuple[int, ...]) -> None:
            seed = catalog.load_catalog(Path(__file__).with_name("catalog.seed.json"))
            before = catalog.render_navigation(seed)
            for collection in ("repositories", "components"):
                seed[collection] = [seed[collection][index] for index in order]
            assert catalog.render_navigation(seed) == before

        @given(st.dictionaries(st.text(max_size=20), st.text(max_size=100), max_size=8))
        def test_extensions_and_notes_never_reach_output(
            self, extensions: dict[str, str]
        ) -> None:
            seed = catalog.load_catalog(Path(__file__).with_name("catalog.seed.json"))
            before = catalog.render_navigation(seed)
            seed["extensions"] = extensions
            for record in seed["components"]:
                record["extensions"] = extensions
                record["private_notes"] = {
                    "sentinel": "PRIVATE SECRET https://example.invalid"
                }
            assert catalog.render_navigation(seed) == before

        def test_repo_order_does_not_change_output(self, seed: dict[str, Any]) -> None:
            seed["components"][0]["repositories"].append("repo-vectors")
            before = catalog.render_navigation(seed)
            seed["components"][0]["repositories"].reverse()
            assert catalog.render_navigation(seed) == before

        def test_ascii_status_and_count_free_heading(
            self, seed: dict[str, Any]
        ) -> None:
            output = catalog.render_navigation(seed)
            assert output["TASKS.md"].splitlines()[0] == "# Find a tool for your task"
            assert "| prototype |" in output["TASKS.md"]
            assert "| unreleased |" in output["TASKS.md"]
            assert all(value.isascii() for value in output.values())

    class TestFailingCases:
        def test_render_validates_before_returning(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["components"][0]["summary"] = "ghp_secret123"
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(
                    catalog.CatalogError,
                    match=r"^Public text contains a forbidden identity or credential$",
                ),
            ):
                catalog.render_navigation(seed)
            assert caplog.messages == [
                "Public text contains a forbidden identity or credential"
            ]


class TestLoadCatalog:
    class TestPassingCases:
        def test_real_seed(self) -> None:
            assert (
                catalog.load_catalog(Path(__file__).with_name("catalog.seed.json"))[
                    "schema_version"
                ]
                == 1
            )

    class TestFailingCases:
        @pytest.mark.parametrize(
            ("body", "message"),
            [
                ('{"a": 1, "a": 2}', "Repeated JSON member: a"),
                ("[]", "Catalog root must be an object"),
                ("{", "Invalid JSON at line 1, column 2"),
            ],
        )
        def test_bad_input(
            self,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            body: str,
            message: str,
        ) -> None:
            path = tmp_path / "bad.json"
            path.write_text(body)
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.load_catalog(path)
            assert str(caught.value) == message
            assert message in caplog.messages


class TestWriteOutputs:
    class TestPassingCases:
        def test_repeatable_dedicated_output(
            self, seed: dict[str, Any], tmp_path: Path
        ) -> None:
            output = tmp_path / "generated"
            contents = catalog.render_navigation(seed)
            catalog.write_outputs(output, contents)
            catalog.write_outputs(output, contents)
            assert {
                path.name: path.read_text() for path in output.iterdir()
            } == contents

        def test_cli_validation_and_build(self, tmp_path: Path) -> None:
            path = Path(__file__).with_name("catalog.seed.json")
            assert catalog.main(["validate", str(path)]) == 0
            assert (
                catalog.main(
                    ["build", str(path), "--output", str(tmp_path / "generated")]
                )
                == 0
            )

    class TestFailingCases:
        def test_symlink_directory(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            real = tmp_path / "real"
            real.mkdir()
            link = tmp_path / "link"
            link.symlink_to(real, target_is_directory=True)
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.write_outputs(link / "generated", {"TASKS.md": "x"})
            assert str(caught.value) == "Output directory must not use symlinks"
            assert str(caught.value) in caplog.messages

        def test_symlink_file(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            outside = tmp_path / "secret"
            outside.write_text("unchanged")
            output = tmp_path / "generated"
            output.mkdir()
            (output / "TASKS.md").symlink_to(outside)
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.write_outputs(output, {"TASKS.md": "changed"})
            assert str(caught.value) == "Output file must be a regular file"
            assert outside.read_text() == "unchanged"
            assert str(caught.value) in caplog.messages

        def test_unrelated_file(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            (tmp_path / "user-file").write_text("keep")
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.write_outputs(tmp_path, {"TASKS.md": "x"})
            assert str(caught.value) == "Output directory contains unrelated files"
            assert str(caught.value) in caplog.messages

        def test_cli_requires_output(self, caplog: pytest.LogCaptureFixture) -> None:
            with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as caught:
                catalog.main(
                    ["build", str(Path(__file__).with_name("catalog.seed.json"))]
                )
            assert caught.value.code == 2
            assert "build requires --output" in caplog.messages


class TestCatalogEvolution:
    class TestPassingCases:
        def test_label_change_and_retirement_preserve_identity(
            self, seed: dict[str, Any]
        ) -> None:
            previous = copy.deepcopy(seed)
            seed["components"][0].update(
                display_name="Vocabulary registry", status="retired"
            )
            assert (
                catalog.validate_catalog(seed, previous)["components"][0]["id"]
                == "vocabulary"
            )

        def test_private_repository_is_not_disclosed(
            self, seed: dict[str, Any]
        ) -> None:
            private = copy.deepcopy(seed["repositories"][0])
            private.update(
                id="repo-hidden",
                full_name="private-owner/private-project",
                url="https://github.com/private-owner/private-project",
                publication="private",
            )
            seed["repositories"].append(private)
            assert "private-owner/private-project" not in json.dumps(
                catalog.render_navigation(seed)
            )

    class TestFailingCases:
        def test_removed_id_is_refused(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            previous = copy.deepcopy(seed)
            seed["components"].pop()
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.validate_catalog(seed, previous)
            assert str(caught.value) == "Stable ID removed or changed kind: atlas"
            assert str(caught.value) in caplog.messages


class TestOutputBoundaries:
    class TestFailingCases:
        def test_commit_pin_cannot_hide_a_newline(
            self, seed: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            seed["repositories"][0]["source"]["commit"] += "\n"
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.validate_catalog(seed)
            assert str(caught.value).startswith(
                "Schema violation at $.repositories[0].source.commit:"
            )
            assert str(caught.value) in caplog.messages

        def test_invalid_utf8_is_refused(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            path = tmp_path / "bad.json"
            path.write_bytes(bytes([255]))
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.load_catalog(path)
            assert str(caught.value) == "Catalog must be UTF-8 JSON"
            assert str(caught.value) in caplog.messages

        @pytest.mark.parametrize(
            ("contents", "message"),
            [
                (
                    {"../outside": "changed"},
                    "Output filenames must be recognized generated artifacts",
                ),
                ({"TASKS.md": chr(233)}, "Output content must be ASCII"),
            ],
        )
        def test_bad_output_before_writes(
            self,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            contents: dict[str, str],
            message: str,
        ) -> None:
            output = tmp_path / "generated"
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.write_outputs(output, contents)
            assert str(caught.value) == message
            assert message in caplog.messages
            assert not output.exists()

        @pytest.mark.parametrize(
            "url",
            [
                "https://github.com/\nprobityai/dsse",
                "https://github.com/probityai/\rdsse",
                "https://[invalid/probityai/dsse",
            ],
        )
        def test_url_parser_cannot_hide_controls(
            self, url: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.check_url(url, {"probityai/dsse"})
            expected = (
                "Public URL must use an approved HTTPS host"
                if "[invalid" in url
                else "Public URL must have a plain repository path"
            )
            assert str(caught.value) == expected
            assert expected in caplog.messages

        def test_hard_link_file(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            secret = tmp_path / "secret"
            secret.write_text("keep")
            output = tmp_path / "generated"
            output.mkdir()
            (output / "TASKS.md").hardlink_to(secret)
            with (
                caplog.at_level(logging.ERROR),
                pytest.raises(catalog.CatalogError) as caught,
            ):
                catalog.write_outputs(output, {"TASKS.md": "changed"})
            assert str(caught.value) == "Output file must be an unshared regular file"
            assert str(caught.value) in caplog.messages
            assert secret.read_text() == "keep"
