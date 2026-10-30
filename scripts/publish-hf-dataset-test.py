#!/usr/bin/env python3
"""Check that the Hugging Face dataset build reproduces the first copy and refuses bad input.

The load-bearing test rebuilds tag v0.25.0 in a checkout of this repository and
requires the bytes the Hub served for that release: the case and corpus tables,
the card, SOURCE.json and SHA256SUMS (pinned by digest in
publish-hf-dataset-v0.25.0.json). It needs the tag in the object store and
cosign on PATH, and it fails, never skips, when either is missing.

Set AEV_HF_NETWORK=1 to also compare the build with the files the Hub serves now.

    python3 scripts/publish-hf-dataset-test.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("publish_hf", HERE / "publish-hf-dataset.py")
assert SPEC is not None and SPEC.loader is not None
pub = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pub)

FIXTURE = json.loads((HERE / "publish-hf-dataset-v0.25.0.json").read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


class ReproducesFirstCopy(unittest.TestCase):
    """Rebuild v0.25.0 and require the first copy's bytes."""

    out: Path
    parent: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.parent = Path(tempfile.mkdtemp(prefix="aev-hf-test-"))
        cls.out = cls.parent / "dataset"
        problems = pub.build(pub.REPO, FIXTURE["tag"], cls.out, "python3", None)
        if problems:
            raise AssertionError(problems)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.parent, ignore_errors=True)

    def test_generated_files_match_the_pinned_digests(self) -> None:
        for name, expected in FIXTURE["sha256"].items():
            with self.subTest(name):
                self.assertEqual(digest(self.out / name), expected)

    def test_files_taken_from_the_tag_match(self) -> None:
        lines = (self.out / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        generated = {"README.md", "SOURCE.json", "data/cases.jsonl", "data/corpora.jsonl"}
        kept = [x for x in lines if x.split("  ", 1)[1] not in generated]
        self.assertEqual(len(kept), FIXTURE["files_from_tag"])
        joined = "".join(x + "\n" for x in kept)
        self.assertEqual(
            hashlib.sha256(joined.encode()).hexdigest(), FIXTURE["tag_files_sums_sha256"]
        )

    def test_the_built_tree_checks_clean(self) -> None:
        self.assertEqual(pub.check_tree(self.out), [])

    def test_source_records_the_tag_and_commit(self) -> None:
        source = json.loads((self.out / "SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual((source["tag"], source["commit"]), (FIXTURE["tag"], FIXTURE["commit"]))

    @unittest.skipUnless(os.environ.get("AEV_HF_NETWORK") == "1", "needs AEV_HF_NETWORK=1")
    def test_build_equals_what_the_hub_serves(self) -> None:
        base = f"https://huggingface.co/datasets/{pub.DATASET}/resolve/{FIXTURE['tag']}/"
        for name in FIXTURE["sha256"]:
            with self.subTest(name), urllib.request.urlopen(base + name, timeout=120) as response:
                self.assertEqual(response.read(), (self.out / name).read_bytes())


class Shapes(unittest.TestCase):
    """The per-shape rules for a manifest entry."""

    def test_case_id_is_the_id(self) -> None:
        self.assertEqual(pub.case_id({"id": "v1", "file": "a/b.json"}), "v1")

    def test_case_id_falls_back_to_the_file_stem_when_an_entry_lists_only_a_path(self) -> None:
        entry = {"path": "a2-signatures-exclusion/A2-001.json", "sha256": "0" * 64}
        self.assertEqual(pub.case_id(entry), "A2-001")

    def test_case_id_refuses_an_entry_with_no_name(self) -> None:
        with self.assertRaises(pub.PublishError):
            pub.case_id({"file": "a.json"})
        with self.assertRaises(pub.PublishError):
            pub.case_id({"id": 7, "path": "a.json"})

    def test_entry_path_is_file_then_path_else_none(self) -> None:
        self.assertEqual(pub.entry_path({"file": "f", "path": "p"}), "f")
        self.assertEqual(pub.entry_path({"path": "cases/honest"}), "cases/honest")
        self.assertIsNone(pub.entry_path({"record": "records/r.json"}))
        self.assertIsNone(pub.entry_path({"manifest": "cases/m/trial.json"}))

    def test_case_row_serialises_entry_and_expected_as_sorted_json_strings(self) -> None:
        manifest = {"corpusDigest": "d", "suite": "s", "suiteRevision": 7, "vectors": []}
        row = pub.derive_case(
            "vectors", manifest, {"id": "x", "file": "f.json", "expected": {"b": 1, "a": 2}}
        )
        self.assertEqual(row["expected"], '{"a": 2, "b": 1}')
        self.assertEqual(row["path"], "vectors/f.json")
        self.assertEqual(row["suite_revision"], "7")
        self.assertIsNone(pub.derive_case("c", manifest, {"id": "y"})["expected"])

    def test_corpora_follow_manifest_path_order_so_vectors_comes_last(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("vectors", "vectors-b", "vectors-a"):
                write_json(root / name / "MANIFEST.json", MANIFEST)
            _cases, corpora = pub.derive_rows(root)
        self.assertEqual([c["corpus"] for c in corpora], ["vectors-a", "vectors-b", "vectors"])

    def test_sums_are_ordered_by_path_component_so_vectors_comes_first(self) -> None:
        text = pub.sums_text({"vectors-a/x": "1" * 64, "vectors/x": "2" * 64, "LICENSE": "3" * 64})
        self.assertEqual(
            [x.split("  ")[1] for x in text.splitlines()], ["LICENSE", "vectors/x", "vectors-a/x"]
        )


MANIFEST = {
    "corpusDigest": "d" * 64,
    "suite": "s",
    "vectors": [
        {
            "id": "v1",
            "file": "v1.json",
            "kind": "accept",
            "expected": {"result": "pass", "verdict": "valid"},
        }
    ],
}


def make_tree(root: Path) -> None:
    """A minimal published tree: a `vectors` corpus, release/, LICENSE, CITATION.cff."""
    write_json(root / "vectors" / "MANIFEST.json", MANIFEST)
    write_json(root / "vectors" / "v1.json", {"a": 1})
    (root / "release").mkdir()
    (root / "release" / "CORPUS-DIGESTS.txt").write_text(
        f"# header\n{'d' * 64}  vectors/MANIFEST.json  s  vectors=1\n"
    )
    (root / "LICENSE").write_text("Apache-2.0\n")
    (root / "CITATION.cff").write_text(
        "repository-code: https://github.com/probityai/agent-evidence-vectors\n"
        "doi: 10.5281/zenodo.1\n"
    )
    pub.check_signed_list(root, ["vectors"])
    pub.write_derived(root, "v9.9.9", "c" * 40, 5)
    pub.write_sums(root)


class CheckRefuses(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        make_tree(self.root)

    def test_a_sound_tree_has_no_problems(self) -> None:
        self.assertEqual(pub.check_tree(self.root), [])

    def test_a_changed_vector_file(self) -> None:
        (self.root / "vectors" / "v1.json").write_text('{"a": 2}')
        self.assertTrue(any("does not hash" in p for p in pub.check_tree(self.root)))

    def test_an_extra_file(self) -> None:
        (self.root / "stray.txt").write_text("x")
        self.assertTrue(any("not listed" in p for p in pub.check_tree(self.root)))

    def test_a_missing_file(self) -> None:
        (self.root / "vectors" / "v1.json").unlink()
        self.assertTrue(any("not present" in p for p in pub.check_tree(self.root)))

    def test_a_case_row_whose_path_is_not_in_the_tree(self) -> None:
        manifest = json.loads((self.root / "vectors" / "MANIFEST.json").read_text())
        manifest["vectors"][0]["file"] = "gone.json"
        write_json(self.root / "vectors" / "MANIFEST.json", manifest)
        pub.write_derived(self.root, "v9.9.9", "c" * 40, 5)
        pub.write_sums(self.root)
        self.assertTrue(any("is not in the tree" in p for p in pub.check_tree(self.root)))

    def test_a_card_whose_numbers_are_not_the_data(self) -> None:
        card = self.root / "README.md"
        card.write_text(card.read_text().replace("1 cases in 1 corpora", "2 cases in 1 corpora"))
        pub.write_sums(self.root)
        self.assertTrue(any("not the card" in p for p in pub.check_tree(self.root)))

    def test_a_count_in_source_json_that_the_data_does_not_bear_out(self) -> None:
        source = json.loads((self.root / "SOURCE.json").read_text())
        source["cases"] = 5
        (self.root / "SOURCE.json").write_text(json.dumps(source, indent=2) + "\n")
        pub.write_sums(self.root)
        self.assertTrue(any("cases is 5" in p for p in pub.check_tree(self.root)))

    def test_a_duplicate_case_id(self) -> None:
        manifest = json.loads((self.root / "vectors" / "MANIFEST.json").read_text())
        manifest["vectors"].append(manifest["vectors"][0])
        write_json(self.root / "vectors" / "MANIFEST.json", manifest)
        self.assertTrue(pub.check_tree(self.root))

    def test_a_signed_list_that_differs_from_the_tree(self) -> None:
        listing = self.root / "release" / "CORPUS-DIGESTS.txt"
        listing.write_text(listing.read_text().replace("d" * 64, "e" * 64))
        with self.assertRaises(pub.PublishError):
            pub.check_signed_list(self.root, ["vectors"])


class BuildRefuses(unittest.TestCase):
    def test_package_tags_are_not_corpus_releases(self) -> None:
        for tag in ("jcs-admit-npm-v0.1.0", "v1.2", "v0.30.0-rc1", "0.30.0", "main"):
            with self.subTest(tag), self.assertRaises(pub.PublishError):
                pub.resolve_tag(pub.REPO, tag)

    def test_missing_cosign_fails_the_build(self) -> None:
        saved = os.environ["PATH"]
        os.environ["PATH"] = ""
        try:
            with self.assertRaises(pub.PublishError) as caught:
                pub.run_release_checks(HERE.parent, "python3", None)
        finally:
            os.environ["PATH"] = saved
        self.assertIn("cosign", str(caught.exception))

    def test_build_runs_the_release_checks_before_it_writes_anything(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dataset"
            refusal = pub.PublishError("sentinel")
            with patch.object(pub, "run_release_checks", side_effect=refusal):
                with self.assertRaises(pub.PublishError) as caught:
                    pub.build(pub.REPO, FIXTURE["tag"], out, "python3", None)
            self.assertIs(caught.exception, refusal)
            self.assertFalse(out.exists())

    def test_a_failing_digest_check_fails_the_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "scripts" / "release-digests.py"
            script.parent.mkdir()
            script.write_text("import sys\nsys.exit(1)\n")
            fake = Path(tmp) / "cosign"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o755)
            with self.assertRaises(pub.PublishError) as caught:
                pub.run_release_checks(Path(tmp), "python3", str(fake))
        self.assertIn("release-digests.py --check", str(caught.exception))

    def test_a_failing_signature_check_fails_the_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "scripts" / "release-digests.py"
            script.parent.mkdir()
            script.write_text("")
            fake = Path(tmp) / "cosign"
            fake.write_text("#!/bin/sh\nexit 1\n")
            fake.chmod(0o755)
            with self.assertRaises(pub.PublishError) as caught:
                pub.run_release_checks(Path(tmp), "python3", str(fake))
        self.assertIn("cosign verify-blob", str(caught.exception))


class UploadPlan(unittest.TestCase):
    def test_the_upload_replaces_every_published_directory_but_not_the_hub_gitattributes(
        self,
    ) -> None:
        for path in (
            "data/cases.jsonl",
            "release/cosign.pub",
            "vectors/a.json",
            "vectors-aci/b/c.json",
        ):
            self.assertTrue(any(_glob(path, p) for p in pub.DELETE_PATTERNS), path)
        self.assertFalse(any(_glob(".gitattributes", p) for p in pub.DELETE_PATTERNS))

    def test_upload_is_one_hf_upload_naming_the_tag(self) -> None:
        command = pub.upload_command(Path("/d"), "v0.30.0", "a" * 40)
        self.assertEqual(command[:2], ["upload", pub.DATASET])
        self.assertIn("v0.30.0", command[-1])

    def test_tag_action(self) -> None:
        refs = {"tags": [{"name": "v1.0.0", "targetCommit": "aaa"}]}
        self.assertEqual(pub.tag_action(refs, "v1.1.0", "bbb"), "create")
        self.assertEqual(pub.tag_action(refs, "v1.0.0", "aaa"), "keep")
        with self.assertRaises(pub.PublishError):
            pub.tag_action(refs, "v1.0.0", "bbb")

    def test_upload_without_a_token_fails_before_anything_is_sent(self) -> None:
        saved = os.environ.pop("HF_TOKEN", None)
        try:
            with self.assertRaises(pub.PublishError) as caught:
                pub.upload(Path("/nonexistent"), "v0.30.0")
        finally:
            if saved is not None:
                os.environ["HF_TOKEN"] = saved
        self.assertIn("HF_TOKEN", str(caught.exception))

    def test_size_buckets(self) -> None:
        self.assertEqual(
            [pub.size_category(n) for n in (999, 1000, 9999, 10000)],
            ["n<1K", "1K<n<10K", "1K<n<10K", "10K<n<100K"],
        )


def _glob(path: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(path, pattern)


if __name__ == "__main__":
    unittest.main()
