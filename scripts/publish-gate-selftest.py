#!/usr/bin/env python3
"""Mutations of the workflows that publish-gate-test.py must refuse."""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gate", HERE / "publish-gate-test.py")
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class Mutations(unittest.TestCase):
    def mutate(self, name: str, old: str, new: str, count: int = 1) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            for src in gate.WORKFLOWS.glob("*.y*ml"):
                shutil.copy(src, tmp)
            path = Path(tmp) / name
            text = path.read_text(encoding="utf-8")
            self.assertIn(old, text)
            path.write_text(text.replace(old, new, count), encoding="utf-8")
            return gate.check_all(Path(tmp))

    def add_workflow(self, filename: str, body: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            for src in gate.WORKFLOWS.glob("*.y*ml"):
                shutil.copy(src, tmp)
            (Path(tmp) / filename).write_text(body, encoding="utf-8")
            return gate.check_all(Path(tmp))

    def test_clean_tree_passes(self) -> None:
        self.assertEqual(gate.check_all(gate.WORKFLOWS), [])

    def test_manual_trigger_on_release_refused(self) -> None:
        self.assertTrue(
            self.mutate(
                "release.yml",
                "  release:\n    types: [published]\n",
                "  release:\n    types: [published]\n  workflow_dispatch:\n",
            )
        )

    def test_branch_filter_on_the_tag_trigger_refused(self) -> None:
        self.assertTrue(
            self.mutate("release.yml", "tags: ['v*']", "tags: ['v*']\n    branches: ['**']")
        )

    def test_corpus_publish_without_environment_refused(self) -> None:
        self.assertTrue(self.mutate("release.yml", "    environment: public-release\n", ""))

    def test_publish_condition_changed_refused(self) -> None:
        self.assertTrue(
            self.mutate(
                "release.yml",
                "startsWith(github.ref, 'refs/tags/v') }}\n    runs-on: ubuntu-latest\n"
                "    # The owner",
                "startsWith(github.ref, 'refs/tags/v') || true }}\n"
                "    runs-on: ubuntu-latest\n    # The owner",
            )
        )

    def test_hf_workflow_gaining_a_publish_job_refused(self) -> None:
        self.assertTrue(
            self.mutate("publish-hf-dataset.yml", "\non:\n", "\non:\n  workflow_dispatch:\n")
        )

    def test_hf_token_in_another_workflow_refused(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ secrets.HF_TOKEN }}\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))

    def test_yaml_extension_is_scanned(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ secrets.HF_TOKEN }}\n"
        )
        self.assertTrue(self.add_workflow("x.yaml", body))

    def test_computed_secret_name_refused(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ${{ secrets[format('HF_{0}','TOKEN')] }}\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))

    def test_to_json_secrets_refused(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ toJSON(secrets) }}\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))

    def test_workflow_level_token_env_refused(self) -> None:
        body = (
            "name: x\non: push\nenv:\n  T: ${{ secrets.HF_TOKEN }}\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))

    def test_uv_publish_with_oidc_refused(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    permissions:\n      id-token: write\n    steps:\n"
            "      - run: uv publish\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))

    def test_environment_without_the_gate_refused(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    environment: github-pages\n    steps:\n"
            "      - run: twine upload dist/*\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))

    def test_computed_environment_refused(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    environment: ${{ matrix.e }}\n    steps:\n      - run: echo hi\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))

    def test_public_release_on_another_job_refused(self) -> None:
        body = (
            "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    environment: public-release\n    steps:\n      - run: echo hi\n"
        )
        self.assertTrue(self.add_workflow("x.yml", body))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
