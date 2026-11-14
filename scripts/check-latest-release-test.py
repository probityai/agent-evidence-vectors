#!/usr/bin/env python3
"""Tests for check-latest-release.py."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from types import ModuleType


def load() -> ModuleType:
    path = pathlib.Path(__file__).with_name("check-latest-release.py")
    spec = importlib.util.spec_from_file_location("chk", path)
    if spec is None or spec.loader is None:
        raise ImportError("check-latest-release.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


chk = load()


class LatestRelease(unittest.TestCase):
    def test_numeric_not_lexical_order(self) -> None:
        self.assertEqual(chk.newest_corpus_tag(["v0.9.0", "v0.10.0", "v0.2.0"]), "v0.10.0")

    def test_sub_package_tags_ignored(self) -> None:
        tags = ["v0.36.3", "dsse-npm-v0.1.0", "jcs-admit-py-v0.1.1", "v0.36.3-rc1"]
        self.assertEqual(chk.newest_corpus_tag(tags), "v0.36.3")

    def test_pass(self) -> None:
        self.assertIsNone(chk.verdict(["v0.36.1", "v0.36.3"], "v0.36.3"))

    def test_sub_package_latest_fails(self) -> None:
        self.assertIn("dsse-npm-v0.1.0", chk.verdict(["v0.36.3"], "dsse-npm-v0.1.0"))

    def test_older_corpus_latest_fails(self) -> None:
        self.assertIsNotNone(chk.verdict(["v0.36.1", "v0.36.3"], "v0.36.1"))

    def test_no_tags_fails(self) -> None:
        self.assertIsNotNone(chk.verdict([], "v0.1.0"))


if __name__ == "__main__":
    unittest.main()
