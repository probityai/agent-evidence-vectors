#!/usr/bin/env python3
"""Hold scripts/check-release-fetch.py and scripts/fetch-tool.py to their refusals.

The lint must flag a release-asset fetch by any client, accept a marker that gives a
reason, and refuse a marker that gives none. The fetch helper must keep bytes only
when they match the pinned sha256 and must fall back from the direct URL to the API.
"""

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lint = load("check_release_fetch", "check-release-fetch.py")
tool = load("fetch_tool", "fetch-tool.py")

# curl-retry: exempt test fixture text, not a fetch
URL = "https://github.com/o/r/releases/download/v1/a.tgz"


class LintTest(unittest.TestCase):
    def test_every_client_is_flagged(self) -> None:
        for line in (
            f"curl -fsSL {URL}",
            f"python -c 'urllib.request.urlopen(\"{URL}\")'",
            f"wget {URL}",
            # curl-retry: exempt test fixture text, not a fetch
            "gh release download v1 --repo o/r",
            # curl-retry: exempt test fixture text, not a fetch
            "uses: golangci/golangci-lint-action@v9",
            # curl-retry: exempt test fixture text, not a fetch
            "gh api repos/o/r/releases/assets/12",
        ):
            with self.subTest(line=line):
                self.assertEqual(len(lint.scan_text("w.yml", line)), 1)

    def test_marker_with_reason_exempts_same_line_and_previous_line(self) -> None:
        self.assertEqual(
            lint.scan_text("w", f"curl {URL}  # curl-retry: exempt measures the host"), []
        )
        self.assertEqual(
            lint.scan_text("w", f"# curl-retry: exempt measures the host\ncurl {URL}"), []
        )

    def test_marker_without_reason_fails(self) -> None:
        for text in (f"# curl-retry: exempt\ncurl {URL}", f"curl {URL} # curl-retry: exempt -"):
            with self.subTest(text=text):
                found = lint.scan_text("w", text)
                self.assertTrue(any("no reason" in f for f in found))

    def test_clean_line_passes(self) -> None:
        self.assertEqual(lint.scan_text("w", "uses: ./.github/actions/fetch-tool"), [])

    def test_repository_is_clean(self) -> None:
        self.assertEqual(lint.main(), 0)


class FetchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.dest = Path(self.dir.name) / "bin" / "tool"
        self.good = b"good bytes"
        self.sha = hashlib.sha256(self.good).hexdigest()

    def test_cache_hit_needs_no_network(self) -> None:
        self.dest.parent.mkdir()
        self.dest.write_bytes(self.good)
        with mock.patch.object(tool, "direct", side_effect=AssertionError("network")):
            self.assertEqual(tool.fetch("o/r", "v1", "a", self.sha, self.dest), "cache")

    def test_stale_cache_is_replaced_by_verified_bytes(self) -> None:
        self.dest.parent.mkdir()
        self.dest.write_bytes(b"edited")
        with mock.patch.object(tool, "direct", lambda url, part: part.write_bytes(self.good)):
            self.assertEqual(tool.fetch("o/r", "v1", "a", self.sha, self.dest), "direct")
        self.assertEqual(self.dest.read_bytes(), self.good)

    def test_direct_failure_falls_back_to_api(self) -> None:
        def broken(url: str, part: Path) -> None:
            raise OSError("504")

        with (
            mock.patch.object(tool, "direct", broken),
            mock.patch.object(
                tool, "via_api", lambda repo, tag, asset, part: part.write_bytes(self.good)
            ),
        ):
            self.assertEqual(tool.fetch("o/r", "v1", "a", self.sha, self.dest), "api")

    def test_wrong_bytes_on_every_path_install_nothing(self) -> None:
        wrong = lambda *args: args[-1].write_bytes(b"wrong")  # noqa: E731
        with mock.patch.object(tool, "direct", wrong), mock.patch.object(tool, "via_api", wrong):
            with self.assertRaises(SystemExit):
                tool.fetch("o/r", "v1", "a", self.sha, self.dest)
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.dest.with_name("tool.part").exists())


if __name__ == "__main__":
    unittest.main()
