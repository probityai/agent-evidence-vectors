"""Fetch the twelve hash-pinned public inputs locally without redistributing their source."""

import argparse
import hashlib
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from json_profile import Refusal, parse, require
from replay import FROZEN_INPUT_MANIFEST, HERE, load_cases

BASE = "https://raw.githubusercontent.com/darklordVirtual/REMORA-research/a4a948cae7044a474fdb55099daea866130c466f/"


class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise Refusal("input_fetch_redirect_refused")


def download(url, expected_size):
    opener = urllib.request.build_opener(RefuseRedirect())
    try:
        with opener.open(url, timeout=30) as response:
            require(response.status == 200 and response.url == url, "input_fetch_response")
            return response.read(expected_size + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise Refusal("input_fetch_failed") from exc


def fetch_locked(root, retrieve):
    raw = (root / "INPUT-MANIFEST.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == FROZEN_INPUT_MANIFEST, "input_manifest_changed")
    manifest = parse(raw)
    target = root / "private-inputs"
    require(not target.exists() and not target.is_symlink(), "input_directory_already_exists")
    with tempfile.TemporaryDirectory(prefix=".trace-fetch-", dir=root) as temporary:
        staged = Path(temporary) / "private-inputs"
        staged.mkdir()
        for item in manifest["cases"]:
            relative = Path(item["path"])
            require(relative.parent.as_posix() == "private-inputs", "unsafe_case_path")
            require(
                item["upstream_path"]
                == "integrations/agentrust-trace/fixtures/cases/" + relative.name,
                "unexpected_upstream_path",
            )
            data = retrieve(BASE + item["upstream_path"], item["bytes"])
            require(type(data) is bytes and len(data) == item["bytes"], "fetched_case_size_changed")
            require(
                hashlib.sha256(data).hexdigest() == item["sha256"], "fetched_case_digest_changed"
            )
            (staged / relative.name).write_bytes(data)
        require(not target.exists() and not target.is_symlink(), "input_directory_already_exists")
        staged.rename(target)
    load_cases(root)
    return len(manifest["cases"])


def fetch(root, retrieve=download):
    lock = root / ".trace-fetch-lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise Refusal("input_fetch_locked") from exc
    try:
        return fetch_locked(root, retrieve)
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=HERE)
    args = parser.parse_args()
    print(f"Fetched and verified {fetch(args.root)} frozen public cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
