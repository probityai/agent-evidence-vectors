#!/usr/bin/env python3
"""Tell IndexNow engines which URLs of this site were added or changed.

Proves the key file first: GET https://<host>/<key>.txt must answer 200 with the key as its body,
or nothing is sent. Then POSTs the URLs to https://api.indexnow.org/IndexNow in batches. HTTP 200
means the submission was accepted; HTTP 202 means accepted with key validation pending, and is
reported as PENDING, never as accepted. Any other status fails the run. A receipt is printed per
batch, and written as JSON when --receipt is given.

    python3 scripts/indexnow.py --key <key> --urls-file <file> [--sitemap <url> ...]
    python3 scripts/indexnow.py --key <key> --sitemap https://probityai.github.io/sitemap.xml
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

HOST = "probityai.github.io"
ENDPOINT = "https://api.indexnow.org/IndexNow"
BATCH = 10000
KEY_SHAPE = re.compile(r"^[A-Za-z0-9-]{8,128}$")
LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")


def http(
    url: str, data: bytes | None = None, headers: dict[str, str] | None = None
) -> tuple[int, bytes]:
    """(status, body); an HTTP error status is returned, a missing answer is status 0."""
    req = urllib.request.Request(
        url, data=data, headers={"User-Agent": "probityai-indexnow", **(headers or {})}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
        return 0, str(err).encode()


def sitemap_urls(url: str) -> list[str]:
    """Every <loc> of a sitemap served at url; fails when it cannot be read."""
    status, body = http(url)
    if status != 200:
        raise SystemExit(f"FAIL sitemap {url} answered {status or 'nothing'}")
    return LOC.findall(body.decode("utf-8", errors="replace"))


def prove_key(host: str, key: str) -> None:
    """Fail unless the key file is served at the host root with the key as its body."""
    status, body = http(f"https://{host}/{key}.txt")
    if status != 200 or body.decode("utf-8", errors="replace").strip() != key:
        raise SystemExit(
            f"FAIL https://{host}/{key}.txt answered {status or 'nothing'}; no URL was sent"
        )


def verdict(status: int) -> str:
    """ACCEPTED for 200, PENDING for 202 (key validation pending), FAILED for anything else."""
    return {200: "ACCEPTED", 202: "PENDING"}.get(status, "FAILED")


def submit(host: str, key: str, urls: list[str], post=http, sleep=time.sleep) -> list[dict]:
    """POST urls in batches; one receipt per batch. A 429 is retried twice after a pause."""
    receipts = []
    for start in range(0, len(urls), BATCH):
        batch = urls[start : start + BATCH]
        body = json.dumps(
            {"host": host, "key": key, "keyLocation": f"https://{host}/{key}.txt", "urlList": batch}
        ).encode()
        for attempt in range(3):
            status, _ = post(ENDPOINT, body, {"Content-Type": "application/json; charset=utf-8"})
            if status != 429:
                break
            sleep(30 * (attempt + 1))
        receipts.append({"status": status, "verdict": verdict(status), "urls": len(batch)})
    return receipts


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--key", required=True)
    parser.add_argument("--urls-file", type=pathlib.Path)
    parser.add_argument(
        "--sitemap", action="append", default=[], help="a live sitemap whose URLs are sent"
    )
    parser.add_argument("--receipt", type=pathlib.Path)
    args = parser.parse_args(argv)
    if not KEY_SHAPE.match(args.key):
        print("FAIL the key must match [A-Za-z0-9-]{8,128}")
        return 1
    urls: list[str] = []
    if args.urls_file is not None:
        urls += [
            line.strip()
            for line in args.urls_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    for sitemap in args.sitemap:
        urls.append(sitemap)
        urls += sitemap_urls(sitemap)
    urls = sorted(set(urls))
    foreign = [u for u in urls if not u.startswith(f"https://{args.host}/")]
    if foreign:
        print(f"FAIL {len(foreign)} URLs are outside https://{args.host}/, first: {foreign[0]}")
        return 1
    if not urls:
        print("nothing to submit")
        return 0
    prove_key(args.host, args.key)
    receipts = submit(args.host, args.key, urls)
    for r in receipts:
        print(f"{r['verdict']} HTTP {r['status']} for {r['urls']} URLs")
    if args.receipt is not None:
        args.receipt.write_text(
            json.dumps({"host": args.host, "receipts": receipts}, indent=1) + "\n"
        )
    return 1 if any(r["verdict"] == "FAILED" for r in receipts) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
