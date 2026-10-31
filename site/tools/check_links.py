#!/usr/bin/env python3
"""Check every link in the built site.

    python3 tools/check_links.py                 internal links and anchors only
    python3 tools/check_links.py --external      also fetch every external URL
    python3 tools/check_links.py --external --live
                                                 also fetch the site's own published URLs

A link under the site's own published home (BASE_URL, such as each page's
canonical link) is checked against the file it names under docs/, because it
points at this build; with --live it is also fetched, which is the read-back
after the site is published.

Internal: every relative href or src must name a file under docs/, and every
fragment must name an id on the target page. External: every http(s) URL is
fetched (GET, redirects followed, 25 s timeout) and must answer 2xx. A URL that
could not be fetched is reported as a failure with its reason; it is never
treated as fine. Exit 0 only when nothing failed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urldefrag, urlparse

DOCS = Path(__file__).resolve().parent.parent / "docs"
BASE_URL = "https://probityai.github.io/agent-evidence-atlas/"
UA = "Mozilla/5.0 (compatible; site-link-check)"


class Collect(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if value is None:
                continue
            if name == "id":
                self.ids.add(value)
            if name in ("href", "src"):
                self.links.append(value)


def parse(page: Path) -> Collect:
    c = Collect()
    text = page.read_text(encoding="utf-8")
    if page.suffix == ".md":
        result = subprocess.run(
            ["pandoc", "--from=gfm", "--to=html5", "--fail-if-warnings"],
            input=text, capture_output=True, text=True, check=False,
        )
        if result.returncode or result.stderr.strip():
            raise ValueError(f"Cannot parse Markdown links for {page.name}: {result.stderr}")
        text = result.stdout
    c.feed(text)
    return c


# Hosts that refuse automated page reads get an equivalent machine read of the same
# resource. Each alternative proves the linked thing exists; it is not a looser check.
def alternative(url: str) -> str | None:
    p = urlparse(url)
    if p.netloc == "crates.io" and p.path.startswith("/crates/"):
        return "https://crates.io/api/v1/crates/" + p.path.split("/")[2]
    if p.netloc == "doi.org":
        return "https://doi.org/api/handles" + p.path
    # EUR-Lex answers automated reads with a bot-wall challenge (HTTP 202) or no answer at
    # all. The Publications Office resolves the same act by its CELEX number and answers
    # the object itself: eli/reg/2024/1689/oj is CELEX 32024R1689.
    if p.netloc == "eur-lex.europa.eu" and p.path.startswith("/eli/"):
        parts = p.path.strip("/").split("/")
        kinds = {"reg": "R", "dir": "L", "dec": "D"}
        if len(parts) >= 4 and parts[1] in kinds and parts[2].isdigit() and parts[3].isdigit():
            return ("https://publications.europa.eu/resource/celex/"
                    f"3{parts[2]}{kinds[parts[1]]}{int(parts[3]):04d}")
    if p.netloc == "github.com" and "/blob/" in p.path:
        owner, repo, _, ref, *rest = p.path.strip("/").split("/")
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{'/'.join(rest)}?ref={ref}"
    return None


# Hosts that refuse every automated read (bot walls). These links were checked by a
# saved capture of the page or of its wire copy; the capture and its date are in the
# claim ledger. They are reported as MANUAL, never as ok. Every entry must still be
# linked from the site and named by a ledger row: tests/test_link_manual_hosts.py
# refuses an entry that fails either, so the list cannot hide a link nobody recorded.
#
# www.reddit.com answers 200 to the same request from a residential address and 403 to
# every GitHub-hosted runner, so the refusal is by network, not by page; ledger rows
# N-08, N-10 and N-11 record the browser read and its date. leginfo.legislature.ca.gov
# serves a Cloudflare challenge (403, cf-mitigated: challenge) to every plain client
# since October 2026; row A-33 records the capture of the bill status page. openai.com
# is row N-12.
MANUAL_HOSTS = {
    "openai.com",
    "www.reddit.com",
    "leginfo.legislature.ca.gov",
}


def fetch(url: str) -> tuple[str, str]:
    alt = alternative(url)
    if urlparse(url).netloc in MANUAL_HOSTS:
        return url, "MANUAL"
    target = alt or url
    headers = {"User-Agent": UA, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and urlparse(target).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return url, f"{resp.status}"
    except urllib.error.HTTPError as e:
        return url, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 - every failure is reported, none is swallowed
        return url, f"ERROR {type(e).__name__}: {e}"


def main() -> int:
    # Root Markdown files are generated page mirrors. Nested Markdown belongs
    # to immutable downloaded evidence and keeps its original source context.
    documents = [*DOCS.rglob("*.html"), *DOCS.glob("*.md")]
    pages = {p: parse(p) for p in documents}
    failures: list[str] = []
    external: set[str] = set()
    own: set[str] = set()
    internal = 0
    for page, c in pages.items():
        for link in c.links:
            scheme = urlparse(link).scheme
            if link.startswith(BASE_URL):
                own.add(urldefrag(link)[0])
                parsed = urlparse(link[len(BASE_URL):])
                target = (DOCS / (unquote(parsed.path) or "index.html")).resolve()
                if not target.is_relative_to(DOCS.resolve()) or not target.is_file():
                    failures.append(f"{page.relative_to(DOCS)}: own-site link names no built file: {link}")
                elif parsed.fragment and unquote(parsed.fragment) not in pages.get(target, Collect()).ids:
                    failures.append(f"{page.relative_to(DOCS)}: missing anchor {link}")
                continue
            if scheme in ("http", "https"):
                external.add(urldefrag(link)[0])
                continue
            if scheme in ("mailto",):
                continue
            internal += 1
            parsed = urlparse(link)
            path, frag = unquote(parsed.path), unquote(parsed.fragment)
            target = (page.parent / path).resolve() if path else page
            if not target.is_relative_to(DOCS.resolve()) or not target.is_file():
                failures.append(f"{page.relative_to(DOCS)}: missing target {link}")
                continue
            if frag:
                ids = pages[target].ids if target in pages else set()
                if frag not in ids:
                    failures.append(f"{page.relative_to(DOCS)}: missing anchor {link}")
    print(f"internal links checked: {internal}; own-site links checked against docs/: {len(own)}")
    if "--external" in sys.argv[1:]:
        targets = external | (own if "--live" in sys.argv[1:] else set())
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = sorted(pool.map(fetch, sorted(targets)))
        for url, status in results:
            ok = status.isdigit() and 200 <= int(status) < 300
            if status == "MANUAL":
                print(f"MANUAL {'':>6}  {url}")
                continue
            print(f"{'ok  ' if ok else 'FAIL'} {status:>8}  {url}")
            if not ok:
                failures.append(f"external {status}: {url}")
        print(f"external links checked: {len(results)}")
    for f in failures:
        print(f"FAIL {f}")
    print("links: PASS" if not failures else f"links: {len(failures)} failure(s)")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
