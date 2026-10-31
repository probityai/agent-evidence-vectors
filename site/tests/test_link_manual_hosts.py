"""Hold the bot-wall list in tools/check_links.py to the contract its comment states."""

from functools import cache
from pathlib import Path

import pytest

import check_links

ROOT = Path(__file__).resolve().parent.parent
LEDGER = (ROOT / "CLAIMS.md").read_text(encoding="utf-8").lower()


@cache
def _linked_hosts() -> frozenset[str]:
    hosts: set[str] = set()
    # The root Markdown files mirror these pages and carry the same links; reading them
    # needs one pandoc call each, so the HTML alone is scanned.
    for page in check_links.DOCS.rglob("*.html"):
        for link in check_links.parse(page).links:
            parsed = check_links.urlparse(link)
            if parsed.scheme in ("http", "https"):
                hosts.add(parsed.netloc)
    return frozenset(hosts)


def _refuse(*_args, **_kwargs):
    raise AssertionError("a bot-walled host was fetched")


@pytest.mark.parametrize("host", sorted(check_links.MANUAL_HOSTS))
def test_manual_host_is_linked_and_recorded(host):
    assert host in _linked_hosts(), f"{host} is exempt from the link check but no page links it"
    label = host.removeprefix("www.").split(".")[0]
    assert label in LEDGER, f"{host} is exempt from the link check but no ledger row names it"


@pytest.mark.parametrize("host", sorted(check_links.MANUAL_HOSTS))
def test_manual_host_is_never_fetched(host, monkeypatch):
    monkeypatch.setattr(check_links.urllib.request, "urlopen", _refuse)
    assert check_links.fetch(f"https://{host}/any") == (f"https://{host}/any", "MANUAL")


@pytest.mark.parametrize(
    "url",
    [
        "https://www.reddit.com/r/ClaudeAI/comments/1pgxckk/claude_cli_deleted_my_entire_home_directory_wiped/",
        "https://leginfo.legislature.ca.gov/faces/billStatusClient.xhtml?bill_id=202520260SB53",
    ],
)
def test_runner_refused_links_are_manual(url, monkeypatch):
    monkeypatch.setattr(check_links.urllib.request, "urlopen", _refuse)
    assert check_links.fetch(url)[1] == "MANUAL"
