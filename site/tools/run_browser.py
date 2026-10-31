"""Project retained Lab records into readable navigation without grading them."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "data/lab-register.json"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
RESULT = re.compile(r"[a-z][a-z0-9-]*\Z")


def text(value: str) -> str:
    """Keep source text literal in Markdown paragraphs, tables and headings."""
    if type(value) is not str:
        raise ValueError("register text must be a string")
    escaped = re.sub(r"([\\`*_{}\[\]()!#])", r"\\\1", html.escape(value, quote=False))
    return escaped.replace("|", "&#124;").replace("\n", "<br />")


def destination(value: str) -> str:
    """Resolve register-relative links from a top-level site page."""
    if type(value) is not str or not value or any(c.isspace() or c in '<>"\\()' for c in value):
        raise ValueError("invalid record destination")
    parts = urlsplit(value)
    if parts.scheme:
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise ValueError("record links must use HTTPS")
        return value
    if parts.netloc or not value.startswith("../"):
        raise ValueError("expected register-relative destination")
    target = value[3:]
    target_parts = urlsplit(target)
    if target_parts.scheme or target_parts.netloc:
        raise ValueError("destination changes the link scheme")
    path = target_parts.path
    if unquote(path) != path or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("destination escapes the site")
    return target


def records(data: dict) -> list[dict]:
    """Validate the fields this presentation consumes, without changing records."""
    if type(data) is not dict or type(data.get("records")) is not list or not data["records"]:
        raise ValueError("a nonempty Lab register is required")
    seen = set()
    for record in data["records"]:
        if type(record) is not dict or type(record.get("id")) is not str or not IDENTIFIER.fullmatch(record["id"]):
            raise ValueError("invalid record identifier")
        if record["id"] in seen:
            raise ValueError("duplicate record identifier")
        seen.add(record["id"])
        for key in ("evidenceClaim", "reviewState"):
            text(record[key])
        if type(record.get("roles")) is not dict or type(record.get("limits")) is not list or type(record.get("claimResults")) is not list:
            raise ValueError("invalid record presentation fields")
        for key, value in record["roles"].items():
            text(key); text(value)
        for value in record["limits"]:
            text(value)
        for claim in record["claimResults"]:
            if type(claim) is not dict or type(claim.get("result")) is not str or not RESULT.fullmatch(claim["result"]):
                raise ValueError("invalid per-claim result")
            text(claim["claim"])
        for key in ("report", "provenance", "contract"):
            destination(record[key])
        if "experiment" in record:
            destination(record["experiment"])
        for key in ("answerExposure", "comparisonOrder"):
            if key in record:
                text(record[key])
    return data["records"]


def markdown(data: dict) -> str:
    """Render every selected fact literally; a result token is not a run grade."""
    selected = records(data)
    tokens = sorted({claim["result"] for record in selected for claim in record["claimResults"]})
    options = "".join(f'<option value="{token}">{token}</option>' for token in tokens)
    lines = [
        '<form id="run-filters" class="run-filters" hidden>',
        '<label for="run-search">Search records, claims, roles or limits</label>',
        '<input id="run-search" type="search" autocomplete="off" aria-controls="run-records" />',
        '<label for="run-result">Contains a per-claim result</label>',
        f'<select id="run-result" aria-controls="run-records"><option value="">All result tokens</option>{options}</select>',
        '<button type="reset">Clear filters</button>',
        '<p id="run-count" role="status" aria-live="polite"></p>',
        '</form>',
        '',
        '<p id="run-empty" hidden>No retained record matches these filters. Clear filters or use another search term.</p>',
        '',
        '::: {#run-records}',
        '',
    ]
    for record in selected:
        values = sorted({claim["result"] for claim in record["claimResults"]})
        lines += [f'::: {{.run-record data-results="{" ".join(values)}"}}', '',
                  f'## {text(record["id"])} {{#record-{record["id"]}}}', '',
                  f'Claim scope: {text(record["evidenceClaim"])}', '',
                  f'Review state: {text(record["reviewState"])}', '',
                  f'Open [Report]({destination(record["report"])}), [Provenance]({destination(record["provenance"])}) and [Contract]({destination(record["contract"])}).', '']
        if "experiment" in record:
            lines += [f'[Recorded procedure]({destination(record["experiment"])})', '']
        lines += ['### Per-claim results', '', '| Claim | Recorded result |', '| --- | --- |']
        lines += [f'| {text(claim["claim"])} | {text(claim["result"])} |' for claim in record["claimResults"]]
        lines += ['', '### Roles', '', '| Role | Declaration |', '| --- | --- |']
        lines += [f'| {text(key)} | {text(value)} |' for key, value in record["roles"].items()]
        lines += ['', '### Limits', '']
        lines += [f'- {text(value)}' for value in record["limits"]]
        for key in ("answerExposure", "comparisonOrder"):
            if key in record:
                lines += ['', f'{key}: {text(record[key])}']
        lines += ['', ':::', '']
    lines += [':::', '']
    return '\n'.join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--register", type=Path, default=REGISTER)
    args = parser.parse_args()
    raw = args.register.read_bytes()
    selected = records(json.loads(raw))
    print(json.dumps({"register_sha256": hashlib.sha256(raw).hexdigest(), "record_ids": [record["id"] for record in selected], "records": len(selected), "per_claim_result_tokens": sorted({claim["result"] for record in selected for claim in record["claimResults"]}), "aggregate_verdict": "not-computed"}, sort_keys=True))


if __name__ == "__main__":
    main()
