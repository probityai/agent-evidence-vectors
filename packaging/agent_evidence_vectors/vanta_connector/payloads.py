"""Build the Vanta custom-resource records and request plans from verifier reports.

Pure functions: nothing here reads the network, the environment or the clock, so the
exact bytes that would be sent can be printed and compared.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

TOKEN_PATH = "/oauth/token"
RESOURCE_PATH = "/v1/resources/custom_resource"
SCOPE = "connectors.self:write-resource"
DEFAULT_API_BASE = "https://api.vanta.com"
DEFAULT_EXTERNAL_URL = "https://github.com/probityai/agent-evidence-vectors"
SECRET_PLACEHOLDER = "<VANTA_CLIENT_SECRET>"
TOKEN_PLACEHOLDER = "<access_token>"
MAX_FAILING_LISTED = 20

# The schema pasted into the Vanta Dashboard when the custom resource is defined
# (Resources tab, Add resource, Custom resource). JSON Type Definition, as Vanta documents.
JTD_SCHEMA: dict[str, Any] = {
    "properties": {
        "corpus": {"type": "string"},
        "suiteVersion": {"type": "string"},
        "corpusDigest": {"type": "string"},
        "vectors": {"type": "int32"},
        "pass": {"type": "int32"},
        "fail": {"type": "int32"},
        "notExercised": {"type": "int32"},
        "suiteRefusals": {"type": "int32"},
        "allPass": {"type": "boolean"},
        "failingVectors": {"type": "string"},
        "verifier": {"type": "string"},
        "packageVersion": {"type": "string"},
        "lastRun": {"type": "timestamp"},
    }
}

# Custom Tests are authored in the Dashboard; Vanta has no API for them.
CUSTOM_TEST_RULE = "allPass equals true"
CUSTOM_TEST_NAME = "Agent-evidence verifier passes its conformance corpus"
CUSTOM_TEST_DESCRIPTION = (
    "The pinned agent-evidence verifier reproduced every expected verdict and failure code "
    "of the conformance corpus, with no vector skipped and no suite refusal."
)


class ReportError(ValueError):
    """A verifier report is missing a member a verdict needs."""


@dataclass(frozen=True)
class HttpPlan:
    """One HTTP request exactly as it would be sent, secrets replaced by placeholders."""

    method: str
    url: str
    headers: dict[str, str]
    body: dict[str, Any]

    def render(self) -> str:
        lines = [f"{self.method} {self.url}"]
        lines += [f"{name}: {value}" for name, value in self.headers.items()]
        lines.append("")
        lines.append(json.dumps(self.body, indent=2, sort_keys=True))
        return "\n".join(lines)


def _count(totals: dict[str, Any], key: str) -> int:
    value = totals.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportError(f"report totals.{key} is {value!r}, not a count")
    return value


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReportError(f"report {where} is {value!r}, not a non-empty string")
    return value


def _failing(report: dict[str, Any]) -> list[str]:
    """Identifiers of the vectors that did not pass, from either report shape."""
    if isinstance(report.get("vectors"), list):
        return sorted(str(v.get("id")) for v in report["vectors"] if v.get("status") != "PASS")
    failures = report.get("failures")
    if not isinstance(failures, list):
        raise ReportError("report carries neither a vectors list nor a failures list")
    return sorted(
        str(f.get("id") or f.get("file")) if isinstance(f, dict) else str(f) for f in failures
    )


def _not_exercised(report: dict[str, Any], totals: dict[str, Any]) -> int:
    """The count of vectors skipped; absent is derived from the executed count or refused."""
    if "notExercised" in totals:
        return _count(totals, "notExercised")
    verifier = report.get("verifier")
    executed = verifier.get("vectorsExecuted") if isinstance(verifier, dict) else None
    if isinstance(executed, int) and not isinstance(executed, bool):
        return max(_count(totals, "vectors") - executed, 0)
    raise ReportError("report states neither totals.notExercised nor verifier.vectorsExecuted")


def _verifier_label(report: dict[str, Any]) -> str:
    verifier = report.get("verifier")
    if isinstance(verifier, dict):
        verifier = verifier.get("command")
    return str(verifier or report.get("rail") or "reference")


def _corpus(report: dict[str, Any]) -> dict[str, Any]:
    corpus = report.get("corpus")
    return corpus if isinstance(corpus, dict) else {}


def _suite_version(report: dict[str, Any], suite: str) -> str:
    revision = _corpus(report).get("suiteRevision")
    if isinstance(revision, int) and not isinstance(revision, bool):
        return str(revision)
    return suite.partition("/")[2] or "unstated"


def _slug(suite: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", suite).strip("-")


def record_from_report(
    report: dict[str, Any], *, run_timestamp: str, package_version: str, external_url: str
) -> dict[str, Any]:
    """One Vanta custom-resource record for one verifier report (either rail shape)."""
    if not isinstance(report, dict) or not isinstance(report.get("totals"), dict):
        raise ReportError("report is not an object with a totals object")
    totals = report["totals"]
    suite = _text(report.get("suite"), "suite")
    digest = _corpus(report).get("corpusDigest") or report.get("corpusDigest")
    vectors, fail = _count(totals, "vectors"), _count(totals, "fail")
    passed = _count(totals, "pass" if "pass" in totals else "conform")
    skipped, refusals = _not_exercised(report, totals), _count(totals, "suiteRefusals")
    failing = _failing(report)
    all_pass = (
        vectors > 0
        and passed == vectors
        and fail == 0
        and skipped == 0
        and refusals == 0
        and not failing
    )
    listed = failing[:MAX_FAILING_LISTED]
    if len(failing) > MAX_FAILING_LISTED:
        listed.append(f"+{len(failing) - MAX_FAILING_LISTED} more")
    return {
        "displayName": f"agent-evidence-vectors {suite}",
        "uniqueId": f"aev-{_slug(suite)}",
        "externalUrl": external_url,
        "customProperties": {
            "corpus": suite,
            "suiteVersion": _suite_version(report, suite),
            "corpusDigest": _text(digest, "corpusDigest"),
            "vectors": vectors,
            "pass": passed,
            "fail": fail,
            "notExercised": skipped,
            "suiteRefusals": refusals,
            "allPass": all_pass,
            "failingVectors": ",".join(listed),
            "verifier": _verifier_label(report),
            "packageVersion": package_version,
            "lastRun": run_timestamp,
        },
    }


def resource_body(resource_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    """The PUT body. Vanta treats it as the full state, so it carries every record."""
    ids = [r["uniqueId"] for r in records]
    if len(set(ids)) != len(ids):
        raise ReportError(f"two reports share a corpus name: {sorted(ids)}")
    return {"resourceId": resource_id, "resources": records}


def plan_requests(api_base: str, resource_id: str, records: list[dict[str, Any]]) -> list[HttpPlan]:
    """The token request and the resource push, with secrets replaced by placeholders."""
    base = api_base.rstrip("/")
    token = HttpPlan(
        "POST",
        base + TOKEN_PATH,
        {"Content-Type": "application/json"},
        {
            "client_id": "<VANTA_CLIENT_ID>",
            "client_secret": SECRET_PLACEHOLDER,
            "scope": SCOPE,
            "grant_type": "client_credentials",
        },
    )
    push = HttpPlan(
        "PUT",
        base + RESOURCE_PATH,
        {"Authorization": f"Bearer {TOKEN_PLACEHOLDER}", "Content-Type": "application/json"},
        resource_body(resource_id, records),
    )
    return [token, push]
